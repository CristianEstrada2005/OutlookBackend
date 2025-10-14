// server.js (versión final con /archivos y /exportaciones)
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import session from "express-session";
import pg from "pg";
import connectPgSimple from "connect-pg-simple";
import axios from "axios";
import crypto from "crypto";
import querystring from "querystring";
import jwt from "jsonwebtoken";
import multer from "multer";
import fs from "fs";
import XLSX from "xlsx";
import { parse } from "json2csv"; // npm i json2csv
import path from "path";

dotenv.config();
const app = express();
const port = process.env.PORT || 5000;


// 🧠 PostgreSQL session store
const PgSession = connectPgSimple(session);
const pgPool = new pg.Pool({
  host: process.env.PG_HOST,
  port: process.env.PG_PORT,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DATABASE,
});

// 🛡️ Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true,
}));

const sessionSecret = process.env.SESSION_SECRET;

app.use(session({
  store: new PgSession({ pool: pgPool, tableName: "user_sessions" }),
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 2,
    secure: false,        // en local; en producción usar true
    sameSite: "none",     // para permitir cookies cross-site
  },
}));



// 📁 Configurar multer para manejar archivos subidos
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "./uploads"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});
const upload = multer({ storage });

// 🔐 Configuración OAuth
const CLIENT_ID = process.env.CLIENT_ID;
const REDIRECT_URI = process.env.REDIRECT_URI;
const AUTHORITY = "https://login.microsoftonline.com/common";
const SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
  "User.Read",
  "Contacts.Read",
  "Contacts.ReadWrite"
];

// Funciones PKCE
function base64URLEncode(str) {
  return str.toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest();
}

// -----------------------------
// Login con Microsoft
// -----------------------------
app.get("/auth/login", async (req, res) => {
  const verifier = base64URLEncode(crypto.randomBytes(32));
  const challenge = base64URLEncode(sha256(verifier));
  req.session.code_verifier = verifier;

  const params = {
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    response_mode: "query",
    scope: SCOPES.join(" "),
    code_challenge: challenge,
    code_challenge_method: "S256",
  };
  const authorizeUrl = `${AUTHORITY}/oauth2/v2.0/authorize?${querystring.stringify(params)}`;
  res.redirect(authorizeUrl);
});

// -----------------------------
// Callback Microsoft
// -----------------------------
app.get("/auth/callback", async (req, res) => {
  const code = req.query.code;
  const verifier = req.session.code_verifier;
  if (!code || !verifier) return res.status(400).send("Código o verificador faltante");

  try {
    const tokenResponse = await axios.post(`${AUTHORITY}/oauth2/v2.0/token`,
      querystring.stringify({
        client_id: CLIENT_ID,
        scope: SCOPES.join(" "),
        code,
        redirect_uri: REDIRECT_URI,
        grant_type: "authorization_code",
        code_verifier: verifier,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const { access_token, refresh_token, id_token } = tokenResponse.data;
    req.session.accessToken = access_token;
    req.session.refreshToken = refresh_token;
    req.session.idToken = id_token;

    // Obtener info del usuario desde Microsoft Graph
    const meResp = await axios.get("https://graph.microsoft.com/v1.0/me", {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const graphUser = meResp.data;
    const microsoftId = graphUser.id;
    const nombre = graphUser.displayName || null;
    const email = graphUser.mail || graphUser.userPrincipalName || null;

    // Upsert en tabla usuario
    const upsertQuery = `
      INSERT INTO public.usuario (nombre, email, microsoft_id)
      VALUES ($1, $2, $3)
      ON CONFLICT (microsoft_id)
      DO UPDATE SET nombre = EXCLUDED.nombre, email = EXCLUDED.email
      RETURNING id, nombre, email, microsoft_id;
    `;
    const result = await pgPool.query(upsertQuery, [nombre, email, microsoftId]);
    const usuarioRow = result.rows[0];

    req.session.user = {
      id: usuarioRow.id,
      nombre: usuarioRow.nombre,
      email: usuarioRow.email,
      microsoftId: usuarioRow.microsoft_id,
    };

    // Actualizar usuario_id en user_sessions
    try {
      await pgPool.query(`
        UPDATE public.user_sessions SET usuario_id = $1 WHERE sid = $2
      `, [usuarioRow.id, req.sessionID]);
    } catch (err) {
      console.error("⚠️ Error al actualizar usuario_id:", err.message);
    }

    res.redirect(`${process.env.FRONTEND_URL}/permissions`);

  } catch (err) {
    console.error("❌ Error en /auth/callback:", err.response?.data || err.message);
    res.status(500).send("Error al iniciar sesión");
  }
});

// -----------------------------
// Endpoint /me
// -----------------------------
app.get("/me", async (req, res) => {
  if (!req.session.accessToken) return res.status(401).send("No autenticado");
  try {
    const response = await axios.get("https://graph.microsoft.com/v1.0/me", {
      headers: { Authorization: `Bearer ${req.session.accessToken}` },
    });
    res.json({ graph: response.data, localUser: req.session.user || null });
  } catch (err) {
    console.error("❌ Error en /me:", err.message);
    res.status(500).send("Error al obtener usuario");
  }
});

// -----------------------------
// Contacts grouped by category
// -----------------------------
app.get("/contacts-by-category", async (req, res) => {
  if (!req.session.accessToken) return res.status(401).send("No autenticado");

  try {
    let allContacts = [];
    let nextLink = "https://graph.microsoft.com/v1.0/me/contacts?$top=100";

    // 🔁 Obtener todas las páginas
    while (nextLink) {
      const resp = await axios.get(nextLink, {
        headers: { Authorization: `Bearer ${req.session.accessToken}` },
      });
      const data = resp.data;
      allContacts = allContacts.concat(data.value || []);
      nextLink = data["@odata.nextLink"] || null;
    }

    console.log(`📬 Total contactos obtenidos: ${allContacts.length}`);

    // 🔹 Agrupar por categorías
    const grouped = {};
    allContacts.forEach((contact) => {
      const categories = contact.categories?.length ? contact.categories : ["Sin categoría"];
      categories.forEach((cat) => {
        if (!grouped[cat]) grouped[cat] = [];
        grouped[cat].push({
          nombre: contact.displayName || "Sin nombre",
          correo: contact.emailAddresses?.[0]?.address || "Sin correo",
        });
      });
    });

    res.json(grouped);
  } catch (err) {
    console.error("❌ Error en /contacts-by-category:", err.message);
    res.status(500).send("Error al obtener contactos");
  }
});

// ✅ Crear carpeta "uploads" automáticamente si no existe
const uploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// No need to redefine storage and upload here, already defined above.


// -----------------------------
// ✅ NUEVOS ENDPOINTS: /archivos
// -----------------------------

// 📤 POST /archivos → guarda archivo importado
app.post("/archivos", upload.single("archivo"), async (req, res) => {
  if (!req.session.user) return res.status(401).send("No autenticado");
  const usuarioId = req.session.user.id;
  const nombreArchivo = req.file.originalname;
  const rutaArchivo = req.file.path;
  const fuente = req.body.fuente || "Plataforma desconocida";

  try {
    await pgPool.query(`
      INSERT INTO public.archivos_importados (usuario_id, nombre_archivo, fuente, ruta_archivo)
      VALUES ($1, $2, $3, $4)
    `, [usuarioId, nombreArchivo, fuente, rutaArchivo]);
    res.status(201).json({ mensaje: "Archivo guardado correctamente", ruta: rutaArchivo });
  } catch (err) {
    console.error("❌ Error al guardar archivo:", err.message);
    res.status(500).send("Error al guardar archivo");
  }
});

// 📥 GET /archivos → listar archivos del usuario
app.get("/archivos", async (req, res) => {
  if (!req.session.user) return res.status(401).send("No autenticado");
  const usuarioId = req.session.user.id;
  try {
    const result = await pgPool.query(`
      SELECT id, nombre_archivo, fuente, ruta_archivo, fecha_subida
      FROM public.archivos_importados
      WHERE usuario_id = $1
      ORDER BY fecha_subida DESC
    `, [usuarioId]);
    res.json(result.rows);
  } catch (err) {
    console.error("❌ Error al obtener archivos:", err.message);
    res.status(500).send("Error al obtener archivos");
  }
});



// -----------------------------
// ✅ NUEVOS ENDPOINTS: /exportaciones
// -----------------------------

// 📤 POST /exportaciones → registra una nueva exportación CSV
app.post("/exportaciones", async (req, res) => {
  if (!req.session.user) return res.status(401).send("No autenticado");
  const usuarioId = req.session.user.id;
  const { nombre_categoria, ruta_csv } = req.body;

  if (!nombre_categoria || !ruta_csv) {
    return res.status(400).send("Faltan datos (nombre_categoria, ruta_csv)");
  }

  try {
    await pgPool.query(`
      INSERT INTO public.exportaciones_outlook (usuario_id, nombre_categoria, ruta_csv)
      VALUES ($1, $2, $3)
    `, [usuarioId, nombre_categoria, ruta_csv]);
    res.status(201).json({ mensaje: "Exportación registrada correctamente" });
  } catch (err) {
    console.error("❌ Error al guardar exportación:", err.message);
    res.status(500).send("Error al guardar exportación");
  }
});

// 📥 GET /exportaciones → listar exportaciones del usuario logueado
app.get("/exportaciones", async (req, res) => {
  if (!req.session.user) return res.status(401).send("No autenticado");
  const usuarioId = req.session.user.id;
  try {
    const result = await pgPool.query(`
      SELECT id, nombre_categoria, ruta_csv, fecha_creacion
      FROM public.exportaciones_outlook
      WHERE usuario_id = $1
      ORDER BY fecha_creacion DESC
    `, [usuarioId]);
    res.json(result.rows);
  } catch (err) {
    console.error("❌ Error al obtener exportaciones:", err.message);
    res.status(500).send("Error al obtener exportaciones");
  }
});


app.post("/merge-files", upload.array("files", 2), async (req, res) => {
  if (!req.session.user) return res.status(401).send("No autenticado");

  const usuarioId = req.session.user.id;
  const categoryName = req.body.categoryName || "NuevaCategoria";

  if (!req.files || req.files.length !== 2)
    return res.status(400).send("Debes subir exactamente dos archivos Excel");

  try {
    const [file1, file2] = req.files;

    // 💾 Registrar los archivos subidos en la BD
    for (const f of req.files) {
      await pgPool.query(
        `
        INSERT INTO public.archivos_importados (usuario_id, nombre_archivo, fuente, ruta_archivo)
        VALUES ($1, $2, $3, $4)
        `,
        [usuarioId, f.originalname, "Plataforma universitaria", f.path]
      );
    }

    // 🧩 Función para leer Excel de forma segura
    const leerExcelSeguros = (filePath) => {
      const wb = XLSX.readFile(filePath);
      const firstSheet = wb.Sheets[wb.SheetNames[0]];
      const data = XLSX.utils.sheet_to_json(firstSheet, { defval: "" });
      if (!data || data.length === 0) {
        throw new Error(`El archivo ${path.basename(filePath)} está vacío o no tiene datos válidos.`);
      }
      return data;
    };

    const data1 = leerExcelSeguros(file1.path);
    const data2 = leerExcelSeguros(file2.path);

    // ⚙️ Detección automática de Moodle / Galileo
    let moodle = [];
    let galileo = [];

    try {
      const data1Keys = Object.keys(data1[0] || {}).map(k => k.toLowerCase());
      const data2Keys = Object.keys(data2[0] || {}).map(k => k.toLowerCase());

      const data1EsMoodle = data1Keys.some(k => k.includes("apellido") || k.includes("dirección"));
      const data2EsMoodle = data2Keys.some(k => k.includes("apellido") || k.includes("dirección"));

      if (data1EsMoodle && !data2EsMoodle) {
        moodle = data1;
        galileo = data2;
      } else if (!data1EsMoodle && data2EsMoodle) {
        moodle = data2;
        galileo = data1;
      } else {
        console.warn("⚠️ No se pudo determinar cuál archivo es Moodle o Galileo. Se usará el orden por defecto.");
        moodle = data1;
        galileo = data2;
      }

      console.log("📄 Moodle columnas:", Object.keys(moodle[0]));
      console.log("📄 Galileo columnas:", Object.keys(galileo[0]));
    } catch (error) {
      console.error("❌ Error al detectar tipo de archivo:", error);
      return res.status(400).send("Error al analizar los encabezados de los archivos Excel.");
    }

    // 🧠 Procesar datos de Moodle
    const moodleData = moodle.map((m) => ({
      firstName: m["Nombre"]?.split(" ")[0] || "",
      middleName: m["Nombre"]?.split(" ").slice(1).join(" ") || "",
      lastName: m["Apellido(s)"] || "",
      email: m["Dirección de correo"] || "",
      phone: "",
      category: categoryName,
    }));

    // 🧠 Procesar datos de Galileo
    const galileoData = galileo
      .filter((g) => g["EMAIL"])
      .map((g) => ({
        firstName: g["NOMBRE"]?.split(" ")[1] || "",
        middleName: g["NOMBRE"]?.split(" ")[0] || "",
        lastName: g["NOMBRE"]?.split(" ").slice(2).join(" ") || "",
        email: g["EMAIL"] || "",
        phone: g["TELÉFONO"] || "",
        category: categoryName,
      }));

    // 🔗 Unir sin duplicados por email
    const combined = [...galileoData];
    const galileoEmails = galileoData.map((g) => g.email.toLowerCase());
    moodleData.forEach((m) => {
      if (m.email && !galileoEmails.includes(m.email.toLowerCase())) combined.push(m);
    });

    // 📑 Formato final Outlook
    const outlookData = combined.map((r) => ({
      "First Name": r.firstName,
      "Middle Name": r.middleName,
      "Last Name": r.lastName,
      "Mobile Phone": r.phone,
      "Categories": r.category,
      "E-mail Address": r.email,
    }));

    // 📦 Guardar CSV en carpeta /exports
    const csv = parse(outlookData);
    const exportDir = path.join(process.cwd(), "exports");
    if (!fs.existsSync(exportDir)) fs.mkdirSync(exportDir);
    const exportPath = path.join(exportDir, `${categoryName.replace(/\s+/g, "_")}.csv`);
    fs.writeFileSync(exportPath, csv, "utf8");

    // 💾 Registrar exportación en BD
    await pgPool.query(
      `
      INSERT INTO public.exportaciones_outlook (usuario_id, nombre_categoria, ruta_csv)
      VALUES ($1, $2, $3)
      `,
      [usuarioId, categoryName, exportPath]
    );

    console.log(`✅ CSV generado: ${exportPath}`);

    // 📤 Devolver respuesta JSON al frontend
    res.status(201).json({
      mensaje: "Archivos unificados correctamente",
      categoria: categoryName,
      totalRegistros: outlookData.length,
      csvPath: `/exports/${categoryName.replace(/\s+/g, "_")}.csv`,
    });
  } catch (error) {
    console.error("❌ Error al unir archivos:", error);
    res.status(500).json({ mensaje: "Error al procesar los archivos" });
  }
});


// 📥 GET /exportaciones/:id/download
// Permite descargar un CSV generado anteriormente
app.get("/exportaciones/:id/download", async (req, res) => {
  if (!req.session.user) return res.status(401).send("No autenticado");

  const usuarioId = req.session.user.id;
  const exportacionId = req.params.id;

  try {
    // Buscar la exportación en la base de datos
    const result = await pgPool.query(
      `
      SELECT ruta_csv, nombre_categoria
      FROM public.exportaciones_outlook
      WHERE id = $1 AND usuario_id = $2
      `,
      [exportacionId, usuarioId]
    );

    if (result.rowCount === 0)
      return res.status(404).send("No se encontró la exportación o no pertenece a este usuario.");

    const { ruta_csv, nombre_categoria } = result.rows[0];

    // Validar existencia del archivo
    const filePath = path.resolve(ruta_csv);
    if (!fs.existsSync(filePath)) {
      return res.status(404).send("El archivo CSV no existe en el servidor.");
    }

    // Forzar descarga con nombre amigable
    res.download(filePath, `${nombre_categoria}.csv`);
  } catch (error) {
    console.error("❌ Error en /exportaciones/:id/download:", error);
    res.status(500).send("Error al descargar la exportación.");
  }
});



// -----------------------------
// Verificación de sesión
// -----------------------------
app.get("/session-check", (req, res) => {
  res.json({ token: req.session.accessToken || null, localUser: req.session.user || null });
});

app.post("/logout", (req, res) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        console.error("❌ Error al cerrar sesión:", err);
        return res.status(500).send("Error al cerrar sesión.");
      }
      res.clearCookie("connect.sid"); // Elimina cookie del navegador
      res.status(200).send("Sesión cerrada correctamente.");
    });
  } else {
    res.status(200).send("No hay sesión activa.");
  }
});


// ✅ Servir carpeta "exports" de forma pública
const exportsPath = path.join(process.cwd(), "exports");
if (!fs.existsSync(exportsPath)) {
  fs.mkdirSync(exportsPath);
}
app.use("/exports", express.static(exportsPath));


app.listen(port, () => {
  console.log(`🚀 Backend corriendo en http://localhost:${port}`);
});
