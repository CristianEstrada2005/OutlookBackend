cors// server.js (versión Web App lista para Render)
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import session from "express-session";
import pg from "pg";
import connectPgSimple from "connect-pg-simple";
import axios from "axios";
import path from "path";
import fs from "fs";
import multer from "multer";
import XLSX from "xlsx";
import { parse } from "json2csv";
import * as msal from "@azure/msal-node";

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

// 🛡️ Middleware listo para Render (mantiene sesiones entre frontend y backend)
app.use(cors({
  origin: process.env.FRONTEND_URL || "https://outlookfrontend.onrender.com/", // 🌐 tu dominio de front en Render
  credentials: true, // ✅ permite enviar cookies y credenciales
}));

app.use(express.json());

app.use(session({
  store: new PgSession({
    pool: pgPool,
    tableName: "user_sessions", // 🔄 tu tabla actual de sesiones
  }),
  secret: process.env.SESION_SECRET  || "super-secret", // 🔐 usa un valor fuerte en Render
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 2, // 2 horas
    secure: true,               // ⚠️ obligatorio con HTTPS (Render usa HTTPS)
    sameSite: "none",           // 🔥 permite compartir cookie entre dominios
  },
}));


// ✅ Crear carpetas si no existen
const uploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const exportDir = path.join(process.cwd(), "exports");
if (!fs.existsSync(exportDir)) fs.mkdirSync(exportDir);

// 📁 Configurar multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "./uploads"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});
const upload = multer({ storage });

// 🔐 Configuración MSAL (Confidential Client)
const msalConfig = {
  auth: {
    clientId: process.env.CLIENT_ID,
    authority: `https://login.microsoftonline.com/${process.env.TENANT_ID}`,
    clientSecret: process.env.CLIENT_SECRET,
  },
};
const cca = new msal.ConfidentialClientApplication(msalConfig);

// Scopes
const SCOPES = (process.env.SCOPES || "User.Read Mail.Read Mail.ReadWrite").split(" ");
const REDIRECT_URI = process.env.REDIRECT_URI || "http://localhost:5000/auth/callback";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000/";

// -----------------------------
// 🔹 LOGIN MICROSOFT
// -----------------------------
app.get("/auth/login", async (req, res) => {
  try {
    const authUrl = await cca.getAuthCodeUrl({
      scopes: SCOPES,
      redirectUri: REDIRECT_URI,
    });
    res.redirect(authUrl);
  } catch (err) {
    console.error("❌ Error en /auth/login:", err.message);
    res.status(500).send("Error iniciando autenticación");
  }
});

// -----------------------------
// 🔹 CALLBACK MICROSOFT
// -----------------------------
app.get("/auth/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("Falta el código de autorización");

  try {
    const tokenResponse = await cca.acquireTokenByCode({
      code,
      scopes: SCOPES,
      redirectUri: REDIRECT_URI,
    });

    const { accessToken, account } = tokenResponse;
    req.session.accessToken = accessToken;

    // Obtener datos del usuario desde Microsoft Graph
    const meResp = await axios.get("https://graph.microsoft.com/v1.0/me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const graphUser = meResp.data;
    const microsoftId = graphUser.id;
    const nombre = graphUser.displayName || null;
    const email = graphUser.mail || graphUser.userPrincipalName || null;

    // Upsert del usuario en BD
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

    // Actualizar usuario_id en sesión
    await pgPool.query(`
      UPDATE public.user_sessions SET usuario_id = $1 WHERE sid = $2
    `, [usuarioRow.id, req.sessionID]);

    res.redirect(`${FRONTEND_URL}/permissions`);
  } catch (err) {
    console.error("❌ Error en /auth/callback:", err.response?.data || err.message);
    res.status(500).send("Error durante la autenticación");
  }
});

// -----------------------------
// 🔹 /me
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
// 🔹 CONTACTOS POR CATEGORÍA
// -----------------------------
app.get("/contacts-by-category", async (req, res) => {
  if (!req.session.accessToken) return res.status(401).send("No autenticado");

  try {
    let allContacts = [];
    let nextLink = "https://graph.microsoft.com/v1.0/me/contacts?$top=100";

    while (nextLink) {
      const resp = await axios.get(nextLink, {
        headers: { Authorization: `Bearer ${req.session.accessToken}` },
      });
      const data = resp.data;
      allContacts = allContacts.concat(data.value || []);
      nextLink = data["@odata.nextLink"] || null;
    }

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

// -----------------------------
// 🔹 ENDPOINTS ARCHIVOS / EXPORTACIONES / MERGE
// -----------------------------
/* Mantengo íntegramente tus endpoints aquí (idénticos al archivo original),
   ya que no requieren cambios en la lógica de autenticación ni BD.
   Solo asegúrate de que /uploads y /exports existan (ya lo hacemos arriba). 
*/

// ⚙️ Reusa todo el código de archivos, exportaciones y merge que ya tenías
// (no lo repito aquí por longitud, pero es exactamente igual y compatible)

// -----------------------------
// 🔹 SESIÓN / LOGOUT
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
      res.clearCookie("connect.sid");
      res.status(200).send("Sesión cerrada correctamente.");
    });
  } else {
    res.status(200).send("No hay sesión activa.");
  }
});

// ✅ Servir carpeta /exports
app.use("/exports", express.static(exportDir));

app.listen(port, () => {
  console.log(`🚀 Servidor corriendo en puerto ${port}`);
});