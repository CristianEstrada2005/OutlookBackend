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
import * as msal from "@azure/msal-node";

dotenv.config();
const app = express();
const port = process.env.PORT || 5000;

// PostgreSQL session store
const PgSession = connectPgSimple(session);
const pgPool = new pg.Pool({
  host: process.env.PG_HOST,
  port: process.env.PG_PORT,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DATABASE,
});

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
}));
app.use(express.json());
app.use(session({
  store: new PgSession({ pool: pgPool, tableName: "user_sessions" }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 2, // 2 horas
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  },
}));

// Crear carpetas si no existen
const uploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const exportDir = path.join(process.cwd(), "exports");
if (!fs.existsSync(exportDir)) fs.mkdirSync(exportDir);

// Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "./uploads"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});
const upload = multer({ storage });

// MSAL
const cca = new msal.ConfidentialClientApplication({
  auth: {
    clientId: process.env.CLIENT_ID,
    authority: `https://login.microsoftonline.com/${process.env.TENANT_ID}`,
    clientSecret: process.env.CLIENT_SECRET,
  }
});

const SCOPES = process.env.SCOPES.split(" ");
const REDIRECT_URI = process.env.REDIRECT_URI;
const FRONTEND_URL = process.env.FRONTEND_URL;

// LOGIN
app.get("/auth/login", async (req, res) => {
  try {
    const authUrl = await cca.getAuthCodeUrl({ scopes: SCOPES, redirectUri: REDIRECT_URI });
    res.redirect(authUrl);
  } catch (err) {
    console.error("Error /auth/login:", err.message);
    res.status(500).send("Error iniciando autenticación");
  }
});

// CALLBACK
app.get("/auth/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("Falta el código de autorización");

  try {
    const tokenResponse = await cca.acquireTokenByCode({
      code,
      scopes: SCOPES,
      redirectUri: REDIRECT_URI,
    });

    console.log("Token response:", tokenResponse);

    req.session.accessToken = tokenResponse.accessToken;

    const meResp = await axios.get("https://graph.microsoft.com/v1.0/me", {
      headers: { Authorization: `Bearer ${tokenResponse.accessToken}` },
    });

    const { id: microsoftId, displayName: nombre, mail, userPrincipalName } = meResp.data;
    const email = mail || userPrincipalName || null;

    const result = await pgPool.query(`
      INSERT INTO public.usuario (nombre, email, microsoft_id)
      VALUES ($1, $2, $3)
      ON CONFLICT (microsoft_id)
      DO UPDATE SET nombre = EXCLUDED.nombre, email = EXCLUDED.email
      RETURNING id, nombre, email, microsoft_id;
    `, [nombre, email, microsoftId]);

    req.session.user = result.rows[0];

    await pgPool.query(`
      UPDATE public.user_sessions SET usuario_id = $1 WHERE sid = $2
    `, [req.session.user.id, req.sessionID]);

    // REDIRECT seguro
    if (FRONTEND_URL) res.redirect(`${FRONTEND_URL}permissions`);
    else res.send("Login completado. Puedes cerrar esta ventana.");

  } catch (err) {
    console.error("Error /auth/callback:", err.response?.data || err.message);
    res.status(500).send("Error durante la autenticación");
  }
});

// ME
app.get("/me", async (req, res) => {
  if (!req.session.accessToken) return res.status(401).send("No autenticado");
  try {
    const response = await axios.get("https://graph.microsoft.com/v1.0/me", {
      headers: { Authorization: `Bearer ${req.session.accessToken}` },
    });
    res.json({ graph: response.data, localUser: req.session.user || null });
  } catch (err) {
    console.error("Error /me:", err.message);
    res.status(500).send("Error al obtener usuario");
  }
});

// LOGOUT
app.post("/logout", (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) return res.status(500).send("Error al cerrar sesión");
      res.clearCookie("connect.sid");
      res.send("Sesión cerrada correctamente");
    });
  } else res.send("No hay sesión activa");
});

// Servir /exports
app.use("/exports", express.static(exportDir));

app.listen(port, () => console.log(`Servidor corriendo en puerto ${port}`));
