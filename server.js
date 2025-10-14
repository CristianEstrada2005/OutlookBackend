// server.js (versión final Render con PKCE seguro)
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

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// -------------------- CORS --------------------
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "https://tufrontend.onrender.com",
    credentials: true,
  })
);

// -------------------- BASE DE DATOS (PostgreSQL) --------------------
const { Pool } = pg;
const pgSession = connectPgSimple(session);

const pool = new Pool({
  connectionString: `postgresql://${process.env.PG_USER}:${process.env.PG_PASSWORD}@${process.env.PG_HOST}/${process.env.PG_DATABASE}?sslmode=${process.env.PGSSLMODE}`,
  ssl: { rejectUnauthorized: false },
});

// -------------------- SESIONES --------------------
app.set("trust proxy", 1); // necesario para cookies seguras en Render

app.use(
  session({
    store: new pgSession({ pool }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true, // HTTPS obligatorio
      sameSite: "none", // Permitir cookies cross-domain
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 día
    },
  })
);

// -------------------- VARIABLES DE ENTORNO --------------------
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const TENANT_ID = process.env.TENANT_ID || "common"; // aceptar cualquier cuenta
const REDIRECT_URI =
  process.env.REDIRECT_URI ||
  "https://outlookbackend.onrender.com/auth/callback";
const SCOPES =
  process.env.SCOPES ||
  "User.Read Mail.Read Mail.ReadWrite offline_access";
const FRONTEND_URL =
  process.env.FRONTEND_URL || "https://tufrontend.onrender.com";

// -------------------- RUTAS PRINCIPALES --------------------
app.get("/", (req, res) => {
  res.send("Servidor funcionando en Render 🚀");
});

// -------------------- LOGIN (PKCE + state) --------------------
app.get("/auth/login", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  const codeVerifier = crypto.randomBytes(64).toString("hex");

  // PKCE: crear code_challenge con SHA256
  const base64URLEncode = (str) =>
    str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const sha256 = (buffer) =>
    crypto.createHash("sha256").update(buffer).digest("base64");
  const codeChallenge = base64URLEncode(sha256(codeVerifier));

  // Guardar valores en la sesión
  req.session.codeVerifier = codeVerifier;
  req.session.state = state;

  console.log("🧩 Estado generado:", state);

  const params = querystring.stringify({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    response_mode: "query",
    scope: SCOPES,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

  const authUrl = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize?${params}`;
  res.redirect(authUrl);
});

// -------------------- CALLBACK --------------------
app.get("/auth/callback", async (req, res) => {
  const { code, state } = req.query;
  console.log("🔄 Estado recibido:", state, "| Estado guardado:", req.session.state);

  if (!code || !state) {
    return res.status(400).send("Falta el código o el estado en la respuesta.");
  }

  if (state !== req.session.state) {
    return res.status(400).send("El estado no coincide, posible ataque CSRF.");
  }

  try {
    const tokenResponse = await axios.post(
      `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`,
      querystring.stringify({
        client_id: CLIENT_ID,
        scope: SCOPES,
        code,
        redirect_uri: REDIRECT_URI,
        grant_type: "authorization_code",
        code_verifier: req.session.codeVerifier, // PKCE real
        client_secret: CLIENT_SECRET,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const { access_token, id_token, refresh_token } = tokenResponse.data;

    req.session.accessToken = access_token;
    req.session.idToken = id_token;
    req.session.refreshToken = refresh_token;

    const user = jwt.decode(id_token);
    req.session.user = user;

    console.log("✅ Usuario autenticado:", user?.name || "sin nombre");
    res.redirect(`${FRONTEND_URL}?login=success`);
  } catch (err) {
    console.error("❌ Error en el callback:", err.response?.data || err.message);
    res.status(500).send("Error en la autenticación con Microsoft.");
  }
});

// -------------------- CERRAR SESIÓN --------------------
app.get("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect(FRONTEND_URL);
  });
});

// -------------------- RUTA DE PRUEBA TOKEN --------------------
app.get("/me", async (req, res) => {
  if (!req.session.accessToken) {
    return res.status(401).json({ error: "No autenticado" });
  }

  try {
    const response = await axios.get("https://graph.microsoft.com/v1.0/me", {
      headers: { Authorization: `Bearer ${req.session.accessToken}` },
    });
    res.json(response.data);
  } catch (error) {
    console.error("Error obteniendo datos del usuario:", error.message);
    res.status(500).send("Error al obtener datos del usuario.");
  }
});

// -------------------- ARRANQUE DEL SERVIDOR --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en Render puerto ${PORT}`);
});
