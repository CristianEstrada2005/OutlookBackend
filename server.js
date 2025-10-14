// server.js - Render optimizado con PKCE y sesiones
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
    origin: process.env.FRONTEND_URL,
    credentials: true,
  })
);

// -------------------- BASE DE DATOS --------------------
const { Pool } = pg;
const pgSession = connectPgSimple(session);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Render te da DATABASE_URL
  ssl: { rejectUnauthorized: false },
});

// -------------------- SESIONES --------------------
app.set("trust proxy", 1); // necesario en Render

app.use(
  session({
    store: new pgSession({ pool }),
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,        // Render usa HTTPS
      sameSite: "none",    // necesario para cross-domain
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 día
    },
  })
);

// -------------------- VARIABLES DE ENTORNO --------------------
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const TENANT_ID = process.env.TENANT_ID || "common";
const REDIRECT_URI =
  process.env.REDIRECT_URI || "https://outlookbackend.onrender.com/auth/callback";
const SCOPES =
  process.env.SCOPES || "User.Read Mail.Read Mail.ReadWrite offline_access";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://tufrontend.onrender.com";

// -------------------- RUTAS --------------------
app.get("/", (req, res) => res.send("Servidor funcionando en Render 🚀"));

// -------------------- LOGIN (PKCE + state) --------------------
app.get("/auth/login", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  const codeVerifier = crypto.randomBytes(64).toString("hex");

  // PKCE: code_challenge
  const base64URLEncode = (str) => str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const sha256 = (buffer) => crypto.createHash("sha256").update(buffer).digest("base64");
  const codeChallenge = base64URLEncode(sha256(codeVerifier));

  req.session.codeVerifier = codeVerifier;
  req.session.state = state;

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

  res.redirect(`https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize?${params}`);
});

// -------------------- CALLBACK --------------------
app.get("/auth/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) return res.status(400).send("Falta código o estado.");

  if (state !== req.session.state) return res.status(400).send("Estado no coincide.");

  try {
    const tokenResponse = await axios.post(
      `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`,
      querystring.stringify({
        client_id: CLIENT_ID,
        scope: SCOPES,
        code,
        redirect_uri: REDIRECT_URI,
        grant_type: "authorization_code",
        code_verifier: req.session.codeVerifier,
        client_secret: CLIENT_SECRET,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const { access_token, id_token, refresh_token } = tokenResponse.data;

    req.session.accessToken = access_token;
    req.session.idToken = id_token;
    req.session.refreshToken = refresh_token;
    req.session.user = jwt.decode(id_token);

    res.redirect(`${FRONTEND_URL}?login=success`);
  } catch (err) {
    console.error("Error callback:", err.response?.data || err.message);
    res.status(500).send("Error en la autenticación con Microsoft.");
  }
});

// -------------------- LOGOUT --------------------
app.get("/auth/logout", (req, res) => {
  req.session.destroy(() => res.redirect(FRONTEND_URL));
});

// -------------------- RUTA PRUEBA --------------------
app.get("/me", async (req, res) => {
  if (!req.session.accessToken) return res.status(401).json({ error: "No autenticado" });

  try {
    const response = await axios.get("https://graph.microsoft.com/v1.0/me", {
      headers: { Authorization: `Bearer ${req.session.accessToken}` },
    });
    res.json(response.data);
  } catch (err) {
    console.error("Error obteniendo usuario:", err.message);
    res.status(500).send("Error al obtener datos del usuario.");
  }
});

// -------------------- INICIO --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor corriendo en Render puerto ${PORT}`));
