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
const port = 5000;

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
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(express.json());
app.use(session({
  store: new PgSession({ pool: pgPool, tableName: "user_sessions" }),
  secret: "super-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 2,
    secure: false,
    sameSite: "lax",
  },
}));

// 🔐 Configuración OAuth
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET; // opcional si usas PKCE puro
const REDIRECT_URI = "http://localhost:5000/auth/callback";
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

// 🧮 Funciones para PKCE
function base64URLEncode(str) {
  return str.toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}
function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest();
}

// 🧭 Paso 1: Redirigir al login de Microsoft
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

// 🧭 Paso 2: Callback para recibir el authorization code
app.get("/auth/callback", async (req, res) => {
  const code = req.query.code;
  const verifier = req.session.code_verifier;

  if (!code || !verifier) {
    return res.status(400).send("Código o verificador faltante");
  }

  try {
    const tokenResponse = await axios.post(`${AUTHORITY}/oauth2/v2.0/token`, querystring.stringify({
      client_id: CLIENT_ID,
      scope: SCOPES.join(" "),
      code,
      redirect_uri: REDIRECT_URI,
      grant_type: "authorization_code",
      code_verifier: verifier,
    }), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    const { access_token, refresh_token, id_token } = tokenResponse.data;

    req.session.accessToken = access_token;
    req.session.refreshToken = refresh_token;
    req.session.idToken = id_token;

    const decoded = jwt.decode(access_token);
    console.log("✅ Token recibido y guardado en sesión");
    console.log("👤 Usuario:", decoded?.name || decoded?.preferred_username);
    console.log("🔍 Scopes:", decoded?.scp);
    console.log("🔍 Expira:", new Date(decoded?.exp * 1000).toLocaleString());

    // 👇 Redirige al frontend directamente
    res.redirect("http://localhost:3000/permissions");
  } catch (err) {
    console.error("❌ Error en /auth/callback:", err.response?.data || err.message);
    res.status(500).send("Error al intercambiar código por token");
  }
});

// 👤 Endpoint protegido /me
app.get("/me", async (req, res) => {
  if (!req.session.accessToken) return res.status(401).send("No autenticado");

  try {
    const response = await axios.get("https://graph.microsoft.com/v1.0/me", {
      headers: { Authorization: `Bearer ${req.session.accessToken}` },
    });
    res.json(response.data);
  } catch (err) {
    console.error("❌ Error en /me:", err.response?.data || err.message);
    res.status(500).send("Error al obtener usuario");
  }
});

// 📇 Contactos agrupados por categoría
app.get("/contacts-by-category", async (req, res) => {
  if (!req.session.accessToken) return res.status(401).send("No autenticado");

  try {
    const response = await axios.get("https://graph.microsoft.com/v1.0/me/contacts", {
      headers: { Authorization: `Bearer ${req.session.accessToken}` },
    });

    const contacts = response.data.value || [];
    const grouped = {};

    contacts.forEach((contact) => {
      const categories = contact.categories?.length ? contact.categories : ["Sin categoría"];
      categories.forEach((cat) => {
        if (!grouped[cat]) grouped[cat] = [];
        grouped[cat].push({
          nombre: contact.displayName,
          correo: contact.emailAddresses?.[0]?.address || "Sin correo",
        });
      });
    });

    res.json(grouped);
  } catch (err) {
    console.error("❌ Error en /contacts-by-category:", err.response?.data || err.message);
    res.status(500).send("Error al obtener contactos");
  }
});

// 🧪 Verificación de sesión
app.get("/session-check", (req, res) => {
  res.json({ token: req.session.accessToken || null });
});

app.listen(port, () => {
  console.log(`🚀 Backend corriendo en http://localhost:${port}`);
  console.log("➡️ Abre http://localhost:5000/auth/login para iniciar login con Microsoft");
});
