"use strict";

const crypto = require("node:crypto");
const path = require("node:path");
const express = require("express");
const session = require("express-session");
const connectPgSimple = require("connect-pg-simple");
const { Pool } = require("pg");

const app = express();
const port = Number(process.env.PORT || 3000);
const clientId = process.env.YANDEX_CLIENT_ID;
const clientSecret = process.env.YANDEX_CLIENT_SECRET;
const sessionSecret = process.env.SESSION_SECRET;
const databaseUrl = process.env.DATABASE_URL;
const redirectUri = "https://drop-me-fail.onrender.com/auth/yandex/callback";
const cookieName = "odmf.sid";
const sessionMaxAge = 7 * 24 * 60 * 60 * 1000;
const staticDir = path.join(__dirname, "DROP ME FAIL");

if (!clientId || !clientSecret || !sessionSecret || !databaseUrl) {
  console.error("Missing required environment variables: YANDEX_CLIENT_ID, YANDEX_CLIENT_SECRET, SESSION_SECRET, DATABASE_URL");
  process.exit(1);
}

const pool = new Pool({ connectionString: databaseUrl });
const PgSessionStore = connectPgSimple(session);

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(session({
  name: cookieName,
  store: new PgSessionStore({ pool, createTableIfMissing: true }),
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: sessionMaxAge
  }
}));

function publicUser(row) {
  return {
    id: row.id,
    yandexId: row.yandex_id,
    firstName: row.first_name || "",
    lastName: row.last_name || "",
    name: row.display_name || row.login || "Yandex user",
    email: row.email || "",
    avatarUrl: row.avatar_url || ""
  };
}

function redirectWithAuthError(res, error) {
  return res.redirect("/?auth_error=" + encodeURIComponent(error));
}

function exchangeCode(code) {
  return fetch("https://oauth.yandex.ru/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: clientId,
      client_secret: clientSecret
    }),
    signal: AbortSignal.timeout(10000)
  }).then(async response => {
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.access_token) {
      throw new Error("Yandex token exchange failed");
    }
    return payload.access_token;
  });
}

async function getYandexProfile(accessToken) {
  const response = await fetch("https://login.yandex.ru/info?format=json", {
    headers: { Authorization: "OAuth " + accessToken },
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error("Yandex profile request failed");
  const profile = await response.json();
  if (!profile.id) throw new Error("Yandex profile did not include an account ID");
  return profile;
}

app.get("/auth/yandex", (req, res) => {
  const mode = req.query.mode === "login" ? "login" : "register";
  const state = crypto.randomBytes(32).toString("hex");
  req.session.yandexOAuthState = state;
  req.session.yandexOAuthMode = mode;

  const authorizeUrl = new URL("https://oauth.yandex.ru/authorize");
  authorizeUrl.search = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: "login:info login:email",
    state
  }).toString();
  res.redirect(authorizeUrl.toString());
});

app.get("/auth/yandex/callback", async (req, res) => {
  const expectedState = req.session.yandexOAuthState;
  const mode = req.session.yandexOAuthMode;
  delete req.session.yandexOAuthState;
  delete req.session.yandexOAuthMode;

  const receivedState = typeof req.query.state === "string" ? req.query.state : "";
  if (!expectedState || !receivedState ||
      Buffer.byteLength(expectedState) !== Buffer.byteLength(receivedState) ||
      !crypto.timingSafeEqual(Buffer.from(expectedState), Buffer.from(receivedState))) {
    return redirectWithAuthError(res, "invalid_state");
  }
  if (req.query.error) return redirectWithAuthError(res, "cancelled");
  if (typeof req.query.code !== "string" || !req.query.code) {
    return redirectWithAuthError(res, "oauth_failed");
  }

  try {
    const accessToken = await exchangeCode(req.query.code);
    const profile = await getYandexProfile(accessToken);
    const existing = await pool.query("SELECT id FROM users WHERE yandex_id = $1", [String(profile.id)]);

    if (mode === "login" && existing.rowCount === 0) {
      return redirectWithAuthError(res, "account_not_found");
    }

    const firstName = profile.first_name || "";
    const lastName = profile.last_name || "";
    const displayName = profile.real_name || profile.display_name || profile.login || "Yandex user";
    const avatarUrl = profile.default_avatar_id
      ? "https://avatars.yandex.net/get-yapic/" + encodeURIComponent(profile.default_avatar_id) + "/islands-200"
      : "";
    const saved = await pool.query(
      `INSERT INTO users (yandex_id, login, email, first_name, last_name, display_name, avatar_url, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       ON CONFLICT (yandex_id) DO UPDATE SET
         login = EXCLUDED.login,
         email = EXCLUDED.email,
         first_name = EXCLUDED.first_name,
         last_name = EXCLUDED.last_name,
         display_name = EXCLUDED.display_name,
         avatar_url = EXCLUDED.avatar_url,
         updated_at = NOW()
       RETURNING id, yandex_id, login, email, first_name, last_name, display_name, avatar_url`,
      [String(profile.id), profile.login || null, profile.default_email || null,
        firstName, lastName, displayName, avatarUrl]
    );

    await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
    req.session.userId = saved.rows[0].id;
    await new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()));
    return res.redirect("/");
  } catch (error) {
    console.error("Yandex OAuth callback failed:", error.message);
    return redirectWithAuthError(res, "oauth_failed");
  }
});

app.post("/auth/logout", (req, res, next) => {
  req.session.destroy(error => {
    if (error) return next(error);
    res.clearCookie(cookieName, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax"
    });
    res.status(204).end();
  });
});

app.get("/api/me", async (req, res, next) => {
  if (!req.session.userId) return res.json({ user: null });
  try {
    const result = await pool.query(
      "SELECT id, yandex_id, login, email, first_name, last_name, display_name, avatar_url FROM users WHERE id = $1",
      [req.session.userId]
    );
    if (!result.rowCount) {
      req.session.destroy(() => {});
      return res.json({ user: null });
    }
    return res.json({ user: publicUser(result.rows[0]) });
  } catch (error) {
    return next(error);
  }
});

app.get("/healthz", (_req, res) => res.json({ ok: true }));
app.get("/", (_req, res) => res.sendFile(path.join(staticDir, "index.html")));
app.use(express.static(staticDir, { index: false, fallthrough: true }));

app.use((error, _req, res, _next) => {
  console.error("Request failed:", error.message);
  if (res.headersSent) return;
  res.status(500).json({ error: "internal_server_error" });
});

async function start() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      yandex_id TEXT NOT NULL UNIQUE,
      login TEXT,
      email TEXT,
      first_name TEXT NOT NULL DEFAULT '',
      last_name TEXT NOT NULL DEFAULT '',
      display_name TEXT NOT NULL DEFAULT '',
      avatar_url TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  app.listen(port, "0.0.0.0", () => console.log(`oura drop me fail listening on port ${port}`));
}

start().catch(error => {
  console.error("Failed to start server:", error.message);
  process.exit(1);
});
