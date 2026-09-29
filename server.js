"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const session = require("express-session");
const connectPgSimple = require("connect-pg-simple");
const { Pool } = require("pg");

const app = express();
const port = Number(process.env.PORT || 3000);
const clientId = process.env.YANDEX_CLIENT_ID;
const clientSecret = process.env.YANDEX_CLIENT_SECRET;
const sessionSecret = process.env.SESSION_SECRET;
const databaseUrl = process.env.DATABASE_URL;
const frontendUrl = (process.env.FRONTEND_URL || "https://drop-me-fail.onrender.com").replace(/\/$/, "");
const apiBaseUrl = (process.env.API_BASE_URL || "").replace(/\/$/, "");
const redirectUri = process.env.YANDEX_REDIRECT_URI;
const cookieName = "odmf.sid";
const sessionMaxAge = 7 * 24 * 60 * 60 * 1000;
const storageRoot = path.resolve(process.env.STORAGE_DIR || path.join(__dirname, "var", "uploads"));

function connectionStringWithExplicitTls(connectionString) {
  const url = new URL(connectionString);
  for (const key of Array.from(url.searchParams.keys())) {
    if (["sslmode", "sslcert", "sslkey", "sslrootcert"].includes(key.toLowerCase())) {
      url.searchParams.delete(key);
    }
  }
  return url.toString();
}

const pool = new Pool({
  connectionString: databaseUrl ? connectionStringWithExplicitTls(databaseUrl) : databaseUrl,
  // Render external PostgreSQL requires TLS. Keep Node's normal certificate verification enabled.
  ssl: { rejectUnauthorized: true }
});
const PgSessionStore = connectPgSimple(session);

function safeErrorCode(error) {
  if (error && typeof error.code === "string" && /^[A-Z0-9_]+$/.test(error.code)) return error.code;
  if (error && typeof error.name === "string" && /^[A-Za-z][A-Za-z0-9]*$/.test(error.name)) return error.name;
  return "Error";
}

pool.on("error", error => {
  console.error("PostgreSQL pool connection error (" + safeErrorCode(error) + "); details omitted");
});

if (!clientId || !clientSecret || !sessionSecret || !databaseUrl || !redirectUri) {
  console.error("Required: YANDEX_CLIENT_ID, YANDEX_CLIENT_SECRET, SESSION_SECRET, DATABASE_URL, YANDEX_REDIRECT_URI");
  process.exit(1);
}
if (new URL(frontendUrl).origin !== "https://drop-me-fail.onrender.com") {
  console.error("FRONTEND_URL must be https://drop-me-fail.onrender.com");
  process.exit(1);
}

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(cors({
  origin(origin, callback) {
    if (origin === frontendUrl) return callback(null, origin);
    return callback(null, false);
  },
  credentials: true,
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Accept"]
}));
app.use((req, res, next) => {
  if (["POST", "PATCH", "DELETE"].includes(req.method) && (req.path.startsWith("/api/") || req.path === "/auth/logout") && req.get("Origin") !== frontendUrl) {
    return res.status(403).json({ error: "origin_not_allowed" });
  }
  next();
});
app.use(express.json({ limit: "1mb" }));
app.use(session({
  name: cookieName,
  store: new PgSessionStore({ pool, createTableIfMissing: true }),
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: "none", maxAge: sessionMaxAge }
}));

function publicUser(row) {
  return { id: String(row.id), yandexId: row.yandex_id, login: row.login || "", firstName: row.first_name || "", lastName: row.last_name || "", name: row.display_name || row.login || "Yandex user", email: row.email || "", avatarUrl: row.avatar_url || "" };
}
function redirectWithAuthError(res, error) { return res.redirect(frontendUrl + "/?auth_error=" + encodeURIComponent(error)); }
function asyncRoute(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }
function requireAuth(req, res, next) { if (!req.session.userId) return res.status(401).json({ error: "authentication_required" }); next(); }
function safeFileName(name) { return path.basename(String(name || "file")).replace(/[\x00-\x1f\x7f]/g, "_").slice(0, 255) || "file"; }
function fileDto(row) { return { id: String(row.id), ownerId: String(row.owner_id), projectId: row.project_id == null ? null : String(row.project_id), name: row.name, size: Number(row.size), mime: row.mime, createdAt: row.created_at, updatedAt: row.updated_at, uploader: row.uploader || "" }; }
function projectDto(row) { return { id: String(row.id), ownerId: String(row.owner_id), name: row.name, createdAt: row.created_at, lastModified: row.updated_at, membersCount: Number(row.members_count || 0), members: row.members || [] }; }
async function canAccessProject(projectId, userId) {
  const r = await pool.query("SELECT p.id, p.owner_id, COALESCE(pm.role, 'viewer') AS role FROM projects p LEFT JOIN project_members pm ON pm.project_id=p.id AND pm.user_id=$2 WHERE p.id=$1 AND (p.owner_id=$2 OR pm.user_id=$2)", [projectId, userId]);
  return r.rows[0] || null;
}
async function canWriteProject(projectId, userId) {
  const p = await canAccessProject(projectId, userId);
  return p && (String(p.owner_id) === String(userId) || p.role === "editor") ? p : null;
}

app.get("/auth/yandex", (req, res) => {
  const state = crypto.randomBytes(32).toString("hex");
  const mode = req.query.mode === "login" ? "login" : "register";
  req.session.yandexOAuthState = state;
  req.session.yandexOAuthMode = mode;
  const authorizeUrl = new URL("https://oauth.yandex.ru/authorize");
  authorizeUrl.search = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirectUri, scope: "login:info login:email", state }).toString();
  res.redirect(authorizeUrl.toString());
});
app.get("/auth/yandex/callback", asyncRoute(async (req, res) => {
  req.oauthStage = "state_validation";
  const expectedState = req.session.yandexOAuthState;
  const mode = req.session.yandexOAuthMode === "login" ? "login" : "register";
  delete req.session.yandexOAuthState;
  delete req.session.yandexOAuthMode;
  const receivedState = typeof req.query.state === "string" ? req.query.state : "";
  if (!expectedState || !receivedState || Buffer.byteLength(expectedState) !== Buffer.byteLength(receivedState) || !crypto.timingSafeEqual(Buffer.from(expectedState), Buffer.from(receivedState))) return redirectWithAuthError(res, "invalid_state");
  if (req.query.error) return redirectWithAuthError(res, "cancelled");
  if (typeof req.query.code !== "string" || !req.query.code) return redirectWithAuthError(res, "oauth_failed");
  req.oauthStage = "token_exchange";
  const tokenResponse = await fetch("https://oauth.yandex.ru/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code: req.query.code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri }), signal: AbortSignal.timeout(10000) });
  const token = await tokenResponse.json().catch(() => ({}));
  if (!tokenResponse.ok || !token.access_token) throw new Error("Yandex token exchange failed");
  req.oauthStage = "profile_lookup";
  const profileResponse = await fetch("https://login.yandex.ru/info?format=json", { headers: { Authorization: "OAuth " + token.access_token }, signal: AbortSignal.timeout(10000) });
  if (!profileResponse.ok) throw new Error("Yandex profile request failed");
  const profile = await profileResponse.json();
  if (!profile.id) throw new Error("Yandex profile did not include an account ID");
  const avatarUrl = profile.default_avatar_id ? "https://avatars.yandex.net/get-yapic/" + encodeURIComponent(profile.default_avatar_id) + "/islands-200" : "";
  const yandexId = String(profile.id);
  const profileValues = [profile.login || null, profile.default_email || null, profile.first_name || "", profile.last_name || "", profile.real_name || profile.display_name || profile.login || "Yandex user", avatarUrl];
  let result;
  req.oauthStage = mode === "login" ? "user_lookup" : "user_create_or_update";
  if (mode === "login") {
    result = await pool.query("SELECT id FROM users WHERE yandex_id=$1", [yandexId]);
    if (!result.rowCount) return redirectWithAuthError(res, "account_not_found");
    await pool.query("UPDATE users SET login=$1,email=$2,first_name=$3,last_name=$4,display_name=$5,avatar_url=$6,updated_at=NOW() WHERE id=$7", [...profileValues, result.rows[0].id]);
  } else {
    result = await pool.query(`INSERT INTO users (yandex_id, login, email, first_name, last_name, display_name, avatar_url) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (yandex_id) DO UPDATE SET login=EXCLUDED.login,email=EXCLUDED.email,first_name=EXCLUDED.first_name,last_name=EXCLUDED.last_name,display_name=EXCLUDED.display_name,avatar_url=EXCLUDED.avatar_url,updated_at=NOW() RETURNING id`, [yandexId, ...profileValues]);
  }
  req.oauthStage = "session_creation";
  await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
  req.session.userId = result.rows[0].id;
  await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));
  res.redirect(frontendUrl + "/");
}));
app.post("/auth/logout", (req, res, next) => req.session.destroy(err => {
  if (err) return next(err);
  res.clearCookie(cookieName, { httpOnly: true, secure: true, sameSite: "none", path: "/" });
  res.status(204).end();
}));

app.get("/api/me", asyncRoute(async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const r = await pool.query("SELECT id,yandex_id,login,email,first_name,last_name,display_name,avatar_url FROM users WHERE id=$1", [req.session.userId]);
  if (!r.rowCount) { req.session.destroy(() => {}); return res.json({ user: null }); }
  res.json({ user: publicUser(r.rows[0]) });
}));
app.get("/api/projects", requireAuth, asyncRoute(async (req, res) => {
  const r = await pool.query(`SELECT p.*, (SELECT COUNT(*) FROM project_members pm WHERE pm.project_id=p.id) AS members_count FROM projects p WHERE p.owner_id=$1 OR EXISTS (SELECT 1 FROM project_members pm WHERE pm.project_id=p.id AND pm.user_id=$1) ORDER BY p.updated_at DESC`, [req.session.userId]);
  res.json({ projects: r.rows.map(projectDto) });
}));
app.post("/api/projects", requireAuth, asyncRoute(async (req, res) => {
  const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
  if (!name || name.length > 120) return res.status(400).json({ error: "invalid_project_name" });
  const r = await pool.query("INSERT INTO projects(owner_id,name) VALUES($1,$2) RETURNING id,owner_id,name,created_at,updated_at,0::int AS members_count", [req.session.userId, name]);
  res.status(201).json({ project: projectDto(r.rows[0]) });
}));
app.delete("/api/projects/:id", requireAuth, asyncRoute(async (req, res) => {
  const r = await pool.query("DELETE FROM projects WHERE id=$1 AND owner_id=$2 RETURNING id", [req.params.id, req.session.userId]);
  if (!r.rowCount) return res.status(404).json({ error: "project_not_found" });
  res.status(204).end();
}));
app.get("/api/projects/:id/members", requireAuth, asyncRoute(async (req, res) => {
  const access = await canAccessProject(req.params.id, req.session.userId);
  if (!access) return res.status(404).json({ error: "project_not_found" });
  const r = await pool.query("SELECT u.id,u.yandex_id,u.login,u.first_name,u.last_name,u.display_name,u.avatar_url,pm.role,pm.created_at FROM project_members pm JOIN users u ON u.id=pm.user_id WHERE pm.project_id=$1 ORDER BY pm.created_at", [req.params.id]);
  res.json({ members: r.rows.map(x => ({ id: String(x.id), yandexId: x.yandex_id, name: x.display_name || x.login || "Yandex user", initials: ((x.first_name || "")[0] || "") + ((x.last_name || "")[0] || ""), role: x.role, createdAt: x.created_at })) });
}));
app.post("/api/projects/:id/members", requireAuth, asyncRoute(async (req, res) => {
  const own = await pool.query("SELECT id FROM projects WHERE id=$1 AND owner_id=$2", [req.params.id, req.session.userId]);
  if (!own.rowCount) return res.status(404).json({ error: "project_not_found" });
  const yandexId = String(req.body.yandexId || "").trim();
  if (!yandexId || yandexId.length > 200) return res.status(400).json({ error: "invalid_yandex_id" });
  const user = await pool.query("SELECT id FROM users WHERE yandex_id=$1", [yandexId]);
  if (!user.rowCount) return res.status(404).json({ error: "user_not_found" });
  if (String(user.rows[0].id) === String(req.session.userId)) return res.status(400).json({ error: "owner_already_has_access" });
  const role = req.body.role === "viewer" ? "viewer" : "editor";
  const r = await pool.query("INSERT INTO project_members(project_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(project_id,user_id) DO UPDATE SET role=EXCLUDED.role RETURNING project_id,user_id,role,created_at", [req.params.id, user.rows[0].id, role]);
  await pool.query("UPDATE projects SET updated_at=NOW() WHERE id=$1", [req.params.id]);
  res.status(201).json({ member: { id: String(r.rows[0].user_id), role: r.rows[0].role, createdAt: r.rows[0].created_at } });
}));
app.delete("/api/projects/:id/members/:userId", requireAuth, asyncRoute(async (req, res) => {
  const own = await pool.query("DELETE FROM project_members pm USING projects p WHERE pm.project_id=p.id AND pm.project_id=$1 AND pm.user_id=$2 AND p.owner_id=$3 RETURNING pm.user_id", [req.params.id, req.params.userId, req.session.userId]);
  if (!own.rowCount) return res.status(404).json({ error: "member_not_found" });
  res.status(204).end();
}));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024, files: 1 } });
app.get("/api/files", requireAuth, asyncRoute(async (req, res) => {
  const r = await pool.query(`SELECT f.*,u.display_name AS uploader FROM files f JOIN users u ON u.id=f.owner_id WHERE f.owner_id=$1 OR EXISTS (SELECT 1 FROM projects p LEFT JOIN project_members pm ON pm.project_id=p.id WHERE p.id=f.project_id AND (p.owner_id=$1 OR pm.user_id=$1)) ORDER BY f.created_at DESC`, [req.session.userId]);
  res.json({ files: r.rows.map(fileDto) });
}));
app.post("/api/files", requireAuth, upload.single("file"), asyncRoute(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "file_required" });
  const projectId = req.body.projectId || null;
  if (projectId && !(await canWriteProject(projectId, req.session.userId))) return res.status(404).json({ error: "project_not_found_or_read_only" });
  const key = crypto.randomUUID();
  const destination = path.join(storageRoot, key);
  await fs.mkdir(storageRoot, { recursive: true });
  await fs.writeFile(destination, req.file.buffer, { flag: "wx", mode: 0o600 });
  try {
    const r = await pool.query("INSERT INTO files(owner_id,project_id,name,size,mime,storage_key) VALUES($1,$2,$3,$4,$5,$6) RETURNING *", [req.session.userId, projectId, safeFileName(req.file.originalname), req.file.size, req.file.mimetype || "application/octet-stream", key]);
    if (projectId) await pool.query("UPDATE projects SET updated_at=NOW() WHERE id=$1", [projectId]);
    res.status(201).json({ file: fileDto(r.rows[0]) });
  } catch (err) { await fs.unlink(destination).catch(() => {}); throw err; }
}));
app.get("/api/files/:id/download", requireAuth, asyncRoute(async (req, res) => {
  const r = await pool.query(`SELECT f.* FROM files f WHERE f.id=$1 AND (f.owner_id=$2 OR EXISTS(SELECT 1 FROM projects p LEFT JOIN project_members pm ON pm.project_id=p.id WHERE p.id=f.project_id AND (p.owner_id=$2 OR pm.user_id=$2)))`, [req.params.id, req.session.userId]);
  if (!r.rowCount) return res.status(404).json({ error: "file_not_found" });
  const row = r.rows[0];
  if (!/^[0-9a-f-]{36}$/i.test(row.storage_key)) return res.status(404).json({ error: "file_not_found" });
  res.download(path.join(storageRoot, row.storage_key), safeFileName(row.name));
}));
app.patch("/api/files/:id", requireAuth, asyncRoute(async (req, res) => {
  const name = typeof req.body.name === "string" ? safeFileName(req.body.name.trim()) : "";
  if (!name) return res.status(400).json({ error: "invalid_file_name" });
  const r = await pool.query("UPDATE files SET name=$1,updated_at=NOW() WHERE id=$2 AND owner_id=$3 RETURNING *", [name, req.params.id, req.session.userId]);
  if (!r.rowCount) return res.status(404).json({ error: "file_not_found" });
  res.json({ file: fileDto(r.rows[0]) });
}));
app.delete("/api/files/:id", requireAuth, asyncRoute(async (req, res) => {
  const r = await pool.query("DELETE FROM files WHERE id=$1 AND owner_id=$2 RETURNING storage_key", [req.params.id, req.session.userId]);
  if (!r.rowCount) return res.status(404).json({ error: "file_not_found" });
  await fs.unlink(path.join(storageRoot, r.rows[0].storage_key)).catch(err => { if (err.code !== "ENOENT") throw err; });
  res.status(204).end();
}));

app.get("/healthz", (_req, res) => res.json({ ok: true }));
app.use((err, req, res, _next) => {
  if (err instanceof multer.MulterError) return res.status(err.code === "LIMIT_FILE_SIZE" ? 413 : 400).json({ error: "upload_rejected" });
  if (err.message === "Origin not allowed") return res.status(403).json({ error: "origin_not_allowed" });
  if (req.path === "/auth/yandex/callback") {
    console.error("Yandex OAuth callback failed at stage " + (req.oauthStage || "unknown") + " (" + (err.name || "Error") + "); sensitive values omitted");
    return redirectWithAuthError(res, "oauth_failed");
  }
  console.error("Request failed (" + safeErrorCode(err) + "); details omitted");
  if (!res.headersSent) res.status(500).json({ error: "internal_server_error" });
});

let startupStage = "storage initialization";
async function start() {
  await fs.mkdir(storageRoot, { recursive: true });
  startupStage = "PostgreSQL connection and schema initialization";
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY, yandex_id TEXT NOT NULL UNIQUE, login TEXT, email TEXT,
      first_name TEXT NOT NULL DEFAULT '', last_name TEXT NOT NULL DEFAULT '', display_name TEXT NOT NULL DEFAULT '', avatar_url TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS projects (
      id BIGSERIAL PRIMARY KEY, owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 120),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS project_members (
      id BIGSERIAL PRIMARY KEY, project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role TEXT NOT NULL DEFAULT 'editor' CHECK(role IN ('editor','viewer')), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(project_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS files (
      id BIGSERIAL PRIMARY KEY, owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      project_id BIGINT REFERENCES projects(id) ON DELETE SET NULL, name TEXT NOT NULL, size BIGINT NOT NULL CHECK(size >= 0),
      mime TEXT NOT NULL, storage_key TEXT NOT NULL UNIQUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS projects_owner_id_idx ON projects(owner_id);
    CREATE INDEX IF NOT EXISTS project_members_user_id_idx ON project_members(user_id);
    CREATE INDEX IF NOT EXISTS files_owner_id_idx ON files(owner_id);
    CREATE INDEX IF NOT EXISTS files_project_id_idx ON files(project_id);
  `);
  startupStage = "HTTP server startup";
  app.listen(port, "0.0.0.0", () => console.log(`oura drop me fail API listening on port ${port}; frontend=${frontendUrl}; api=${apiBaseUrl || "unset"}`));
}
start().catch(error => {
  console.error("Failed to start server during " + startupStage + " (" + safeErrorCode(error) + "); sensitive details omitted");
  process.exit(1);
});
