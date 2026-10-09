'use strict';
const express = require('express');
const snmp    = require('net-snmp');
const multer  = require('multer');
const fs      = require('fs');
const path    = require('path');
const https   = require('https');
const os      = require('os');
const { execFile, exec } = require('child_process');
const { promisify } = require('util');
const crypto  = require('crypto');
const QRCode  = require('qrcode');
const scryptAsync = promisify(crypto.scrypt);
const app  = express();
const PORT = process.env.PORT || 3003;

// ── Environment & File Paths ───────────────────────────────────────────────────
const USERS_FILE        = process.env.USERS_FILE        || './users.json';
const SESSIONS_FILE     = process.env.SESSIONS_FILE     || './sessions.json';
const DATA_FILE         = process.env.DATA_FILE         || './printers.json';
const ALERT_STATE_FILE  = process.env.ALERT_STATE_FILE  || './alert-state.json';
const SETTINGS_FILE     = process.env.SETTINGS_FILE     || './settings.json';
const JOB_METADATA_FILE = process.env.JOB_METADATA_FILE || './job-metadata.json';
const GROUPS_FILE       = process.env.GROUPS_FILE       || './groups.json';
const DELETED_JOBS_FILE = process.env.DELETED_JOBS_FILE || './data/deleted-jobs.json';

function resolveWritableDir(targetPath, fallbackPath) {
  try {
    fs.mkdirSync(targetPath, { recursive: true });
    fs.accessSync(targetPath, fs.constants.W_OK);
    return targetPath;
  } catch {
    const fallback = path.isAbsolute(fallbackPath) ? fallbackPath : path.join(__dirname, fallbackPath);
    try { fs.mkdirSync(fallback, { recursive: true }); } catch {}
    return fallback;
  }
}

const SCAN_DIR          = resolveWritableDir(process.env.SCAN_DIR || '/opt/scans', './data/scans');
const UPLOAD_DIR        = resolveWritableDir(process.env.UPLOAD_DIR || '/tmp/printserver-uploads', './data/uploads');

const ensureDir = file => { try { fs.mkdirSync(path.dirname(file), { recursive: true }); } catch {} };
[USERS_FILE, SESSIONS_FILE, DATA_FILE, SETTINGS_FILE, ALERT_STATE_FILE, JOB_METADATA_FILE, GROUPS_FILE, DELETED_JOBS_FILE].forEach(ensureDir);

function loadDeletedJobs() {
  try { if (fs.existsSync(DELETED_JOBS_FILE)) return new Set(JSON.parse(fs.readFileSync(DELETED_JOBS_FILE, 'utf8'))); } catch {}
  return new Set();
}
function saveDeletedJobs() {
  try { fs.writeFileSync(DELETED_JOBS_FILE, JSON.stringify(Array.from(DELETED_JOB_IDS), null, 2)); } catch(e) {}
}
let DELETED_JOB_IDS = loadDeletedJobs();

// ── Auth: users + sessions ──────────────────────────────────────────────────────
function hashPasswordSync(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
async function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const derivedKey = await scryptAsync(password, salt, 64);
  return `${salt}:${derivedKey.toString('hex')}`;
}
async function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  try {
    const check = await scryptAsync(password, salt, 64);
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), check);
  } catch {
    return false;
  }
}
function normalizeUser(u) {
  if (!u) return u;
  if (typeof u.phone !== 'string') u.phone = '';
  if (!u.notifications || typeof u.notifications !== 'object') {
    u.notifications = { printSuccess: true, scanSuccess: true, printFailed: true, scanFailed: true };
  } else {
    u.notifications.printSuccess = u.notifications.printSuccess !== false;
    u.notifications.scanSuccess = u.notifications.scanSuccess !== false;
    u.notifications.printFailed = u.notifications.printFailed !== false;
    u.notifications.scanFailed = u.notifications.scanFailed !== false;
  }
  return u;
}
function loadUsers() {
  let list = [];
  try { if (fs.existsSync(USERS_FILE)) list = JSON.parse(fs.readFileSync(USERS_FILE,'utf8')); } catch {}
  if (!Array.isArray(list) || !list.length) {
    list = [
      { username:'admin', role:'admin', password: hashPasswordSync('admin123'), phone:'', notifications: { printSuccess: true, scanSuccess: true, printFailed: true, scanFailed: true } },
      { username:'user',  role:'user',  password: hashPasswordSync('user123'), phone:'', notifications: { printSuccess: true, scanSuccess: true, printFailed: true, scanFailed: true } },
    ];
    try { fs.writeFileSync(USERS_FILE, JSON.stringify(list,null,2)); } catch {}
  }
  return list.map(normalizeUser);
}
function saveUsers() {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(USERS, null, 2));
  } catch (e) {
    console.error('Failed to save users:', e.message);
  }
}
let USERS = loadUsers();

const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h
function loadSessions() {
  try {
    if (fs.existsSync(SESSIONS_FILE)) {
      const raw = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
      const map = new Map();
      const now = Date.now();
      for (const [token, s] of Object.entries(raw)) {
        if (s && s.exp > now) map.set(token, s);
      }
      return map;
    }
  } catch {}
  return new Map();
}
function saveSessions() {
  try {
    const obj = Object.fromEntries(sessions);
    fs.promises.writeFile(SESSIONS_FILE, JSON.stringify(obj, null, 2)).catch(e=>console.error('Failed to save sessions:',e.message));
  } catch (e) { console.error('Failed to save sessions:', e.message); }
}
let sessions = loadSessions();

function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username:user.username, role:user.role, printerAccess:user.printerAccess||null, exp:Date.now()+SESSION_TTL_MS });
  saveSessions();
  return token;
}

// ── Document Name & Job Metadata Store ─────────────────────────────────────────
function loadJobMetadata() {
  try { if (fs.existsSync(JOB_METADATA_FILE)) return JSON.parse(fs.readFileSync(JOB_METADATA_FILE, 'utf8')); } catch {}
  return {};
}
function saveJobMetadata() {
  fs.promises.writeFile(JOB_METADATA_FILE, JSON.stringify(JOB_METADATA, null, 2))
    .catch(e => console.error('Failed to save job metadata:', e.message));
}
let JOB_METADATA = loadJobMetadata();

// ── Print Groups Store ──────────────────────────────────────────────────────────
function loadGroups() {
  try { if (fs.existsSync(GROUPS_FILE)) return JSON.parse(fs.readFileSync(GROUPS_FILE, 'utf8')); } catch {}
  return [];
}
function saveGroups() {
  fs.promises.writeFile(GROUPS_FILE, JSON.stringify(GROUPS, null, 2))
    .catch(e => console.error('Failed to save groups:', e.message));
}
let GROUPS = loadGroups();

function recordJobMetadata(jobId, docName, username) {
  if (!jobId) return;
  JOB_METADATA[jobId] = {
    docName: docName || 'Document',
    username: username || 'system',
    createdAt: new Date().toISOString()
  };
  saveJobMetadata();
}
function getAllowedPrinterNames(user) {
  if (!user || user.role === 'admin') return null; // null = unrestricted (admin)

  const allowedNames = new Set();
  let hasRestrictions = false;

  const resolvePrinterName = (pId) => {
    const p = PRINTERS.find(pr => String(pr.id) === String(pId) || pr.name.toLowerCase() === String(pId).toLowerCase());
    if (p) return p.name.toLowerCase();
    return String(pId).toLowerCase();
  };

  // 1. Direct user printerAccess
  if (Array.isArray(user.printerAccess) && user.printerAccess.length > 0) {
    hasRestrictions = true;
    user.printerAccess.forEach(pId => {
      const resolved = resolvePrinterName(pId);
      if (resolved) allowedNames.add(resolved);
    });
  }

  // 2. Group membership access
  GROUPS.forEach(g => {
    if (Array.isArray(g.users) && g.users.includes(user.username)) {
      hasRestrictions = true;
      if (Array.isArray(g.printers)) {
        g.printers.forEach(pId => {
          const resolved = resolvePrinterName(pId);
          if (resolved) allowedNames.add(resolved);
        });
      }
    }
  });

  if (!hasRestrictions) return null;
  return allowedNames;
}

function allowedPrinterObjs(user) {
  const allowed = getAllowedPrinterNames(user);
  if (allowed === null) return null;
  return PRINTERS.filter(p => allowed.has(p.name.toLowerCase()));
}

function isPrinterNameAllowed(user, name) {
  const allowed = getAllowedPrinterNames(user);
  if (allowed === null) return true; // unrestricted
  if (!name) return false;
  return allowed.has(String(name).toLowerCase());
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i>-1) out[p.slice(0,i).trim()] = decodeURIComponent(p.slice(i+1).trim());
  });
  return out;
}
function getSession(req) {
  const token = parseCookies(req).session;
  if (!token) return null;
  const s = sessions.get(token);
  if (!s || s.exp < Date.now()) {
    if (s) { sessions.delete(token); saveSessions(); }
    return null;
  }
  return s;
}
// API routes the 'user' role IS allowed to use (everything else is admin-only)
const USER_ALLOWED = [
  /^\/api\/me$/, /^\/api\/logout$/,
  /^\/api\/printers$/, /^\/api\/printers\/refresh$/,
  /^\/api\/cups\/printers$/, /^\/api\/print$/, /^\/api\/cups\/jobs$/,
  /^\/api\/scans(\/.*)?$/,
  /^\/api\/shared-docs/, /^\/api\/mobile\/print-shared$/, /^\/api\/mobile\/print-scan$/,
  /^\/api\/mobile\/token$/, /^\/api\/mobile\/qr-image$/,
];
app.get('/bg.jpg', (_req,res) => res.sendFile(path.resolve(__dirname, 'bg.jpg')));
app.use((req, res, next) => {
  if (req.path === '/login' || req.path === '/api/login' || req.path === '/mobile' || req.path === '/manifest.json' || req.path === '/sw.js' || req.path === '/bg.jpg') return next();
  const session = getSession(req);
  if (session && session.isMobile && req.path === '/') {
    return res.redirect('/mobile');
  }
  if (!session) {
    if (req.path.startsWith('/api/')) return res.status(401).json({error:'Not authenticated'});
    return res.redirect('/login');
  }
  req.user = session;
  if (req.path.startsWith('/api/') && session.role !== 'admin') {
    const allowed = USER_ALLOWED.some(re => re.test(req.path));
    if (!allowed) return res.status(403).json({error:'Forbidden — admin access required'});
  }
  next();
});
app.get('/login', (_req,res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.send(LOGIN_HTML);
});
app.post('/api/login', express.json(), async (req,res) => {
  const { username, password } = req.body || {};
  const user = USERS.find(u => u.username === username);
  if (!user || !(await verifyPassword(password||'', user.password))) {
    return res.status(401).json({error:'Invalid username or password'});
  }
  const token = createSession(user);
  res.setHeader('Set-Cookie', `session=${token}; HttpOnly; Path=/; Max-Age=${SESSION_TTL_MS/1000}; SameSite=Lax`);
  res.json({ok:true, role:user.role});
});
app.post('/api/logout', (req,res) => {
  const token = parseCookies(req).session;
  if (token) { sessions.delete(token); saveSessions(); }
  res.setHeader('Set-Cookie', 'session=; HttpOnly; Path=/; Max-Age=0');
  res.json({ok:true});
});
app.get('/api/me', (req,res) => res.json({username:req.user.username, role:req.user.role}));

// ══════════════════════════════════════════════════════════════════════════════
// MOBILE QR PRINT FEATURE
// ══════════════════════════════════════════════════════════════════════════════

// ── Mobile token store ──────────────────────────────────────────────────────
const MOBILE_TOKENS_FILE = process.env.MOBILE_TOKENS_FILE || './mobile-tokens.json';
const SHARED_DOCS_DIR    = resolveWritableDir(process.env.SHARED_DOCS_DIR || '/opt/shared-docs', './data/shared-docs');
ensureDir(MOBILE_TOKENS_FILE);

function loadMobileTokens() {
  try { if (fs.existsSync(MOBILE_TOKENS_FILE)) return JSON.parse(fs.readFileSync(MOBILE_TOKENS_FILE, 'utf8')); } catch {}
  return {};
}
function saveMobileTokens() {
  fs.promises.writeFile(MOBILE_TOKENS_FILE, JSON.stringify(MOBILE_TOKENS, null, 2)).catch(()=>{});
}
function createMobileTokenForUser(username) {
  for (const [tok, t] of Object.entries(MOBILE_TOKENS)) {
    if (t.username === username) delete MOBILE_TOKENS[tok];
  }
  const token = crypto.randomBytes(32).toString('hex');
  MOBILE_TOKENS[token] = { username, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 };
  saveMobileTokens();
  return token;
}

function ensureMobileTokensForAllUsers() {
  let changed = false;
  (USERS || []).forEach(u => {
    const hasToken = Object.values(MOBILE_TOKENS).some(t => t.username === u.username && t.exp > Date.now());
    if (!hasToken) {
      const token = crypto.randomBytes(32).toString('hex');
      MOBILE_TOKENS[token] = { username: u.username, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 };
      changed = true;
    }
  });
  if (changed) saveMobileTokens();
}

let MOBILE_TOKENS = loadMobileTokens();
ensureMobileTokensForAllUsers();

// Cleanup expired tokens every hour
setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const [tok, t] of Object.entries(MOBILE_TOKENS)) {
    if (t.exp < now) { delete MOBILE_TOKENS[tok]; changed = true; }
  }
  if (changed) saveMobileTokens();
}, 60 * 60 * 1000);

// ── API: generate local SVG QR code image (no external third-party API) ────
app.get('/api/mobile/qr-image', async (req, res) => {
  const text = req.query.text || req.query.data;
  if (!text) return res.status(400).send('Missing text parameter');
  try {
    const svg = await QRCode.toString(text, { type: 'svg', margin: 2, width: 220 });
    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.send(svg);
  } catch (e) {
    res.status(500).send('Error generating QR code');
  }
});

function getServerIp() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

// ── API: generate QR token for a user ───────────────────────────────────────
app.post('/api/mobile/token', express.json(), (req, res) => {
  const targetUsername = req.user.role === 'admin' ? ((req.body && req.body.username) || req.user.username) : req.user.username;
  const user = USERS.find(u => u.username === targetUsername);
  if (!user) return res.status(404).json({error:'User not found'});
  
  const rotate = req.body && req.body.rotate === true;
  let existingToken = null;
  if (!rotate) {
    for (const [tok, t] of Object.entries(MOBILE_TOKENS)) {
      if (t.username === targetUsername && t.exp > Date.now()) {
        existingToken = tok;
        break;
      }
    }
  }

  if (existingToken) {
    return res.json({ ok: true, token: existingToken, serverIp: getServerIp(), isNew: false });
  }

  // Revoke old token for this user
  for (const [tok, t] of Object.entries(MOBILE_TOKENS)) {
    if (t.username === targetUsername) delete MOBILE_TOKENS[tok];
  }
  const token = crypto.randomBytes(32).toString('hex');
  MOBILE_TOKENS[token] = { username: targetUsername, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 }; // 30 days
  saveMobileTokens();
  res.json({ ok: true, token, serverIp: getServerIp(), isNew: true });
});

// ── API: revoke QR token & active mobile sessions ───────────────────────────
app.delete('/api/mobile/token/:username', (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({error:'Admin only'});
  const { username } = req.params;
  for (const [tok, t] of Object.entries(MOBILE_TOKENS)) {
    if (t.username === username) delete MOBILE_TOKENS[tok];
  }
  saveMobileTokens();
  // Invalidate active mobile sessions for revoked user
  let sessChanged = false;
  for (const [sTok, s] of sessions.entries()) {
    if (s.username === username && s.isMobile) {
      sessions.delete(sTok);
      sessChanged = true;
    }
  }
  if (sessChanged) saveSessions();
  res.json({ ok: true });
});

// ── Shared Docs Metadata & History Audit Helpers ─────────────────────────────
const SHARED_DOCS_META_FILE = path.join(SHARED_DOCS_DIR, '.meta.json');
const SHARED_DOCS_HIST_FILE = path.join(SHARED_DOCS_DIR, '.history.json');

function loadSharedDocsMeta() {
  try {
    if (fs.existsSync(SHARED_DOCS_META_FILE)) {
      return JSON.parse(fs.readFileSync(SHARED_DOCS_META_FILE, 'utf8'));
    }
  } catch {}
  return {};
}

function saveSharedDocsMeta(meta) {
  try {
    fs.writeFileSync(SHARED_DOCS_META_FILE, JSON.stringify(meta, null, 2));
  } catch (e) {
    console.error('Failed to save shared docs meta:', e.message);
  }
}

function loadSharedDocsHistory() {
  try {
    if (fs.existsSync(SHARED_DOCS_HIST_FILE)) {
      return JSON.parse(fs.readFileSync(SHARED_DOCS_HIST_FILE, 'utf8'));
    }
  } catch {}
  return [];
}

function logSharedDocAction(action, user, filename, targetUser = 'all', details = '') {
  try {
    const history = loadSharedDocsHistory();
    history.unshift({
      id: Date.now() + '-' + Math.floor(Math.random() * 1000),
      timestamp: new Date().toISOString(),
      action, // 'UPLOAD', 'DOWNLOAD', 'PRINT', 'DELETE'
      user: user || 'anonymous',
      filename,
      targetUser: targetUser || 'all',
      details
    });
    if (history.length > 500) history.length = 500;
    fs.writeFileSync(SHARED_DOCS_HIST_FILE, JSON.stringify(history, null, 2));
  } catch (e) {
    console.error('Failed to log shared doc action:', e.message);
  }
}

// ── API: get list of target users ──────────────────────────────────────────
app.get('/api/shared-docs/targets', (req, res) => {
  const targets = USERS.map(u => ({ username: u.username, role: u.role }));
  res.json({ targets });
});

// ── API: list shared documents with privacy filter & unread badge ────────────
app.get('/api/shared-docs', async (req, res) => {
  try {
    const files = await fs.promises.readdir(SHARED_DOCS_DIR);
    const metaMap = loadSharedDocsMeta();
    const currentUser = req.user ? req.user.username : 'user';
    const isAdmin = req.user && req.user.role === 'admin';

    const rawDocs = await Promise.all(files.map(async name => {
      if (name.startsWith('.')) return null;
      try {
        const stat = await fs.promises.stat(path.join(SHARED_DOCS_DIR, name));
        const meta = metaMap[name] || { uploader: 'admin', targetUser: 'all', uploadTime: stat.mtime, downloads: 0, prints: 0 };
        return {
          name,
          size: stat.size,
          mtime: stat.mtime,
          uploader: meta.uploader || 'admin',
          targetUser: meta.targetUser || 'all',
          uploadTime: meta.uploadTime || stat.mtime,
          downloads: meta.downloads || 0,
          prints: meta.prints || 0
        };
      } catch { return null; }
    }));

    const validDocs = rawDocs.filter(Boolean);

    // Privacy Filter
    const docs = isAdmin ? validDocs : validDocs.filter(d => 
      d.targetUser === 'all' || d.targetUser === currentUser || d.uploader === currentUser
    );

    // Unread count (private docs for currentUser that haven't been downloaded or printed)
    const unreadCount = validDocs.filter(d => 
      d.targetUser === currentUser && d.uploader !== currentUser && (d.downloads === 0 && d.prints === 0)
    ).length;

    res.json({ docs, unreadCount, currentUser });
  } catch { res.json({ docs: [], unreadCount: 0 }); }
});

// ── API: upload shared doc (available to all logged-in users) ───────────────
const sharedUpload = multer({ dest: SHARED_DOCS_DIR, limits: { fileSize: 50 * 1024 * 1024 } });
app.post('/api/shared-docs', sharedUpload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const targetUser = (req.body.targetUser || 'all').trim();
  const uploader = req.user ? req.user.username : 'user';
  const safeName = path.basename(req.file.originalname).replace(/[^a-zA-Z0-9.\-_ ]/g, '_');
  const dest = path.join(SHARED_DOCS_DIR, safeName);

  try {
    await fs.promises.rename(req.file.path, dest);
    
    // Save metadata
    const metaMap = loadSharedDocsMeta();
    metaMap[safeName] = {
      uploader,
      targetUser,
      uploadTime: new Date().toISOString(),
      originalName: req.file.originalname,
      downloads: 0,
      prints: 0
    };
    saveSharedDocsMeta(metaMap);

    // Audit log
    logSharedDocAction('UPLOAD', uploader, safeName, targetUser, `Dokumen diunggah untuk: ${targetUser}`);

    res.json({ ok: true, name: safeName, targetUser, uploader });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── API: download shared doc (with privacy check & history logging) ─────────
app.get('/api/shared-docs/download/:name', async (req, res) => {
  const name = path.basename(req.params.name);
  const full = path.join(SHARED_DOCS_DIR, name);
  const currentUser = req.user ? req.user.username : 'user';
  const isAdmin = req.user && req.user.role === 'admin';
  const metaMap = loadSharedDocsMeta();
  const meta = metaMap[name] || { uploader: 'admin', targetUser: 'all' };

  // Privacy Check
  if (!isAdmin && meta.targetUser !== 'all' && meta.targetUser !== currentUser && meta.uploader !== currentUser) {
    return res.status(403).json({ error: 'Akses ditolak: Dokumen ini bersifat privat' });
  }

  try {
    await fs.promises.access(full);
    
    // Update download counter & log
    meta.downloads = (meta.downloads || 0) + 1;
    metaMap[name] = meta;
    saveSharedDocsMeta(metaMap);
    logSharedDocAction('DOWNLOAD', currentUser, name, meta.targetUser, 'Mengunduh file');

    if (req.query.inline === '1' && /\.(pdf|jpe?g|png|txt)$/i.test(name)) {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Disposition', `inline; filename*=UTF-8''${encodeURIComponent(name)}`);
      return res.sendFile(path.resolve(full));
    }
    res.download(full);
  } catch {
    res.status(404).json({ error: 'File tidak ditemukan' });
  }
});

// ── API: delete shared doc (admin or uploader) ──────────────────────────────
app.delete('/api/shared-docs/:name', async (req, res) => {
  const name = path.basename(req.params.name);
  const currentUser = req.user ? req.user.username : 'user';
  const isAdmin = req.user && req.user.role === 'admin';
  const metaMap = loadSharedDocsMeta();
  const meta = metaMap[name] || { uploader: 'admin', targetUser: 'all' };

  if (!isAdmin && meta.uploader !== currentUser) {
    return res.status(403).json({ error: 'Hanya pengirim file atau admin yang dapat menghapus' });
  }

  try {
    await fs.promises.unlink(path.join(SHARED_DOCS_DIR, name));
    delete metaMap[name];
    saveSharedDocsMeta(metaMap);
    logSharedDocAction('DELETE', currentUser, name, meta.targetUser, 'Menghapus dokumen');
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'Gagal menghapus dokumen' });
  }
});

// ── API: shared docs audit history ──────────────────────────────────────────
app.get('/api/shared-docs/history', (req, res) => {
  const history = loadSharedDocsHistory();
  const currentUser = req.user ? req.user.username : 'user';
  const isAdmin = req.user && req.user.role === 'admin';

  const docsHistory = isAdmin ? history : history.filter(h => 
    h.user === currentUser || h.targetUser === currentUser || h.targetUser === 'all'
  );

  res.json({ history: docsHistory });
});

// ── API: print shared doc by name ──────────────────────────────────────────
app.post('/api/mobile/print-shared', express.json(), async (req, res) => {
  const { docName, copies, duplex, color, printer } = req.body || {};
  if (!docName) return res.status(400).json({error:'docName required'});
  const name = path.basename(docName);
  const filePath = path.join(SHARED_DOCS_DIR, name);
  const currentUser = req.user ? req.user.username : 'user';
  const isAdmin = req.user && req.user.role === 'admin';
  const metaMap = loadSharedDocsMeta();
  const meta = metaMap[name] || { uploader: 'admin', targetUser: 'all' };

  // Privacy Check
  if (!isAdmin && meta.targetUser !== 'all' && meta.targetUser !== currentUser && meta.uploader !== currentUser) {
    return res.status(403).json({ error: 'Akses ditolak: Dokumen ini bersifat privat' });
  }

  try { await fs.promises.access(filePath); } catch { return res.status(404).json({error:'Document not found'}); }
  // Find printer assigned to this user
  const allowedNames = getAllowedPrinterNames(req.user);
  let printerName = null;
  if (printer) {
    if (!isPrinterNameAllowed(req.user, printer)) {
      return res.status(403).json({error:'Not permitted to print to this printer'});
    }
    printerName = printer;
  } else if (allowedNames === null) {
    // admin or unrestricted — use CUPS default
    try {
      const { stdout } = await new Promise((resolve, reject) =>
        exec('LC_ALL=C lpstat -d 2>/dev/null', (e, o, er) => e ? reject(er) : resolve({stdout: o}))
      );
      const m = stdout.match(/system default destination:\s+(.+)/);
      printerName = m ? m[1].trim() : null;
    } catch {}
  } else {
    // Get first allowed CUPS printer name
    const cupsRes = await new Promise(resolve =>
      exec('LC_ALL=C lpstat -p 2>/dev/null', (e, o) => resolve(o||''))
    );
    const cupsLines = cupsRes.split('\n').map(l => {
      const m = l.match(/^printer (\S+)/); return m ? m[1] : null;
    }).filter(Boolean);
    printerName = cupsLines.find(n => allowedNames.has(n.toLowerCase())) || null;
  }
  if (!printerName) return res.status(400).json({error:'No printer assigned to this user. Please contact admin.'});
  try {
    const result = await printFile(filePath, printerName, copies||1, duplex||'none', color||'', docName);
    if (result.jobId) recordJobMetadata(result.jobId, docName, req.user.username);
    meta.prints = (meta.prints || 0) + 1;
    metaMap[name] = meta;
    saveSharedDocsMeta(metaMap);
    logSharedDocAction('PRINT', currentUser, name, meta.targetUser, `Cetak ke printer: ${printerName}`);
    res.json({ok:true, printer: printerName, ...result});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── API: print scanned file by name ──────────────────────────────────────────
app.post('/api/mobile/print-scan', express.json(), async (req, res) => {
  const { scanName, copies, duplex, color, printer } = req.body || {};
  if (!scanName) return res.status(400).json({error:'scanName required'});
  const filePath = path.join(SCAN_DIR, path.basename(scanName));
  try { await fs.promises.access(filePath); } catch { return res.status(404).json({error:'Scanned file not found'}); }

  // Find printer assigned to this user
  const allowedNames = getAllowedPrinterNames(req.user);
  let printerName = null;
  if (printer) {
    if (!isPrinterNameAllowed(req.user, printer)) {
      return res.status(403).json({error:'Not permitted to print to this printer'});
    }
    printerName = printer;
  } else if (allowedNames === null) {
    // admin or unrestricted — use CUPS default
    try {
      const { stdout } = await new Promise((resolve, reject) =>
        exec('LC_ALL=C lpstat -d 2>/dev/null', (e, o, er) => e ? reject(er) : resolve({stdout: o}))
      );
      const m = stdout.match(/system default destination:\s+(.+)/);
      printerName = m ? m[1].trim() : null;
    } catch {}
  } else {
    // Get first allowed CUPS printer name
    const cupsRes = await new Promise(resolve =>
      exec('LC_ALL=C lpstat -p 2>/dev/null', (e, o) => resolve(o||''))
    );
    const cupsLines = cupsRes.split('\n').map(l => {
      const m = l.match(/^printer (\S+)/); return m ? m[1] : null;
    }).filter(Boolean);
    printerName = cupsLines.find(n => allowedNames.has(n.toLowerCase())) || null;
  }
  if (!printerName) return res.status(400).json({error:'No printer assigned to this user. Please contact admin.'});
  try {
    const result = await printFile(filePath, printerName, copies||1, duplex||'none', color||'', scanName);
    if (result.jobId) recordJobMetadata(result.jobId, scanName, req.user.username);
    res.json({ok:true, printer: printerName, ...result});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── Mobile portal page ──────────────────────────────────────────────────────
// This route authenticates via QR token then sets a session cookie
app.get('/mobile', async (req, res) => {
  const token = req.query.token || req.query.t;
  let mobileUser = null;

  if (token) {
    const t = MOBILE_TOKENS[token];
    if (t && t.exp > Date.now()) {
      const user = USERS.find(u => u.username === t.username);
      if (user) {
        const sessToken = createSession(user);
        const sObj = sessions.get(sessToken);
        if (sObj) { sObj.isMobile = true; saveSessions(); }
        res.setHeader('Set-Cookie', `session=${sessToken}; HttpOnly; Path=/; Max-Age=${SESSION_TTL_MS/1000}; SameSite=Lax`);
        return res.redirect('/mobile');
      }
    }
  } else {
    // Check existing session
    const sess = getSession(req);
    if (sess) mobileUser = USERS.find(u => u.username === sess.username);
  }

  if (!mobileUser) {
    return res.status(401).send(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PrintServer Mobile</title><style>body{font-family:system-ui;background:#0f172a;color:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px;box-sizing:border-box}.card{background:#1e293b;border-radius:16px;padding:32px;text-align:center;max-width:340px;width:100%}.icon{font-size:3rem;margin-bottom:12px}.title{font-size:1.2rem;font-weight:700;margin-bottom:8px}.sub{font-size:.85rem;color:#94a3b8}</style></head><body><div class="card"><div class="icon">❌</div><div class="title">Invalid or Expired QR Code</div><div class="sub">Please ask your administrator to generate a new QR code for your account.</div></div></body></html>`);
  }

  // Determine assigned printer label
  const allowedNames = getAllowedPrinterNames(mobileUser);
  const allowedLabel = allowedNames ? [...allowedNames].join(', ') : 'All Printers';

  res.send(`<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>PrintServer Mobile — ${mobileUser.username}</title>
<meta name="theme-color" content="#0f172a">
<meta name="apple-mobile-web-app-capable" content="yes">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#f1f5f9;min-height:100vh;padding:0 0 80px}
  header{background:linear-gradient(135deg,#1e3a5f,#1e293b);padding:20px 16px 16px;display:flex;align-items:center;gap:12px;border-bottom:1px solid rgba(255,255,255,.08)}
  .logo{width:40px;height:40px;background:linear-gradient(135deg,#3b82f6,#6366f1);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:1.3rem;flex-shrink:0}
  .hinfo h1{font-size:1rem;font-weight:700;color:#f1f5f9}
  .hinfo .sub{font-size:.72rem;color:#64748b}
  .user-chip{margin-left:auto;background:rgba(59,130,246,.18);border:1px solid rgba(59,130,246,.3);color:#60a5fa;border-radius:20px;padding:4px 12px;font-size:.75rem;white-space:nowrap}
  .section{padding:16px}
  .section-title{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:#64748b;margin-bottom:10px}
  .printer-badge{background:linear-gradient(135deg,rgba(34,197,94,.15),rgba(16,185,129,.1));border:1px solid rgba(34,197,94,.3);border-radius:12px;padding:12px 16px;display:flex;align-items:center;gap:10px;margin-bottom:4px}
  .printer-badge .picon{font-size:1.5rem}
  .printer-badge .pinfo .name{font-weight:700;font-size:.9rem;color:#34d399}
  .printer-badge .pinfo .sub{font-size:.72rem;color:#64748b;margin-top:2px}
  .card{background:#1e293b;border:1px solid rgba(255,255,255,.07);border-radius:16px;overflow:hidden;margin-bottom:12px}
  .card-header{padding:12px 16px;border-bottom:1px solid rgba(255,255,255,.06);display:flex;align-items:center;justify-content:space-between}
  .card-header h2{font-size:.9rem;font-weight:700;display:flex;align-items:center;gap:8px}
  .card-body{padding:12px 16px}
  /* Doc list */
  .doc-item{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.05);cursor:pointer;transition:.15s}
  .doc-item:last-child{border-bottom:none}
  .doc-item:active{background:rgba(59,130,246,.08);margin:0 -16px;padding:10px 16px;border-radius:8px}
  .doc-icon{width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1.2rem;flex-shrink:0}
  .doc-icon.pdf{background:rgba(239,68,68,.15)}
  .doc-icon.doc{background:rgba(59,130,246,.15)}
  .doc-icon.img{background:rgba(234,179,8,.15)}
  .doc-icon.txt{background:rgba(100,116,139,.15)}
  .doc-name{font-size:.85rem;font-weight:600;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .doc-size{font-size:.7rem;color:#64748b;flex-shrink:0}
  .doc-radio{display:none}
  .doc-item.selected{background:rgba(59,130,246,.12);margin:0 -16px;padding:10px 16px;border-radius:8px;border-left:3px solid #3b82f6}
  /* Upload drop */
  .upload-zone{border:2px dashed rgba(255,255,255,.12);border-radius:12px;padding:24px;text-align:center;cursor:pointer;transition:.2s;background:rgba(255,255,255,.02)}
  .upload-zone:active,.upload-zone.drag{border-color:#3b82f6;background:rgba(59,130,246,.08)}
  .upload-zone .uz-icon{font-size:2rem;margin-bottom:8px}
  .upload-zone .uz-label{font-size:.82rem;color:#94a3b8}
  .upload-zone .uz-sub{font-size:.7rem;color:#64748b;margin-top:4px}
  .selected-file{background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.3);border-radius:10px;padding:10px 12px;margin-top:8px;display:none;align-items:center;gap:8px}
  .selected-file span{font-size:.82rem;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  /* Options */
  .opts-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:10px 0}
  .opt-field label{font-size:.68rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;display:block;margin-bottom:4px}
  select,input[type=number]{width:100%;background:#0f172a;border:1px solid rgba(255,255,255,.1);border-radius:8px;color:#f1f5f9;padding:8px 10px;font-size:.82rem;-webkit-appearance:none}
  select:focus,input:focus{outline:none;border-color:#3b82f6}
  /* Tabs */
  .tabs{display:grid;grid-template-columns:1fr 1fr;background:rgba(0,0,0,.25);border-radius:10px;padding:3px;margin-bottom:12px}
  .tab-btn{padding:8px;text-align:center;border-radius:8px;font-size:.78rem;font-weight:600;cursor:pointer;color:#94a3b8;transition:.2s;border:none;background:transparent}
  .tab-btn.active{background:#1e293b;color:#f1f5f9;box-shadow:0 2px 8px rgba(0,0,0,.3)}
  .tab-panel{display:none}
  .tab-panel.active{display:block}
  /* Print button */
  .print-btn{position:fixed;bottom:60px;left:0;right:0;padding:12px 16px;background:#0f172a;border-top:1px solid rgba(255,255,255,.08)}
  .print-btn button{width:100%;padding:16px;background:linear-gradient(135deg,#2563eb,#4f46e5);border:none;border-radius:14px;color:#fff;font-size:1rem;font-weight:700;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:10px;letter-spacing:.02em;transition:.2s;-webkit-tap-highlight-color:transparent}
  .print-btn button:active{transform:scale(.98)}
  .print-btn button:disabled{opacity:.5;transform:none}
  /* Bottom nav bar */
  .bottom-nav{position:fixed;bottom:0;left:0;right:0;display:grid;grid-template-columns:1fr 1fr;background:#0f172a;border-top:1px solid rgba(255,255,255,.1);z-index:100}
  .nav-tab{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:8px 0;cursor:pointer;color:#64748b;font-size:.68rem;font-weight:600;gap:2px;transition:.2s;border:none;background:transparent;-webkit-tap-highlight-color:transparent}
  .nav-tab .nav-icon{font-size:1.2rem;transition:.2s}
  .nav-tab.active{color:#3b82f6}
  .nav-tab.active .nav-icon{transform:scale(1.15)}
  .nav-tab:active{background:rgba(59,130,246,.08)}
  /* Page views */
  .page-view{display:none}
  .page-view.active{display:block}
  /* Print page: reserve room for fixed print bar (~76px @ bottom:60px) + bottom nav, on top of body's 80px */
  #page-print{padding-bottom:80px}
  /* Scans panel */
  .scan-item{display:flex;align-items:center;gap:10px;padding:12px 0;border-bottom:1px solid rgba(255,255,255,.05)}
  .scan-item:last-child{border-bottom:none}
  .scan-icon{width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:1.3rem;flex-shrink:0;background:rgba(239,68,68,.12)}
  .scan-info{flex:1;min-width:0}
  .scan-name{font-size:.82rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .scan-meta{font-size:.68rem;color:#64748b;margin-top:2px}
  .scan-actions{display:flex;gap:6px;flex-shrink:0}
  .scan-btn{width:36px;height:36px;border-radius:10px;border:none;display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:1rem;transition:.15s;-webkit-tap-highlight-color:transparent;text-decoration:none}
  .scan-btn.preview{background:rgba(59,130,246,.15);color:#60a5fa}
  .scan-btn.download{background:rgba(34,197,94,.15);color:#34d399}
  .scan-btn.print{background:rgba(99,102,241,.18);color:#a5b4fc}
  .scan-btn.share{background:rgba(234,179,8,.18);color:#facc15}
  .scan-btn.delete{background:rgba(239,68,68,.18);color:#f87171}
  .scan-btn:active{transform:scale(.9)}
  .scan-count{background:rgba(59,130,246,.15);color:#60a5fa;border-radius:20px;padding:2px 10px;font-size:.72rem;font-weight:700}
  .scan-refresh-btn{background:transparent;border:1px solid rgba(255,255,255,.12);color:#94a3b8;border-radius:8px;padding:4px 10px;font-size:.72rem;cursor:pointer;display:flex;align-items:center;gap:4px}
  .scan-refresh-btn:active{background:rgba(255,255,255,.05)}
  /* Status */
  .status-toast{position:fixed;top:20px;left:16px;right:16px;padding:14px 16px;border-radius:12px;font-weight:600;font-size:.85rem;z-index:999;display:none;animation:slideIn .3s ease}
  .status-toast.ok{background:rgba(34,197,94,.2);border:1px solid rgba(34,197,94,.4);color:#34d399}
  .status-toast.err{background:rgba(239,68,68,.2);border:1px solid rgba(239,68,68,.4);color:#f87171}
  @keyframes slideIn{from{transform:translateY(-20px);opacity:0}to{transform:translateY(0);opacity:1}}
  .spinner{width:18px;height:18px;border:2.5px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  .empty-docs{text-align:center;padding:30px 16px;color:#64748b;font-size:.82rem}
  .empty-docs .ei{font-size:2rem;margin-bottom:8px}
</style>
</head>
<body>

<div class="status-toast" id="toast"></div>

<header>
  <div class="logo">🖨</div>
  <div class="hinfo">
    <h1>PrintServer Mobile</h1>
    <div class="sub">Print & Scan Portal</div>
  </div>
  <div class="user-chip">👤 ${mobileUser.username}</div>
</header>

<!-- ═══ PAGE: PRINT ═══ -->
<div class="page-view active" id="page-print">
<div class="section">
  <div class="section-title">🖨 Assigned Printer</div>
  <div class="printer-badge" style="flex-wrap:wrap">
    <div class="picon">🖨</div>
    <div class="pinfo" style="flex:1;min-width:160px">
      <div class="name" id="printer-name-label">Loading…</div>
      <div class="sub">${allowedLabel === 'All Printers' ? 'Auto-selected from available printers' : 'Assigned printer'}</div>
    </div>
    <div id="printer-select-wrapper" style="display:none;width:100%;margin-top:8px">
      <select id="printer-select" onchange="onPrinterSelected(this.value)" style="background:#0f172a;border:1px solid rgba(255,255,255,.2);color:#34d399;font-weight:700;padding:6px 10px;border-radius:8px">
      </select>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">📄 Select Document to Print</div>
  <div class="card">
    <div class="card-body">
      <div class="tabs">
        <button class="tab-btn active" id="tab-server" onclick="switchDocTab('server')">
          📁 Server Docs <span class="badge" id="shared-docs-badge" style="display:none;background:#ef4444;color:#fff;font-size:0.68rem;padding:2px 6px;border-radius:10px;margin-left:4px;"></span>
        </button>
        <button class="tab-btn" id="tab-upload" onclick="switchDocTab('upload')">📤 Upload from HP</button>
      </div>

      <!-- Server docs tab -->
      <div class="tab-panel active" id="panel-server">
        <div id="docs-list"><div class="empty-docs"><div class="ei">⏳</div>Loading documents…</div></div>
      </div>

      <!-- Upload tab -->
      <div class="tab-panel" id="panel-upload">
        <div class="upload-zone" id="upload-zone" onclick="document.getElementById('file-input').click()">
          <input type="file" id="file-input" accept=".pdf,.doc,.docx,.dot,.dotx,.docm,.rtf,.odt,.txt,.jpg,.jpeg,.png,.xls,.xlsx,.ppt,.pptx" style="display:none" onchange="onFileSelected(this)">
          <div class="uz-icon">📤</div>
          <div class="uz-label">Tap to pilih file dari HP</div>
          <div class="uz-sub">PDF, Word (DOC/DOCX), RTF, TXT, Excel, PNG, JPG • maks 50MB</div>
        </div>
        <div class="selected-file" id="selected-file-info">
          <span id="selected-file-name">—</span>
          <span style="color:#94a3b8;font-size:.72rem" id="selected-file-size"></span>
        </div>
        <div class="opt-field" style="margin-top:10px;">
          <label style="font-size:.75rem;color:#94a3b8;font-weight:600;">Kirim Ke (Target Penerima Privasi)</label>
          <select id="upload-target-user" style="width:100%;background:#0f172a;border:1px solid rgba(255,255,255,.2);color:#f1f5f9;padding:8px 10px;border-radius:8px;font-size:.82rem">
            <option value="all">🌐 Semua User (Publik)</option>
          </select>
        </div>
      </div>
    </div>
  </div>

  <!-- Print options -->
  <div class="card">
    <div class="card-header"><h2>⚙️ Print Options</h2></div>
    <div class="card-body">
      <div class="opts-grid">
        <div class="opt-field">
          <label>Copies</label>
          <input type="number" id="opt-copies" value="1" min="1" max="99">
        </div>
        <div class="opt-field">
          <label>Duplex</label>
          <select id="opt-duplex">
            <option value="none">Single sided</option>
            <option value="long">Double (long edge)</option>
            <option value="short">Double (short edge)</option>
          </select>
        </div>
        <div class="opt-field">
          <label>Color</label>
          <select id="opt-color">
            <option value="">Printer default</option>
            <option value="color">Color</option>
            <option value="mono">Black &amp; White</option>
          </select>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="print-btn" id="print-btn-bar">
  <button id="print-btn" onclick="doPrint()" disabled>
    <span id="print-btn-icon">🖨</span>
    <span id="print-btn-label">Pilih Dokumen Dahulu</span>
  </button>
</div>
</div><!-- /page-print -->

<!-- ═══ PAGE: SCANS ═══ -->
<div class="page-view" id="page-scans">
<div class="section">
  <div class="card" style="margin-bottom:12px;">
    <div class="card-header"><h2>🖨 Remote Scanner (Scan to HP)</h2></div>
    <div class="card-body" style="padding:12px 16px;">
      <div class="opts-grid" style="grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px;">
        <div class="opt-field" style="grid-column:1 / -1;">
          <label>Pilih Scanner</label>
          <select id="mobile-scan-device"><option value="">Memuat scanner…</option></select>
        </div>
        <div class="opt-field">
          <label>Sumber Kertas</label>
          <select id="mobile-scan-source">
            <option value="Flatbed">Flatbed (Kaca)</option>
            <option value="ADF">ADF Simplex</option>
            <option value="ADF Duplex">ADF Duplex</option>
          </select>
        </div>
        <div class="opt-field" style="display:flex;align-items:flex-end;">
          <button class="scan-refresh-btn" style="width:100%;height:35px;justify-content:center;background:rgba(59,130,246,.18);color:#60a5fa;border-color:rgba(59,130,246,.3);font-weight:700;" onclick="triggerMobileScanNow()" id="mobile-scan-now-btn">
            🖨 Scan Now
          </button>
        </div>
        <div class="opt-field" style="grid-column:1 / -1;margin-top:4px;border-top:1px dashed rgba(255,255,255,0.1);padding-top:10px;">
          <input type="file" id="mobile-cam-input" accept="image/*,application/pdf" capture="environment" style="display:none" onchange="uploadMobileCamScan(this)">
          <button class="scan-refresh-btn" style="width:100%;height:38px;justify-content:center;background:linear-gradient(135deg,#059669,#10b981);color:#fff;border:none;font-weight:700;border-radius:8px;" onclick="document.getElementById('mobile-cam-input').click()" id="mobile-cam-btn">
            📷 Scan / Foto Dokumen via Kamera HP
          </button>
        </div>
      </div>
      <div id="mobile-scan-status"></div>
    </div>
  </div>

  <div class="section-title" style="display:flex;align-items:center;justify-content:space-between">
    <span>📄 Hasil Scan</span>
    <div style="display:flex;align-items:center;gap:8px">
      <span class="scan-count" id="scan-count">0</span>
      <button class="scan-refresh-btn" onclick="loadMobileScans()">🔄 Refresh</button>
    </div>
  </div>
  <div class="card">
    <div class="card-body" id="scans-list" style="padding:6px 16px">
      <div class="empty-docs"><div class="ei">⏳</div>Memuat file scan…</div>
    </div>
  </div>
</div>
<div class="section" style="padding-bottom:80px">
  <div class="card">
    <div class="card-body" style="text-align:center;padding:16px">
      <div style="font-size:.75rem;color:#64748b;line-height:1.6">
        📌 <strong>Cara Scan:</strong> Taruh dokumen di mesin printer MFP,<br>pilih <em>Scan to Folder</em> pada layar printer, lalu tekan Start.<br>Hasil scan otomatis muncul di sini dalam beberapa detik.
      </div>
    </div>
  </div>
</div>
</div><!-- /page-scans -->

<!-- ═══ BOTTOM TAB NAVIGATION ═══ -->
<nav class="bottom-nav">
  <button class="nav-tab active" id="nav-print" onclick="switchPage('print')">
    <span class="nav-icon">🖨</span> Print
  </button>
  <button class="nav-tab" id="nav-scans" onclick="switchPage('scans')">
    <span class="nav-icon">📄</span> Scans
  </button>
</nav>

<script>
let docTab = 'server';
let selectedServerDoc = null;
let selectedUploadFile = null;
let assignedPrinter = null;

// ── Resolve assigned printer ──────────────────────────────────────────────
// Map CUPS state from /api/cups/printers/detail ("is idle" | "now printing" | "disabled")
function printerStateLabel(state) {
  const s = String(state || '').toLowerCase();
  if (s.includes('disabled')) return 'Disabled';
  if (s.includes('printing')) return 'Printing';
  return 'Ready';
}
const PRINTER_PREF_KEY = 'ps-mobile-printer';
function isPrinterOff(p) { return String(p && p.state || '').toLowerCase().includes('disabled'); }
function loadPrinterPref() { try { return localStorage.getItem(PRINTER_PREF_KEY) || ''; } catch { return ''; } }
function savePrinterPref(name) { try { localStorage.setItem(PRINTER_PREF_KEY, name); } catch {} }
let printerList = [];
function updatePrinterLabel() {
  const p = printerList.find(x => x.name === assignedPrinter);
  document.getElementById('printer-name-label').textContent =
    p ? p.name + ' (' + printerStateLabel(p.state) + ')' : (assignedPrinter || '');
}
async function resolveAssignedPrinter() {
  try {
    const r = await fetch('/api/cups/printers/detail');
    const d = await r.json();
    const def = d.defaultPrinter;
    // Same ordering as dashboard: enabled first, CUPS default first, then A–Z
    const printers = (d.printers || []).slice().sort((a, b) => {
      const aOn = !isPrinterOff(a), bOn = !isPrinterOff(b);
      if (aOn !== bOn) return aOn ? -1 : 1;
      if (a.name === def) return -1;
      if (b.name === def) return 1;
      return a.name.localeCompare(b.name);
    });
    printerList = printers;
    const selectEl = document.getElementById('printer-select');
    const selectWrap = document.getElementById('printer-select-wrapper');
    const nameLabel = document.getElementById('printer-name-label');

    if (!printers.length) {
      selectWrap.style.display = 'none';
      assignedPrinter = null;
      nameLabel.textContent = 'Tidak Ada Printer Assigned / Aktif';
      return;
    }

    // Pick: last choice on this device → CUPS default → first enabled → first
    const usable = name => printers.some(p => p.name === name && !isPrinterOff(p));
    const saved = loadPrinterPref();
    const firstOn = printers.find(p => !isPrinterOff(p));
    assignedPrinter = usable(saved) ? saved
      : usable(def) ? def
      : (firstOn || printers[0]).name;

    if (printers.length > 1) {
      selectWrap.style.display = 'block';
      selectEl.innerHTML = printers.map(p =>
        '<option value="' + escHtml(p.name) + '">' + escHtml(p.name) +
        (p.name === def ? ' ★' : '') + ' (' + printerStateLabel(p.state) + ')</option>'
      ).join('');
      selectEl.value = assignedPrinter;
    } else {
      selectWrap.style.display = 'none';
    }
    updatePrinterLabel();
  } catch {
    document.getElementById('printer-name-label').textContent = 'Gagal memuat printer';
  }
}

function onPrinterSelected(val) {
  assignedPrinter = val;
  savePrinterPref(val);
  updatePrinterLabel();
}

// ── Server docs ───────────────────────────────────────────────────────────
async function loadSharedDocTargets() {
  try {
    const r = await fetch('/api/shared-docs/targets');
    const d = await r.json();
    const sel = document.getElementById('upload-target-user');
    if (sel && d.targets) {
      sel.innerHTML = '<option value="all">🌐 Semua User (Publik)</option>' +
        d.targets.map(u => '<option value="' + escHtml(u.username) + '">🔒 ' + escHtml(u.username) + '</option>').join('');
    }
  } catch {}
}

async function loadServerDocs() {
  try {
    const r = await fetch('/api/shared-docs');
    const d = await r.json();
    const docs = d.docs || [];
    const list = document.getElementById('docs-list');
    
    // Update badge
    const badge = document.getElementById('shared-docs-badge');
    if (badge) {
      if (d.unreadCount > 0) {
        badge.style.display = 'inline-block';
        badge.textContent = '📩 ' + d.unreadCount + ' Baru';
      } else {
        badge.style.display = 'none';
      }
    }

    if (!docs.length) {
      list.innerHTML = '<div class="empty-docs"><div class="ei">📂</div>Belum ada dokumen di server.<br>Minta admin untuk upload dokumen.</div>';
      return;
    }

    list.innerHTML = docs.map(doc => {
      const ext = doc.name.split('.').pop().toLowerCase();
      const icons = {pdf:'📕',doc:'📘',docx:'📘',dot:'📘',dotx:'📘',docm:'📘',rtf:'📄',odt:'📄',txt:'📄',jpg:'🖼',jpeg:'🖼',png:'🖼',xls:'📊',xlsx:'📊',ppt:'📊',pptx:'📊'};
      const iconClass = {pdf:'pdf',doc:'doc',docx:'doc',dot:'doc',dotx:'doc',docm:'doc',rtf:'txt',odt:'txt',txt:'txt',jpg:'img',jpeg:'img',png:'img',xls:'doc',xlsx:'doc',ppt:'doc',pptx:'doc'};
      const isTargetMe = doc.targetUser === d.currentUser;
      const isPublic = doc.targetUser === 'all';
      const targetTag = isPublic 
        ? '<span style="font-size:.65rem;background:rgba(59,130,246,.2);color:#60a5fa;padding:1px 5px;border-radius:4px;">🌐 Publik</span>'
        : '<span style="font-size:.65rem;background:rgba(234,179,8,.2);color:#fde047;padding:1px 5px;border-radius:4px;">🔒 Privat (' + (isTargetMe ? 'Untuk Anda' : 'Dari: ' + escHtml(doc.uploader)) + ')</span>';

      return '<div class="doc-item" id="ditem-' + escJs(doc.name) + '" onclick="selectServerDoc(\\\'' + escJs(doc.name) + '\\\')">' +
        '<div class="doc-icon ' + (iconClass[ext]||'txt') + '">' + (icons[ext]||'📄') + '</div>' +
        '<div style="flex:1;min-width:0;">' +
          '<div class="doc-name">' + escHtml(doc.name) + '</div>' +
          '<div style="display:flex;align-items:center;gap:6px;margin-top:2px;">' +
            '<div class="doc-size">' + fmtSize(doc.size) + '</div>' +
            targetTag +
          '</div>' +
        '</div>' +
        '<div style="display:flex;align-items:center;gap:4px;" onclick="event.stopPropagation()">' +
          '<a class="scan-btn download" href="/api/shared-docs/download/' + encodeURIComponent(doc.name) + '" download title="Download">⬇</a>' +
          '<button class="scan-btn delete" onclick="deleteSharedDocFromMobile(\\\'' + escJs(doc.name) + '\\\')" title="Hapus">🗑</button>' +
        '</div>' +
      '</div>';
    }).join('');
  } catch {
    document.getElementById('docs-list').innerHTML = '<div class="empty-docs">Gagal memuat dokumen</div>';
  }
}

async function deleteSharedDocFromMobile(name) {
  if (!confirm('Hapus dokumen bersama: "' + name + '"?')) return;
  try {
    const r = await fetch('/api/shared-docs/' + encodeURIComponent(name), { method: 'DELETE' });
    const d = await r.json();
    if (d.ok) {
      showToast('🗑 Dokumen berhasil dihapus', 'ok');
      loadServerDocs();
    } else {
      throw new Error(d.error || 'Gagal menghapus dokumen');
    }
  } catch(e) {
    showToast('❌ ' + e.message, 'err');
  }
}

function selectServerDoc(name) {
  document.querySelectorAll('.doc-item').forEach(el => el.classList.remove('selected'));
  const el = document.getElementById('ditem-' + escJs(name));
  if (el) el.classList.add('selected');
  selectedServerDoc = name;
  selectedUploadFile = null;
  const info = document.getElementById('selected-file-info');
  if (info) info.style.display = 'none';
  updatePrintBtn();
}

function switchDocTab(tab) {
  docTab = tab;
  document.getElementById('tab-server').classList.toggle('active', tab==='server');
  document.getElementById('tab-upload').classList.toggle('active', tab==='upload');
  document.getElementById('panel-server').classList.toggle('active', tab==='server');
  document.getElementById('panel-upload').classList.toggle('active', tab==='upload');
  updatePrintBtn();
}

// ── Upload ────────────────────────────────────────────────────────────────
function onFileSelected(input) {
  const file = input.files[0];
  if (!file) return;
  selectedUploadFile = file;
  selectedServerDoc = null;
  document.querySelectorAll('.doc-item').forEach(el => el.classList.remove('selected'));
  const info = document.getElementById('selected-file-info');
  info.style.display = 'flex';
  document.getElementById('selected-file-name').textContent = file.name;
  document.getElementById('selected-file-size').textContent = fmtSize(file.size);
  updatePrintBtn();
}

// ── Print button ──────────────────────────────────────────────────────────
function updatePrintBtn() {
  const btn = document.getElementById('print-btn');
  const label = document.getElementById('print-btn-label');
  const activeDocName = docTab === 'server' ? selectedServerDoc : (selectedUploadFile ? selectedUploadFile.name : null);
  if (activeDocName) {
    btn.disabled = false;
    label.textContent = 'Print: ' + activeDocName.substring(0, 28) + (activeDocName.length > 28 ? '…' : '');
  } else {
    btn.disabled = true;
    label.textContent = 'Pilih Dokumen Dahulu';
  }
}

async function doPrint() {
  const btn = document.getElementById('print-btn');
  const icon = document.getElementById('print-btn-icon');
  const label = document.getElementById('print-btn-label');
  btn.disabled = true;
  icon.outerHTML = '<div class="spinner" id="print-btn-icon"></div>';
  label.textContent = 'Mengirim ke printer…';

  try {
    const copies = parseInt(document.getElementById('opt-copies').value) || 1;
    const duplex = document.getElementById('opt-duplex').value;
    const color  = document.getElementById('opt-color').value;
    let res, d;

    if (docTab === 'server' && selectedServerDoc) {
      // Print from server doc
      res = await fetch('/api/mobile/print-shared', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ docName: selectedServerDoc, copies, duplex, color, printer: assignedPrinter })
      });
      d = await res.json();
    } else if (docTab === 'upload' && selectedUploadFile) {
      // Upload then print
      const fd = new FormData();
      fd.append('file', selectedUploadFile);
      fd.append('copies', copies);
      fd.append('duplex', duplex);
      fd.append('color', color);
      if (!assignedPrinter) { throw new Error('Tidak ada printer yang ditugaskan / aktif untuk akun Anda'); }
      fd.append('printer', assignedPrinter);
      res = await fetch('/api/print', { method:'POST', body: fd });
      d = await res.json();
    } else {
      throw new Error('Silakan pilih dokumen terlebih dahulu');
    }

    if (d && d.ok) {
      const activeDocName = docTab === 'server' ? selectedServerDoc : (selectedUploadFile ? selectedUploadFile.name : '');
      showPrintSuccessModal({
        title: 'Successfully',
        docName: activeDocName,
        printerName: d.printer || assignedPrinter || '',
        jobId: d.jobId || 'queued'
      });
      selectedServerDoc = null;
      selectedUploadFile = null;
      document.querySelectorAll('.doc-item').forEach(el => el.classList.remove('selected'));
      document.getElementById('selected-file-info').style.display = 'none';
      document.getElementById('file-input').value = '';
    } else {
      throw new Error((d && d.error) || 'Print gagal');
    }
  } catch(e) {
    showToast('❌ ' + e.message, 'err');
    showPrintErrorModal({ title: 'Failed', message: e.message });
  } finally {
    document.getElementById('print-btn-icon').outerHTML = '<span id="print-btn-icon">🖨</span>';
    updatePrintBtn();
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────
function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function escJs(s)   { return String(s).replace(/'/g,"\\\\'").replace(/"/g,'\\\\"'); }
function fmtSize(b) { if (b>1048576) return (b/1048576).toFixed(1)+'MB'; if (b>1024) return (b/1024).toFixed(0)+'KB'; return b+'B'; }
function showToast(msg, type) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'status-toast ' + type;
  el.style.display = 'block';
  setTimeout(() => { el.style.display = 'none'; }, 4000);
}

function showPrintSuccessModal({ title = 'Successfully', docName = '', printerName = '', jobId = '', message = '' }) {
  const old = document.getElementById('print-success-modal-overlay');
  if (old) old.remove();

  if (!document.getElementById('print-success-style')) {
    const st = document.createElement('style');
    st.id = 'print-success-style';
    st.textContent =
      '@keyframes popInModal { 0% { opacity:0; transform:scale(0.8); } 70% { transform:scale(1.05); } 100% { opacity:1; transform:scale(1); } }' +
      '@keyframes fadeInModal { from { opacity:0; } to { opacity:1; } }';
    document.head.appendChild(st);
  }

  const overlay = document.createElement('div');
  overlay.id = 'print-success-modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.65);backdrop-filter:blur(6px);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;animation:fadeInModal 0.2s ease-out;';

  const defaultMsg = (docName ? 'Dokumen <strong>' + escHtml(docName) + '</strong>' : 'Dokumen')
    + (printerName ? ' berhasil dikirim ke printer <strong>' + escHtml(printerName) + '</strong>.' : ' berhasil dikirim ke printer.')
    + (jobId ? '<br><span style="font-size:0.78rem;color:#64748b;margin-top:6px;display:inline-block;background:#f1f5f9;padding:2px 8px;border-radius:6px;">Job ID: #' + escHtml(jobId) + '</span>' : '');

  const finalMsg = message || defaultMsg;

  overlay.innerHTML =
    '<div style="background:#ffffff;color:#1e293b;border-radius:24px;width:100%;max-width:360px;text-align:center;position:relative;box-shadow:0 25px 50px -12px rgba(0,0,0,0.4);overflow:hidden;animation:popInModal 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);font-family:system-ui,sans-serif;">'
      + '<div style="background:#f8fafc;padding:32px 20px 20px;position:relative;display:flex;justify-content:center;align-items:center;">'
        + '<svg style="position:absolute;top:16px;left:40px;width:22px;height:22px;color:#3b82f6;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10"/></svg>'
        + '<svg style="position:absolute;top:12px;right:45px;width:26px;height:26px;color:#ef4444;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M4 12a8 8 0 0 1 8-8"/></svg>'
        + '<svg style="position:absolute;bottom:14px;left:50px;width:18px;height:18px;color:#a855f7;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 22a10 10 0 0 0 10-10"/></svg>'

        + '<div style="width:72px;height:72px;background:#22c55e;border-radius:50%;display:flex;align-items:center;justify-content:center;box-shadow:0 10px 20px rgba(34,197,94,0.35);position:relative;z-index:2;">'
          + '<svg style="width:40px;height:40px;color:#ffffff;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round">'
            + '<polyline points="20 6 9 17 4 12"></polyline>'
          + '</svg>'
        + '</div>'
      + '</div>'

      + '<div style="padding:10px 24px 20px;">'
        + '<h2 style="margin:0 0 10px;font-size:1.7rem;font-weight:800;color:#0f172a;letter-spacing:-0.02em;">' + escHtml(title) + '</h2>'
        + '<div style="font-size:0.9rem;color:#64748b;line-height:1.5;">' + finalMsg + '</div>'
      + '</div>'

      + '<div style="padding:0 24px 24px;">'
        + '<button style="width:100%;padding:14px;background:#e2e8f0;color:#0f172a;border:none;border-radius:14px;font-size:1.05rem;font-weight:700;cursor:pointer;box-shadow:0 2px 6px rgba(0,0,0,0.05);transition:background 0.2s;" onclick="closePrintSuccessModal()">'
          + 'Oke'
        + '</button>'
      + '</div>'
    + '</div>';

  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) closePrintSuccessModal(); });
}

function closePrintSuccessModal() {
  const o = document.getElementById('print-success-modal-overlay');
  if (o) o.remove();
}

function showPrintErrorModal({ title = 'Failed', message = 'Terjadi kesalahan saat memproses permintaan.' }) {
  const old = document.getElementById('print-error-modal-overlay');
  if (old) old.remove();

  if (!document.getElementById('print-success-style')) {
    const st = document.createElement('style');
    st.id = 'print-success-style';
    st.textContent =
      '@keyframes popInModal { 0% { opacity:0; transform:scale(0.8); } 70% { transform:scale(1.05); } 100% { opacity:1; transform:scale(1); } }' +
      '@keyframes fadeInModal { from { opacity:0; } to { opacity:1; } }';
    document.head.appendChild(st);
  }

  const overlay = document.createElement('div');
  overlay.id = 'print-error-modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.65);backdrop-filter:blur(6px);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;animation:fadeInModal 0.2s ease-out;';

  overlay.innerHTML =
    '<div style="background:#ffffff;color:#1e293b;border-radius:24px;width:100%;max-width:360px;text-align:center;position:relative;box-shadow:0 25px 50px -12px rgba(0,0,0,0.4);overflow:hidden;animation:popInModal 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);font-family:system-ui,sans-serif;">'
      + '<div style="background:#fef2f2;padding:32px 20px 20px;position:relative;display:flex;justify-content:center;align-items:center;">'
        + '<svg style="position:absolute;top:16px;left:40px;width:22px;height:22px;color:#f59e0b;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
        + '<svg style="position:absolute;top:12px;right:45px;width:26px;height:26px;color:#ef4444;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 9v4m0 4h.01"/></svg>'

        + '<div style="width:72px;height:72px;background:#ef4444;border-radius:50%;display:flex;align-items:center;justify-content:center;box-shadow:0 10px 20px rgba(239,68,68,0.35);position:relative;z-index:2;">'
          + '<svg style="width:38px;height:38px;color:#ffffff;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round">'
            + '<line x1="18" y1="6" x2="6" y2="18"></line>'
            + '<line x1="6" y1="6" x2="18" y2="18"></line>'
          + '</svg>'
        + '</div>'
      + '</div>'

      + '<div style="padding:10px 24px 20px;">'
        + '<h2 style="margin:0 0 10px;font-size:1.7rem;font-weight:800;color:#0f172a;letter-spacing:-0.02em;">' + escHtml(title) + '</h2>'
        + '<div style="font-size:0.9rem;color:#64748b;line-height:1.5;">' + escHtml(message) + '</div>'
      + '</div>'

      + '<div style="padding:0 24px 24px;">'
        + '<button style="width:100%;padding:14px;background:#fee2e2;color:#991b1b;border:none;border-radius:14px;font-size:1.05rem;font-weight:700;cursor:pointer;box-shadow:0 2px 6px rgba(0,0,0,0.05);transition:background 0.2s;" onclick="closePrintErrorModal()">'
          + 'Tutup'
        + '</button>'
      + '</div>'
    + '</div>';

  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) closePrintErrorModal(); });
}

function closePrintErrorModal() {
  const o = document.getElementById('print-error-modal-overlay');
  if (o) o.remove();
}

// ── Page switching ────────────────────────────────────────────────────────
let currentPage = 'print';
function switchPage(page) {
  currentPage = page;
  document.querySelectorAll('.page-view').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(el => el.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  document.getElementById('nav-' + page).classList.add('active');
  if (page === 'scans') { loadMobileScans(); loadMobileScanDevices(); }
}

// ── Mobile Scans ──────────────────────────────────────────────────────────
let scanRefreshTimer = null;
async function loadMobileScans() {
  const list = document.getElementById('scans-list');
  const countEl = document.getElementById('scan-count');
  try {
    const r = await fetch('/api/scans');
    const d = await r.json();
    const scans = d.scans || [];
    countEl.textContent = scans.length;
    if (!scans.length) {
      list.innerHTML = '<div class="empty-docs"><div class="ei">📂</div>Belum ada file scan.<br>Silakan scan dokumen dari mesin printer MFP.</div>';
      return;
    }
    list.innerHTML = scans.map(s => {
      const ext = s.name.split('.').pop().toLowerCase();
      const icons = {pdf:'📕',jpg:'🖼',jpeg:'🖼',png:'🖼',tiff:'🖼',tif:'🖼'};
      return '<div class="scan-item">' +
        '<div class="scan-icon">' + (icons[ext]||'📄') + '</div>' +
        '<div class="scan-info">' +
          '<div class="scan-name">' + escHtml(s.name) + '</div>' +
          '<div class="scan-meta">' + fmtSize(s.size) + (s.mtime ? ' • ' + new Date(s.mtime).toLocaleString('id-ID',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}) : '') + '</div>' +
        '</div>' +
        '<div class="scan-actions">' +
          '<a class="scan-btn preview" href="/api/scans/download/' + encodeURIComponent(s.name) + '?inline=1" target="_blank" rel="noopener" title="Preview">👁</a>' +
          '<a class="scan-btn download" href="/api/scans/download/' + encodeURIComponent(s.name) + '" download title="Download">⬇</a>' +
          '<button class="scan-btn print" onclick="openScanPrintModal(\\\'' + escJs(s.name) + '\\\')" title="Print">🖨</button>' +
          '<button class="scan-btn share" onclick="shareMobileScan(\\\'' + escJs(s.name) + '\\\')" title="Share">📤</button>' +
          '<button class="scan-btn delete" onclick="deleteMobileScan(\\\'' + escJs(s.name) + '\\\')" title="Hapus">🗑</button>' +
        '</div>' +
      '</div>';
    }).join('');
  } catch {
    list.innerHTML = '<div class="empty-docs">Gagal memuat file scan</div>';
  }
  // Auto-refresh every 30 seconds when on scans page
  clearTimeout(scanRefreshTimer);
  if (currentPage === 'scans') {
    scanRefreshTimer = setTimeout(loadMobileScans, 30000);
  }
}

// ── Direct Print from Scan modal ──────────────────────────────────────────
function openScanPrintModal(scanName) {
  closeScanPrintModal();
  const overlay = document.createElement('div');
  overlay.id = 'scan-print-modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center;padding:20px;';
  
  const pName = assignedPrinter || 'Default Printer';
  const optionsHtml = printerList && printerList.length > 1
    ? '<select id="sp-printer-select" style="background:#0f172a;border:1px solid rgba(255,255,255,.2);color:#34d399;font-weight:700;padding:6px 10px;border-radius:8px;width:100%">' +
        printerList.map(p => '<option value="' + escHtml(p.name) + '"' + (p.name === assignedPrinter ? ' selected' : '') + '>' + escHtml(p.name) + ' (' + printerStateLabel(p.state) + ')</option>').join('') +
      '</select>'
    : '<div style="font-weight:700;color:#34d399;font-size:.88rem;background:#0f172a;padding:8px 12px;border-radius:8px;border:1px solid rgba(255,255,255,.1);">' + escHtml(pName) + '</div>';

  overlay.innerHTML =
    '<div style="background:#1e293b;border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:20px;max-width:360px;width:100%;text-align:left;box-shadow:0 10px 30px rgba(0,0,0,0.5);">'
    + '<h3 style="margin:0 0 4px;color:#f1f5f9;font-size:1rem;display:flex;align-items:center;gap:8px;">🖨 Print Hasil Scan</h3>'
    + '<div style="font-size:.78rem;color:#94a3b8;margin-bottom:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">📄 <strong>' + escHtml(scanName) + '</strong></div>'
    
    + '<div style="margin-bottom:10px;">'
    + '<label style="font-size:.68rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;display:block;margin-bottom:4px;">Target Printer</label>'
    + optionsHtml
    + '</div>'

    + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px;">'
    + '<div><label style="font-size:.68rem;color:#94a3b8;text-transform:uppercase;display:block;margin-bottom:4px;">Copies</label>'
    + '<input type="number" id="sp-copies" value="1" min="1" max="99" style="width:100%;background:#0f172a;border:1px solid rgba(255,255,255,.1);border-radius:8px;color:#f1f5f9;padding:8px;font-size:.82rem;"></div>'
    + '<div><label style="font-size:.68rem;color:#94a3b8;text-transform:uppercase;display:block;margin-bottom:4px;">Duplex</label>'
    + '<select id="sp-duplex" style="width:100%;background:#0f172a;border:1px solid rgba(255,255,255,.1);border-radius:8px;color:#f1f5f9;padding:8px;font-size:.82rem;">'
    + '<option value="none">Single sided</option><option value="long">Double (long edge)</option><option value="short">Double (short edge)</option></select></div>'
    + '</div>'

    + '<div style="display:flex;gap:8px;">'
    + '<button class="btn-primary btn-sm" id="sp-submit-btn" style="flex:1;padding:12px;border-radius:10px;font-weight:700;" onclick="doPrintScan(\\\'' + escJs(scanName) + '\\\')">🖨 Kirim ke Printer</button>'
    + '<button class="btn-outline btn-sm" style="padding:12px;" onclick="closeScanPrintModal()">Batal</button>'
    + '</div>'
    + '</div>';

  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) closeScanPrintModal(); });
}

function closeScanPrintModal() {
  const o = document.getElementById('scan-print-modal-overlay');
  if (o) o.remove();
}

async function doPrintScan(scanName) {
  const btn = document.getElementById('sp-submit-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Mengirim…'; }
  const pSel = document.getElementById('sp-printer-select');
  const targetPrinter = pSel ? pSel.value : assignedPrinter;
  const copies = parseInt(document.getElementById('sp-copies')?.value || '1') || 1;
  const duplex = document.getElementById('sp-duplex')?.value || 'none';

  try {
    const res = await fetch('/api/mobile/print-scan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ scanName, copies, duplex, printer: targetPrinter })
    });
    const d = await res.json();
    if (d && d.ok) {
      closeScanPrintModal();
      showPrintSuccessModal({
        title: 'Successfully',
        docName: scanName,
        printerName: d.printer || targetPrinter || '',
        jobId: d.jobId || 'queued'
      });
    } else {
      throw new Error((d && d.error) || 'Gagal mengirim ke printer');
    }
  } catch(e) {
    showToast('❌ ' + e.message, 'err');
    showPrintErrorModal({ title: 'Failed', message: e.message });
    if (btn) { btn.disabled = false; btn.textContent = '🖨 Kirim ke Printer'; }
  }
}

// ── Web Share API for Mobile Scans ───────────────────────────────────────
async function shareMobileScan(scanName) {
  const fileUrl = window.location.origin + '/api/scans/download/' + encodeURIComponent(scanName);
  const inlineUrl = fileUrl + '?inline=1';

  if (navigator.share) {
    try {
      if (navigator.canShare) {
        showToast('⏳ Menyiapkan file untuk dibagikan…', 'ok');
        const resp = await fetch(inlineUrl);
        const blob = await resp.blob();
        const mimeType = blob.type || (scanName.endsWith('.pdf') ? 'application/pdf' : scanName.endsWith('.png') ? 'image/png' : 'image/jpeg');
        const file = new File([blob], scanName, { type: mimeType });
        if (navigator.canShare({ files: [file] })) {
          await navigator.share({
            title: scanName,
            text: 'Hasil scan: ' + scanName,
            files: [file]
          });
          return;
        }
      }
      await navigator.share({
        title: scanName,
        text: 'Hasil scan: ' + scanName,
        url: inlineUrl
      });
      return;
    } catch(err) {
      if (err.name === 'AbortError') return;
    }
  }

  try {
    await navigator.clipboard.writeText(inlineUrl);
    showToast('📋 Link hasil scan berhasil disalin ke clipboard!', 'ok');
  } catch {
    const input = document.createElement('input');
    input.value = inlineUrl;
    document.body.appendChild(input);
    input.select();
    document.execCommand('copy');
    document.body.removeChild(input);
    showToast('📋 Link hasil scan berhasil disalin!', 'ok');
  }
}

// ── Remote Scan Trigger from HP ───────────────────────────────────────────
async function loadMobileScanDevices() {
  const sel = document.getElementById('mobile-scan-device');
  if (!sel) return;
  try {
    const r = await fetch('/api/scans/devices');
    const d = await r.json();
    const devs = d.devices || [];
    sel.innerHTML = devs.length
      ? devs.map(x => '<option value="' + escHtml(x.id) + '">' + escHtml(x.label) + '</option>').join('')
      : '<option value="">Tidak ada scanner terdeteksi</option>';
  } catch {
    sel.innerHTML = '<option value="">Gagal memuat scanner</option>';
  }
}

async function triggerMobileScanNow() {
  const device = document.getElementById('mobile-scan-device')?.value;
  const source = document.getElementById('mobile-scan-source')?.value || 'Flatbed';
  const btn = document.getElementById('mobile-scan-now-btn');
  const status = document.getElementById('mobile-scan-status');

  if (!device) {
    showToast('⚠️ Silakan pilih scanner terlebih dahulu', 'err');
    return;
  }

  if (btn) { btn.disabled = true; btn.textContent = '⏳ Scanning…'; }
  if (status) status.innerHTML = '<div style="font-size:.75rem;color:#94a3b8;margin-top:6px;">⏳ Memindai dokumen, mohon tunggu hingga 1 menit…</div>';

  try {
    const r = await fetch('/api/scans/trigger', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ device, source })
    });
    const d = await r.json();
    if (d.ok) {
      showToast('✅ Berhasil memindai: ' + d.name, 'ok');
      if (status) status.innerHTML = '<div style="font-size:.75rem;color:#34d399;margin-top:6px;">✅ Berhasil memindai: <strong>' + escHtml(d.name) + '</strong></div>';
      loadMobileScans();
    } else {
      throw new Error(d.error || 'Pemindaian gagal');
    }
  } catch(e) {
    showToast('❌ ' + e.message, 'err');
    if (status) status.innerHTML = '<div style="font-size:.75rem;color:#f87171;margin-top:6px;">❌ ' + escHtml(e.message) + '</div>';
  }
}

// ── Upload Camera Scan from HP ──────────────────────────────────────────
async function uploadMobileCamScan(input) {
  if (!input.files || !input.files[0]) return;
  const file = input.files[0];
  const btn = document.getElementById('mobile-cam-btn');
  const status = document.getElementById('mobile-scan-status');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Mengunggah foto scan...'; }
  if (status) status.innerHTML = '<div style="font-size:.75rem;color:#94a3b8;margin-top:6px;">⏳ Memproses foto dari kamera HP...</div>';

  try {
    const fd = new FormData();
    fd.append('scanFile', file);

    const r = await fetch('/api/scans/upload', {
      method: 'POST',
      body: fd
    });
    const d = await r.json();
    if (d.ok) {
      showToast('✅ Foto scan kamera berhasil disimpan: ' + d.name, 'ok');
      if (status) status.innerHTML = '<div style="font-size:.75rem;color:#34d399;margin-top:6px;">✅ Foto scan kamera disimpan: <strong>' + escHtml(d.name) + '</strong></div>';
      loadMobileScans();
    } else {
      throw new Error(d.error || 'Gagal menyimpan foto scan');
    }
  } catch(e) {
    showToast('❌ ' + e.message, 'err');
    if (status) status.innerHTML = '<div style="font-size:.75rem;color:#f87171;margin-top:6px;">❌ ' + escHtml(e.message) + '</div>';
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '📷 Scan / Foto Dokumen via Kamera HP'; }
    input.value = '';
  }
}

// ── Delete Scan File from HP ──────────────────────────────────────────────
async function deleteMobileScan(scanName) {
  if (!confirm('Hapus file hasil scan "' + scanName + '" dari server?')) return;
  try {
    const r = await fetch('/api/scans/' + encodeURIComponent(scanName), { method: 'DELETE' });
    const d = await r.json();
    if (d.ok) {
      showToast('🗑 File scan berhasil dihapus', 'ok');
      loadMobileScans();
    } else {
      throw new Error(d.error || 'Gagal menghapus file');
    }
  } catch(e) {
    showToast('❌ ' + e.message, 'err');
  }
}

// ── Init ──────────────────────────────────────────────────────────────────
resolveAssignedPrinter();
loadServerDocs();
</script>
</body>
</html>`);
});

app.get('/api/analytics', async (_req, res) => {
  try {
    const printers = (typeof PRINTERS !== 'undefined' && Array.isArray(PRINTERS)) ? PRINTERS : [];
    let printJobs = [];
    try {
      if (typeof getCompletedJobs === 'function') {
        printJobs = (await getCompletedJobs()) || [];
      }
    } catch(e) {
      console.error('Error fetching completed jobs for analytics:', e);
    }

    let scanJobs = [];
    try {
      if (typeof SCAN_DIR !== 'undefined' && fs.existsSync(SCAN_DIR)) {
        const scanFiles = fs.readdirSync(SCAN_DIR);
        scanJobs = scanFiles.map(f => ({ name: f, details: f }));
      }
    } catch(e) {
      console.error('Error reading scan dir for analytics:', e);
    }

    let totalPages = printJobs.reduce((sum, j) => sum + (Number(j.pages) || 1), 0);
    printers.forEach(p => { if (p.pages) totalPages += Number(p.pages); });

    const onlinePrinters = printers.filter(p => p.online !== false).length;
    const activePrintersCount = onlinePrinters;
    const totalPrintersCount = printers.length;

    const totalScans = scanJobs.length;
    const lowTonerWarnings = printers.filter(p => p.toners && p.toners.some(t => t.pct < 20 && !t.unknown)).length;

    const printerUsageMap = {};
    printJobs.forEach(j => {
      const pName = j.printer || j.dest || 'Generic Printer';
      const cleanName = pName.replace(/_/g, ' ').replace(/\.[a-z]+$/i, '');
      const displayName = cleanName.length > 16 ? cleanName.substring(0, 13) + '...' : cleanName;
      printerUsageMap[displayName] = (printerUsageMap[displayName] || 0) + (Number(j.pages) || 1);
    });

    const paperPerPrinter = Object.keys(printerUsageMap)
      .map(name => ({ name, pages: printerUsageMap[name] }))
      .sort((a,b) => b.pages - a.pages);

    const userUsageMap = {};
    printJobs.forEach(j => {
      const uName = j.user || j.username || 'admin';
      userUsageMap[uName] = (userUsageMap[uName] || 0) + (Number(j.pages) || 1);
    });

    const paperPerUser = Object.keys(userUsageMap)
      .map(name => ({ name, pages: userUsageMap[name], avatar: '👤' }))
      .sort((a,b) => b.pages - a.pages)
      .slice(0, 5);

    let saneScans = 0;
    let cameraScans = 0;
    scanJobs.forEach(s => {
      const d = (s.details || s.name || '').toLowerCase();
      if (d.includes('sane') || d.includes('hardware')) saneScans++;
      else cameraScans++;
    });

    const printerHealth = printers.map(p => {
      let statusBadge = p.online !== false ? 'Online' : 'Offline';
      if (p.online !== false && p.toners && p.toners.some(t => t.pct < 20)) statusBadge = 'Low Toner';
      if (p.online !== false && p.trays && p.trays.some(t => t.status === 'Empty' || t.pct < 10)) statusBadge = 'Low Paper';
      const cleanName = p.name.replace(/_/g, ' ');
      return {
        id: p.id,
        name: cleanName.length > 16 ? cleanName.substring(0, 13) + '...' : cleanName,
        brand: p.brand || p.model || 'Printer',
        location: p.location || 'Network Printer',
        status: statusBadge,
        toners: p.toners && p.toners.length ? p.toners : []
      };
    });

    res.json({
      summary: {
        totalPages,
        activePrinters: activePrintersCount,
        totalPrinters: totalPrintersCount,
        totalScans,
        lowTonerWarnings
      },
      paperPerPrinter,
      paperPerUser,
      scannerUsage: {
        saneScans,
        cameraScans,
        totalScans: saneScans + cameraScans
      },
      printerHealth
    });
  } catch(e) {
    console.error('Error generating analytics:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/users', (_req,res) => {
  res.json({users: USERS.map(u=>({
    username: u.username,
    role: u.role,
    phone: u.phone || '',
    notifications: u.notifications || { printSuccess: true, scanSuccess: true, printFailed: true, scanFailed: true },
    printerAccess: u.printerAccess || null
  }))});
});
app.post('/api/users', express.json(), async (req,res) => {
  const { username, password, role, printerAccess, phone, notifications } = req.body || {};
  if (!username || !password || !['admin','user'].includes(role)) return res.status(400).json({error:'username, password, and valid role required'});
  if (USERS.find(u=>u.username===username)) return res.status(409).json({error:'username already exists'});
  const hashedPassword = await hashPassword(password);
  const newUser = {
    username,
    role,
    password: hashedPassword,
    phone: (phone || '').trim(),
    notifications: {
      printSuccess: notifications ? notifications.printSuccess !== false : true,
      scanSuccess: notifications ? notifications.scanSuccess !== false : true,
      printFailed: notifications ? notifications.printFailed !== false : true,
      scanFailed: notifications ? notifications.scanFailed !== false : true
    }
  };
  if (role === 'user' && Array.isArray(printerAccess) && printerAccess.length) {
    newUser.printerAccess = printerAccess.map(String).filter(Boolean);
  }
  USERS.push(newUser);
  saveUsers();
  createMobileTokenForUser(username);
  res.json({ok:true});
});
app.put('/api/users/:username', express.json(), async (req,res) => {
  const u = USERS.find(x=>x.username===req.params.username);
  if (!u) return res.status(404).json({error:'not found'});
  const { password, role, printerAccess, phone, notifications } = req.body || {};
  if (role) {
    if (!['admin','user'].includes(role)) return res.status(400).json({error:'invalid role'});
    if (u.username === 'admin' && role !== 'admin') return res.status(400).json({error:'cannot demote primary admin user'});
    u.role = role;
  }
  if (password) u.password = await hashPassword(password);
  if (phone !== undefined) u.phone = (phone || '').trim();
  if (notifications && typeof notifications === 'object') {
    u.notifications = {
      printSuccess: notifications.printSuccess !== false,
      scanSuccess: notifications.scanSuccess !== false,
      printFailed: notifications.printFailed !== false,
      scanFailed: notifications.scanFailed !== false
    };
  }
  if (printerAccess !== undefined) {
    if (Array.isArray(printerAccess) && printerAccess.length) u.printerAccess = printerAccess.map(String).filter(Boolean);
    else delete u.printerAccess; // empty/[] => unrestricted
  }
  if (u.role === 'admin') delete u.printerAccess;
  saveUsers();
  for (const [token,s] of sessions) if (s.username===u.username) { s.role=u.role; s.printerAccess=u.printerAccess||null; }
  saveSessions();
  res.json({ok:true});
});
app.delete('/api/users/:username', (req,res) => {
  if (req.params.username === req.user.username) return res.status(400).json({error:"can't delete your own account"});
  if (USERS.filter(u=>u.role==='admin').length<=1 && USERS.find(u=>u.username===req.params.username)?.role==='admin')
    return res.status(400).json({error:'cannot delete the last admin'});
  USERS = USERS.filter(x=>x.username!==req.params.username);
  saveUsers();
  for (const [token,s] of sessions) if (s.username===req.params.username) sessions.delete(token);
  saveSessions();
  res.json({ok:true});
});

// ── Groups API ────────────────────────────────────────────────────────────────
app.get('/api/groups', (_req,res) => res.json({groups: GROUPS}));

app.post('/api/groups', express.json(), (req,res) => {
  const {name, users, printers} = req.body;
  if (!name || !name.trim()) return res.status(400).json({error:'Group name is required'});
  if (GROUPS.find(g=>g.name.toLowerCase()===name.trim().toLowerCase()))
    return res.status(409).json({error:'A group with that name already exists'});
  const group = {
    id: Date.now(),
    name: name.trim(),
    users: Array.isArray(users) ? users : [],
    printers: Array.isArray(printers) ? printers : [],
    createdAt: new Date().toISOString()
  };
  GROUPS.push(group);
  saveGroups();
  res.json({ok:true, group});
});

app.put('/api/groups/:id', express.json(), (req,res) => {
  const id = Number(req.params.id);
  const idx = GROUPS.findIndex(g=>g.id===id);
  if (idx<0) return res.status(404).json({error:'Group not found'});
  const {name, users, printers} = req.body;
  if (name) {
    const dup = GROUPS.find((g,i)=>i!==idx && g.name.toLowerCase()===name.trim().toLowerCase());
    if (dup) return res.status(409).json({error:'A group with that name already exists'});
    GROUPS[idx].name = name.trim();
  }
  if (Array.isArray(users))    GROUPS[idx].users    = users;
  if (Array.isArray(printers)) GROUPS[idx].printers = printers;
  GROUPS[idx].updatedAt = new Date().toISOString();
  saveGroups();
  res.json({ok:true, group: GROUPS[idx]});
});

app.delete('/api/groups/:id', (req,res) => {
  const id = Number(req.params.id);
  const before = GROUPS.length;
  GROUPS = GROUPS.filter(g=>g.id!==id);
  if (GROUPS.length===before) return res.status(404).json({error:'Group not found'});
  saveGroups();
  res.json({ok:true});
});

const LOGIN_HTML = `<!DOCTYPE html><html><head><meta charset="utf-8"/><title>PrintServer Login</title>
<style>
body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:linear-gradient(135deg,rgba(15,23,42,0.75),rgba(15,23,42,0.65)),url('/bg.jpg') center/cover no-repeat fixed;display:flex;align-items:center;justify-content:center;height:100vh}
.card{background:rgba(15,23,42,0.85);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.18);border-radius:16px;padding:32px;width:330px;box-shadow:0 16px 40px rgba(0,0,0,0.6)}
h1{color:#ffffff;font-size:1.25rem;font-weight:700;margin:0 0 20px;display:flex;align-items:center;gap:8px;text-shadow:0 1px 2px rgba(0,0,0,0.5)}
label{color:#cbd5e1;font-size:.85rem;display:block;margin-bottom:6px;font-weight:600}
input{width:100%;box-sizing:border-box;background:rgba(15,23,42,0.9);border:1px solid rgba(255,255,255,0.22);border-radius:8px;padding:10px 12px;color:#ffffff;margin-bottom:16px;font-size:.9rem;font-weight:500;outline:none}
input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,0.3)}
button{width:100%;background:#3b82f6;color:#ffffff;border:none;border-radius:8px;padding:11px;font-weight:700;cursor:pointer;font-size:.9rem;letter-spacing:.02em;box-shadow:0 4px 12px rgba(59,130,246,0.3)}
button:disabled{opacity:.6}
#err{color:#f87171;font-size:.8rem;margin-bottom:10px;min-height:14px;font-weight:500}
</style></head><body>
<div class="card">
  <h1>🖨 PrintServer</h1>
  <div id="err"></div>
  <label>Username</label><input id="u" autofocus/>
  <label>Password</label><input id="p" type="password"/>
  <button id="btn" onclick="doLogin()">Sign In</button>
  <div style="text-align:center;color:#94a3b8;font-size:.75rem;margin-top:16px;font-weight:500">Developed By Rama MKT</div>
</div>
<script>
document.getElementById('p').addEventListener('keydown', e => { if (e.key==='Enter') doLogin(); });
async function doLogin(){
  const btn=document.getElementById('btn'), err=document.getElementById('err');
  btn.disabled=true; err.textContent='';
  try{
    const r = await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
    const d = await r.json();
    if (d.ok) location.href='/'; else { err.textContent=d.error||'Login failed'; btn.disabled=false; }
  } catch(e){ err.textContent='Network error'; btn.disabled=false; }
}
</script></body></html>`;



// ── Persistence ───────────────────────────────────────────────────────────────
function loadPrinters() {
  try { if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE,'utf8')); } catch {}
  return [];
}
function savePrinters() {
  fs.promises.writeFile(DATA_FILE, JSON.stringify(PRINTERS,null,2)).catch(e=>console.error('Failed to save printers:',e.message));
}
let PRINTERS = loadPrinters();

async function syncCupsToPrinters() {
  try {
    const detail = await getCupsPrinterDetail();
    const cupsPrinters = detail.printers || [];
    let changed = false;

    for (const cp of cupsPrinters) {
      if (!cp.name) continue;
      const exists = PRINTERS.some(p => p.name.toLowerCase() === cp.name.toLowerCase() || String(p.id).toLowerCase() === cp.name.toLowerCase());
      if (!exists) {
        PRINTERS.push({
          id: cp.name,
          name: cp.name,
          ip: '127.0.0.1',
          brand: 'CUPS Printer',
          location: 'Auto-Synced CUPS',
          community: 'public',
          alertsEnabled: true
        });
        changed = true;
      }
    }

    if (changed) {
      savePrinters();
    }
  } catch (e) {
    // Ignore transient errors
  }
}
syncCupsToPrinters();

// ── Settings (Telegram + discovery) ────────────────────────────────────────────
const DEFAULT_SETTINGS = {
  telegram: { enabled:false, botToken:'', chatId:'', alertToner:true, tonerThreshold:20,
              alertOffline:true, alertJams:true, alertTrayEmpty:true, cooldownMinutes:240,
              alertPrintSuccess:true, alertPrintFailed:true, alertScanSuccess:true, alertScanFailed:true },
  network: { scanSubnet:'' }
};
function loadSettings() {
  try { if (fs.existsSync(SETTINGS_FILE)) return {...DEFAULT_SETTINGS, ...JSON.parse(fs.readFileSync(SETTINGS_FILE,'utf8'))}; } catch {}
  return {...DEFAULT_SETTINGS};
}
function saveSettings() { return fs.promises.writeFile(SETTINGS_FILE, JSON.stringify(SETTINGS,null,2)).catch(e=>{ console.error('Failed to save settings:',e.message); throw e; }); }
let SETTINGS = loadSettings();

// ── Telegram ──────────────────────────────────────────────────────────────────
function sendTelegram(text, tokenOverride, chatIdOverride) {
  const token = tokenOverride || SETTINGS.telegram.botToken;
  const chatId = chatIdOverride || SETTINGS.telegram.chatId;
  return new Promise(resolve => {
    if (!token || !chatId) return resolve({ok:false,error:'Missing bot token or chat ID'});
    const payload = JSON.stringify({chat_id:chatId, text, parse_mode:'HTML'});
    const req = https.request({
      hostname:'api.telegram.org', path:`/bot${token}/sendMessage`, method:'POST',
      headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(payload)},
      timeout:8000,
    }, res => {
      let data=''; res.on('data',c=>data+=c);
      res.on('end',()=>{ try { resolve(JSON.parse(data)); } catch { resolve({ok:false,raw:data}); } });
    });
    req.on('error', e => resolve({ok:false,error:e.message}));
    req.on('timeout', () => { req.destroy(); resolve({ok:false,error:'timeout'}); });
    req.write(payload); req.end();
  });
}

async function notifyUserEvent(username, eventType, data = {}) {
  try {
    if (!SETTINGS.telegram || !SETTINGS.telegram.enabled) return;
    const user = (USERS || []).find(u => u.username && u.username.toLowerCase() === String(username || '').toLowerCase());
    const notifs = user && user.notifications ? user.notifications : { printSuccess: true, scanSuccess: true, printFailed: true, scanFailed: true };

    let icon = '';
    let title = '';

    if (eventType === 'PRINT_SUCCESS') {
      if (SETTINGS.telegram.alertPrintSuccess === false) return;
      if (!notifs.printSuccess) return;
      icon = '🖨️ ✅';
      title = 'PRINT BERHASIL';
    } else if (eventType === 'PRINT_FAILED') {
      if (SETTINGS.telegram.alertPrintFailed === false) return;
      if (!notifs.printFailed) return;
      icon = '🖨️ ❌';
      title = 'PRINT GAGAL';
    } else if (eventType === 'SCAN_SUCCESS') {
      if (SETTINGS.telegram.alertScanSuccess === false) return;
      if (!notifs.scanSuccess) return;
      icon = '📷 ✅';
      title = 'SCAN BERHASIL';
    } else if (eventType === 'SCAN_FAILED') {
      if (SETTINGS.telegram.alertScanFailed === false) return;
      if (!notifs.scanFailed) return;
      icon = '📷 ❌';
      title = 'SCAN GAGAL';
    } else {
      return;
    }

    const timeStr = new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' });
    let msg = `${icon} <b>${title}</b>\n` +
      `• <b>User:</b> ${esc(username || 'System')}\n`;

    if (data.docName) msg += `• <b>Dokumen:</b> ${esc(data.docName)}\n`;
    if (data.scanName) msg += `• <b>File Scan:</b> ${esc(data.scanName)}\n`;
    if (data.printerName) msg += `• <b>Printer:</b> ${esc(data.printerName)}\n`;
    if (data.scanType) msg += `• <b>Tipe Scan:</b> ${esc(data.scanType)}\n`;
    if (data.scanFormat) msg += `• <b>Format:</b> ${esc(data.scanFormat)}\n`;
    if (data.jobId) msg += `• <b>Job ID:</b> #${esc(data.jobId)}\n`;
    if (data.error) msg += `• <b>Error:</b> <i>${esc(data.error)}</i>\n`;
    msg += `• <b>Waktu:</b> ${timeStr}`;

    // Send to default global Telegram bot Chat ID
    await sendTelegram(msg);

    // If user has direct Chat ID or No. HP configured, send direct alert as well
    const userChatId = (user && (user.phone || user.telegramChatId || '')).trim();
    if (userChatId && userChatId !== SETTINGS.telegram.chatId && /^\d+$/.test(userChatId)) {
      await sendTelegram(msg, null, userChatId);
    }
  } catch (e) {
    console.error('Failed to notifyUserEvent:', e.message);
  }
}

// ── Alert state trackers ───────────────────────────────────────────────────────
const offlineStreak    = {}; // printerId -> consecutive failed SNMP polls
const offlineAlertSent = {}; // printerId -> bool: true while printer is in a confirmed-offline period

// Toner recovery debounce: require this many consecutive above-threshold polls before clearing
// the low-toner alert flag. Prevents a single bad SNMP reading (e.g. cur=-3 "unknown" remapped
// momentarily to a high value) from clearing the flag and causing a re-alert next poll.
const tonerRecoverStreak  = {}; // key -> consecutive above-threshold poll count
const TONER_RECOVER_CONFIRM = 2;

// SNMP failure confirmation: require this many consecutive failures AND a failed ping before
// declaring a printer truly offline. Eliminates false alerts from transient SNMP timeouts
// where the printer is actually still reachable on the network.
const OFFLINE_CONFIRM = 3; // consecutive SNMP failures needed before we even try ping

// Alert state is persisted to disk so that server restarts don't re-fire alerts
// for conditions that were already reported (low toner, jams, etc.)
let _alertState = { permanentAlerted: [], lastSent: {}, offlineAlertSent: {} };
try {
  const raw = fs.readFileSync(ALERT_STATE_FILE, 'utf8');
  _alertState = JSON.parse(raw);
  if (!Array.isArray(_alertState.permanentAlerted)) _alertState.permanentAlerted = [];
  if (typeof _alertState.lastSent !== 'object') _alertState.lastSent = {};
  if (typeof _alertState.offlineAlertSent !== 'object') _alertState.offlineAlertSent = {};
} catch { /* first run or file missing — start fresh */ }

const permanentAlerted = new Set(_alertState.permanentAlerted);
const lastSent = _alertState.lastSent;

// Restore persisted offlineAlertSent flags into the in-memory map
Object.assign(offlineAlertSent, _alertState.offlineAlertSent);

function saveAlertState() {
  fs.promises.writeFile(ALERT_STATE_FILE,
    JSON.stringify({
      permanentAlerted: [...permanentAlerted],
      lastSent,
      offlineAlertSent,
    }, null, 2)).catch(e => console.error('Failed to save alert state:', e.message));
}

function shouldSend(key) {
  const cd = (SETTINGS.telegram.cooldownMinutes||240)*60*1000;
  const now = Date.now();
  if (lastSent[key] && now-lastSent[key] < cd) return false;
  lastSent[key] = now;
  saveAlertState();
  return true;
}

async function checkAlerts(newP, oldP) {
  const t = SETTINGS.telegram;
  if (!t.enabled || !t.botToken || !t.chatId) return;
  if (newP.alertsEnabled === false) return; // per-printer alerts disabled
  const tag = `<b>${esc(newP.name)}</b> (${newP.ip})`;

  // ── Offline / online detection ───────────────────────────────────────────────
  // Flow:
  //   SNMP fails → increment streak (silent)
  //   Streak hits OFFLINE_CONFIRM → ping the IP
  //     Ping also fails → printer is genuinely off → send 🔴 once, set offlineAlertSent
  //     Ping succeeds  → SNMP glitch only, printer is reachable → reset streak, stay silent
  //   SNMP succeeds again → if offlineAlertSent, send 🟢 and clear flag
  if (t.alertOffline) {
    if (newP.online === false) {
      offlineStreak[newP.id] = (offlineStreak[newP.id] || 0) + 1;
      if (offlineStreak[newP.id] === OFFLINE_CONFIRM && !offlineAlertSent[newP.id]) {
        // SNMP has failed OFFLINE_CONFIRM times in a row — now confirm with a ping
        const pingOk = await pingHost(newP.ip);
        if (!pingOk) {
          // Ping also fails → printer is genuinely offline
          offlineAlertSent[newP.id] = true;
          saveAlertState();
          await sendTelegram(`🔴 ${tag} went OFFLINE`);
        } else {
          // Ping succeeded → SNMP is flaky but printer is reachable, reset silently
          offlineStreak[newP.id] = 0;
        }
      }
      // streak > OFFLINE_CONFIRM → already alerted or waiting for ping result, stay silent
    } else {
      // SNMP succeeded → printer is online
      if (offlineAlertSent[newP.id]) {
        // We had sent an OFFLINE alert → send recovery, clear everything
        offlineAlertSent[newP.id] = false;
        offlineStreak[newP.id] = 0;
        saveAlertState();
        await sendTelegram(`🟢 ${tag} is back ONLINE`);
      } else {
        offlineStreak[newP.id] = 0;
      }
    }
  }

  // ── Low toner — ONE alert per cartridge, resets when toner is genuinely replenished ───
  // Problem: HP printers sometimes return cur=-3 (remapped to pct=100, unknown=false) for one
  // or two polls during warm-up or partial SNMP walks. Without debouncing, that single
  // above-threshold reading clears the permanentAlerted flag, and the next poll re-alerts.
  // Fix: require TONER_RECOVER_CONFIRM consecutive above-threshold readings before clearing.
  if (t.alertToner && newP.online && newP.toners) {
    for (const tn of newP.toners) {
      if (tn.unknown) continue;
      const key = `${newP.id}:toner:${tn.name}`;
      if (tn.pct < (t.tonerThreshold || 20)) {
        // Toner is low — reset recovery streak and alert once
        tonerRecoverStreak[key] = 0;
        if (!permanentAlerted.has(key)) {
          permanentAlerted.add(key);
          saveAlertState();
          await sendTelegram(`🟡 ${tag} — <b>${esc(tn.name)}</b> low: ${tn.pct}%`);
        }
        // flag already set → cartridge still low, stay silent
      } else {
        // Toner appears above threshold — only clear flag after TONER_RECOVER_CONFIRM polls in a row
        if (permanentAlerted.has(key)) {
          tonerRecoverStreak[key] = (tonerRecoverStreak[key] || 0) + 1;
          if (tonerRecoverStreak[key] >= TONER_RECOVER_CONFIRM) {
            tonerRecoverStreak[key] = 0;
            permanentAlerted.delete(key);
            saveAlertState();
          }
          // still counting up — don't clear yet
        } else {
          tonerRecoverStreak[key] = 0; // nothing to clear, reset counter
        }
      }
    }
  }

  // ── Tray empty — ONE alert per tray, resets when paper is loaded ────────────
  if (t.alertTrayEmpty && newP.online && newP.trays) {
    for (const tr of newP.trays) {
      if (tr.unsupported || tr.pct === null) continue; // skip if firmware doesn't report tray levels
      const key = `${newP.id}:tray:${tr.name}`;
      if (tr.pct === 0) {
        if (!permanentAlerted.has(key)) {
          permanentAlerted.add(key);
          saveAlertState();
          await sendTelegram(`📄 ${tag} — <b>${esc(tr.name)}</b> is empty`);
        }
      } else {
        if (permanentAlerted.delete(key)) saveAlertState();
      }
    }
  }

  // ── Jams / cover open / service — alert on new events, cooldown after ───────
  if (t.alertJams && newP.online && newP.alerts && newP.alerts.length) {
    const oldDescs = new Set((oldP && oldP.alerts || []).map(a => a.desc));
    for (const a of newP.alerts) {
      if (!oldDescs.has(a.desc)) {
        const key = `${newP.id}:alert:${a.desc}`;
        if (shouldSend(key)) await sendTelegram(`⚠️ ${tag} — ${esc(a.severity)}: ${esc(a.desc)}`);
      }
    }
  }
}
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// ── Page history ───────────────────────────────────────────────────────────────
const pageHistory = {};

// ── SNMP OIDs ─────────────────────────────────────────────────────────────────
const OID = {
  sysDescr:'1.3.6.1.2.1.1.1.0', sysUpTime:'1.3.6.1.2.1.1.3.0',
  sysContact:'1.3.6.1.2.1.1.4.0', sysName:'1.3.6.1.2.1.1.5.0', sysLocation:'1.3.6.1.2.1.1.6.0',
  macAddress:'1.3.6.1.2.1.2.2.1.6.1', memSize:'1.3.6.1.2.1.25.2.2.0',
  deviceDesc:'1.3.6.1.2.1.25.3.2.1.3.1', deviceState:'1.3.6.1.2.1.25.3.2.1.5.1',
  deviceErrors:'1.3.6.1.2.1.25.3.2.1.6.1', printerStatus:'1.3.6.1.2.1.25.3.5.1.1.1',
  serialNumber:'1.3.6.1.2.1.43.5.1.1.17.1', pageCount:'1.3.6.1.2.1.43.10.2.1.4.1.1',
  tonerName:'1.3.6.1.2.1.43.11.1.1.6.1', tonerMax:'1.3.6.1.2.1.43.11.1.1.8.1',
  tonerCurrent:'1.3.6.1.2.1.43.11.1.1.9.1', colorant:'1.3.6.1.2.1.43.12.1.1.4.1',
  consoleDisplay:'1.3.6.1.2.1.43.16.5.1.2.1.1', alertTable:'1.3.6.1.2.1.43.18.1.1',
  trayName:'1.3.6.1.2.1.43.8.2.1.13.1', trayCapacity:'1.3.6.1.2.1.43.8.2.1.9.1',
  trayLevel:'1.3.6.1.2.1.43.8.2.1.10.1', trayStatus:'1.3.6.1.2.1.43.8.2.1.11.1',
};
const PRINTER_STATUS = {1:'Other',2:'Unknown',3:'Idle',4:'Printing',5:'Warmup',6:'Stopped',7:'Offline'};
const ALERT_SEVERITY = {1:'Other',2:'Critical',3:'Warning',4:'Informational'};
const ALERT_CODES    = {1:'Cover Open',3:'Paper Jam',4:'Paper Out',5:'Offline',6:'Service Requested',
  7:'Input Tray Missing',8:'Output Full',9:'Marker Supply Empty',11:'Output Near Full',12:'Input Tray Empty'};

function bufToStr(v) {
  if (!v) return null;
  if (Buffer.isBuffer(v)) return v.toString('utf8').replace(/\0/g,'').trim();
  return String(v).trim();
}
function snmpGetMulti(ip, community, oids) {
  return new Promise(resolve => {
    const s = snmp.createSession(ip, community||'public', {timeout:4000,retries:1,version:snmp.Version1});
    s.get(oids, (err, vb) => {
      s.close();
      if (err) return resolve(null);
      const r = {};
      vb.forEach((v,i) => { r[oids[i]] = snmp.isVarbindError(v) ? null : v.value; });
      resolve(r);
    });
  });
}
function snmpWalk(ip, community, oid) {
  return new Promise(resolve => {
    const s = snmp.createSession(ip, community||'public', {timeout:4000,retries:1,version:snmp.Version1});
    const res = [];
    s.subtree(oid, 30, vb => vb.forEach(v => { if (!snmp.isVarbindError(v)) res.push({oid:v.oid,value:v.value}); }),
      () => { s.close(); resolve(res); });
  });
}

function formatUptime(sec) {
  const d=Math.floor(sec/86400), h=Math.floor((sec%86400)/3600), m=Math.floor((sec%3600)/60);
  return d>0?`${d}d ${h}h ${m}m`:h>0?`${h}h ${m}m`:`${m}m`;
}

function parseAlerts(walk) {
  const groups = {};
  walk.forEach(e => {
    const p=e.oid.split('.'), col=parseInt(p[p.length-2]), idx=p[p.length-1];
    if (!groups[idx]) groups[idx]={};
    groups[idx][col]=e.value;
  });
  return Object.values(groups).map(g => {
    const severity = ALERT_SEVERITY[g[2]]||'Info';
    const code     = g[4] ? ALERT_CODES[Number(g[4])] : null;
    const desc     = bufToStr(g[8])||code||'Unknown Alert';
    return desc && desc!=='Sleep' && desc!=='Unknown Alert' ? {severity,desc} : null;
  }).filter(Boolean);
}

function pingHost(ip) {
  return new Promise(resolve => {
    exec(`ping -c 1 -W 1 ${ip} 2>/dev/null`, err => resolve(!err));
  });
}

async function getPrinterData(printer, preloadedCupsDetail) {
  const {ip,community} = printer;
  try {
    const basic = await snmpGetMulti(ip, community, [
      OID.sysDescr,OID.sysUpTime,OID.sysContact,OID.sysName,OID.sysLocation,
      OID.macAddress,OID.memSize,OID.deviceDesc,OID.deviceState,OID.deviceErrors,
      OID.printerStatus,OID.serialNumber,OID.pageCount,OID.consoleDisplay,
    ]);
    if (!basic) {
      try {
        const cupsDetail = preloadedCupsDetail || await getCupsPrinterDetail().catch(()=>null);
        if (cupsDetail) {
          const pNameLower = String(printer.name||'').toLowerCase();
          const pNameClean = pNameLower.replace(/[^a-z0-9]/g, '');
          const cupsMatch = (cupsDetail.printers || []).find(cp => {
            const cNameLower = String(cp.name||'').toLowerCase();
            const cNameClean = cNameLower.replace(/[^a-z0-9]/g, '');
            return cNameLower === pNameLower || cNameClean === pNameClean || pNameLower.includes(cNameLower) || cNameLower.includes(pNameLower);
          });
          if (cupsMatch && cupsMatch.state !== 'disabled') {
            const isPrinting = (cupsMatch.state||'').toLowerCase().includes('printing');
            return {
              ...printer,
              online: true,
              status: isPrinting ? 'Printing' : 'Idle',
              model: printer.name + ' (CUPS)',
              toners: [{ name: 'Printer Ready (CUPS)', pct: 100, color: '#0ea5e9', unknown: true }],
              trays: [{ name: 'Paper Tray', capacity: 100, level: 100, pct: 100, status: 'Available' }],
              alerts: [],
              pages: null,
              pageHistory: pageHistory[printer.id] || [],
              lastChecked: new Date().toISOString()
            };
          }
        }
      } catch {}

      const reachable = await pingHost(ip);
      return {...printer,online:false,status:reachable?'SNMP Error':'Offline',snmpError:reachable,toners:[],trays:[],alerts:[],pages:null,pageHistory:pageHistory[printer.id]||[]};
    }

    const uptimeSec = basic[OID.sysUpTime] ? Math.floor(Number(basic[OID.sysUpTime])/100) : 0;
    let mac = basic[OID.macAddress];
    if (Buffer.isBuffer(mac)) mac = Array.from(mac).map(b=>b.toString(16).padStart(2,'0')).join(':').toUpperCase();
    const status = PRINTER_STATUS[basic[OID.printerStatus]]||'Unknown';
    const pages  = basic[OID.pageCount]!=null ? Number(basic[OID.pageCount]) : null;
    const model  = bufToStr(basic[OID.deviceDesc])||bufToStr(basic[OID.sysDescr])||printer.name;
    const serial = bufToStr(basic[OID.serialNumber]);
    const console_msg = bufToStr(basic[OID.consoleDisplay]);
    const memKB  = basic[OID.memSize] ? Number(basic[OID.memSize]) : null;

    const [nameW,maxW,curW,colorW,trayNW,trayCW,trayLW,traySW,alertW] = await Promise.all([
      snmpWalk(ip,community,OID.tonerName), snmpWalk(ip,community,OID.tonerMax),
      snmpWalk(ip,community,OID.tonerCurrent), snmpWalk(ip,community,OID.colorant),
      snmpWalk(ip,community,OID.trayName), snmpWalk(ip,community,OID.trayCapacity),
      snmpWalk(ip,community,OID.trayLevel), snmpWalk(ip,community,OID.trayStatus),
      snmpWalk(ip,community,OID.alertTable),
    ]);

    const toners = nameW.map((n,i) => {
      let name = bufToStr(n.value)||`Supply ${i+1}`;
      const max = maxW[i]?Number(maxW[i].value):100;
      const cur = curW[i]?Number(curW[i].value):0;
      const pct = max>0 ? Math.max(0,Math.round((cur/max)*100)) : (cur===-3?-1:0);
      const colorStr = colorW[i] ? bufToStr(colorW[i].value)||'' : '';
      const nl=(name+colorStr).toLowerCase();
      let color='#64748b';
      if (nl.includes('black')||nl.includes('bk')||nl.includes('mono')) color='#1e293b';
      else if (nl.includes('cyan')||nl.includes(' c ')||nl.includes('cy')) color='#0ea5e9';
      else if (nl.includes('magenta')||nl.includes(' m ')||nl.includes('mg')) color='#d946ef';
      else if (nl.includes('yellow')||nl.includes(' y ')||nl.includes('yl')) color='#eab308';
      else if (nl.includes('fuser')||nl.includes('drum')||nl.includes('kit')||nl.includes('waste')) color='#f97316';
      return {name,pct:pct===-1?100:pct,color,unknown:pct===-1};
    });

    const trays = trayNW.map((t,i) => {
      const name=bufToStr(t.value)||`Tray ${i+1}`;
      const cap=trayCW[i]?Number(trayCW[i].value):0;
      const lvl=trayLW[i]?Number(trayLW[i].value):0;
      const stat=traySW[i]?Number(traySW[i].value):0;
      const unsupported = cap<0 || lvl<0;
      const pct = unsupported ? null : (cap>0?Math.min(100,Math.max(0,Math.round((lvl/cap)*100))):(lvl>0?50:0));
      const statusMap={1:'Other',2:'Unknown',3:'Available',4:'Printing',5:'Busy',6:'Offline'};
      return {name,capacity:cap,level:lvl,pct,unsupported,status:statusMap[stat]||'Unknown'};
    });

    const alerts = parseAlerts(alertW);

    if (pages!==null) {
      if (!pageHistory[printer.id]) pageHistory[printer.id]=[];
      const hist=pageHistory[printer.id], last=hist[hist.length-1];
      if (!last||last.pages!==pages) { hist.push({time:new Date().toISOString(),pages}); if(hist.length>48)hist.shift(); }
    }

    return {...printer,online:true,status,model:model.substring(0,60),serial,mac,memKB,
      uptime:formatUptime(uptimeSec),uptimeSec,pages,pageHistory:pageHistory[printer.id]||[],
      console_msg,toners,trays,alerts,lastChecked:new Date().toISOString()};
  } catch { return {...printer,online:false,status:'Offline',toners:[],trays:[],alerts:[],pages:null,pageHistory:pageHistory[printer.id]||[]}; }
}

// ── Cache & Concurrency Pool ──────────────────────────────────────────────────
let cache = {
  data: PRINTERS.map(p => ({
    ...p,
    online: false,
    status: 'Polling...',
    toners: [],
    trays: [],
    alerts: [],
    pages: null,
    pageHistory: pageHistory[p.id] || []
  })),
  updatedAt: null,
  refreshing: true
};
let polling = false;
const POLLING_CONCURRENCY = 5;

async function mapConcurrent(items, limit, fn) {
  if (!items || !items.length) return [];
  const results = new Array(items.length);
  let index = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length) {
      const i = index++;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

async function syncCupsPrintersToPrintersList() {
  // Disabled per user request (automatic printer detection removed)
}

async function refreshAll() {
  if (polling) return;
  polling=true;
  cache.refreshing=true;
  try {
    const cupsDetail = await getCupsPrinterDetail().catch(() => ({ defaultPrinter: null, printers: [] }));
    const oldData = cache.data;
    const newData = await mapConcurrent(PRINTERS, POLLING_CONCURRENCY, p => getPrinterData(p, cupsDetail));
    cache = {data:newData, updatedAt:new Date().toISOString(), refreshing:false};
    for (const p of newData) {
      const old = oldData.find(o=>o.id===p.id);
      checkAlerts(p, old).catch(()=>{});
    }
  }
  finally { polling=false; cache.refreshing=false; }
}
refreshAll();
setInterval(refreshAll, 1*60*1000);

// ── Multer ────────────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (_req,_file,cb) => cb(null, UPLOAD_DIR),
  filename: (_req,file,cb) => cb(null, Date.now()+'-'+file.originalname.replace(/[^a-zA-Z0-9._-]/g,'_')),
});
const upload = multer({ storage, limits:{fileSize:50*1024*1024} });

// ── Auto-provisioning: driverless CUPS queue + SANE airscan entry ─────────────
const AIRSCAN_CONF = process.env.AIRSCAN_CONF || '/etc/sane.d/airscan.conf';

function provisionCupsPrinter(name, ip) {
  return new Promise(resolve => {
    const safeName = String(name).replace(/[^a-zA-Z0-9_-]/g, '_');
    execFile('lpadmin', ['-p', safeName, '-E', '-v', `ipp://${ip}/ipp/print`, '-m', 'everywhere'], (err, stdout, stderr) => {
      if (err) {
        const msg = (stderr || err.message || '').trim();
        const hint = msg.toLowerCase().includes('forbidden') || msg.toLowerCase().includes('not-authorized')
          ? ' (Ensure user is in lpadmin group: sudo usermod -aG lpadmin $USER)'
          : '';
        return resolve({ok:false, error: (msg || 'lpadmin failed') + hint});
      }
      resolve({ok:true});
    });
  });
}

function provisionSaneAirscan(name, ip) {
  return new Promise(async resolve => {
    // Name must be a bare, quoted airscan.conf key — strip characters that would break the config line.
    const safeName = String(name).replace(/[^a-zA-Z0-9_-]/g, '_');
    const entryLine = `  "${safeName}" = http://${ip}:80/eSCL`;
    try {
      let conf = '';
      try { conf = await fs.promises.readFile(AIRSCAN_CONF, 'utf8'); } catch { conf = ''; }

      // Already present for this exact name+ip? nothing to do.
      const already = conf.split('\n').some(l => l.includes(`"${safeName}"`) && l.includes(ip));
      if (already) return resolve({ok:true, note:'already configured'});

      const lines = conf.split('\n');
      // Only match a real, uncommented "[devices]" section header — not the one in the
      // instructional comment block at the top of the default template.
      const headerIdxs = lines.reduce((acc,l,i) => { if (/^\s*\[devices\]\s*$/.test(l)) acc.push(i); return acc; }, []);

      if (headerIdxs.length) {
        // Insert right after the LAST [devices] header, so repeated runs always land
        // in the same place instead of creating a new section each time.
        const insertAt = headerIdxs[headerIdxs.length - 1] + 1;
        lines.splice(insertAt, 0, entryLine);
        conf = lines.join('\n');
      } else {
        conf = conf.trim() + (conf.trim() ? '\n\n' : '') + `[devices]\n${entryLine}\n`;
      }
      await fs.promises.writeFile(AIRSCAN_CONF, conf);
      resolve({ok:true});
    } catch (e) {
      const isPermission = e.code === 'EACCES' || e.code === 'EPERM';
      const hint = isPermission
        ? `. Grant write permissions: sudo chown root:lpadmin ${AIRSCAN_CONF} && sudo chmod 664 ${AIRSCAN_CONF}`
        : '';
      resolve({ok:false, error: e.message + hint});
    }
  });
}

async function autoProvisionPrinter(name, ip) {
  const [cups, scan] = await Promise.all([
    provisionCupsPrinter(name, ip),
    provisionSaneAirscan(name, ip),
  ]);
  return { cups, scan };
}

// ── CUPS helpers ──────────────────────────────────────────────────────────────
function listCupsPrinters() {
  return new Promise(resolve => {
    exec('lpstat -p 2>/dev/null || echo ""', (err,stdout) => {
      const printers=[];
      (stdout||'').split('\n').forEach(line => {
        const m=line.match(/^printer\s+(\S+)\s+/);
        if (m) printers.push(m[1]);
      });
      resolve(printers);
    });
  });
}

function printFile(filePath, printerName, copies, duplex, colorMode, title) {
  return new Promise(async (resolve, reject) => {
    let fileToPrint = filePath;
    let tempPdfPath = null;
    const ext = path.extname(filePath).toLowerCase();
    const docFormats = ['.doc', '.docx', '.dot', '.dotx', '.docm', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf', '.odt', '.ods', '.csv'];

    if (docFormats.includes(ext)) {
      try {
        const outDir = path.dirname(filePath);
        const uniqueId = Date.now() + '_' + Math.floor(Math.random() * 10000);
        const tempBase = `conv_${uniqueId}`;
        const tempDocPath = path.join(outDir, `${tempBase}${ext}`);
        
        await fs.promises.copyFile(filePath, tempDocPath);

        await new Promise((res, rej) => {
          const convertWith = (cmd) => {
            execFile(cmd, ['--headless', '--convert-to', 'pdf', '--outdir', outDir, tempDocPath], (err, stdout, stderr) => {
              if (err && err.code === 'ENOENT' && cmd === 'soffice') {
                return convertWith('libreoffice');
              }
              try { fs.unlinkSync(tempDocPath); } catch {}
              if (err) {
                if (err.code === 'ENOENT') {
                  return rej(new Error('LibreOffice (soffice/libreoffice) tidak terinstall di server. Install dengan: sudo apt install -y libreoffice-writer-nogui libreoffice-calc-nogui'));
                }
                return rej(new Error('Konversi dokumen Word/Office gagal: ' + (stderr || err.message)));
              }
              tempPdfPath = path.join(outDir, `${tempBase}.pdf`);
              if (fs.existsSync(tempPdfPath)) {
                res();
              } else {
                rej(new Error('Hasil konversi PDF tidak ditemukan'));
              }
            });
          };
          convertWith('soffice');
        });
        fileToPrint = tempPdfPath;
      } catch (convErr) {
        return reject(convErr);
      }
    }

    const safeCopies = Math.max(1, Math.min(99, parseInt(copies, 10) || 1));
    const args = ['-d', printerName, '-n', String(safeCopies)];
    if (title) args.push('-t', String(title));
    if (duplex === 'long') args.push('-o', 'sides=two-sided-long-edge');
    else if (duplex === 'short') args.push('-o', 'sides=two-sided-short-edge');
    if (colorMode === 'color') args.push('-o', 'print-color-mode=color');
    else if (colorMode === 'mono') args.push('-o', 'print-color-mode=monochrome');
    args.push(fileToPrint);

    execFile('lp', args, (err, stdout, stderr) => {
      if (tempPdfPath) {
        try { fs.unlinkSync(tempPdfPath); } catch {}
      }
      if (err) return reject(new Error(stderr || err.message));
      const m = (stdout || '').match(/request id is (\S+)/);
      resolve({ jobId: m ? m[1] : null, message: stdout.trim() });
    });
  });
}

// Parses a raw `lpstat -o` line, e.g. "HP-OGF-27 root 175104 Mon 10 Aug 2026 07:57:49 PM +0530"
// into a structured job object. Printer names may themselves contain hyphens, so we only
// split off the trailing "-<jobNumber>" from the id token.
function parseJobLine(line) {
  const m = line.match(/^(\S+)\s+(\S+)\s+(\d+)\s+(.+)$/);
  if (!m) return { id: line, printer: '', jobNum: '', user: '', sizeBytes: 0, submitted: line, docName: 'Document', raw: line };
  const [, idToken, user, sizeStr, rest] = m;
  const pm = idToken.match(/^(.+)-(\d+)$/);

  const meta = JOB_METADATA[idToken] || {};
  const docName = meta.docName || (pm ? `${pm[1]}_Doc_${pm[2]}` : idToken);

  return {
    id: idToken,
    printer: pm ? pm[1] : idToken,
    jobNum: pm ? pm[2] : '',
    user: meta.username || user,
    sizeBytes: Number(sizeStr) || 0,
    submitted: rest.trim(),
    docName: docName,
    raw: line,
  };
}
function getJobStatus() {
  return new Promise(resolve => {
    exec('lpstat -o 2>/dev/null || echo ""', (err,stdout) => {
      const jobs=(stdout||'').split('\n').map(l=>l.trim()).filter(Boolean).map(parseJobLine);
      resolve(jobs);
    });
  });
}
function getCompletedJobs() {
  return new Promise(resolve => {
    exec('lpstat -W completed -o 2>/dev/null || echo ""', (err,stdout) => {
      const jobs=(stdout||'').split('\n').map(l=>l.trim()).filter(Boolean).map(parseJobLine).filter(j => !DELETED_JOB_IDS.has(String(j.id)));
      resolve(jobs);
    });
  });
}
// Marks each printer's earliest queued job as "printing" if that printer's CUPS state says so.
async function annotateJobStatuses(jobs) {
  const detail = await getCupsPrinterDetail();
  const printingPrinters = new Set((detail.printers||[]).filter(p=>/printing/i.test(p.state)).map(p=>p.name.toLowerCase()));
  const seenPrinting = new Set();
  return jobs.map(j => {
    const key = String(j.printer).toLowerCase();
    let status = 'queued';
    if (printingPrinters.has(key) && !seenPrinting.has(key)) { status='printing'; seenPrinting.add(key); }
    return { ...j, status };
  });
}
function cancelJob(jobId) {
  return new Promise((resolve,reject) => {
    execFile('cancel', [jobId], (err,stdout,stderr) => err ? reject(new Error(stderr||err.message)) : resolve(true));
  });
}
function setPrinterEnabled(name, enabled) {
  return new Promise((resolve,reject) => {
    execFile(enabled?'cupsenable':'cupsdisable', [name], (err,stdout,stderr) => err ? reject(new Error(stderr||err.message)) : resolve(true));
  });
}
function setDefaultPrinter(name) {
  return new Promise((resolve,reject) => {
    execFile('lpadmin', ['-d', name], (err,stdout,stderr) => err ? reject(new Error(stderr||err.message)) : resolve(true));
  });
}
function getCupsPrinterDetail() {
  return new Promise(resolve => {
    exec('LC_ALL=C lpstat -p -d 2>/dev/null || echo ""', (err,stdout) => {
      const lines=(stdout||'').split('\n');
      let defaultPrinter=null;
      const printers=[];
      lines.forEach(line=>{
        const dm=line.match(/system default destination:\s*(\S+)/i);
        if (dm) defaultPrinter=dm[1];
        // CUPS: "printer X is idle." | "printer X now printing X-12." | "printer X disabled since ..."
        const pm=line.match(/^printer\s+(\S+)\s+(is idle|now printing|is printing|disabled)/i);
        if (pm) printers.push({name:pm[1], state:pm[2]});
      });
      resolve({defaultPrinter, printers});
    });
  });
}
// Discover printers CUPS can see (network/IPP/DNS-SD/USB) without adding them yet
function lpinfoDiscover() {
  return new Promise(resolve => {
    exec('lpinfo --include-schemes dnssd,snmp,lpd,socket,ipp,ipps,usb -v 2>/dev/null; echo "---"; lpstat -e 2>/dev/null; echo "---"; lpstat -v 2>/dev/null', (err, stdout) => {
      const found = [];
      const seenUris = new Set();
      const parts = (stdout || '').split('---');
      const lpinfoOut = parts[0] || '';
      const lpstatEOut = parts[1] || '';
      const lpstatVOut = parts[2] || '';

      // 1. Parse lpinfo lines with actual URIs (containing ://)
      lpinfoOut.split('\n').forEach(line => {
        const m = line.trim().match(/^(network|direct)\s+(\S+:\/\/.*)$/i);
        if (m) {
          const kind = m[1];
          const uri = m[2];
          if (!seenUris.has(uri)) {
            seenUris.add(uri);
            const rawTarget = uri.split('://')[1] || '';
            const nameGuess = decodeURIComponent(rawTarget.split('/')[0].split('?')[0]);
            found.push({ kind: kind.toUpperCase() + ' (lpinfo)', uri, name: nameGuess });
          }
        }
      });

      // 2. Parse lpstat -e (discovered printers by CUPS)
      lpstatEOut.split('\n').forEach(line => {
        const name = line.trim();
        if (name && !name.includes(' ') && !seenUris.has(name)) {
          seenUris.add(name);
          found.push({ kind: 'CUPS Discovered', uri: 'cups://' + name, name });
        }
      });

      // 3. Parse lpstat -v (configured CUPS printers)
      lpstatVOut.split('\n').forEach(line => {
        const m = line.trim().match(/^device for (\S+):\s+(\S+)$/i);
        if (m) {
          const name = m[1];
          const uri = m[2];
          if (!seenUris.has(uri) && uri !== '/dev/null') {
            seenUris.add(uri);
            found.push({ kind: 'CUPS Printer (' + name + ')', uri, name });
          }
        }
      });

      resolve(found);
    });
  });
}
function lpadminAddPrinter(name, uri) {
  return new Promise((resolve,reject) => {
    const safe = name.replace(/[^a-zA-Z0-9_-]/g,'_');
    if (uri.startsWith('cups://')) {
      const cupsPrinterName = uri.replace('cups://', '');
      return resolve(cupsPrinterName);
    }
    execFile('lpadmin', ['-p', safe, '-E', '-v', uri, '-m', 'everywhere'], (err,stdout,stderr) => {
      if (err) return reject(new Error(stderr||err.message));
      resolve(safe);
    });
  });
}

// ── SNMP subnet discovery ──────────────────────────────────────────────────────
function guessLocalSubnet() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    if (/^(docker|br-|veth|vbox|virbr|tun|tap)/i.test(name)) continue;
    for (const ifc of ifaces[name]) {
      if (ifc.family==='IPv4' && !ifc.internal) {
        const parts = ifc.address.split('.');
        return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
      }
    }
  }
  return '192.168.1.0/24';
}
function snmpProbe(ip, community) {
  return new Promise(resolve => {
    const s = snmp.createSession(ip, community||'public', {timeout:600,retries:0,version:snmp.Version1});
    s.get([OID.sysDescr], (err, vb) => {
      s.close();
      if (err || !vb || snmp.isVarbindError(vb[0])) return resolve(null);
      resolve(bufToStr(vb[0].value));
    });
  });
}
async function discoverSnmpDevices(cidr, community) {
  const base = (cidr||'').split('/')[0].split('.').slice(0,3).join('.');
  if (!base) return [];
  const ips = Array.from({length:254}, (_,i)=>`${base}.${i+1}`);
  const results = [];
  const BATCH=32;
  for (let i=0;i<ips.length;i+=BATCH) {
    const batch = ips.slice(i,i+BATCH);
    const res = await Promise.all(batch.map(async ip => {
      const descr = await snmpProbe(ip, community);
      return descr ? {ip, descr} : null;
    }));
    res.forEach(r=>{ if (r) results.push(r); });
  }
  return results;
}

// ── Scan folder helpers ───────────────────────────────────────────────────────
async function listScans() {
  try {
    const files = await fs.promises.readdir(SCAN_DIR);
    const scans = await Promise.all(
      files
        .filter(f => /\.(pdf|jpg|jpeg|png|tiff?|bmp)$/i.test(f))
        .map(async f => {
          try {
            const stat = await fs.promises.stat(path.join(SCAN_DIR, f));
            return {name: f, size: stat.size, mtime: stat.mtime.toISOString()};
          } catch { return null; }
        })
    );
    return scans.filter(Boolean).sort((a, b) => new Date(b.mtime) - new Date(a.mtime));
  } catch { return []; }
}

// ── eSCL scan trigger (scanimage / sane-airscan) ───────────────────────────────
let scanDevicesCache = { devices: [], at: 0 };
const SCAN_DEVICES_TTL_MS = 30 * 1000;
function listScanDevices(forceRefresh) {
  if (!forceRefresh && (Date.now() - scanDevicesCache.at) < SCAN_DEVICES_TTL_MS) {
    return Promise.resolve(scanDevicesCache.devices);
  }
  return new Promise(resolve => {
    exec('scanimage -L 2>/dev/null', (err, stdout) => {
      const devices = [];
      (stdout || '').split('\n').forEach(line => {
        const m = line.match(/device `([^']+)' is a (.+)/);
        if (m) devices.push({ id: m[1], label: m[2] });
      });
      scanDevicesCache = { devices, at: Date.now() };
      resolve(devices);
    });
  });
}
function triggerScan(deviceId, source) {
  return new Promise((resolve, reject) => {
    if (!deviceId) return reject(new Error('No scanner device specified'));
    const file = path.join(SCAN_DIR, `scan-${Date.now()}.pdf`);
    const args = ['-d', deviceId, '--format=pdf', '-o', file];
    if (source && source !== 'Flatbed') args.push('--source', source);
    execFile('scanimage', args, { timeout: 120000 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr || err.message));
      resolve(path.basename(file));
    });
  });
}

// ── API routes ────────────────────────────────────────────────────────────────
app.use(express.json());

// Printers CRUD
app.get('/api/printers', (req,res) => {
  const allowed = allowedPrinterObjs(req.user);
  if (!allowed) return res.json(cache);
  const ids = new Set(allowed.map(p=>p.id));
  res.json({ ...cache, data: (cache.data||[]).filter(p=>ids.has(p.id)) });
});
app.get('/api/printers/refresh', (req,res) => {
  // Non-blocking: return current cache immediately and kick off a background refresh.
  // The client will see updatedAt change on the next automatic poll (every 3 min)
  // or can use ?wait=1 to block until refresh finishes (for manual refresh button).
  if (req.query.wait === '1') {
    // wait=1: honour explicit manual refresh — block until done (user pressed Refresh)
    refreshAll().then(() => {
      const allowed = allowedPrinterObjs(req.user);
      if (!allowed) return res.json(cache);
      const ids = new Set(allowed.map(p=>p.id));
      res.json({ ...cache, data: (cache.data||[]).filter(p=>ids.has(p.id)) });
    }).catch(() => res.json(cache));
  } else {
    // Default: fire-and-forget refresh, return current snapshot immediately
    refreshAll().catch(()=>{});
    const allowed = allowedPrinterObjs(req.user);
    if (!allowed) return res.json(cache);
    const ids = new Set(allowed.map(p=>p.id));
    res.json({ ...cache, data: (cache.data||[]).filter(p=>ids.has(p.id)) });
  }
});
app.post('/api/printers', async (req,res) => {
  const {name,ip,brand,location,community,autoProvision}=req.body;
  if (!name||!ip) return res.status(400).json({error:'name and ip required'});
  const id=Date.now();
  PRINTERS.push({id,name,ip,brand:brand||'generic',location:location||'',community:community||'public'});
  savePrinters(); refreshAll();
  if (autoProvision) {
    const provision = await autoProvisionPrinter(name, ip);
    return res.json({ok:true, id, provision});
  }
  res.json({ok:true,id});
});
app.put('/api/printers/:id', async (req,res) => {
  const targetId = String(req.params.id);
  const idx = PRINTERS.findIndex(p => String(p.id) === targetId || String(p.name).toLowerCase() === targetId.toLowerCase());
  if (idx === -1) return res.status(404).json({error:'not found'});
  const {autoProvision, ...rest} = req.body;
  PRINTERS[idx]={...PRINTERS[idx],...rest,id:PRINTERS[idx].id,alertsEnabled:rest.alertsEnabled!==undefined?rest.alertsEnabled:PRINTERS[idx].alertsEnabled};
  savePrinters(); refreshAll();
  if (autoProvision) {
    const provision = await autoProvisionPrinter(PRINTERS[idx].name, PRINTERS[idx].ip);
    return res.json({ok:true, provision});
  }
  res.json({ok:true});
});
app.delete('/api/printers/:id', (req,res) => {
  const targetId = String(req.params.id);
  PRINTERS = PRINTERS.filter(p => String(p.id) !== targetId && String(p.name).toLowerCase() !== targetId.toLowerCase());
  if (cache.data) {
    cache.data = cache.data.filter(p => String(p.id) !== targetId && String(p.name).toLowerCase() !== targetId.toLowerCase());
  }
  savePrinters();
  res.json({ok:true});
});

// Print jobs
app.get('/api/cups/printers', async (req,res) => {
  let list = await listCupsPrinters();
  const allowed = allowedPrinterObjs(req.user);
  if (allowed) {
    const names = new Set(allowed.map(p=>p.name.toLowerCase()));
    list = list.filter(name => names.has(String(name).toLowerCase()));
  }
  res.json({printers:list});
});
app.get('/api/cups/jobs', async (req,res) => {
  let jobs = await getJobStatus();
  const allowed = allowedPrinterObjs(req.user);
  if (allowed) {
    const names = new Set(allowed.map(p=>p.name.toLowerCase()));
    jobs = jobs.filter(j => names.has(String(j.printer).toLowerCase()));
  }
  jobs = await annotateJobStatuses(jobs);
  res.json({jobs});
});
// Poll a single job (used by the Print page to show live status after sending)
app.get('/api/cups/jobs/:jobId/status', async (req,res) => {
  const jobId = req.params.jobId;
  const active = await annotateJobStatuses(await getJobStatus());
  const found = active.find(j=>j.id===jobId);
  if (found) return res.json({status: found.status, job: found});
  const completed = await getCompletedJobs();
  const foundC = completed.find(j=>j.id===jobId);
  if (foundC) return res.json({status:'completed', job: foundC});
  res.json({status:'unknown'});
});
app.post('/api/print', upload.single('file'), async (req,res) => {
  if (!req.file) return res.status(400).json({error:'No file uploaded'});
  const {printer, copies, duplex, color} = req.body;
  if (!printer) { try{ await fs.promises.unlink(req.file.path); }catch{} return res.status(400).json({error:'printer name required'}); }
  if (!isPrinterNameAllowed(req.user, printer)) {
    try{ await fs.promises.unlink(req.file.path); }catch{}
    return res.status(403).json({error:'Not permitted to print to this printer'});
  }
  const username = req.user ? req.user.username : 'system';
  const docName = req.file.originalname;
  try {
    const result = await printFile(req.file.path, printer, copies||1, duplex||'none', color||'', docName);
    if (result.jobId) {
      recordJobMetadata(result.jobId, docName, username);
    }
    notifyUserEvent(username, 'PRINT_SUCCESS', { docName, printerName: printer, jobId: result.jobId });
    res.json({ok:true,...result});
  } catch(e) {
    notifyUserEvent(username, 'PRINT_FAILED', { docName, printerName: printer, error: e.message });
    res.status(500).json({error:e.message});
  } finally {
    try { await fs.promises.unlink(req.file.path); } catch {}
  }
});

// Scans
app.get('/api/scans', async (_req,res) => res.json({scans: await listScans(), dir:SCAN_DIR}));
app.get('/api/scans/download/:name', async (req,res) => {
  const name = path.basename(req.params.name);
  const full = path.join(SCAN_DIR, name);
  try {
    await fs.promises.access(full);
    if (req.query.inline === '1' && /\.(pdf|jpe?g|png)$/i.test(name)) {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Disposition', `inline; filename*=UTF-8''${encodeURIComponent(name)}`);
      return res.sendFile(path.resolve(full));
    }
    res.download(full);
  } catch {
    res.status(404).json({error:'not found'});
  }
});
app.delete('/api/scans/:name', async (req,res) => {
  const name = path.basename(req.params.name);
  const full = path.join(SCAN_DIR, name);
  try { await fs.promises.unlink(full); res.json({ok:true}); }
  catch { res.status(500).json({error:'could not delete'}); }
});
function deviceMatchesAllowed(deviceId, allowed) {
  if (!allowed) return true; // unrestricted
  if (!deviceId) return false;
  return allowed.some(p => p.ip && deviceId.includes(p.ip));
}
app.get('/api/scans/devices', async (req,res) => {
  let devices = await listScanDevices(req.query.refresh === '1');
  const allowed = allowedPrinterObjs(req.user);
  if (allowed) devices = devices.filter(d => deviceMatchesAllowed(d.id, allowed));
  res.json({devices});
});
app.post('/api/scans/trigger', async (req,res) => {
  const { device, source } = req.body || {};
  const allowed = allowedPrinterObjs(req.user);
  if (allowed && !deviceMatchesAllowed(device, allowed)) {
    return res.status(403).json({error:'Not permitted to scan from this device'});
  }
  const username = req.user ? req.user.username : 'system';
  try {
    const name = await triggerScan(device, source);
    notifyUserEvent(username, 'SCAN_SUCCESS', { scanName: name, scanType: 'Hardware SANE (' + (source || 'Flatbed') + ')', scanFormat: path.extname(name).toUpperCase() });
    res.json({ok:true, name});
  }
  catch(e) {
    notifyUserEvent(username, 'SCAN_FAILED', { scanType: 'Hardware SANE', error: e.message });
    res.status(500).json({error:e.message});
  }
});
app.post('/api/scans/upload', upload.single('scanFile'), async (req,res) => {
  if (!req.file) return res.status(400).json({error:'Tidak ada file yang diunggah'});
  const username = req.user ? req.user.username : 'system';
  try {
    const origExt = path.extname(req.file.originalname).toLowerCase() || '.png';
    const ext = ['.pdf', '.png', '.jpg', '.jpeg', '.webp'].includes(origExt) ? origExt : '.png';
    const timestamp = new Date().toISOString().replace(/[-:T.]/g, '').slice(0, 14);
    const filename = `cam-scan-${timestamp}-${Math.floor(Math.random()*1000)}${ext}`;
    const destPath = path.join(SCAN_DIR, filename);
    await fs.promises.mkdir(SCAN_DIR, { recursive: true });
    await fs.promises.copyFile(req.file.path, destPath);
    notifyUserEvent(username, 'SCAN_SUCCESS', { scanName: filename, scanType: 'Kamera HP', scanFormat: ext.toUpperCase() });
    res.json({ ok: true, name: filename });
  } catch(e) {
    notifyUserEvent(username, 'SCAN_FAILED', { scanType: 'Kamera HP', error: e.message });
    res.status(500).json({ error: e.message });
  } finally {
    try { await fs.promises.unlink(req.file.path); } catch {}
  }
});

// Samba setup helper — returns config snippet
app.get('/api/samba-config', (_req,res) => {
  const conf=`[scans]\n   path = ${SCAN_DIR}\n   browseable = yes\n   read only = no\n   guest ok = yes\n   create mask = 0777\n   directory mask = 0777`;
  res.json({config:conf, dir:SCAN_DIR});
});

// Settings + Telegram
app.get('/api/settings', (_req,res) => res.json(SETTINGS));
app.post('/api/settings', async (req,res) => {
  SETTINGS = {...SETTINGS, ...req.body,
    telegram:{...SETTINGS.telegram, ...(req.body.telegram||{})},
    network:{...SETTINGS.network, ...(req.body.network||{})}};
  try { await saveSettings(); res.json({ok:true, settings:SETTINGS}); }
  catch (e) { res.status(500).json({ok:false, error:'Cannot write '+SETTINGS_FILE+': '+e.message}); }
});
app.post('/api/settings/test-telegram', async (req,res) => {
  const {botToken, chatId} = req.body;
  const r = await sendTelegram('✅ PrintServer test message — Telegram alerts are working.', botToken, chatId);
  if (r && r.ok) res.json({ok:true});
  else res.status(400).json({ok:false, error:(r&&(r.description||r.error))||'Failed to send'});
});

// ── Backup & Restore API ──────────────────────────────────────────────────────
app.get('/api/backup/export', (_req, res) => {
  const backupData = {
    version: '4.0.0',
    appName: 'PrintServer',
    exportedAt: new Date().toISOString(),
    printers: PRINTERS,
    users: USERS,
    settings: SETTINGS,
    groups: GROUPS,
    mobileTokens: MOBILE_TOKENS,
    jobMetadata: JOB_METADATA
  };
  const dateStr = new Date().toISOString().split('T')[0];
  const filename = `printserver-backup-${dateStr}.json`;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(JSON.stringify(backupData, null, 2));
});

app.post('/api/backup/import', express.json({ limit: '10mb' }), async (req, res) => {
  try {
    const data = req.body;
    if (!data || typeof data !== 'object') {
      return res.status(400).json({ ok: false, error: 'File backup tidak valid' });
    }
    if (!Array.isArray(data.printers) || !Array.isArray(data.users) || !data.settings) {
      return res.status(400).json({ ok: false, error: 'Komponen backup tidak lengkap (printers, users, settings)' });
    }

    // Update in-memory data
    PRINTERS = data.printers;
    USERS = data.users;
    SETTINGS = { ...DEFAULT_SETTINGS, ...data.settings };
    if (Array.isArray(data.groups)) GROUPS = data.groups;
    if (data.mobileTokens && typeof data.mobileTokens === 'object') MOBILE_TOKENS = data.mobileTokens;
    if (data.jobMetadata && typeof data.jobMetadata === 'object') JOB_METADATA = data.jobMetadata;

    // Persist all data files to disk
    await savePrinters();
    await saveUsers();
    await saveSettings();
    saveGroups();
    saveMobileTokens();
    saveJobMetadata();

    res.json({ ok: true, message: 'Konfigurasi PrintServer berhasil dipulihkan (Restored)!' });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Gagal memulihkan backup: ' + e.message });
  }
});

// SNMP subnet discovery
app.get('/api/discover/snmp', async (req,res) => {
  const cidr = (req.query.cidr || SETTINGS.network.scanSubnet || guessLocalSubnet()).trim();
  if (!/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(cidr)) return res.status(400).json({error:'Invalid subnet, use format 192.168.1.0/24'});
  const community = req.query.community || 'public';
  try {
    const found = await discoverSnmpDevices(cidr, community);
    const existingIps = new Set(PRINTERS.map(p=>p.ip));
    res.json({cidr, results: found.map(f=>({...f, alreadyAdded: existingIps.has(f.ip)}))});
  } catch(e) { res.status(500).json({error:e.message}); }
});
app.get('/api/discover/subnet-guess', (_req,res) => {
  const saved = (SETTINGS.network && SETTINGS.network.scanSubnet || '').trim();
  res.json({cidr: saved || guessLocalSubnet(), saved: !!saved});
});

// CUPS network discovery (lpinfo) + one-click add via lpadmin
app.get('/api/cups/discover', async (_req,res) => {
  try {
    await syncCupsToPrinters();
    const found = await lpinfoDiscover();
    const registeredNames = new Set((PRINTERS || []).map(p => p.name.toLowerCase()));
    try {
      const cupsDetail = await getCupsPrinterDetail();
      (cupsDetail.printers || []).forEach(cp => {
        if (cp.name) registeredNames.add(cp.name.toLowerCase());
      });
    } catch (_) {}

    const enrichedFound = found.map(f => {
      const nameMatch = f.name && registeredNames.has(f.name.toLowerCase());
      const uriMatch = f.uri && registeredNames.has(f.uri.replace('cups://', '').toLowerCase());
      return { ...f, alreadyAdded: !!(nameMatch || uriMatch) };
    });

    res.json({ found: enrichedFound });
  } catch(e) { res.status(500).json({error:e.message}); }
});
app.post('/api/cups/discover/add', async (req,res) => {
  const {name, uri} = req.body;
  if (!name||!uri) return res.status(400).json({error:'name and uri required'});
  try {
    const finalName = await lpadminAddPrinter(name, uri);
    await syncCupsToPrinters();
    const exists = PRINTERS.some(p => p.name.toLowerCase() === finalName.toLowerCase());
    if (!exists) {
      PRINTERS.push({
        id: finalName,
        name: finalName,
        ip: '127.0.0.1',
        brand: 'CUPS Printer',
        location: 'Auto-Synced CUPS',
        community: 'public',
        alertsEnabled: true
      });
      savePrinters();
    }
    res.json({ok:true, name:finalName});
  } catch(e) { res.status(500).json({error:e.message}); }
});

// CUPS job management
app.get('/api/cups/jobs/history', async (req,res) => {
  let jobs = await getCompletedJobs();
  const allowed = allowedPrinterObjs(req.user);
  if (allowed) {
    const names = new Set(allowed.map(p=>p.name.toLowerCase()));
    jobs = jobs.filter(j => names.has(String(j.printer).toLowerCase()));
  }
  res.json({jobs});
});
app.post('/api/cups/jobs/:jobId/cancel', async (req,res) => {
  try { await cancelJob(req.params.jobId); res.json({ok:true}); }
  catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/cups/jobs/history/delete', express.json(), async (req, res) => {
  const { jobIds } = req.body || {};
  if (!Array.isArray(jobIds) || !jobIds.length) return res.status(400).json({ error: 'No jobIds provided' });
  jobIds.forEach(id => {
    const strId = String(id);
    DELETED_JOB_IDS.add(strId);
    execFile('cancel', ['-x', strId], () => {});
  });
  saveDeletedJobs();
  res.json({ ok: true, deletedCount: jobIds.length });
});

app.get('/api/cups/printers/detail', async (req,res) => {
  const detail = await getCupsPrinterDetail();
  const allowed = getAllowedPrinterNames(req.user);
  if (allowed) {
    detail.printers = (detail.printers||[]).filter(p => allowed.has(p.name.toLowerCase()));
  }
  res.json(detail);
});
app.post('/api/cups/printers/:name/pause', async (req,res) => {
  try { await setPrinterEnabled(req.params.name, false); res.json({ok:true}); }
  catch(e) { res.status(500).json({error:e.message}); }
});
app.post('/api/cups/printers/:name/resume', async (req,res) => {
  try { await setPrinterEnabled(req.params.name, true); res.json({ok:true}); }
  catch(e) { res.status(500).json({error:e.message}); }
});
app.post('/api/cups/printers/:name/default', async (req,res) => {
  try { await setDefaultPrinter(req.params.name); res.json({ok:true}); }
  catch(e) { res.status(500).json({error:e.message}); }
});
app.delete('/api/cups/printers/:name', async (req,res) => {
  try {
    await new Promise((resolve,reject) => {
      execFile('lpadmin', ['-x', req.params.name], (err,_,stderr) =>
        err ? reject(new Error(stderr||err.message)) : resolve());
    });
    res.json({ok:true});
  }
  catch(e) { res.status(500).json({error:e.message}); }
});

// ── (more routes appended below) ──────────────────────────────────────────────


app.get('/', (_req,res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.send(HTML.replace('</head>', `<script>window.USER_ROLE=${JSON.stringify(_req.user.role)};window.USERNAME=${JSON.stringify(_req.user.username)};</script></head>`));
});

// ── HTML ──────────────────────────────────────────────────────────────────────
const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="theme-color" content="#1e293b"/>
<meta name="mobile-web-app-capable" content="yes"/>
<meta name="apple-mobile-web-app-capable" content="yes"/>
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"/>
<meta name="apple-mobile-web-app-title" content="PrintServer"/>
<link rel="manifest" href="/manifest.json"/>
<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
<script>
  if (typeof pdfjsLib !== 'undefined') {
    pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
  }
</script>
<title>PrintServer</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f172a;--surface:rgba(15,23,42,0.85);--surface2:rgba(15,23,42,0.92);--border:rgba(255,255,255,0.16);--border2:rgba(59,130,246,0.4);
  --text:#ffffff;--muted:#cbd5e1;--subtle:#f1f5f9;
  --blue:#3b82f6;--green:#22c55e;--red:#ef4444;--amber:#f59e0b;--orange:#f97316;
}
body{font-family:'Segoe UI',system-ui,sans-serif;background:linear-gradient(135deg,rgba(15,23,42,0.55),rgba(15,23,42,0.45)),url('/bg.jpg') center/cover no-repeat fixed;color:var(--text);min-height:100vh}
.layout{display:flex;min-height:100vh}
.sidebar{width:224px;background:rgba(15,23,42,0.88);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;bottom:0;z-index:20;overflow-y:auto}
.sidebar-logo{padding:18px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;font-weight:700;font-size:1.05rem;color:#ffffff;text-shadow:0 1px 2px rgba(0,0,0,0.5)}
.sidebar-logo svg{color:var(--blue);flex-shrink:0}
.sidebar-nav{flex:1;padding:12px 8px;overflow-y:auto}
.nav-section{font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;font-weight:700;padding:10px 12px 4px;margin-top:4px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;cursor:pointer;font-size:.88rem;font-weight:600;color:#e2e8f0;transition:all .15s;margin-bottom:2px;user-select:none}
.nav-item:hover{background:rgba(255,255,255,.12);color:#ffffff}
.nav-item.active{background:rgba(59,130,246,.32);color:#ffffff;font-weight:700}
.nav-item svg{flex-shrink:0;opacity:.85}.nav-item.active svg{opacity:1;color:var(--blue)}
.nbadge{margin-left:auto;background:#ef444433;color:#f87171;border:1px solid #7f1d1d;border-radius:999px;padding:1px 7px;font-size:.7rem;font-weight:700}
.sidebar-footer{padding:12px;border-top:1px solid var(--border);font-size:.75rem;color:var(--muted);font-weight:500}
.main{margin-left:224px;flex:1;display:flex;flex-direction:column;background:transparent}
header{background:rgba(15,23,42,0.88);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
.header-title{font-size:1.1rem;font-weight:700;color:#ffffff;text-shadow:0 1px 2px rgba(0,0,0,0.5)}
.header-sub{font-size:.8rem;color:var(--muted);font-weight:500;margin-top:1px}
.hactions{display:flex;gap:8px;align-items:center}
.content{padding:24px;max-width:1400px;margin:0 auto;width:100%}
button{cursor:pointer;border:none;border-radius:8px;padding:8px 16px;font-size:.85rem;font-weight:600;transition:all .15s}
.btn-primary{background:var(--blue);color:#ffffff;font-weight:700;box-shadow:0 2px 8px rgba(59,130,246,0.3)}.btn-primary:hover{background:#2563eb}
.btn-outline{background:rgba(15,23,42,0.4);color:var(--subtle);border:1px solid var(--border);font-weight:600}.btn-outline:hover{background:rgba(255,255,255,.1);color:#ffffff}
.btn-sm{padding:6px 12px;font-size:.8rem}
.btn-danger{background:var(--red);color:#ffffff;font-weight:700}.btn-danger:hover{background:#dc2626}
.data-table{width:100%;border-collapse:collapse;margin-top:8px}
.data-table th{text-align:left;font-size:.75rem;text-transform:uppercase;color:var(--muted);font-weight:700;padding:10px 8px;border-bottom:1px solid var(--border)}
.data-table td{padding:11px 8px;border-bottom:1px solid var(--border);font-size:.85rem;color:#ffffff;font-weight:500}
.chip{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.75rem;font-weight:600}
.btn-ghost{background:transparent;color:var(--subtle);padding:6px 10px}.btn-ghost:hover{color:#ffffff}
.btn-green{background:#16a34a;color:#fff;font-weight:700}.btn-green:hover{background:#15803d}
.btn-amber{background:#b45309;color:#fff;font-weight:700}.btn-amber:hover{background:#92400e}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:24px}
.stat-card{background:var(--surface);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid var(--border);border-radius:12px;padding:16px;box-shadow:0 4px 16px rgba(0,0,0,0.3)}
.stat-label{font-size:.74rem;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.06em;font-weight:700}
.stat-value{font-size:2.1rem;font-weight:800;color:#ffffff;line-height:1;text-shadow:0 2px 4px rgba(0,0,0,0.4)}
.stat-value.green{color:#4ade80}.stat-value.red{color:#f87171}.stat-value.amber{color:#fbbf24}.stat-value.blue{color:#60a5fa}
.stat-sub{font-size:.74rem;color:var(--muted);font-weight:600;margin-top:4px}
.printer-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(400px,1fr));gap:20px}
.pcard{background:var(--surface);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid var(--border);border-radius:14px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.35);transition:all .2s}
.pcard:hover{border-color:rgba(255,255,255,0.25);transform:translateY(-2px)}.pcard.offline{opacity:.75}
.pcard-header{padding:16px 18px 12px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.pcard-name{font-size:1.05rem;font-weight:700;color:#ffffff;text-shadow:0 1px 2px rgba(0,0,0,0.5)}
.pcard-model{font-size:.78rem;color:var(--muted);font-weight:500;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:230px}
.pcard-badges{display:flex;gap:6px;align-items:center;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end}
.badge{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:999px;font-size:.72rem;font-weight:700;white-space:nowrap}
.badge.idle{background:#0c4a6e66;color:#38bdf8;border:1px solid #0284c7}
.badge.printing{background:#78350f66;color:#fbbf24;border:1px solid #d97706}
.badge.online{background:#14532d66;color:#4ade80;border:1px solid #16a34a}
.badge.offline{background:#450a0a66;color:#f87171;border:1px solid #dc2626}
.badge.warn{background:#78350f66;color:#fcd34d;border:1px solid #d97706}
.dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.dot.on{background:#4ade80;animation:pulse 2s infinite}.dot.off{background:#ef4444}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.pcard-tabs{display:flex;border-bottom:1px solid var(--border);padding:0 18px;overflow-x:auto}
.tab{padding:10px 14px;font-size:.8rem;font-weight:700;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;white-space:nowrap;flex-shrink:0}
.tab:hover{color:#ffffff}.tab.active{color:#60a5fa;border-bottom-color:#3b82f6}
.pcard-body{padding:14px 18px}
.tab-panel{display:none}.tab-panel.active{display:block}
.toner-list,.tray-list{display:flex;flex-direction:column;gap:9px}
.toner-row,.tray-row{}
.toner-meta,.tray-meta{display:flex;justify-content:space-between;align-items:center;margin-bottom:4px}
.toner-name,.tray-name{font-size:.77rem;color:var(--subtle)}
.toner-pct{font-size:.77rem;font-weight:600}.toner-pct.warn{color:var(--red)}
.tray-stat{font-size:.77rem;color:var(--muted)}
.track{height:9px;background:#0f172a;border-radius:999px;overflow:hidden;border:1px solid var(--border2)}
.fill{height:100%;border-radius:999px;transition:width .6s ease}
.fill.low{animation:blink 1.4s infinite}
.fill.tray{background:var(--blue)}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.4}}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.info-item{background:var(--surface2);border-radius:8px;padding:9px 12px}
.info-label{font-size:.68rem;color:var(--muted);margin-bottom:3px;text-transform:uppercase;letter-spacing:.04em}
.info-value{font-size:.8rem;color:var(--text);word-break:break-all;font-family:monospace}
.alert-list{display:flex;flex-direction:column;gap:7px}
.alert-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;font-size:.8rem}
.alert-item.Critical{background:#450a0a33;border:1px solid #7f1d1d;color:#fca5a5}
.alert-item.Warning{background:#78350f33;border:1px solid #92400e;color:#fcd34d}
.alert-item.Informational{background:#0c4a6e33;border:1px solid #075985;color:#7dd3fc}
.no-data{color:var(--muted);font-size:.8rem;padding:16px 0;text-align:center}
.ok-icon{font-size:2rem;display:block;margin-bottom:8px}
.pages-big{text-align:center;padding:12px 0}
.pages-num{font-size:2.8rem;font-weight:700;color:#f1f5f9;line-height:1}
.pages-label{font-size:.77rem;color:var(--muted);margin-top:4px}
.mini-chart{display:flex;align-items:flex-end;gap:2px;height:50px;padding:0 2px;margin-top:12px}
.mini-bar{flex:1;background:var(--blue);border-radius:2px 2px 0 0;opacity:.7;min-height:3px}
.console-msg{background:var(--surface2);border:1px solid var(--border2);border-radius:8px;padding:9px 12px;font-size:.8rem;color:var(--amber);font-family:monospace}
.pcard-footer{padding:10px 18px;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.footer-ip{font-size:.72rem;color:var(--muted);font-family:monospace}
.footer-actions{display:flex;gap:6px}

/* Print panel */
.print-panel{display:flex;flex-direction:column;gap:12px}
.drop-zone{border:2px dashed var(--border);border-radius:10px;padding:24px;text-align:center;cursor:pointer;transition:border-color .2s;color:var(--muted);font-size:.84rem}
.drop-zone:hover,.drop-zone.drag{border-color:var(--blue);color:var(--text)}
.drop-zone input{display:none}
.drop-zone .icon{font-size:2rem;margin-bottom:8px}
.print-opts{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.field-sm label{display:block;font-size:.72rem;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em}
.field-sm select,.field-sm input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:7px;padding:7px 10px;color:var(--text);font-size:.84rem;outline:none}
.field-sm select:focus,.field-sm input:focus{border-color:var(--blue)}
.print-status{padding:9px 12px;border-radius:8px;font-size:.8rem}
.print-status.ok{background:#14532d33;color:#4ade80;border:1px solid #14532d}
.print-status.err{background:#450a0a33;color:#fca5a5;border:1px solid #7f1d1d}

/* Scan view */
.scan-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.scan-table{width:100%;border-collapse:collapse}
.scan-table th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:8px 12px;border-bottom:1px solid var(--border)}
.scan-table td{padding:10px 12px;border-bottom:1px solid var(--border);font-size:.83rem}
.scan-table tr:hover td{background:rgba(255,255,255,.02)}
.scan-name{font-weight:600;color:#f1f5f9;font-family:monospace;font-size:.8rem}
.scan-size{color:var(--muted);white-space:nowrap}
.scan-time{color:var(--muted);white-space:nowrap}
.scan-actions{display:flex;gap:6px;justify-content:flex-end}
.samba-box{background:var(--surface2);border:1px solid var(--border2);border-radius:10px;padding:16px;margin-bottom:20px}
.samba-box h3{font-size:.84rem;font-weight:700;color:#f1f5f9;margin-bottom:8px}
.samba-box p{font-size:.78rem;color:var(--muted);margin-bottom:10px}
.code-block{background:#0a0f1a;border:1px solid var(--border);border-radius:7px;padding:10px 14px;font-family:monospace;font-size:.78rem;color:#7dd3fc;white-space:pre;overflow-x:auto}

/* Jobs view */
.jobs-list{display:flex;flex-direction:column;gap:8px}
.job-item{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 14px;font-size:.82rem;font-family:monospace;color:var(--subtle);display:flex;justify-content:space-between;align-items:center;gap:10px}
.job-text{overflow-wrap:anywhere}
.cups-printer-row{display:flex;justify-content:space-between;align-items:center;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 16px;margin-bottom:8px}
.cups-printer-name{font-weight:700;color:#f1f5f9;font-size:.86rem}
.cups-printer-state{font-size:.74rem;color:var(--muted);margin-top:2px}
.cups-actions{display:flex;gap:6px}
.default-star{color:var(--amber);margin-left:6px}
.job-id{font-family:monospace;color:#f1f5f9}
.job-time{color:var(--muted);white-space:nowrap}
.badge.printing{animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.55}}
.section-title{font-size:.82rem;font-weight:700;color:#f1f5f9;text-transform:uppercase;letter-spacing:.04em;margin:22px 0 10px}
.section-title:first-child{margin-top:0}

/* Grouping toggle buttons */
.grp-btn{transition:background .15s,color .15s}
.grp-btn.active{background:var(--blue,#3b82f6)!important;color:#fff!important;border-color:var(--blue,#3b82f6)!important}

/* History group accordion */
.hist-group{border:1px solid var(--border);border-radius:12px;margin-bottom:10px;overflow:hidden}
.hist-group-header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;cursor:pointer;background:var(--surface);user-select:none;transition:background .15s}
.hist-group-header:hover{background:rgba(255,255,255,.04)}
.hist-group-title{font-weight:700;color:#f1f5f9;font-size:.86rem}
.hist-group-meta{display:flex;align-items:center;gap:10px}
.hist-group-chevron{color:var(--muted);font-size:1rem;transition:transform .2s}
.hist-group.collapsed .hist-group-chevron{transform:rotate(-90deg)}
.hist-group-body{padding:0 0 8px}
.hist-group.collapsed .hist-group-body{display:none}
.hist-group .data-table{margin:0;border-radius:0;border:none;border-top:1px solid var(--border)}

/* Settings view */
.settings-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:20px;margin-bottom:20px;max-width:100%}
.settings-card h3{font-size:.92rem;font-weight:700;color:#f1f5f9;margin-bottom:4px}
.settings-card .desc{font-size:.78rem;color:var(--muted);margin-bottom:16px}
.toggle-row{display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--border)}
.toggle-row:last-child{border-bottom:none}
.toggle-label{font-size:.83rem;color:var(--text)}
.switch{position:relative;width:40px;height:22px;flex-shrink:0}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background:#374151;border-radius:999px;transition:.2s}
.slider:before{position:absolute;content:"";height:16px;width:16px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s}
input:checked + .slider{background:var(--blue)}
input:checked + .slider:before{transform:translateX(18px)}
.settings-status{margin-top:12px;padding:9px 12px;border-radius:8px;font-size:.8rem;display:none}
.help-box{background:var(--surface2);border:1px solid var(--border2);border-radius:8px;padding:12px 14px;font-size:.78rem;color:var(--subtle);margin-top:14px;line-height:1.5}
.help-box code{color:#7dd3fc}

/* Discover view */
.discover-row{display:flex;justify-content:space-between;align-items:center;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 16px;margin-bottom:8px;gap:12px}
.discover-info{min-width:0}
.discover-ip{font-weight:700;color:#f1f5f9;font-family:monospace;font-size:.84rem}
.discover-descr{font-size:.76rem;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.discover-controls{display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;margin-bottom:16px}
.discover-controls .field-sm{min-width:160px}

#modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:100;align-items:center;justify-content:center}
#modal-overlay.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:28px;width:100%;max-width:460px;max-height:90vh;overflow-y:auto}
.modal h2{font-size:1.05rem;font-weight:700;margin-bottom:20px;color:#f1f5f9}
.field{margin-bottom:13px}
.field label{display:block;font-size:.75rem;color:var(--subtle);margin-bottom:5px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.field input,.field select{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:9px 12px;color:var(--text);font-size:.88rem;outline:none}
.field input:focus,.field select:focus{border-color:var(--blue)}
.field-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.modal-footer{display:flex;justify-content:flex-end;gap:10px;margin-top:20px}
.empty{text-align:center;padding:60px 20px;color:var(--muted)}
.spin{display:inline-block;width:16px;height:16px;border:2px solid var(--border);border-top-color:var(--blue);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
select option{background:var(--surface)}
.hamburger{display:none;background:transparent;border:none;padding:6px;cursor:pointer;color:var(--text);margin-right:8px}
.hamburger svg{display:block}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:19}
@media(max-width:760px){
  .main{margin-left:0}
  .sidebar{transform:translateX(-224px);transition:transform .25s}
  .sidebar.open{transform:translateX(0)}
  .sidebar-overlay.open{display:block}
  .printer-grid{grid-template-columns:1fr}
  .info-grid{grid-template-columns:1fr}
  .field-row{grid-template-columns:1fr}
  .hamburger{display:flex;align-items:center}
  .hactions .btn-outline{display:none}
}
/* PDF Preview Split View Styles */
.print-split-container {
  display: grid;
  grid-template-columns: 380px 1fr;
  gap: 20px;
  max-width: 1150px;
  margin: 10px auto 40px;
  align-items: start;
}
@media (max-width: 920px) {
  .print-split-container {
    grid-template-columns: 1fr;
  }
}
.preview-panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 20px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.3);
  display: flex;
  flex-direction: column;
  min-height: 520px;
}
.preview-header-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 14px;
  gap: 10px;
  flex-wrap: wrap;
}
.preview-title {
  font-weight: 700;
  font-size: 0.9rem;
  color: #f1f5f9;
  display: flex;
  align-items: center;
  gap: 8px;
}
.preview-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
}
.btn-tool {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text);
  padding: 4px 10px;
  font-size: 0.78rem;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  transition: background 0.15s;
}
.btn-tool:hover { background: rgba(59,130,246,0.2); border-color: var(--blue); }
.btn-tool:disabled { opacity: 0.4; cursor: not-allowed; }
.preview-canvas-wrapper {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #090d16;
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow: auto;
  padding: 16px;
  min-height: 420px;
  position: relative;
}
#pdf-canvas-main {
  box-shadow: 0 4px 20px rgba(0,0,0,0.5);
  border-radius: 4px;
  max-width: 100%;
  height: auto;
  display: none;
}
#img-preview-main {
  max-width: 100%;
  max-height: 400px;
  border-radius: 8px;
  box-shadow: 0 4px 20px rgba(0,0,0,0.5);
  display: none;
}
.preview-empty-state {
  text-align: center;
  color: var(--muted);
  padding: 40px 20px;
}
.preview-empty-state .empty-icon {
  font-size: 3rem;
  margin-bottom: 12px;
  opacity: 0.7;
}
.summary-card {
  background: rgba(59,130,246,0.08);
  border: 1px solid rgba(59,130,246,0.25);
  border-radius: 12px;
  padding: 14px 16px;
  margin: 14px 0;
}
.summary-title {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--blue);
  font-weight: 700;
  margin-bottom: 10px;
  display: flex;
  align-items: center;
  gap: 6px;
}
.summary-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 0.82rem;
  margin-bottom: 6px;
  color: var(--muted);
}
.summary-row:last-child { margin-bottom: 0; }
.summary-val {
  font-weight: 700;
  color: #ffffff;
}
.sheet-highlight {
  color: #4ade80;
  font-size: 0.95rem;
}
.warning-badge {
  background: rgba(245,158,11,0.15);
  border: 1px solid rgba(245,158,11,0.3);
  color: #fbbf24;
  padding: 6px 10px;
  border-radius: 8px;
  font-size: 0.75rem;
  margin-top: 8px;
  display: flex;
  align-items: center;
  gap: 6px;
}

/* Grouping View Styles */
.grp-stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:20px}
.grp-stat-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:16px 18px;display:flex;align-items:center;gap:14px}
.grp-stat-icon{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.grp-stat-icon.blue{background:rgba(59,130,246,.15);color:#60a5fa}
.grp-stat-icon.purple{background:rgba(168,85,247,.15);color:#c084fc}
.grp-stat-icon.green{background:rgba(34,197,94,.15);color:#4ade80}
.grp-stat-num{font-size:1.4rem;font-weight:800;color:#f1f5f9;line-height:1}
.grp-stat-label{font-size:.75rem;color:var(--muted);margin-top:4px;font-weight:600}

.grp-form-card{max-width:100% !important;margin-bottom:24px}
.grp-form-header{display:flex;align-items:center;gap:12px;padding-bottom:12px;border-bottom:1px solid var(--border)}
.grp-icon{width:36px;height:36px;background:rgba(59,130,246,.15);color:var(--blue);border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0}

.grp-chip-container{display:flex;flex-direction:column;gap:6px;max-height:180px;overflow-y:auto;overflow-x:hidden;background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:10px}
.grp-chip-item{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;font-size:.82rem;color:var(--subtle);cursor:pointer;user-select:none;transition:all .15s ease;min-width:0;width:100%}
.grp-chip-item:hover{border-color:var(--blue);color:#f1f5f9;background:rgba(59,130,246,.08)}
.grp-chip-item.selected{background:rgba(59,130,246,.18);border-color:#3b82f6;color:#60a5fa;font-weight:600}
.grp-chip-item.printer-chip-item.selected{background:rgba(34,197,94,.18);border-color:#22c55e;color:#4ade80;font-weight:600}
.grp-chip-item svg{flex-shrink:0}
.grp-chip-item>span:first-of-type{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chip-badge{font-size:.68rem;background:rgba(255,255,255,.08);padding:2px 8px;border-radius:10px;color:var(--muted);flex-shrink:0;white-space:nowrap}

.grp-list-header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:16px;flex-wrap:wrap}
.grp-list-title h3{font-size:1rem;font-weight:700;color:#f1f5f9}
.grp-list-title .desc{font-size:.78rem;color:var(--muted)}
.grp-search-box{display:flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:8px 14px;min-width:240px}
.grp-search-box input{background:transparent;border:none;outline:none;color:#f1f5f9;font-size:.82rem;width:100%}

.group-card-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px}
.grp-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;overflow:hidden;transition:all .2s ease;display:flex;flex-direction:column}
.grp-card:hover{border-color:rgba(59,130,246,.4);box-shadow:0 4px 20px rgba(0,0,0,.3);transform:translateY(-2px)}
.grp-card-header{padding:16px;background:rgba(255,255,255,.02);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:10px}
.grp-card-title{display:flex;align-items:center;gap:10px}
.grp-card-title h4{font-size:.95rem;font-weight:700;color:#f1f5f9}
.grp-meta{font-size:.72rem;color:var(--muted);margin-top:2px}
.grp-card-actions{display:flex;gap:6px}
.btn-action{padding:5px 10px;border-radius:8px;font-size:.75rem;font-weight:600;display:inline-flex;align-items:center;gap:4px;cursor:pointer;border:none;transition:.15s}
.btn-action.edit{background:rgba(59,130,246,.15);color:#60a5fa;border:1px solid rgba(59,130,246,.3)}
.btn-action.edit:hover{background:rgba(59,130,246,.3)}
.btn-action.delete{background:rgba(239,68,68,.15);color:#f87171;border:1px solid rgba(239,68,68,.3)}
.btn-action.delete:hover{background:rgba(239,68,68,.3)}

.grp-card-body{padding:16px;flex:1}
.grp-section-label{font-size:.72rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;display:flex;align-items:center;gap:6px;margin-bottom:8px}
.grp-pills-wrap{display:flex;flex-wrap:wrap;gap:6px}
.grp-member-pill{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;font-size:.76rem;font-weight:600}
.grp-member-pill.user-pill{background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.25);color:#60a5fa}
.grp-member-pill.printer-pill{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.25);color:#4ade80}
.grp-empty-state{grid-column:1/-1;background:var(--surface);border:1px dashed var(--border);border-radius:16px;padding:40px;text-align:center;color:var(--muted)}
.grp-empty-icon{font-size:2.5rem;margin-bottom:10px}

#grp-edit-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(6px);z-index:9999;align-items:center;justify-content:center;padding:16px}
.grp-modal-card{background:var(--surface);border:1px solid var(--border);border-radius:18px;padding:28px;width:100%;max-width:680px;max-height:92vh;overflow-y:auto;overflow-x:hidden;box-shadow:0 20px 60px rgba(0,0,0,.6)}
.grp-modal-field-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}
@media(max-width:600px){.grp-modal-field-row{grid-template-columns:1fr}}
.grp-modal-header{display:flex;align-items:center;justify-content:space-between;padding-bottom:12px;border-bottom:1px solid var(--border)}
.grp-modal-header h3{font-size:1.1rem;font-weight:700;color:#f1f5f9}
.grp-modal-close{background:transparent;border:none;color:var(--muted);font-size:1.5rem;cursor:pointer;padding:0 4px}
.settings-status.ok-msg{background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.3);color:#4ade80}
.settings-status.err-msg{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);color:#f87171}
.grp-modal-close:hover{color:#f1f5f9}
</style>
</head>
<body>
<div class="layout">
<div class="sidebar-overlay" id="sidebar-overlay" onclick="closeSidebar()"></div>
<nav class="sidebar">
  <div class="sidebar-logo">
    <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/></svg>
    PrintServer
  </div>
  <div class="sidebar-nav">
    <div class="nav-section">Monitor</div>
    <div class="nav-item active" onclick="showView('analytics')" id="nav-analytics">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 20V10"/><path d="M12 20V4"/><path d="M6 20v-6"/></svg>Dashboard
    </div>
    <div class="nav-item" onclick="showView('overview')" id="nav-overview">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>Overview
    </div>
    <div class="nav-item" onclick="showView('alerts')" id="nav-alerts">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>Alerts
      <span id="alert-badge" class="nbadge" style="display:none"></span>
    </div>
    <div class="nav-item" onclick="showView('supplies')" id="nav-supplies">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>Supplies
    </div>
    <div class="nav-section">Actions</div>
    <div class="nav-item" onclick="showView('print')" id="nav-print">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/></svg>Print
    </div>
    <div class="nav-item" onclick="showView('scans')" id="nav-scans">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>Scans
    </div>
    <div class="nav-item" onclick="showView('jobs')" id="nav-jobs">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>Print Jobs
    </div>
    <div class="nav-section">Mobile</div>
    <div class="nav-item" onclick="showView('qr')" id="nav-qr">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h.01M18 14h.01M14 18h.01M18 18h.01M21 14v4M14 21h4"/></svg>Mobile QR
    </div>
    <div class="nav-item" onclick="showView('shared-docs')" id="nav-shared-docs">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>Shared Docs
    </div>
    <div class="nav-section">Tools</div>
    <div class="nav-item" onclick="showView('discover')" id="nav-discover">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>Discover Printers
    </div>
    <div class="nav-item" onclick="showView('groups')" id="nav-groups">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="7" width="8" height="8" rx="1"/><rect x="14" y="7" width="8" height="8" rx="1"/><line x1="6" y1="3" x2="6" y2="7"/><line x1="18" y1="3" x2="18" y2="7"/><line x1="6" y1="15" x2="6" y2="21"/><line x1="18" y1="15" x2="18" y2="21"/></svg>Grouping
    </div>
    <div class="nav-item" onclick="showView('settings')" id="nav-settings">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>Settings
    </div>
    <div class="nav-section">Manage</div>
    <div class="nav-item" onclick="showView('users')" id="nav-users">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>Users
    </div>
    <div class="nav-item" onclick="openModal()" id="nav-add-printer">
      <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>Add Printer
    </div>
  </div>
  <div class="sidebar-footer" id="sidebar-updated">Loading…</div>
  <div id="pwa-install-btn" style="display:none;padding:8px 12px;cursor:pointer;align-items:center;gap:8px;font-size:.75rem;color:var(--blue);border-top:1px solid var(--border)" onclick="installPWA()">
    📲 Install App
  </div>
  <div class="sidebar-footer" style="display:flex;align-items:center;justify-content:space-between;border-top:1px solid var(--border)">
    <span id="whoami" style="color:var(--subtle)"></span>
    <a href="#" onclick="doLogout();return false" style="color:var(--blue)">Logout</a>
  </div>
  <div class="sidebar-footer" style="text-align:center;border-top:1px solid var(--border);color:var(--muted)">
    coded by rama mkt
  </div>
</nav>

<div class="main">
  <header>
    <div style="display:flex;align-items:center;min-width:0">
      <button class="hamburger" onclick="toggleSidebar()" aria-label="Menu">
        <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
      </button>
      <div>
        <div class="header-title" id="view-title">Overview</div>
        <div class="header-sub" id="view-sub">All printers</div>
      </div>
    </div>
    <div class="hactions">
      <button class="btn-outline btn-sm" onclick="doRefresh()" id="refresh-btn"><span id="refresh-icon">↻</span> Refresh</button>
      <button class="btn-primary btn-sm" onclick="openModal()">+ Add Printer</button>
    </div>
  </header>
  <div class="content" id="content"><div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span> Loading…</div></div>
</div>
</div>

<!-- Modal -->
<div id="modal-overlay">
  <div class="modal">
    <h2 id="modal-title">Add Printer</h2>
    <input type="hidden" id="edit-id"/>
    <div class="field-row">
      <div class="field"><label>Name *</label><input id="f-name" placeholder="Canon-Floor2"/></div>
      <div class="field"><label>IP Address *</label><input id="f-ip" placeholder="192.168.18.x"/></div>
    </div>
    <div class="field-row">
      <div class="field"><label>Brand</label>
        <select id="f-brand">
          <option value="canon">Canon</option><option value="hp">HP</option>
          <option value="brother">Brother</option><option value="epson">Epson</option>
          <option value="ricoh">Ricoh</option><option value="xerox">Xerox</option>
          <option value="generic">Other</option>
        </select>
      </div>
      <div class="field"><label>SNMP Community</label><input id="f-community" value="public"/></div>
    </div>
    <div class="field"><label>Location / Department</label><input id="f-location" placeholder="Floor 2, HR Dept…"/></div>
    <div class="toggle-row" style="padding:8px 0">
      <span style="font-size:.82rem;color:var(--text)">Enable Telegram alerts for this printer</span>
      <label class="switch"><input type="checkbox" id="f-alerts" checked><span class="slider"></span></label>
    </div>
    <div class="toggle-row" style="padding:8px 0">
      <span style="font-size:.82rem;color:var(--text)">Also create CUPS print queue + SANE scan device (driverless IPP)</span>
      <label class="switch"><input type="checkbox" id="f-autoprovision" checked><span class="slider"></span></label>
    </div>
    <div style="font-size:.72rem;color:var(--muted);margin-top:-4px">Requires the printer to support IPP Everywhere / eSCL. Runs <code>lpadmin</code> and updates airscan.conf on the server.</div>
    <div class="modal-footer">
      <button class="btn-outline" onclick="closeModal()">Cancel</button>
      <button class="btn-primary" onclick="savePrinter()">Save</button>
    </div>
  </div>
</div>

<script>
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function escJs(s){ return String(s||'').replace(/'/g,"\\'").replace(/"/g,'\\"'); }
let state = {data:[], updatedAt:null, refreshing:false};
let currentView = 'overview';
let cupsPrinters = [];
let settingsCache = null;
let _autoRefreshTimer = null;

async function load(url='/api/printers') {
  try {
    const r = await fetch(url);
    state = await r.json();
    render();
    // If server is still doing its initial SNMP scan, schedule a fast re-poll
    if (state.refreshing || (state.data && state.data.length === 0 && PRINTERS_EXPECTED > 0)) {
      scheduleQuickPoll();
    } else {
      clearQuickPoll();
    }
  } catch {
    document.getElementById('content').innerHTML='<div class="empty">⚠ Could not load data. Is the server running?</div>';
  }
}

// How many printers are configured (we get this from the first load response)
let PRINTERS_EXPECTED = -1;

let _quickPollTimer = null;
function scheduleQuickPoll() {
  if (_quickPollTimer) return; // already scheduled
  _quickPollTimer = setTimeout(async () => {
    _quickPollTimer = null;
    await load('/api/printers');
  }, 4000);
}
function clearQuickPoll() {
  if (_quickPollTimer) { clearTimeout(_quickPollTimer); _quickPollTimer = null; }
}

async function doRefresh() {
  const btn=document.getElementById('refresh-btn'), icon=document.getElementById('refresh-icon');
  btn.disabled=true; icon.innerHTML='<span class="spin"></span>';
  // wait=1: block until SNMP polling for all printers is complete
  await load('/api/printers/refresh?wait=1');
  btn.disabled=false; icon.textContent='↻';
}

setInterval(()=>load('/api/printers'), 3*60*1000);



let cupsDetail = { defaultPrinter: null, printers: [] };
async function loadCupsPrinters() {
  try {
    const r = await fetch('/api/cups/printers/detail');
    const d = await r.json();
    cupsDetail = d;
    cupsPrinters = (d.printers || []).map(p => p.name);
  } catch {
    cupsPrinters = [];
    cupsDetail = { defaultPrinter: null, printers: [] };
  }
}

const ADMIN_ONLY_VIEWS = ['analytics','overview','alerts','supplies','jobs','discover','settings','users','groups','add-printer'];
function applyRoleUI() {
  const isAdmin = window.USER_ROLE === 'admin';
  document.getElementById('whoami').textContent = (window.USERNAME||'') + ' ('+(window.USER_ROLE||'')+')';
  ADMIN_ONLY_VIEWS.forEach(v=>{
    const el=document.getElementById('nav-'+v);
    if (el) el.style.display = isAdmin ? '' : 'none';
  });
  document.querySelectorAll('.nav-section').forEach(s=>{
    const t=s.textContent.trim();
    if (!isAdmin && (t==='Monitor'||t==='Tools'||t==='Manage')) s.style.display='none';
  });
  if (!isAdmin) {
    const addPrinterHeaderBtn = document.querySelector('.hactions .btn-primary');
    if (addPrinterHeaderBtn) addPrinterHeaderBtn.style.display='none';
    if (ADMIN_ONLY_VIEWS.includes(currentView)) currentView='print';
  }
}
async function doLogout(){ await fetch('/api/logout',{method:'POST'}); location.href='/login'; }

function toggleSidebar(){
  document.querySelector('.sidebar').classList.toggle('open');
  document.getElementById('sidebar-overlay').classList.toggle('open');
}
function closeSidebar(){
  document.querySelector('.sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('open');
}

function showView(v) {
  if (window.USER_ROLE!=='admin' && ADMIN_ONLY_VIEWS.includes(v)) return;
  if (v!=='jobs') stopJobsAutoRefresh();
  currentView=v;
  closeSidebar();
  ['analytics','overview','alerts','supplies','print','scans','jobs','discover','groups','settings','users','qr','shared-docs'].forEach(id=>{
    const el=document.getElementById('nav-'+id);
    if (el) el.classList.toggle('active',id===v);
  });
  render();
}

function render() {
  updateSidebar();
  if (currentView==='analytics') renderAnalyticsView();
  else if (currentView==='overview') renderOverview();
  else if (currentView==='alerts') renderAlertsView();
  else if (currentView==='supplies') renderSuppliesView();
  else if (currentView==='print') renderPrintView();
  else if (currentView==='scans') renderScansView();
  else if (currentView==='jobs') renderJobsView();
  else if (currentView==='discover') renderDiscoverView();
  else if (currentView==='groups') renderGroupsView();
  else if (currentView==='settings') renderSettingsView();
  else if (currentView==='users') renderUsersView();
  else if (currentView==='qr') renderQRView();
  else if (currentView==='shared-docs') renderSharedDocsView();
}

function updateSidebar() {
  const printers=state.data||[];
  // Track PRINTERS_EXPECTED for smart polling: on first successful non-empty response,
  // lock in the count so we know when to stop polling.
  if (printers.length > 0 && PRINTERS_EXPECTED < 0) PRINTERS_EXPECTED = printers.length;
  const ac=printers.reduce((a,p)=>a+(p.alerts?p.alerts.filter(x=>x.severity==='Critical'||x.severity==='Warning').length:0),0);
  const badge=document.getElementById('alert-badge');
  badge.style.display=ac>0?'':'none'; badge.textContent=ac;
  const upEl=document.getElementById('sidebar-updated');
  if (upEl) {
    if (state.refreshing) {
      upEl.innerHTML='<span class="spin" style="width:10px;height:10px;border-width:1.5px;margin-right:4px"></span> Polling printers…';
    } else if (state.updatedAt) {
      upEl.textContent='Updated '+new Date(state.updatedAt).toLocaleTimeString();
    } else {
      upEl.textContent='Waiting for first poll…';
    }
  }
}

// ── Dashboard Analytics View ──────────────────────────────────────────────────
async function renderAnalyticsView() {
  document.getElementById('view-title').textContent = 'Dashboard';
  document.getElementById('view-sub').textContent = 'Monitoring printer status, paper consumption & scanner analytics';
  document.getElementById('content').innerHTML = '<div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span></div>';

  try {
    const r = await fetch('/api/analytics');
    if (!r.ok) {
      if (r.status === 401) { location.href = '/login'; return; }
      const errTxt = await r.text();
      let errMsg = 'HTTP ' + r.status;
      try { const d = JSON.parse(errTxt); if (d.error) errMsg = d.error; } catch {}
      document.getElementById('content').innerHTML = '<div style="color:var(--red,#ef4444);padding:20px;text-align:center;">Gagal memuat data Dashboard Analytics: ' + esc(errMsg) + '</div>';
      return;
    }
    const data = await r.json();
    const s = data.summary || {};
    const pPrinter = data.paperPerPrinter || [];
    const pUser = data.paperPerUser || [];
    const sc = data.scannerUsage || {};
    const pHealth = data.printerHealth || [];

    const totalSc = sc.totalScans || 0;
    const saneSc = sc.saneScans || 0;
    const cameraSc = sc.cameraScans || 0;
    const sanePct = totalSc > 0 ? Math.round((saneSc / totalSc) * 100) : 0;
    const cameraPct = totalSc > 0 ? 100 - sanePct : 0;

    const circumference = 2 * Math.PI * 54;
    const saneDash = Math.round((sanePct / 100) * circumference);

    const summaryCards =
      '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:24px;">' +
        '<div style="background:linear-gradient(135deg,rgba(15,23,42,0.85),rgba(30,58,138,0.35));border:1px solid rgba(59,130,246,0.35);border-radius:16px;padding:20px;position:relative;box-shadow:0 8px 24px rgba(0,0,0,0.3);">' +
          '<div style="display:flex;justify-content:space-between;align-items:flex-start;">' +
            '<div>' +
              '<div style="font-size:0.82rem;color:#94a3b8;font-weight:600;">Total Pages Printed</div>' +
              '<div style="font-size:1.95rem;font-weight:800;color:#f8fafc;margin:6px 0 2px;">' + (s.totalPages || 0).toLocaleString() + '</div>' +
              '<div style="font-size:0.76rem;color:#34d399;font-weight:600;">pages</div>' +
            '</div>' +
            '<div style="width:44px;height:44px;border-radius:12px;background:rgba(59,130,246,0.15);border:1px solid rgba(59,130,246,0.35);display:flex;align-items:center;justify-content:center;color:#60a5fa;font-size:1.3rem;">🖨️</div>' +
          '</div>' +
          '<svg style="width:100%;height:32px;margin-top:8px;overflow:visible;" viewBox="0 0 100 30" preserveAspectRatio="none">' +
            '<path d="M0,25 Q25,15 50,22 T100,5" fill="none" stroke="#60a5fa" stroke-width="2.5" />' +
            '<circle cx="100" cy="5" r="3.5" fill="#60a5fa"/>' +
          '</svg>' +
        '</div>' +

        '<div style="background:linear-gradient(135deg,rgba(15,23,42,0.85),rgba(6,182,212,0.25));border:1px solid rgba(6,182,212,0.35);border-radius:16px;padding:20px;position:relative;box-shadow:0 8px 24px rgba(0,0,0,0.3);">' +
          '<div style="display:flex;justify-content:space-between;align-items:flex-start;">' +
            '<div>' +
              '<div style="font-size:0.82rem;color:#94a3b8;font-weight:600;">Active Printers</div>' +
              '<div style="font-size:1.95rem;font-weight:800;color:#f8fafc;margin:6px 0 2px;">' + (s.activePrinters || 0) + '</div>' +
              '<div style="font-size:0.76rem;color:#38bdf8;font-weight:600;">online <span style="color:#94a3b8;font-weight:400;">' + (s.totalPrinters || 0) + ' Total</span></div>' +
            '</div>' +
            '<div style="width:44px;height:44px;border-radius:12px;background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.35);display:flex;align-items:center;justify-content:center;color:#38bdf8;font-size:1.3rem;">🌐</div>' +
          '</div>' +
          '<div style="margin-top:16px;background:rgba(255,255,255,0.05);height:6px;border-radius:999px;overflow:hidden;">' +
            '<div style="width:' + (s.totalPrinters ? Math.round(((s.activePrinters||0)/(s.totalPrinters))*100) : 0) + '%;height:100%;background:linear-gradient(90deg,#06b6d4,#38bdf8);"></div>' +
          '</div>' +
        '</div>' +

        '<div style="background:linear-gradient(135deg,rgba(15,23,42,0.85),rgba(16,185,129,0.25));border:1px solid rgba(16,185,129,0.35);border-radius:16px;padding:20px;position:relative;box-shadow:0 8px 24px rgba(0,0,0,0.3);">' +
          '<div style="display:flex;justify-content:space-between;align-items:flex-start;">' +
            '<div>' +
              '<div style="font-size:0.82rem;color:#94a3b8;font-weight:600;">Total Scans Performed</div>' +
              '<div style="font-size:1.95rem;font-weight:800;color:#f8fafc;margin:6px 0 2px;">' + (totalSc).toLocaleString() + '</div>' +
              '<div style="font-size:0.76rem;color:#34d399;font-weight:600;">docs</div>' +
            '</div>' +
            '<div style="width:44px;height:44px;border-radius:12px;background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.35);display:flex;align-items:center;justify-content:center;color:#34d399;font-size:1.3rem;">📷</div>' +
          '</div>' +
          '<svg style="width:100%;height:32px;margin-top:8px;overflow:visible;" viewBox="0 0 100 30" preserveAspectRatio="none">' +
            '<path d="M0,22 Q25,28 50,15 T100,8" fill="none" stroke="#34d399" stroke-width="2.5" />' +
            '<circle cx="100" cy="8" r="3.5" fill="#34d399"/>' +
          '</svg>' +
        '</div>' +

        '<div style="background:linear-gradient(135deg,rgba(15,23,42,0.85),rgba(168,85,247,0.25));border:1px solid rgba(168,85,247,0.35);border-radius:16px;padding:20px;position:relative;box-shadow:0 8px 24px rgba(0,0,0,0.3);">' +
          '<div style="display:flex;justify-content:space-between;align-items:flex-start;">' +
            '<div>' +
              '<div style="font-size:0.82rem;color:#94a3b8;font-weight:600;">Low Toner Warnings</div>' +
              '<div style="font-size:1.95rem;font-weight:800;color:#f8fafc;margin:6px 0 2px;">' + (s.lowTonerWarnings || 0) + '</div>' +
              '<div style="font-size:0.76rem;color:#c084fc;font-weight:600;">Alerts</div>' +
            '</div>' +
            '<div style="width:44px;height:44px;border-radius:12px;background:rgba(168,85,247,0.15);border:1px solid rgba(168,85,247,0.35);display:flex;align-items:center;justify-content:center;color:#c084fc;font-size:1.3rem;">⚠️</div>' +
          '</div>' +
          '<div style="margin-top:16px;display:flex;gap:4px;">' +
            '<span class="chip" style="background:rgba(239,68,68,0.2);color:#f87171;border:1px solid rgba(239,68,68,0.3);font-size:0.7rem;">Critical Toner</span>' +
            '<span class="chip" style="background:rgba(245,158,11,0.2);color:#fbbf24;border:1px solid rgba(245,158,11,0.3);font-size:0.7rem;">Tray Warning</span>' +
          '</div>' +
        '</div>' +
      '</div>';

    // Printer Paper Bar Chart
    let printerBarsContent = '';
    if (pPrinter.length > 0) {
      const maxPrinterPages = Math.max(...pPrinter.map(p => p.pages), 1);
      const printerBars = pPrinter.map(p => {
        const heightPct = Math.max(10, Math.min(100, Math.round((p.pages / maxPrinterPages) * 100)));
        return '<div style="display:flex;flex-direction:column;align-items:center;flex:1;min-width:55px;z-index:2;">' +
            '<div style="font-size:0.75rem;font-weight:700;color:#38bdf8;margin-bottom:6px;">' + p.pages.toLocaleString() + '</div>' +
            '<div style="width:100%;max-width:44px;height:160px;background:rgba(255,255,255,0.02);border-radius:8px 8px 4px 4px;display:flex;align-items:flex-end;padding:2px;border:1px solid rgba(255,255,255,0.04);">' +
              '<div style="width:100%;height:' + heightPct + '%;background:linear-gradient(180deg,#38bdf8,#0284c7);border-radius:6px 6px 2px 2px;box-shadow:0 0 14px rgba(56,189,248,0.4);transition:height 0.4s ease;"></div>' +
            '</div>' +
            '<div style="font-size:0.7rem;color:#cbd5e1;font-weight:600;margin-top:8px;text-align:center;line-height:1.2;width:100%;" title="' + esc(p.name) + '">' + esc(p.name) + '</div>' +
          '</div>';
      }).join('');

      const maxLabel = maxPrinterPages.toLocaleString();
      const midLabel = Math.round(maxPrinterPages / 2).toLocaleString();
      const yAxisTicks =
        '<div style="display:flex;flex-direction:column;justify-content:space-between;height:160px;font-size:0.68rem;color:#64748b;font-weight:500;padding-right:8px;text-align:right;">' +
          '<div>' + maxLabel + '</div>' +
          '<div>' + midLabel + '</div>' +
          '<div>0</div>' +
        '</div>';

      const gridLines =
        '<div style="position:absolute;top:38px;left:45px;right:20px;height:160px;display:flex;flex-direction:column;justify-content:space-between;pointer-events:none;z-index:1;">' +
          '<div style="border-top:1px dashed rgba(255,255,255,0.08);width:100%;"></div>' +
          '<div style="border-top:1px dashed rgba(255,255,255,0.08);width:100%;"></div>' +
          '<div style="border-top:1px solid rgba(255,255,255,0.12);width:100%;"></div>' +
        '</div>';

      printerBarsContent = gridLines +
        '<div style="display:flex;align-items:flex-end;padding-top:10px;">' +
          yAxisTicks +
          '<div style="display:flex;gap:12px;align-items:flex-end;flex:1;overflow-x:auto;z-index:2;">' +
            printerBars +
          '</div>' +
        '</div>';
    } else {
      printerBarsContent = '<div style="padding:60px 20px;text-align:center;color:var(--muted);font-size:0.85rem;">Belum ada riwayat cetak per printer</div>';
    }

    // Top Users Consumption
    let userBarsContent = '';
    if (pUser.length > 0) {
      const maxUserPages = Math.max(...pUser.map(u => u.pages), 1);
      userBarsContent = pUser.map(u => {
        const widthPct = Math.max(10, Math.min(100, Math.round((u.pages / maxUserPages) * 100)));
        return '<div style="margin-bottom:12px;">' +
            '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;font-size:0.8rem;">' +
              '<div style="display:flex;align-items:center;gap:8px;">' +
                '<span style="width:26px;height:26px;border-radius:50%;background:rgba(59,130,246,0.25);display:flex;align-items:center;justify-content:center;font-size:0.8rem;">' + (u.avatar || '👤') + '</span>' +
                '<span style="font-weight:600;color:#f1f5f9;">' + esc(u.name) + '</span>' +
              '</div>' +
              '<span style="font-weight:700;color:#f8fafc;font-size:0.82rem;">' + u.pages.toLocaleString() + '</span>' +
            '</div>' +
            '<div style="background:rgba(255,255,255,0.04);height:10px;border-radius:999px;overflow:hidden;border:1px solid rgba(255,255,255,0.05);">' +
              '<div style="width:' + widthPct + '%;height:100%;background:linear-gradient(90deg,#10b981,#a855f7);border-radius:999px;box-shadow:0 0 10px rgba(16,185,129,0.3);"></div>' +
            '</div>' +
          '</div>';
      }).join('');
    } else {
      userBarsContent = '<div style="padding:60px 20px;text-align:center;color:var(--muted);font-size:0.85rem;">Belum ada riwayat cetak per user</div>';
    }

    const middleGrid =
      '<div style="display:grid;grid-template-columns:2.2fr 1.6fr 1.3fr;gap:16px;margin-bottom:24px;flex-wrap:wrap;">' +
        '<div style="background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:20px;position:relative;box-shadow:0 8px 24px rgba(0,0,0,0.2);">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">' +
            '<div>' +
              '<h3 style="font-size:0.92rem;font-weight:700;color:#f1f5f9;margin:0;letter-spacing:0.02em;">PAPER USAGE PER PRINTER</h3>' +
              '<div style="font-size:0.75rem;color:var(--muted);">(Pages Printed)</div>' +
            '</div>' +
          '</div>' +
          printerBarsContent +
        '</div>' +

        '<div style="background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:20px;display:flex;flex-direction:column;justify-content:space-between;box-shadow:0 8px 24px rgba(0,0,0,0.2);">' +
          '<div>' +
            '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">' +
              '<div>' +
                '<h3 style="font-size:0.92rem;font-weight:700;color:#f1f5f9;margin:0;letter-spacing:0.02em;">TOP USERS: PAPER CONSUMPTION</h3>' +
                '<div style="font-size:0.75rem;color:var(--muted);">(Top Users)</div>' +
              '</div>' +
            '</div>' +
            '<div>' +
              userBarsContent +
            '</div>' +
          '</div>' +
        '</div>' +

        '<div style="background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:20px;box-shadow:0 8px 24px rgba(0,0,0,0.2);display:flex;flex-direction:column;align-items:center;justify-content:center;">' +
          '<h3 style="font-size:0.88rem;font-weight:700;color:#f1f5f9;margin-bottom:14px;width:100%;text-align:left;letter-spacing:0.02em;">SCANNER USAGE BREAKDOWN</h3>' +
          '<div style="position:relative;width:140px;height:140px;display:flex;align-items:center;justify-content:center;">' +
            '<svg width="140" height="140" viewBox="0 0 120 120" style="transform:rotate(-90deg);">' +
              '<circle cx="60" cy="60" r="54" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="12" />' +
              '<circle cx="60" cy="60" r="54" fill="none" stroke="#a855f7" stroke-width="12" stroke-dasharray="' + circumference + '" stroke-dashoffset="0" stroke-linecap="round" />' +
              '<circle cx="60" cy="60" r="54" fill="none" stroke="#10b981" stroke-width="12" stroke-dasharray="' + saneDash + ' ' + circumference + '" stroke-dashoffset="0" stroke-linecap="round" />' +
            '</svg>' +
            '<div style="position:absolute;text-align:center;">' +
              '<div style="font-size:1.25rem;font-weight:800;color:#f8fafc;line-height:1;">' + (totalSc).toLocaleString() + '</div>' +
              '<div style="font-size:0.62rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;margin-top:2px;">TOTAL SCANS</div>' +
            '</div>' +
          '</div>' +
          '<div style="width:100%;margin-top:16px;font-size:0.76rem;">' +
            '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">' +
              '<span style="display:flex;align-items:center;gap:6px;color:#e2e8f0;"><span style="width:8px;height:8px;border-radius:50%;background:#10b981;"></span> Hardware SANE</span>' +
              '<span style="font-weight:700;color:#10b981;">' + (saneSc).toLocaleString() + ' <span style="font-weight:400;color:#34d399;">' + sanePct + '%</span></span>' +
            '</div>' +
            '<div style="display:flex;justify-content:space-between;align-items:center;">' +
              '<span style="display:flex;align-items:center;gap:6px;color:#e2e8f0;"><span style="width:8px;height:8px;border-radius:50%;background:#a855f7;"></span> Camera Capture</span>' +
              '<span style="font-weight:700;color:#c084fc;">' + (cameraSc).toLocaleString() + ' <span style="font-weight:400;color:#c084fc;">' + cameraPct + '%</span></span>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>';

    let healthCardsContent = '';
    if (pHealth.length > 0) {
      healthCardsContent = pHealth.map(p => {
        const isOnline = p.status === 'Online';
        const badgeStyle = isOnline
          ? 'background:rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.3);'
          : p.status === 'Low Paper'
          ? 'background:rgba(245,158,11,0.15);color:#fbbf24;border:1px solid rgba(245,158,11,0.3);'
          : p.status === 'Low Toner'
          ? 'background:rgba(168,85,247,0.15);color:#c084fc;border:1px solid rgba(168,85,247,0.3);'
          : 'background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3);';

        const tonerBars = (p.toners && p.toners.length)
          ? p.toners.map(t => {
              const warn = t.pct < 20;
              return '<div style="flex:1;">' +
                  '<div style="display:flex;justify-content:space-between;font-size:0.68rem;color:#94a3b8;margin-bottom:2px;">' +
                    '<span>' + esc(t.name) + '</span>' +
                    '<span style="' + (warn ? 'color:#f87171;font-weight:700;' : '') + '">' + t.pct + '%</span>' +
                  '</div>' +
                  '<div style="height:5px;background:rgba(255,255,255,0.06);border-radius:999px;overflow:hidden;">' +
                    '<div style="width:' + t.pct + '%;height:100%;background:' + (t.color || '#3b82f6') + ';border-radius:999px;"></div>' +
                  '</div>' +
                '</div>';
            }).join('')
          : '<div style="font-size:0.7rem;color:var(--muted);">Informasi toner tidak tersedia (SNMP)</div>';

        return '<div style="background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:14px;box-shadow:0 4px 14px rgba(0,0,0,0.15);">' +
            '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">' +
              '<div>' +
                '<div style="font-weight:700;color:#f8fafc;font-size:0.88rem;">' + esc(p.name) + '</div>' +
                '<div style="font-size:0.72rem;color:var(--muted);">' + esc(p.location || 'Network Printer') + '</div>' +
              '</div>' +
              '<span class="chip" style="font-size:0.7rem;padding:3px 8px;border-radius:6px;' + badgeStyle + '">' + esc(p.status) + '</span>' +
            '</div>' +
            '<div style="display:flex;gap:6px;">' +
              tonerBars +
            '</div>' +
          '</div>';
      }).join('');
    } else {
      healthCardsContent = '<div style="padding:40px 20px;text-align:center;color:var(--muted);font-size:0.88rem;grid-column:1/-1;">Belum ada printer terkonfigurasi</div>';
    }

    const healthGrid =
      '<div style="background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:20px;box-shadow:0 8px 24px rgba(0,0,0,0.2);">' +
        '<h3 style="font-size:0.92rem;font-weight:700;color:#f1f5f9;margin-bottom:16px;letter-spacing:0.02em;">PRINTER HEALTH & TONER STATUS</h3>' +
        '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px;">' +
          healthCardsContent +
        '</div>' +
      '</div>';

    document.getElementById('content').innerHTML = summaryCards + middleGrid + healthGrid;

  } catch (e) {
    document.getElementById('content').innerHTML = '<div style="color:var(--red,#ef4444);padding:20px;">Gagal memuat data Dashboard Analytics: ' + e.message + '</div>';
  }
}

// ── Overview ──────────────────────────────────────────────────────────────────
function renderOverview() {
  document.getElementById('view-title').textContent='Overview';
  document.getElementById('view-sub').textContent='All printers — status, toner, trays';
  const printers=state.data||[];
  const total=printers.length, online=printers.filter(p=>p.online).length;
  const printing=printers.filter(p=>p.status==='Printing').length;
  const lowToner=printers.filter(p=>p.toners&&p.toners.some(t=>t.pct<20&&!t.unknown)).length;
  const alerts=printers.reduce((a,p)=>a+(p.alerts?p.alerts.length:0),0);
  const stats=\`<div class="stats-grid">
    <div class="stat-card"><div class="stat-label">Printers</div><div class="stat-value blue">\${total}</div></div>
    <div class="stat-card"><div class="stat-label">Online</div><div class="stat-value green">\${online}</div><div class="stat-sub">\${total-online} offline</div></div>
    <div class="stat-card"><div class="stat-label">Printing</div><div class="stat-value amber">\${printing}</div></div>
    <div class="stat-card"><div class="stat-label">Low Toner</div><div class="stat-value \${lowToner>0?'red':''}">\${lowToner}</div></div>
    <div class="stat-card"><div class="stat-label">Alerts</div><div class="stat-value \${alerts>0?'red':''}">\${alerts}</div></div>
  </div>\`;
  const cards = printers.length
    ? printers.map(printerCard).join('')
    : state.refreshing
      ? '<div class="empty" style="padding:60px 20px">' +
          '<span class="spin" style="width:28px;height:28px;border-width:3px;margin-bottom:16px;display:block;margin-left:auto;margin-right:auto"></span>' +
          '<div style="font-size:.95rem;color:var(--text);margin-bottom:8px">Polling printers via SNMP\u2026</div>' +
          '<div style="font-size:.78rem;color:var(--muted)">This usually takes 5\u201330 seconds depending on how many printers are configured.<br>The page will update automatically.</div>' +
        '</div>'
      : '<div class="empty">No printers configured. Click <strong>Add Printer</strong> to start, or use <strong>Discover Printers</strong> in the sidebar.</div>';
  document.getElementById('content').innerHTML=stats+'<div class="printer-grid">'+cards+'</div>';
}

function printerCard(p) {
  const sc=!p.online?(p.snmpError?'warn':'offline'):p.status==='Printing'?'printing':'idle';
  const alertBadge=(p.alerts&&p.alerts.length)?'<span class="badge warn">⚠ '+p.alerts.length+'</span>':'';
  return \`<div class="pcard \${p.online?'':'offline'}" id="pcard-\${p.id}">
    <div class="pcard-header">
      <div style="min-width:0">
        <div class="pcard-name">🖨 \${esc(p.name)}</div>
        <div class="pcard-model">\${esc(p.model||p.ip)} · \${esc(p.location||'—')}</div>
      </div>
      <div class="pcard-badges">\${alertBadge}<span class="badge \${sc}"><span class="dot \${p.online?'on':'off'}"></span>\${p.status||'Offline'}</span></div>
    </div>
    <div class="pcard-tabs">
      <div class="tab active" onclick="switchTab('\${escJs(p.id)}','toner',this)">Toner</div>
      <div class="tab" onclick="switchTab('\${escJs(p.id)}','trays',this)">Trays</div>
      <div class="tab" onclick="switchTab('\${escJs(p.id)}','info',this)">Info</div>
      <div class="tab" onclick="switchTab('\${escJs(p.id)}','alerts',this)">Alerts\${p.alerts&&p.alerts.length?' ('+p.alerts.length+')':''}</div>
      <div class="tab" onclick="switchTab('\${escJs(p.id)}','pages',this)">Pages</div>
      <div class="tab" onclick="switchTab('\${escJs(p.id)}','printcard',this)">🖨 Print</div>
    </div>
    <div class="pcard-body">
      <div class="tab-panel active" id="tp-\${p.id}-toner">\${tonerPanel(p)}</div>
      <div class="tab-panel" id="tp-\${p.id}-trays">\${traysPanel(p)}</div>
      <div class="tab-panel" id="tp-\${p.id}-info">\${infoPanel(p)}</div>
      <div class="tab-panel" id="tp-\${p.id}-alerts">\${alertsPanel(p)}</div>
      <div class="tab-panel" id="tp-\${p.id}-pages">\${pagesPanel(p)}</div>
      <div class="tab-panel" id="tp-\${p.id}-printcard">\${printCardPanel(p)}</div>
    </div>
    <div class="pcard-footer">
      <span class="footer-ip">\${p.ip} · \${(p.brand||'').toUpperCase()}</span>
      <div class="footer-actions">
        <button class="btn-ghost btn-sm" onclick="editPrinter('\${escJs(p.id)}')" title="Edit Printer">✏</button>
        <button class="btn-danger btn-sm" onclick="delPrinter('\${escJs(p.id)}','\${escJs(p.name)}')" title="Hapus Printer">✕</button>
      </div>
    </div>
  </div>\`;
}

function switchTab(id,tab,el) {
  const card=document.getElementById('pcard-'+id);
  card.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  card.querySelectorAll('.tab-panel').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  const panel=document.getElementById('tp-'+id+'-'+tab);
  if (panel) panel.classList.add('active');
  if (tab==='printcard') populatePrinterSelects(); // load CUPS list on demand
}

function tonerPanel(p) {
  if (!p.online) return '<div class="no-data">Printer offline</div>';
  if (!p.toners||!p.toners.length) return '<div class="no-data">No toner data — enable SNMP on printer</div>';
  return '<div class="toner-list">'+p.toners.map(t=>{
    const warn=t.pct<20&&!t.unknown;
    return \`<div class="toner-row">
      <div class="toner-meta"><span class="toner-name">\${esc(t.name)}</span><span class="toner-pct \${warn?'warn':''}">\${t.unknown?'OK':t.pct+'%'}</span></div>
      <div class="track"><div class="fill \${warn?'low':''}" style="width:\${t.unknown?100:t.pct}%;background:\${t.color}"></div></div>
    </div>\`}).join('')+'</div>';
}

function traysPanel(p) {
  if (!p.online && !p.snmpError) return '<div class="no-data">Printer offline</div>';
  if (!p.trays||!p.trays.length) return '<div class="no-data">No tray data available</div>';
  return '<div class="tray-list">'+p.trays.map(t=>\`<div class="tray-row">
    <div class="tray-meta"><span class="tray-name">\${esc(t.name)}</span><span class="tray-stat" style="\${t.unsupported?'color:var(--muted);font-style:italic':''}">\${t.unsupported?'Not reported by printer firmware':t.pct+'% · '+t.status}</span></div>
    <div class="track"><div class="fill tray" style="width:\${t.unsupported?0:t.pct}%;opacity:\${t.unsupported?0.15:1}"></div></div>
  </div>\`).join('')+'</div>';
}

function infoPanel(p) {
  const items=[['IP',p.ip],['Model',p.model],['Serial',p.serial||'—'],['MAC',p.mac||'—'],
    ['Uptime',p.uptime||'—'],['Memory',p.memKB?Math.round(p.memKB/1024)+'MB':'—'],
    ['Location',p.location||'—'],['Brand',(p.brand||'—').toUpperCase()],
    ['Community',p.community||'public'],['Checked',p.lastChecked?new Date(p.lastChecked).toLocaleTimeString():'—']];
  const grid=items.map(([l,v])=>\`<div class="info-item"><div class="info-label">\${l}</div><div class="info-value">\${esc(String(v||'—'))}</div></div>\`).join('');
  const con=p.console_msg?'<div style="margin-top:10px"><div class="info-label" style="font-size:.68rem;color:var(--muted);text-transform:uppercase;margin-bottom:5px">Console</div><div class="console-msg">'+esc(p.console_msg)+'</div></div>':'';
  return '<div class="info-grid">'+grid+'</div>'+con;
}

function alertsPanel(p) {
  if (!p.online) return '<div class="no-data">Printer offline</div>';
  if (!p.alerts||!p.alerts.length) return '<div class="no-data"><span class="ok-icon">✅</span>No active alerts</div>';
  return '<div class="alert-list">'+p.alerts.map(a=>\`<div class="alert-item \${a.severity}">
    <span>\${a.severity==='Critical'?'🔴':a.severity==='Warning'?'🟡':'ℹ️'}</span>
    <div><strong>\${a.severity}</strong> · \${esc(a.desc)}</div>
  </div>\`).join('')+'</div>';
}

function pagesPanel(p) {
  const hist=p.pageHistory||[];
  let chart='';
  if (hist.length>1) {
    const vals=hist.map(h=>h.pages), maxV=Math.max(...vals), minV=Math.min(...vals), range=maxV-minV||1;
    chart='<div class="mini-chart">'+vals.map(v=>{
      const h=Math.max(4,Math.round(((v-minV)/range)*46));
      return '<div class="mini-bar" style="height:'+h+'px" title="'+v+'"></div>';
    }).join('')+'</div>';
  }
  return '<div class="pages-big"><div class="pages-num">'+(p.pages!=null?p.pages.toLocaleString():'—')+'</div><div class="pages-label">Total pages printed</div></div>'+chart;
}

function printCardPanel(p) {
  const pid=p.id;
  return \`<div class="print-panel" id="pp-\${pid}">
    <div class="drop-zone" id="dz-\${pid}" onclick="document.getElementById('pf-\${pid}').click()" ondragover="dzDrag(event,'\${pid}')" ondragleave="dzLeave('\${pid}')" ondrop="dzDrop(event,'\${pid}')">
      <input type="file" id="pf-\${pid}" accept=".pdf,.doc,.docx,.dot,.dotx,.docm,.rtf,.odt,.txt,.jpg,.jpeg,.png,.xls,.xlsx,.ppt,.pptx" onchange="dzFile('\${pid}',this.files[0])"/>
      <div class="icon">📄</div>
      <div id="dz-label-\${pid}">Drop file here or click to browse</div>
      <div style="font-size:.72rem;margin-top:4px;color:var(--muted)">PDF, Word (DOC/DOCX), RTF, TXT, Excel, PNG, JPG</div>
    </div>
    <div class="print-opts">
      <div class="field-sm"><label>CUPS Printer</label>
        <select id="po-printer-\${pid}"><option value="">Loading…</option></select>
      </div>
      <div class="field-sm"><label>Copies</label>
        <input type="number" id="po-copies-\${pid}" value="1" min="1" max="99"/>
      </div>
      <div class="field-sm"><label>Duplex</label>
        <select id="po-duplex-\${pid}">
          <option value="none">Single sided</option>
          <option value="long">Double (long edge)</option>
          <option value="short">Double (short edge)</option>
        </select>
      </div>
      <div class="field-sm"><label>Color</label>
        <select id="po-color-\${pid}">
          <option value="">Printer default</option>
          <option value="color">Color</option>
          <option value="mono">Black &amp; White</option>
        </select>
      </div>
    </div>
    <button class="btn-primary" onclick="submitPrint('\${pid}')">🖨 Send to Printer</button>
    <div id="pstatus-\${pid}" style="display:none" class="print-status ok"></div>
  </div>\`;
}

// ── Print view ─────────────────────────────────────────────────────────────────
function renderPrintView() {
  document.getElementById('view-title').textContent='Print';
  document.getElementById('view-sub').textContent='Send a file to any CUPS printer';
  const html=\`<div style="max-width:580px;margin:20px auto 40px;background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;box-shadow:0 8px 32px rgba(0,0,0,0.3)">
    <div class="print-panel" id="pp-main">
      <div class="drop-zone" id="dz-main" onclick="document.getElementById('pf-main').click()" ondragover="dzDrag(event,'main')" ondragleave="dzLeave('main')" ondrop="dzDrop(event,'main')">
        <input type="file" id="pf-main" accept=".pdf,.doc,.docx,.dot,.dotx,.docm,.rtf,.odt,.txt,.jpg,.jpeg,.png,.xls,.xlsx,.ppt,.pptx" onchange="dzFile('main',this.files[0])"/>
        <div class="icon">📄</div>
        <div id="dz-label-main">Drop file here or click to browse</div>
        <div style="font-size:.72rem;margin-top:4px;color:var(--muted)">PDF, Word (DOC/DOCX), RTF, TXT, Excel, PNG, JPG — max 50MB</div>
      </div>
      <div class="print-opts">
        <div class="field-sm"><label>Printer</label>
          <select id="po-printer-main"><option value="">Loading…</option></select>
        </div>
        <div class="field-sm"><label>Copies</label>
          <input type="number" id="po-copies-main" value="1" min="1" max="99"/>
        </div>
        <div class="field-sm"><label>Duplex</label>
          <select id="po-duplex-main">
            <option value="none">Single sided</option>
            <option value="long">Double (long edge)</option>
            <option value="short">Double (short edge)</option>
          </select>
        </div>
        <div class="field-sm"><label>Color</label>
          <select id="po-color-main">
            <option value="">Printer default</option>
            <option value="color">Color</option>
            <option value="mono">Black &amp; White</option>
          </select>
        </div>
      </div>
      <button class="btn-primary" style="width:100%;padding:12px" onclick="submitPrint('main')">🖨 Send to Printer</button>
      <div id="pstatus-main" style="display:none" class="print-status ok"></div>
    </div>
  </div>\`;
  document.getElementById('content').innerHTML=html;
  populatePrinterSelects();
}

// ── Scans view ────────────────────────────────────────────────────────────────
// Scan UI state survives re-renders (Refresh button, periodic render(), reload after a scan)
let scanUi = { busy:false, statusHtml:'', device:'', source:'' };
function scanStatusHtml(color, text) {
  return '<div style="margin-top:8px;color:var('+color+');font-size:.8rem">'+text+'</div>';
}
function applyScanUi() {
  const status = document.getElementById('scan-now-status');
  const btn = document.getElementById('scan-now-btn');
  const src = document.getElementById('scan-source');
  if (status) status.innerHTML = scanUi.statusHtml;
  if (btn) { btn.disabled = scanUi.busy; btn.textContent = scanUi.busy ? '⏳ Scanning…' : '🖨 Scan Now'; }
  if (src && scanUi.source) src.value = scanUi.source;
}
async function renderScansView(forceRefresh) {
  document.getElementById('view-title').textContent='Scans';
  document.getElementById('view-sub').textContent='Files scanned to the server share folder';
  // Remember selections before the DOM is replaced; no select present = view just opened
  const prevDev = document.getElementById('scan-device');
  const prevSrc = document.getElementById('scan-source');
  if (prevDev) { if (prevDev.value) scanUi.device = prevDev.value; if (prevSrc) scanUi.source = prevSrc.value; }
  else if (!scanUi.busy) scanUi.statusHtml = '';
  // Spinner only on first open; on refresh keep the current table to avoid flicker
  if (!prevDev) document.getElementById('content').innerHTML='<div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span> Loading scans…</div>';
  try {
    const isAdmin = window.USER_ROLE==='admin';
    const r=await fetch('/api/scans'); const d=await r.json();
    // /api/samba-config is admin-only (403 for users) — don't fetch or show it to regular users
    const smbaConf = isAdmin ? await fetch('/api/samba-config').then(x=>x.json()).catch(()=>({config:''})) : null;
    if (currentView!=='scans') return; // user navigated away
    const scans=d.scans||[];
    let rows=scans.length?scans.map(s=>{
      const delBtn=window.USER_ROLE===\'admin\'
        ? \'<button class="btn-danger btn-sm" data-scan=\'+JSON.stringify(s.name)+\'  onclick="deleteScan(JSON.parse(this.dataset.scan))">✕</button>\'
        : \'\';
      return \'<tr>\'
        +\'<td><span class="scan-name">\'+ esc(s.name)+\'</span></td>\'
        +\'<td class="scan-size">\'+fmtSize(s.size)+\'</td>\'
        +\'<td class="scan-time">\'+new Date(s.mtime).toLocaleString()+\'</td>\'
        +\'<td><div class="scan-actions">\'
        +\'<a href="/api/scans/download/\'+encodeURIComponent(s.name)+\'" class="btn-green btn-sm" style="text-decoration:none;display:inline-flex;align-items:center;gap:4px">⬇ Download</a>\'
        +delBtn
        +\'</div></td></tr>\';
    }).join(\'\'):\'<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:30px">No scan files yet</td></tr>\';
    const sambaBox = isAdmin ? \`
      <div class="samba-box">
        <h3>📁 Scan-to-Folder Setup</h3>
        <p>Configure your Canon/HP printer's web UI to scan directly to this server. Add this to <code>/etc/samba/smb.conf</code> and run <code>systemctl restart smbd</code>:</p>
        <div class="code-block">\${esc(smbaConf.config)}</div>
        <div style="margin-top:10px;font-size:.78rem;color:var(--muted)">Then on the printer web UI: <strong>Scan → Scan to Folder → \\\\\\\\SERVER_IP\\\\scans</strong></div>
        <div style="margin-top:6px;font-size:.78rem;color:var(--muted)">Scan folder on server: <code>\${esc(d.dir)}</code></div>
      </div>\` : '';
    document.getElementById('content').innerHTML=\`
      \${sambaBox}
      <div class="scan-header">
        <div style="font-weight:700;color:#f1f5f9">\${scans.length} file\${scans.length!==1?'s':''} in scan folder</div>
        <div style="display:flex;gap:8px">
          <select id="scan-device" class="btn-outline btn-sm" style="cursor:pointer"></select>
          <select id="scan-source" class="btn-outline btn-sm" style="cursor:pointer">
            <option value="Flatbed">Flatbed (Glass)</option>
            <option value="ADF">ADF Simplex</option>
            <option value="ADF Duplex">ADF Duplex</option>
          </select>
          <button class="btn-primary btn-sm" id="scan-now-btn" onclick="triggerScanNow()">🖨 Scan Now</button>
          <button class="btn-outline btn-sm" onclick="renderScansView(true)">↻ Refresh</button>
        </div>
      </div>
      <div id="scan-now-status"></div>
      <table class="scan-table">
        <thead><tr><th>File Name</th><th>Size</th><th>Date</th><th style="text-align:right">Actions</th></tr></thead>
        <tbody>\${rows}</tbody>
      </table>\`;
    applyScanUi();
    const devs = await fetch('/api/scans/devices'+(forceRefresh?'?refresh=1':'')).then(x=>x.json()).then(x=>x.devices||[]).catch(()=>[]);
    if (currentView!=='scans') return;
    const devSel = document.getElementById('scan-device');
    if (!devSel) return;
    devSel.innerHTML = devs.length
      ? devs.map(d=>'<option value="'+esc(d.id)+'">'+esc(d.label)+'</option>').join('')
      : '<option value="">No scanners found</option>';
    if (scanUi.device && devs.some(x=>x.id===scanUi.device)) devSel.value = scanUi.device;
  } catch { if (currentView==='scans') document.getElementById('content').innerHTML='<div class="empty">⚠ Could not load scans</div>'; }
}

async function deleteScan(name) {
  if (!confirm('Delete '+name+'?')) return;
  await fetch('/api/scans/'+encodeURIComponent(name),{method:'DELETE'});
  renderScansView();
}

async function triggerScanNow() {
  if (scanUi.busy) return;
  const device = document.getElementById('scan-device').value;
  const source = document.getElementById('scan-source').value;
  scanUi.device = device; scanUi.source = source;
  if (!device) { scanUi.statusHtml = scanStatusHtml('--red', '⚠ No scanner selected'); applyScanUi(); return; }
  scanUi.busy = true;
  scanUi.statusHtml = scanStatusHtml('--muted', 'Scanning in progress, this can take up to a minute…');
  applyScanUi();
  let ok = false;
  try {
    const r = await fetch('/api/scans/trigger', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({device, source})});
    const d = await r.json();
    ok = !!d.ok;
    scanUi.statusHtml = ok
      ? scanStatusHtml('--green', '✅ Saved '+esc(d.name))
      : scanStatusHtml('--red', '❌ '+esc(d.error || 'Scan failed'));
  } catch(e) {
    scanUi.statusHtml = scanStatusHtml('--red', '❌ '+esc(e.message));
  } finally {
    scanUi.busy = false;
  }
  // DOM may have been re-rendered while scanning — re-apply state; reload list on success
  if (currentView !== 'scans') return;
  if (ok) renderScansView(); else applyScanUi();
}

// ── Jobs view ─────────────────────────────────────────────────────────────────
let jobsAutoTimer=null;
let histGroupBy = 'none'; // 'none' | 'user' | 'printer'
function stopJobsAutoRefresh(){ if (jobsAutoTimer) { clearInterval(jobsAutoTimer); jobsAutoTimer=null; } }

// Renders a single flat history table
function renderHistTable(jobs) {
  if (!jobs.length) return '<div class="no-data">No completed jobs in this group</div>';
  return \`<table class="data-table">
    <thead><tr><th style="width:36px;text-align:center"><input type="checkbox" class="chk-hist-all" onclick="toggleSelectAllHist(this)" title="Pilih semua"></th><th>Job</th><th>Printer</th><th>Submitted by</th><th>Size</th><th>Time</th><th>Document Name</th></tr></thead>
    <tbody>\${jobs.map(j=>\`<tr>
      <td style="text-align:center"><input type="checkbox" class="chk-hist-item" value="\${esc(j.id)}" onchange="updateHistSelectCount()"></td>
      <td><span class="job-id">\${esc(j.id)}</span></td>
      <td>\${esc(j.printer)}</td>
      <td>\${esc(j.user)}</td>
      <td>\${fmtSize(j.sizeBytes)}</td>
      <td class="job-time">\${esc(j.submitted)}</td>
      <td><span class="doc-name" style="font-weight:600;color:var(--blue,#60a5fa)">\${esc(j.docName||j.id)}</span></td>
    </tr>\`).join('')}</tbody>
  </table>\`;
}

// Renders grouped history with collapsible sections
function renderHistGrouped(hist, groupKey) {
  if (!hist.length) return '<div class="no-data">No completed jobs yet</div>';
  const groups = {};
  hist.forEach(j => {
    const key = esc(j[groupKey] || 'Unknown');
    if (!groups[key]) groups[key] = [];
    groups[key].push(j);
  });
  return Object.entries(groups).sort(([a],[b])=>a.localeCompare(b)).map(([grpName, items]) => {
    const totalSize = items.reduce((s,j)=>s+j.sizeBytes,0);
    const icon = groupKey==='user' ? '👤' : '🖨';
    return \`<div class="hist-group">
      <div class="hist-group-header" onclick="this.parentElement.classList.toggle('collapsed')">
        <span class="hist-group-title">\${icon} \${grpName}</span>
        <span class="hist-group-meta">
          <span class="badge idle">\${items.length} job\${items.length!==1?'s':''}</span>
          <span style="color:var(--muted);font-size:.75rem">\${fmtSize(totalSize)} total</span>
          <span class="hist-group-chevron">▾</span>
        </span>
      </div>
      <div class="hist-group-body">\${renderHistTable(items)}</div>
    </div>\`;
  }).join('');
}

function setHistGroup(mode, el) {
  histGroupBy = mode;
  document.querySelectorAll('.grp-btn').forEach(b=>b.classList.remove('active'));
  if (el) el.classList.add('active');
  renderJobsView(true);
}

function toggleSelectAllHist(masterCb) {
  const cbs = document.querySelectorAll('.chk-hist-item');
  cbs.forEach(cb => cb.checked = masterCb.checked);
  document.querySelectorAll('.chk-hist-all').forEach(m => m.checked = masterCb.checked);
  updateHistSelectCount();
}

function updateHistSelectCount() {
  const selected = document.querySelectorAll('.chk-hist-item:checked');
  const countSpan = document.getElementById('selected-hist-count');
  const delBtn = document.getElementById('btn-delete-selected-hist');
  if (countSpan) countSpan.textContent = selected.length;
  if (delBtn) {
    if (selected.length > 0) delBtn.style.display = 'inline-flex';
    else delBtn.style.display = 'none';
  }
}

async function deleteSelectedHistory() {
  const selected = Array.from(document.querySelectorAll('.chk-hist-item:checked')).map(cb => cb.value);
  if (!selected.length) return;
  if (!confirm('Hapus ' + selected.length + ' riwayat cetak terpilih?')) return;
  
  try {
    const res = await fetch('/api/cups/jobs/history/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jobIds: selected })
    });
    const d = await res.json();
    if (d.ok) renderJobsView(true);
    else alert('Gagal menghapus: ' + (d.error || 'Unknown error'));
  } catch (e) { alert('Gagal menghapus: ' + e.message); }
}

function downloadHistoryPDF() {
  const jobs = window.currentHistJobs || [];
  if (!jobs.length) {
    alert('Tidak ada riwayat cetak untuk diunduh.');
    return;
  }
  const printWindow = window.open('', '_blank');
  if (!printWindow) {
    alert('Gagal membuka jendela cetak. Mohon izinkan pop-up di browser Anda.');
    return;
  }
  const nowStr = new Date().toLocaleString('id-ID');
  const rowsHtml = jobs.map((j, idx) => \`
    <tr>
      <td style="padding:8px;border-bottom:1px solid #ddd;">\${idx + 1}</td>
      <td style="padding:8px;border-bottom:1px solid #ddd;font-family:monospace;">\${esc(j.id)}</td>
      <td style="padding:8px;border-bottom:1px solid #ddd;">\${esc(j.printer)}</td>
      <td style="padding:8px;border-bottom:1px solid #ddd;">\${esc(j.user)}</td>
      <td style="padding:8px;border-bottom:1px solid #ddd;">\${fmtSize(j.sizeBytes)}</td>
      <td style="padding:8px;border-bottom:1px solid #ddd;">\${esc(j.submitted)}</td>
      <td style="padding:8px;border-bottom:1px solid #ddd;font-weight:bold;">\${esc(j.docName || j.id)}</td>
    </tr>\`).join('');

  printWindow.document.write(\`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Laporan Print History - PrintServer</title>
      <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; padding: 24px; color: #1e293b; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #3b82f6; padding-bottom: 12px; margin-bottom: 20px; }
        .title { font-size: 20px; font-weight: bold; color: #1e3a8a; }
        .meta { font-size: 12px; color: #64748b; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 10px; }
        th { background: #f1f5f9; text-align: left; padding: 10px 8px; border-bottom: 2px solid #cbd5e1; font-weight: 600; }
        .summary { display: flex; gap: 20px; margin-bottom: 16px; background: #f8fafc; padding: 12px; border-radius: 6px; font-size: 13px; }
        .sum-card { flex: 1; }
        .sum-card span { font-weight: bold; color: #2563eb; }
        @media print { body { padding: 0; } .no-print { display: none; } }
      </style>
    </head>
    <body>
      <div class="header">
        <div>
          <div class="title">🖨️ PrintServer - Laporan Riwayat Cetak</div>
          <div class="meta">Tanggal Cetak Laporan: \${nowStr}</div>
        </div>
        <div class="no-print">
          <button onclick="window.print()" style="padding:8px 16px;background:#2563eb;color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:bold;">📄 Simpan sebagai PDF / Cetak</button>
        </div>
      </div>
      <div class="summary">
        <div class="sum-card">Total Jobs History: <span>\${jobs.length}</span></div>
        <div class="sum-card">Tanggal Export: <span>\${new Date().toLocaleDateString('id-ID')}</span></div>
      </div>
      <table>
        <thead>
          <tr><th>#</th><th>Job ID</th><th>Printer</th><th>User</th><th>Ukuran</th><th>Waktu Submit</th><th>Nama Dokumen</th></tr>
        </thead>
        <tbody>\${rowsHtml}</tbody>
      </table>
      <script>setTimeout(() => { window.print(); }, 500);<\\/script>
    </body>
    </html>
  \`);
  printWindow.document.close();
}

function check30DayAutoDownload() {
  const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
  const lastDownload = localStorage.getItem('last30DayPdfDownload');
  if (!lastDownload || Date.now() - Number(lastDownload) >= THIRTY_DAYS_MS) {
    if (window.currentHistJobs && window.currentHistJobs.length > 0) {
      localStorage.setItem('last30DayPdfDownload', String(Date.now()));
      showToast('📅 Otomatis mengunduh laporan PDF Print History...');
      setTimeout(downloadHistoryPDF, 1500);
    }
  }
}

function showToast(msg) {
  let toast = document.getElementById('toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast';
    toast.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#2563eb;color:white;padding:12px 20px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.15);z-index:9999;transition:opacity 0.3s, transform 0.3s;opacity:0;transform:translateY(20px);';
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.style.opacity = '1';
  toast.style.transform = 'translateY(0)';
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(20px)';
  }, 4000);
}

function showPrintSuccessModal({ title = 'Successfully', docName = '', printerName = '', jobId = '', message = '' }) {
  const old = document.getElementById('print-success-modal-overlay');
  if (old) old.remove();

  if (!document.getElementById('print-success-style')) {
    const st = document.createElement('style');
    st.id = 'print-success-style';
    st.textContent =
      '@keyframes popInModal { 0% { opacity:0; transform:scale(0.8); } 70% { transform:scale(1.05); } 100% { opacity:1; transform:scale(1); } }' +
      '@keyframes fadeInModal { from { opacity:0; } to { opacity:1; } }';
    document.head.appendChild(st);
  }

  const overlay = document.createElement('div');
  overlay.id = 'print-success-modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.65);backdrop-filter:blur(6px);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;animation:fadeInModal 0.2s ease-out;';

  const defaultMsg = (docName ? 'Dokumen <strong>' + esc(docName) + '</strong>' : 'Dokumen')
    + (printerName ? ' berhasil dikirim ke printer <strong>' + esc(printerName) + '</strong>.' : ' berhasil dikirim ke printer.')
    + (jobId ? '<br><span style="font-size:0.78rem;color:#64748b;margin-top:6px;display:inline-block;background:#f1f5f9;padding:2px 8px;border-radius:6px;">Job ID: #' + esc(jobId) + '</span>' : '');

  const finalMsg = message || defaultMsg;

  overlay.innerHTML =
    '<div style="background:#ffffff;color:#1e293b;border-radius:24px;width:100%;max-width:360px;text-align:center;position:relative;box-shadow:0 25px 50px -12px rgba(0,0,0,0.4);overflow:hidden;animation:popInModal 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);font-family:system-ui,sans-serif;">'
      + '<div style="background:#f8fafc;padding:32px 20px 20px;position:relative;display:flex;justify-content:center;align-items:center;">'
        + '<svg style="position:absolute;top:16px;left:40px;width:22px;height:22px;color:#3b82f6;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10"/></svg>'
        + '<svg style="position:absolute;top:12px;right:45px;width:26px;height:26px;color:#ef4444;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M4 12a8 8 0 0 1 8-8"/></svg>'
        + '<svg style="position:absolute;bottom:14px;left:50px;width:18px;height:18px;color:#a855f7;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 22a10 10 0 0 0 10-10"/></svg>'

        + '<div style="width:72px;height:72px;background:#22c55e;border-radius:50%;display:flex;align-items:center;justify-content:center;box-shadow:0 10px 20px rgba(34,197,94,0.35);position:relative;z-index:2;">'
          + '<svg style="width:40px;height:40px;color:#ffffff;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round">'
            + '<polyline points="20 6 9 17 4 12"></polyline>'
          + '</svg>'
        + '</div>'
      + '</div>'

      + '<div style="padding:10px 24px 20px;">'
        + '<h2 style="margin:0 0 10px;font-size:1.7rem;font-weight:800;color:#0f172a;letter-spacing:-0.02em;">' + esc(title) + '</h2>'
        + '<div style="font-size:0.9rem;color:#64748b;line-height:1.5;">' + finalMsg + '</div>'
      + '</div>'

      + '<div style="padding:0 24px 24px;">'
        + '<button style="width:100%;padding:14px;background:#e2e8f0;color:#0f172a;border:none;border-radius:14px;font-size:1.05rem;font-weight:700;cursor:pointer;box-shadow:0 2px 6px rgba(0,0,0,0.05);transition:background 0.2s;" onclick="closePrintSuccessModal()">'
          + 'Oke'
        + '</button>'
      + '</div>'
    + '</div>';

  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) closePrintSuccessModal(); });
}

function closePrintSuccessModal() {
  const o = document.getElementById('print-success-modal-overlay');
  if (o) o.remove();
}

function showPrintErrorModal({ title = 'Gagal', message = 'Terjadi kesalahan saat memproses permintaan.' }) {
  const old = document.getElementById('print-error-modal-overlay');
  if (old) old.remove();

  if (!document.getElementById('print-success-style')) {
    const st = document.createElement('style');
    st.id = 'print-success-style';
    st.textContent =
      '@keyframes popInModal { 0% { opacity:0; transform:scale(0.8); } 70% { transform:scale(1.05); } 100% { opacity:1; transform:scale(1); } }' +
      '@keyframes fadeInModal { from { opacity:0; } to { opacity:1; } }';
    document.head.appendChild(st);
  }

  const overlay = document.createElement('div');
  overlay.id = 'print-error-modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.65);backdrop-filter:blur(6px);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;animation:fadeInModal 0.2s ease-out;';

  overlay.innerHTML =
    '<div style="background:#ffffff;color:#1e293b;border-radius:24px;width:100%;max-width:360px;text-align:center;position:relative;box-shadow:0 25px 50px -12px rgba(0,0,0,0.4);overflow:hidden;animation:popInModal 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);font-family:system-ui,sans-serif;">'
      + '<div style="background:#fef2f2;padding:32px 20px 20px;position:relative;display:flex;justify-content:center;align-items:center;">'
        + '<svg style="position:absolute;top:16px;left:40px;width:22px;height:22px;color:#f59e0b;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
        + '<svg style="position:absolute;top:12px;right:45px;width:26px;height:26px;color:#ef4444;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 9v4m0 4h.01"/></svg>'

        + '<div style="width:72px;height:72px;background:#ef4444;border-radius:50%;display:flex;align-items:center;justify-content:center;box-shadow:0 10px 20px rgba(239,68,68,0.35);position:relative;z-index:2;">'
          + '<svg style="width:38px;height:38px;color:#ffffff;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round">'
            + '<line x1="18" y1="6" x2="6" y2="18"></line>'
            + '<line x1="6" y1="6" x2="18" y2="18"></line>'
          + '</svg>'
        + '</div>'
      + '</div>'

      + '<div style="padding:10px 24px 20px;">'
        + '<h2 style="margin:0 0 10px;font-size:1.7rem;font-weight:800;color:#0f172a;letter-spacing:-0.02em;">' + esc(title) + '</h2>'
        + '<div style="font-size:0.9rem;color:#64748b;line-height:1.5;">' + esc(message) + '</div>'
      + '</div>'

      + '<div style="padding:0 24px 24px;">'
        + '<button style="width:100%;padding:14px;background:#e2e8f0;color:#0f172a;border:none;border-radius:14px;font-size:1.05rem;font-weight:700;cursor:pointer;box-shadow:0 2px 6px rgba(0,0,0,0.05);transition:background 0.2s;" onclick="closePrintErrorModal()">'
          + 'Tutup'
        + '</button>'
      + '</div>'
    + '</div>';

  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) closePrintErrorModal(); });
}

function closePrintErrorModal() {
  const o = document.getElementById('print-error-modal-overlay');
  if (o) o.remove();
}

async function renderJobsView(silent) {
  document.getElementById('view-title').textContent='Print Jobs';
  document.getElementById('view-sub').textContent='CUPS printers, active queue, and history';
  if (!silent) document.getElementById('content').innerHTML='<div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span></div>';
  try {
    const [detail,jobsD,histD]=await Promise.all([
      fetch('/api/cups/printers/detail').then(x=>x.json()),
      fetch('/api/cups/jobs').then(x=>x.json()),
      fetch('/api/cups/jobs/history').then(x=>x.json()),
    ]);
    if (currentView!=='jobs') return; // user navigated away while this was loading
    const printers=detail.printers||[], def=detail.defaultPrinter;
    const printerRows=printers.length?printers.map(pr=>{
      const st=pr.state.toLowerCase();
      const badgeClass = st.includes('disabled') ? 'offline' : st.includes('printing') ? 'printing' : 'idle';
      return \`<div class="cups-printer-row">
      <div>
        <div class="cups-printer-name">\${esc(pr.name)}\${pr.name===def?'<span class="default-star">★ default</span>':''}</div>
        <div class="cups-printer-state"><span class="badge \${badgeClass}">\${esc(pr.state)}</span></div>
      </div>
      <div class="cups-actions">
        \${st.includes('disabled')
          ?'<button class="btn-green btn-sm" data-printer="'+esc(pr.name)+'" onclick="resumePrinter(this.dataset.printer)">▶ Resume</button>'
          :'<button class="btn-amber btn-sm" data-printer="'+esc(pr.name)+'" onclick="pausePrinter(this.dataset.printer)">⏸ Pause</button>'}
        \${pr.name!==def?'<button class="btn-outline btn-sm" data-printer="'+esc(pr.name)+'" onclick="setDefaultPrinter(this.dataset.printer)">Set Default</button>':''}
        <button class="btn-danger btn-sm" data-printer="'+esc(pr.name)+'" onclick="deleteCupsPrinter(this.dataset.printer)" title="Hapus printer">✕</button>
      </div>
    </div>\`;
    }).join(''):'<div class="no-data">No CUPS printers configured yet — add one from Discover Printers.</div>';

    const jobs=jobsD.jobs||[];
    const printingCount=jobs.filter(j=>j.status==='printing').length;
    const jobRows=jobs.length?\`<table class="data-table">
      <thead><tr><th>Status</th><th>Job</th><th>Printer</th><th>Submitted by</th><th>Size</th><th>Time</th><th>Document Name</th><th></th></tr></thead>
      <tbody>\${jobs.map(j=>\`<tr>
        <td>\${j.status==='printing'?'<span class="badge printing">🖨 Printing</span>':'<span class="badge idle">⏳ Queued</span>'}</td>
        <td><span class="job-id">\${esc(j.id)}</span></td>
        <td>\${esc(j.printer)}</td>
        <td>\${esc(j.user)}</td>
        <td>\${fmtSize(j.sizeBytes)}</td>
        <td class="job-time">\${esc(j.submitted)}</td>
        <td><span class="doc-name" style="font-weight:600;color:var(--blue,#60a5fa)">\${esc(j.docName||j.id)}</span></td>
        <td style="text-align:right"><button class="btn-danger btn-sm" data-jobid="\${esc(j.id)}" onclick="cancelJob(this.dataset.jobid)">✕ Cancel</button></td>
      </tr>\`).join('')}</tbody>
    </table>\`:'<div class="no-data" style="padding:24px 0;text-align:center"><span class="ok-icon">✅</span>Print queue is empty</div>';

    const hist=histD.jobs||[];
    const histContent = histGroupBy==='user'
      ? renderHistGrouped(hist, 'user')
      : histGroupBy==='printer'
        ? renderHistGrouped(hist, 'printer')
        : (hist.length ? renderHistTable(hist.slice(0,20)) : '<div class="no-data">No completed jobs yet</div>');

    document.getElementById('content').innerHTML=\`
      <div class="section-title" style="display:flex;align-items:center;justify-content:space-between">
        <span>CUPS Printers</span>
      </div>
      \${printerRows}
      <div class="section-title" style="display:flex;align-items:center;justify-content:space-between">
        <span>Active Queue (\${jobs.length}\${printingCount?', '+printingCount+' printing':''})</span>
        <button class="btn-outline btn-sm" onclick="renderJobsView()">↻ Refresh</button>
      </div>
      \${jobRows}
      <div class="section-title" style="display:flex;align-items:center;justify-content:space-between">
        <span>Recent History (\${hist.length})</span>
        <div style="display:flex;gap:6px;align-items:center">
          <span style="font-size:.72rem;color:var(--muted);margin-right:2px">Group by:</span>
          <button id="grp-none" class="grp-btn btn-outline btn-sm\${histGroupBy==='none'?' active':''}" onclick="setHistGroup('none',this)">None</button>
          <button id="grp-user" class="grp-btn btn-outline btn-sm\${histGroupBy==='user'?' active':''}" onclick="setHistGroup('user',this)">👤 User</button>
          <button id="grp-printer" class="grp-btn btn-outline btn-sm\${histGroupBy==='printer'?' active':''}" onclick="setHistGroup('printer',this)">🖨 Printer</button>
          <button id="btn-download-hist-pdf" class="btn-outline btn-sm" onclick="downloadHistoryPDF()" title="Download PDF (otomatis tiap 30 hari)">📄 Download PDF</button>
          <button id="btn-delete-selected-hist" class="btn-danger btn-sm" style="display:none" onclick="deleteSelectedHistory()">🗑 Hapus (<span id="selected-hist-count">0</span>)</button>
        </div>
      </div>
      <div id="hist-container">\${histContent}</div>
    \`;
    window.currentHistJobs = hist;
    check30DayAutoDownload();

    // Auto-refresh quietly while there's something happening in the queue
    stopJobsAutoRefresh();
    if (jobs.length>0) jobsAutoTimer=setInterval(()=>{ if (currentView==='jobs') renderJobsView(true); else stopJobsAutoRefresh(); }, 5000);
  } catch { if (!silent) document.getElementById('content').innerHTML='<div class="empty">⚠ Could not load jobs</div>'; }
}

async function cancelJob(jobId) {
  await fetch('/api/cups/jobs/'+encodeURIComponent(jobId)+'/cancel',{method:'POST'});
  renderJobsView();
}
async function pausePrinter(name) {
  await fetch('/api/cups/printers/'+encodeURIComponent(name)+'/pause',{method:'POST'});
  renderJobsView();
}
async function resumePrinter(name) {
  await fetch('/api/cups/printers/'+encodeURIComponent(name)+'/resume',{method:'POST'});
  renderJobsView();
}
async function setDefaultPrinter(name) {
  await fetch('/api/cups/printers/'+encodeURIComponent(name)+'/default',{method:'POST'});
  renderJobsView();
}
async function deleteCupsPrinter(name) {
  if (!confirm('Hapus printer CUPS "'+name+'"?')) return;
  const res = await fetch('/api/cups/printers/'+encodeURIComponent(name), {method:'DELETE'});
  if (res.ok) {
    renderJobsView();
  } else {
    const d = await res.json().catch(()=>({}));
    alert('Gagal menghapus printer: ' + (d.error || 'Unknown error'));
  }
}

// ── Discover view ─────────────────────────────────────────────────────────────
async function renderDiscoverView() {
  document.getElementById('view-title').textContent='Discover Printers';
  document.getElementById('view-sub').textContent='Find printers on your network automatically';
  let guess='192.168.1.0/24';
  try { const g=await fetch('/api/discover/subnet-guess').then(x=>x.json()); guess=g.cidr||guess; } catch {}
  document.getElementById('content').innerHTML=\`
    <div class="section-title">SNMP Scan (for monitoring — toner, trays, alerts)</div>
    <div class="discover-controls">
      <div class="field-sm"><label>Subnet (CIDR)</label><input id="disc-cidr" value="\${esc(guess)}"/></div>
      <div class="field-sm"><label>SNMP Community</label><input id="disc-community" value="public"/></div>
      <button class="btn-primary" onclick="runSnmpDiscover()">🔍 Scan Network</button>
    </div>
    <div id="snmp-results"><div class="no-data">Click "Scan Network" — this checks ~254 addresses, takes 10-30s.</div></div>

    <div class="section-title">CUPS Network Discovery (for printing/scanning)</div>
    <div class="discover-controls">
      <button class="btn-primary" onclick="runCupsDiscover()">🔍 Scan via CUPS (lpinfo)</button>
    </div>
    <div id="cups-results"><div class="no-data">Finds printers via IPP/DNS-SD/network broadcast that CUPS can register directly.</div></div>
  \`;
}

async function runSnmpDiscover() {
  const cidr=document.getElementById('disc-cidr').value.trim();
  const community=document.getElementById('disc-community').value.trim()||'public';
  document.getElementById('snmp-results').innerHTML='<div style="text-align:center;padding:30px;color:var(--muted)"><span class="spin"></span> Scanning \${esc(cidr)}…</div>'.replace('\${esc(cidr)}',esc(cidr));
  try {
    const r=await fetch('/api/discover/snmp?cidr='+encodeURIComponent(cidr)+'&community='+encodeURIComponent(community));
    const d=await r.json();
    if (!r.ok) { document.getElementById('snmp-results').innerHTML='<div class="empty">⚠ '+esc(d.error||'Scan failed')+'</div>'; return; }
    const results=d.results||[];
    if (!results.length) { document.getElementById('snmp-results').innerHTML='<div class="no-data">No SNMP-responding devices found on '+esc(cidr)+'</div>'; return; }
    document.getElementById('snmp-results').innerHTML=results.map(rr=>\`<div class="discover-row">
      <div class="discover-info"><div class="discover-ip">\${esc(rr.ip)}</div><div class="discover-descr">\${esc(rr.descr)}</div></div>
      \${rr.alreadyAdded?'<span class="badge online">✓ Added</span>':'<button class="btn-green btn-sm" data-ip="'+esc(rr.ip)+'" data-descr="'+esc(rr.descr)+'" onclick="addSnmpResult(this.dataset.ip,this.dataset.descr)">+ Add Printer</button>'}
    </div>\`).join('');
  } catch { document.getElementById('snmp-results').innerHTML='<div class="empty">⚠ Scan failed</div>'; }
}

async function addSnmpResult(ip, descr) {
  const name=prompt('Printer name:', descr.substring(0,30)||ip)||ip;
  const community=document.getElementById('disc-community').value.trim()||'public';
  await fetch('/api/printers',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name, ip, brand:'generic', community})});
  alert('Added! Check the Overview tab.');
  runSnmpDiscover();
}

async function runCupsDiscover() {
  document.getElementById('cups-results').innerHTML='<div style="text-align:center;padding:30px;color:var(--muted)"><span class="spin"></span> Asking CUPS…</div>';
  try {
    const r=await fetch('/api/cups/discover'); const d=await r.json();
    const found=d.found||[];
    if (!found.length) { document.getElementById('cups-results').innerHTML='<div class="no-data">CUPS found nothing. Printer may need to be on and IPP-capable.</div>'; return; }
    document.getElementById('cups-results').innerHTML=found.map((f,i)=>{
      if (f.alreadyAdded) {
        return '<div class="discover-row" style="background:rgba(16,185,129,0.05);border:1px solid rgba(16,185,129,0.2);display:flex;align-items:center;justify-content:space-between;padding:12px;border-radius:8px;margin-bottom:8px">' +
          '<div class="discover-info">' +
            '<div class="discover-ip" style="display:flex;align-items:center;gap:8px;font-weight:600">' +
              esc(f.name || f.kind) +
              ' <span class="badge online" style="background:rgba(16,185,129,0.15);color:#10b981;border:1px solid rgba(16,185,129,0.3);padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600">✓ Terdaftar & Tersimpan</span>' +
            '</div>' +
            '<div class="discover-descr" style="color:var(--muted);font-size:12px;margin-top:2px">' + esc(f.uri) + '</div>' +
          '</div>' +
          '<button class="btn-secondary btn-sm" disabled style="opacity:0.75;cursor:default"><i class="fas fa-check-circle"></i> Sudah Terdaftar</button>' +
        '</div>';
      }
      return '<div class="discover-row">' +
        '<div class="discover-info"><div class="discover-ip">' + esc(f.name || f.kind) + '</div><div class="discover-descr">' + esc(f.uri) + '</div></div>' +
        '<button class="btn-green btn-sm" data-uri="' + esc(f.uri) + '" data-name="' + esc(f.name||'') + '" onclick="addCupsResult(this.dataset.uri, this.dataset.name)">+ Add to CUPS</button>' +
      '</div>';
    }).join('');
  } catch { document.getElementById('cups-results').innerHTML='<div class="empty">⚠ Scan failed</div>'; }
}

async function addCupsResult(uri, defaultName) {
  const suggestedName = (defaultName || 'Printer'+Math.floor(Math.random()*1000)).replace(/[^a-zA-Z0-9_-]/g,'_');
  const name=prompt('CUPS printer name (letters/numbers/dashes only):', suggestedName);
  if (!name) return;
  try {
    const r=await fetch('/api/cups/discover/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,uri})});
    const d=await r.json();
    if (d.ok) { alert('Added to CUPS as "'+d.name+'". It will now appear in Print and Print Jobs.'); populatePrinterSelects(); }
    else alert('Failed: '+(d.error||'unknown error'));
  } catch(e) { alert('Failed: '+e.message); }
}

// ── Settings view ─────────────────────────────────────────────────────────────
async function renderSettingsView() {
  document.getElementById('view-title').textContent='Settings';
  document.getElementById('view-sub').textContent='Telegram alerts & network defaults';
  document.getElementById('content').innerHTML='<div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span></div>';
  try { settingsCache = await fetch('/api/settings').then(x=>x.json()); } catch { settingsCache=null; }
  const t = (settingsCache&&settingsCache.telegram) || {};
  const n = (settingsCache&&settingsCache.network) || {};
  document.getElementById('content').innerHTML=\`
    <div class="settings-card">
      <h3>📲 Telegram Alerts</h3>
      <div class="desc">Get notified instantly when toner is low, a printer goes offline, or a jam is reported.</div>
      <div class="toggle-row">
        <span class="toggle-label">Enable Telegram alerts</span>
        <label class="switch"><input type="checkbox" id="s-enabled" \${t.enabled?'checked':''}><span class="slider"></span></label>
      </div>
      <div class="field" style="margin-top:14px"><label>Bot Token</label><input id="s-token" placeholder="123456:ABC-DEF..." value="\${esc(t.botToken||'')}"/></div>
      <div class="field"><label>Chat ID</label><input id="s-chatid" placeholder="-1001234567890 or your user id" value="\${esc(t.chatId||'')}"/></div>
      <div class="field-row">
        <div class="field"><label>Toner alert threshold (%)</label><input type="number" id="s-threshold" value="\${t.tonerThreshold!=null?t.tonerThreshold:20}" min="1" max="90"/></div>
        <div class="field"><label>Re-alert cooldown (minutes)</label><input type="number" id="s-cooldown" value="\${t.cooldownMinutes!=null?t.cooldownMinutes:240}" min="5"/></div>
      </div>
      <div class="toggle-row"><span class="toggle-label">Alert on low toner</span><label class="switch"><input type="checkbox" id="s-toner" \${t.alertToner!==false?'checked':''}><span class="slider"></span></label></div>
      <div class="toggle-row"><span class="toggle-label">Alert when printer goes offline</span><label class="switch"><input type="checkbox" id="s-offline" \${t.alertOffline!==false?'checked':''}><span class="slider"></span></label></div>
      <div class="toggle-row"><span class="toggle-label">Alert on jams / cover open / service</span><label class="switch"><input type="checkbox" id="s-jams" \${t.alertJams!==false?'checked':''}><span class="slider"></span></label></div>
      <div class="toggle-row"><span class="toggle-label">Alert when a paper tray is empty</span><label class="switch"><input type="checkbox" id="s-tray" \${t.alertTrayEmpty!==false?'checked':''}><span class="slider"></span></label></div>
      <div class="toggle-row"><span class="toggle-label">Alert on Print Success</span><label class="switch"><input type="checkbox" id="s-print-succ" \${t.alertPrintSuccess!==false?'checked':''}><span class="slider"></span></label></div>
      <div class="toggle-row"><span class="toggle-label">Alert on Print Failed</span><label class="switch"><input type="checkbox" id="s-print-fail" \${t.alertPrintFailed!==false?'checked':''}><span class="slider"></span></label></div>
      <div class="toggle-row"><span class="toggle-label">Alert on Scan Success</span><label class="switch"><input type="checkbox" id="s-scan-succ" \${t.alertScanSuccess!==false?'checked':''}><span class="slider"></span></label></div>
      <div class="toggle-row"><span class="toggle-label">Alert on Scan Failed</span><label class="switch"><input type="checkbox" id="s-scan-fail" \${t.alertScanFailed!==false?'checked':''}><span class="slider"></span></label></div>
      <div style="display:flex;gap:10px;margin-top:16px">
        <button class="btn-primary" onclick="saveTelegramSettings()">Save Settings</button>
        <button class="btn-outline" onclick="testTelegram()">Send Test Message</button>
      </div>
      <div id="settings-status" class="settings-status"></div>
      <div class="help-box">
        <strong>How to set this up:</strong><br/>
        1. In Telegram, message <code>@BotFather</code> → <code>/newbot</code> → copy the token it gives you.<br/>
        2. Message your new bot once (anything), then open <code>https://api.telegram.org/bot&lt;TOKEN&gt;/getUpdates</code> in a browser — your Chat ID is the <code>chat.id</code> field. For a group, add the bot to the group first.<br/>
        3. Paste both above, hit Save, then Send Test Message.
      </div>
    </div>

    <div class="settings-card">
      <h3>🌐 Network Discovery Default</h3>
      <div class="desc">Used as the default subnet when scanning for printers.</div>
      <div class="field"><label>Default Subnet (CIDR)</label><input id="s-subnet" placeholder="192.168.18.0/24" value="\${esc(n.scanSubnet||'')}"/></div>
      <button class="btn-primary" onclick="saveNetworkSettings()">Save</button>
    </div>

    <div class="settings-card">
      <h3>💾 Backup & Restore System Configuration</h3>
      <div class="desc">Ekspor seluruh konfigurasi PrintServer (printers, users, settings, groups) ke file JSON atau pulihkan dari file backup.</div>
      <div style="display:flex;gap:12px;margin-top:16px;flex-wrap:wrap;align-items:center;">
        <button class="btn-primary" onclick="exportSystemBackup()" style="display:inline-flex;align-items:center;gap:6px;">
          📥 Download Export Backup (.json)
        </button>
        <label class="btn-outline" style="cursor:pointer;display:inline-flex;align-items:center;gap:6px;margin:0;padding:8px 14px;border-radius:8px;font-weight:600;font-size:.85rem;">
          📤 Import Restore (.json)
          <input type="file" id="backup-file-input" accept=".json" style="display:none" onchange="importSystemBackup(this)"/>
        </label>
      </div>
      <div id="backup-status" class="settings-status"></div>
    </div>
  \`;
}

async function renderUsersView() {
  document.getElementById('view-title').textContent='Users';
  document.getElementById('view-sub').textContent='Manage admin & user accounts';
  document.getElementById('content').innerHTML='<div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span></div>';
  let users=[];
  try { users = (await fetch('/api/users').then(x=>x.json())).users||[]; } catch {}
  let printers=[];
  try { printers = (await fetch('/api/printers').then(x=>x.json())).data||[]; } catch {}
  const printerName = id => {
    const found = printers.find(p => String(p.id) === String(id) || String(p.name) === String(id));
    return found ? (found.name + (found.brand ? ' (' + found.brand + ')' : '')) : ('#' + id);
  };

  const rows = users.map(u => {
    const isUserRole = u.role === 'user';
    const accessText = u.role === 'admin'
      ? '<span class="chip" style="background:rgba(148,163,184,.12);color:var(--subtle);border:1px solid rgba(148,163,184,.2)">Semua Printer (Admin)</span>'
      : (Array.isArray(u.printerAccess) && u.printerAccess.length
          ? '<div style="display:flex;flex-wrap:wrap;gap:4px;max-width:260px;align-items:center">' +
              u.printerAccess.map(id => '<span class="chip" style="background:rgba(59,130,246,.15);color:#60a5fa;border:1px solid rgba(59,130,246,.3);padding:2px 8px;border-radius:6px;font-size:0.75rem;font-weight:500;">' + esc(printerName(id)) + '</span>').join('') +
            '</div>'
          : '<span class="chip" style="background:rgba(16,185,129,.15);color:#34d399;border:1px solid rgba(16,185,129,.3)">Semua Printer</span>');

    const notifs = u.notifications || { printSuccess: true, scanSuccess: true, printFailed: true, scanFailed: true };
    const notifBadges = '<div style="display:flex;flex-wrap:nowrap;gap:4px;align-items:center;white-space:nowrap;">' +
      '<span class="chip" style="font-size:0.7rem;padding:2px 6px;border-radius:4px;background:' + (notifs.printSuccess ? 'rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.1);color:#f87171;border:1px solid rgba(239,68,68,0.2)') + '">🖨️' + (notifs.printSuccess ? '✓' : '✕') + '</span>' +
      '<span class="chip" style="font-size:0.7rem;padding:2px 6px;border-radius:4px;background:' + (notifs.printFailed ? 'rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3)' : 'rgba(148,163,184,0.1);color:#94a3b8;border:1px solid rgba(148,163,184,0.2)') + '">🖨️' + (notifs.printFailed ? '✓' : '✕') + '</span>' +
      '<span class="chip" style="font-size:0.7rem;padding:2px 6px;border-radius:4px;background:' + (notifs.scanSuccess ? 'rgba(59,130,246,0.15);color:#60a5fa;border:1px solid rgba(59,130,246,0.3)' : 'rgba(239,68,68,0.1);color:#f87171;border:1px solid rgba(239,68,68,0.2)') + '">📷' + (notifs.scanSuccess ? '✓' : '✕') + '</span>' +
      '<span class="chip" style="font-size:0.7rem;padding:2px 6px;border-radius:4px;background:' + (notifs.scanFailed ? 'rgba(245,158,11,0.15);color:#fbbf24;border:1px solid rgba(245,158,11,0.3)' : 'rgba(148,163,184,0.1);color:#94a3b8;border:1px solid rgba(148,163,184,0.2)') + '">📷' + (notifs.scanFailed ? '✓' : '✕') + '</span>' +
    '</div>';

    return '<tr style="border-bottom:1px solid rgba(255,255,255,0.06);">' +
      '<td style="vertical-align:middle;font-weight:700;color:#f8fafc;padding:12px 14px;white-space:nowrap;">' + esc(u.username) + '</td>' +
      '<td style="vertical-align:middle;padding:12px 14px;white-space:nowrap;"><span class="chip" style="background:' + (u.role==='admin'?'rgba(59,130,246,.18);color:#60a5fa;border:1px solid rgba(59,130,246,.35)':'rgba(148,163,184,.15);color:#cbd5e1;border:1px solid rgba(148,163,184,.25)') + '">' + esc(u.role) + '</span></td>' +
      '<td style="vertical-align:middle;padding:12px 14px;white-space:nowrap;font-size:0.85rem;color:#cbd5e1;">' + esc(u.phone || '-') + '</td>' +
      '<td style="vertical-align:middle;padding:12px 14px;">' + accessText + '</td>' +
      '<td style="vertical-align:middle;padding:12px 14px;white-space:nowrap;">' + notifBadges + '</td>' +
      '<td style="vertical-align:middle;padding:12px 14px;">' +
        '<div style="display:flex;gap:6px;flex-wrap:nowrap;align-items:center;">' +
          '<button class="btn-outline btn-sm" style="padding:5px 10px;font-size:0.78rem;border-radius:6px;white-space:nowrap;display:inline-flex;align-items:center;gap:4px;" onclick="resetUserPassword(\\\'' + escJs(u.username) + '\\\')">🔑 Reset</button>' +
          '<button class="btn-outline btn-sm" style="padding:5px 10px;font-size:0.78rem;border-radius:6px;white-space:nowrap;display:inline-flex;align-items:center;gap:4px;" onclick="openEditUserModal(\\\'' + escJs(u.username) + '\\\')">⚙️ Edit</button>' +
          '<button class="btn-outline btn-sm" style="padding:5px 10px;font-size:0.78rem;border-radius:6px;white-space:nowrap;display:inline-flex;align-items:center;gap:4px;" onclick="toggleUserRole(\\\'' + escJs(u.username) + '\\\',\\\'' + (u.role==='admin'?'user':'admin') + '\\\')">' + (u.role==='admin'?'👤 Make User':'🛡️ Make Admin') + '</button>' +
          '<button class="btn-danger btn-sm" style="padding:5px 10px;font-size:0.78rem;border-radius:6px;white-space:nowrap;display:inline-flex;align-items:center;gap:4px;" onclick="deleteUser(\\\'' + escJs(u.username) + '\\\')">🗑️ Hapus</button>' +
        '</div>' +
      '</td>' +
    '</tr>';
  }).join('');

  const printerCheckboxes = printers.length ? (
    '<div style="max-height:140px;overflow-y:auto;border:1px solid var(--border);padding:10px;border-radius:8px;background:rgba(0,0,0,0.2);margin-top:6px;display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:6px">' +
      printers.map(p =>
        '<label style="display:flex;align-items:center;gap:8px;font-weight:400;margin:0;cursor:pointer;font-size:0.84rem;color:#e2e8f0;background:rgba(255,255,255,0.03);padding:6px 10px;border-radius:6px;border:1px solid rgba(255,255,255,0.05)">' +
          '<input type="checkbox" class="nu-printer-cb" value="' + esc(p.id) + '" style="width:15px;height:15px;flex-shrink:0;margin:0;accent-color:var(--blue)"/>' +
          '<span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + esc(p.name) + ' <span style="color:var(--muted);font-size:.75rem">(' + esc(p.brand||'Generic') + ')</span></span>' +
        '</label>'
      ).join('') +
    '</div>'
  ) : '<div style="color:var(--muted);font-size:0.85rem;margin-top:6px">No printers configured yet</div>';

  document.getElementById('content').innerHTML =
    '<div class="settings-card" style="max-width:100%;margin-bottom:24px">' +
      '<h3 style="margin-bottom:14px;font-size:1.1rem;display:flex;align-items:center;gap:8px">➕ Add New User</h3>' +
      '<div class="field-row" style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px">' +
        '<div class="field" style="flex:1;min-width:180px"><label>Username</label><input id="nu-username" placeholder="jdoe"/></div>' +
        '<div class="field" style="flex:1;min-width:180px"><label>Password</label><input id="nu-password" type="password" placeholder="••••••••"/></div>' +
        '<div class="field" style="flex:1;min-width:180px"><label>No. HP / Telegram Chat ID</label><input id="nu-phone" placeholder="081234567890 / Chat ID"/></div>' +
        '<div class="field" style="width:180px"><label>Role</label>' +
          '<select id="nu-role" onchange="onUserRoleChange(this.value)"><option value="user">User (Print + Scans only)</option><option value="admin">Admin (Full access)</option></select>' +
        '</div>' +
      '</div>' +
      '<div class="field" style="margin-bottom:14px">' +
        '<label style="display:block;margin-bottom:6px;font-weight:600">📲 Notifikasi Alert Telegram <span style="color:var(--muted);font-weight:400">— centang notifikasi yang ingin diterima user</span></label>' +
        '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;background:rgba(0,0,0,0.2);padding:10px;border-radius:8px;border:1px solid var(--border)">' +
          '<label style="display:flex;align-items:center;gap:8px;font-size:0.84rem;cursor:pointer;color:#e2e8f0;background:rgba(255,255,255,0.03);padding:6px 10px;border-radius:6px;border:1px solid rgba(255,255,255,0.05)"><input type="checkbox" id="nu-n-print-succ" checked style="accent-color:#22c55e"/> 🖨️ Print Success</label>' +
          '<label style="display:flex;align-items:center;gap:8px;font-size:0.84rem;cursor:pointer;color:#e2e8f0;background:rgba(255,255,255,0.03);padding:6px 10px;border-radius:6px;border:1px solid rgba(255,255,255,0.05)"><input type="checkbox" id="nu-n-print-fail" checked style="accent-color:#ef4444"/> 🖨️ Print Failed</label>' +
          '<label style="display:flex;align-items:center;gap:8px;font-size:0.84rem;cursor:pointer;color:#e2e8f0;background:rgba(255,255,255,0.03);padding:6px 10px;border-radius:6px;border:1px solid rgba(255,255,255,0.05)"><input type="checkbox" id="nu-n-scan-succ" checked style="accent-color:#3b82f6"/> 📷 Scan Success</label>' +
          '<label style="display:flex;align-items:center;gap:8px;font-size:0.84rem;cursor:pointer;color:#e2e8f0;background:rgba(255,255,255,0.03);padding:6px 10px;border-radius:6px;border:1px solid rgba(255,255,255,0.05)"><input type="checkbox" id="nu-n-scan-fail" checked style="accent-color:#f59e0b"/> 📷 Scan Failed</label>' +
        '</div>' +
      '</div>' +
      '<div class="field" id="nu-printer-access" style="margin-bottom:16px">' +
        '<label style="display:block;margin-bottom:4px;font-weight:600">Restrict to printer(s) <span style="color:var(--muted);font-weight:400">— leave all unchecked to allow every printer</span></label>' +
        printerCheckboxes +
      '</div>' +
      '<button class="btn-primary" onclick="addUser()" style="padding:8px 20px;font-size:0.9rem;border-radius:8px">Create User</button>' +
      '<div id="users-status" class="settings-status"></div>' +
    '</div>' +
    '<div class="settings-card" style="max-width:100%">' +
      '<h3 style="margin-bottom:16px;font-size:1.1rem;display:flex;align-items:center;gap:8px">👥 Existing Users</h3>' +
      '<div style="overflow-x:auto">' +
        '<table class="data-table" style="width:100%;border-collapse:separate;border-spacing:0">' +
          '<thead>' +
            '<tr style="background:rgba(255,255,255,0.03)">' +
              '<th style="padding:12px 14px;border-bottom:1px solid var(--border)">USERNAME</th>' +
              '<th style="padding:12px 14px;border-bottom:1px solid var(--border)">ROLE</th>' +
              '<th style="padding:12px 14px;border-bottom:1px solid var(--border)">NO. HP / CHAT ID</th>' +
              '<th style="padding:12px 14px;border-bottom:1px solid var(--border)">PRINTER ACCESS</th>' +
              '<th style="padding:12px 14px;border-bottom:1px solid var(--border)">NOTIF TELEGRAM</th>' +
              '<th style="padding:12px 14px;border-bottom:1px solid var(--border)">ACTIONS</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>' + (rows || '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px;">No users found</td></tr>') + '</tbody>' +
        '</table>' +
      '</div>' +
    '</div>';
}

async function renderQRView() {
  document.getElementById('view-title').textContent = 'Mobile QR';
  document.getElementById('view-sub').textContent = 'Generate QR codes for mobile printing';
  
  if (window.USER_ROLE !== 'admin') {
    const uname = esc(window.USERNAME || 'user');
    document.getElementById('content').innerHTML = 
      '<div class="settings-card">'
      + '<h3>📱 Mobile QR Code — ' + uname + '</h3>'
      + '<p style="color:var(--subtle);font-size:.85rem;margin-bottom:16px;">Scan QR Code ini menggunakan HP Anda untuk login otomatis & mencetak dokumen langsung dari HP.</p>'
      + '<button class="btn-primary" style="display:inline-flex;align-items:center;gap:8px;padding:10px 18px;border-radius:10px;" onclick="generateQR(&quot;' + uname + '&quot;)">📱 Generate QR Code Saya</button>'
      + '</div>';
    return;
  }

  document.getElementById('content').innerHTML = '<div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span></div>';
  let users = [];
  try { users = (await fetch('/api/users').then(x => x.json())).users || []; } catch {}

  const userCards = users.map(u => {
    const uname = esc(u.username);
    const roleStyle = u.role==='admin' ? 'rgba(59,130,246,.15);color:var(--blue)' : 'rgba(148,163,184,.15);color:var(--subtle)';
    return '<div style="background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px 20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;">'
      + '<div style="flex:1;min-width:140px;">'
      + '<div style="font-weight:700;color:#f1f5f9;font-size:1rem;">' + uname + '</div>'
      + '<div style="margin-top:4px;"><span class="chip" style="background:' + roleStyle + ';">' + esc(u.role) + '</span></div>'
      + '</div>'
      + '<div style="display:flex;gap:8px;flex-wrap:wrap;">'
      + '<button class="btn-primary" style="display:flex;align-items:center;gap:6px;padding:10px 16px;border-radius:10px;font-size:.88rem;white-space:nowrap;" onclick="generateQR(&quot;' + uname + '&quot;, false)">' 
      + '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h.01M18 14h.01M14 18h.01M18 18h.01M21 14v4M14 21h4"/></svg>'
      + ' Tampilkan QR'
      + '</button>'
      + '<button class="btn-danger btn-sm" style="display:flex;align-items:center;gap:6px;padding:10px 14px;border-radius:10px;font-size:.85rem;white-space:nowrap;" onclick="revokeQR(&quot;' + uname + '&quot;)">'
      + '❌ Revoke Token'
      + '</button>'
      + '</div>'
      + '</div>';
  }).join('');

  document.getElementById('content').innerHTML =
    '<div class="settings-card">'
    + '<h3>\u{1F4F1} Mobile QR Code per User</h3>'
    + '<div style="font-size:.85rem;color:var(--muted);margin-bottom:16px;">'
    + 'Klik <strong>Generate QR</strong> pada user yang ingin bisa print dari HP.<br>'
    + 'Scan QR dengan HP \u2192 otomatis login \u2192 pilih dokumen \u2192 print sesuai hak akses. '
    + 'QR valid selama <strong>30 hari</strong>.'
    + '</div>'
    + '<div style="display:flex;flex-direction:column;gap:10px;">'
    + (userCards || '<div style="color:var(--muted);padding:16px;">No users found</div>')
    + '</div>'
    + '</div>';
}

async function generateQR(username, rotate = false) {
  try {
    const r = await fetch('/api/mobile/token', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username, rotate })
    });
    const d = await r.json();
    if (!d.ok) { alert('Failed to get token: ' + (d.error||'Unknown error')); return; }

    const serverIp = d.serverIp || location.hostname;
    let host = location.host;
    if ((location.hostname === 'localhost' || location.hostname === '127.0.0.1') && serverIp && serverIp !== 'localhost') {
      const port = location.port ? ':' + location.port : '';
      host = serverIp + port;
    }
    const link = location.protocol + '//' + host + '/mobile?t=' + d.token;
    const qrApi = '/api/mobile/qr-image?data=' + encodeURIComponent(link);
    const ipNotice = (location.hostname === 'localhost' || location.hostname === '127.0.0.1')
      ? '<div style="font-size:.72rem;color:#34d399;background:rgba(52,211,153,.1);border:1px solid rgba(52,211,153,.25);border-radius:8px;padding:6px 10px;margin-bottom:12px;text-align:left;">💡 <strong>IP LAN Otomatis:</strong> QR link menggunakan IP Server (<strong>' + esc(serverIp) + '</strong>) agar dapat di-scan langsung oleh HP di Wi-Fi.</div>'
      : '';

    closeQRModal();

    const overlay = document.createElement('div');
    overlay.id = 'qr-modal-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center;padding:20px;';
    overlay.innerHTML = 
      '<div style="background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;max-width:380px;width:100%;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,0.5);">'
      + '<h3 style="margin:0 0 6px;color:#f1f5f9;font-size:1.1rem;">📱 Mobile QR Code</h3>'
      + '<div style="font-size:.82rem;color:var(--subtle);margin-bottom:12px;">User: <strong style="color:var(--blue);">' + esc(username) + '</strong> (Valid 30 Days)</div>'
      + ipNotice
      + '<div style="background:#fff;padding:12px;border-radius:12px;display:inline-block;margin-bottom:16px;">'
      + '<img src="' + qrApi + '" alt="QR Code (Local)" style="width:200px;height:200px;display:block;margin:0 auto;" />'
      + '</div>'
      + '<div style="margin-bottom:16px;">'
      + '<input type="text" readonly value="' + esc(link) + '" id="qr-modal-link" style="width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:8px 10px;color:#f1f5f9;font-size:.75rem;text-align:center;margin-bottom:8px;" />'
      + '<button class="btn-primary btn-sm" style="width:100%;padding:8px;margin-bottom:8px;" onclick="copyQRModalLink()">📋 Copy Mobile Link</button>'
      + '<button class="btn-outline btn-sm" style="width:100%;padding:8px;color:#f87171;border-color:rgba(239,68,68,0.3);" onclick="if(confirm(&quot;Buat QR Token baru untuk ' + escJs(username) + '? Token QR lama akan langsung tidak berlaku.&quot;)) generateQR(&quot;' + escJs(username) + '&quot;, true)">🔄 Regenerate / Rotasi QR</button>'
      + '</div>'
      + '<button class="btn-outline btn-sm" style="width:100%;" onclick="closeQRModal()">Close</button>'
      + '</div>';
    document.body.appendChild(overlay);
    overlay.addEventListener('click', e => { if (e.target === overlay) closeQRModal(); });
  } catch(e) {
    alert('Error getting QR: ' + e.message);
  }
}
async function revokeQR(username) {
  if (!confirm('Cabut (Revoke) akses QR token untuk user "' + username + '"? Token QR dan semua sesi mobile aktif user ini akan dibatalkan.')) return;
  try {
    const r = await fetch('/api/mobile/token/' + encodeURIComponent(username), { method: 'DELETE' });
    const d = await r.json();
    if (d.ok) {
      alert('Token QR untuk ' + username + ' berhasil dicabut.');
      renderQRView();
    } else {
      alert('Gagal mencabut token: ' + (d.error || 'Unknown error'));
    }
  } catch(e) {
    alert('Error: ' + e.message);
  }
}
function closeQRModal() {
  const o = document.getElementById('qr-modal-overlay');
  if (o) o.remove();
}
function copyQRModalLink() {
  const el = document.getElementById('qr-modal-link');
  if (el) {
    el.select();
    navigator.clipboard.writeText(el.value).then(() => alert('Link copied to clipboard!'))
      .catch(() => { document.execCommand('copy'); alert('Link copied!'); });
  }
}

// ── Shared Documents View ─────────────────────────────────────────────────────
async function renderSharedDocsView() {
  document.getElementById('view-title').textContent = 'Shared Documents';
  document.getElementById('view-sub').textContent = 'Dokumen bersama untuk mobile print';
  document.getElementById('content').innerHTML =
    '<div class="settings-card" style="max-width:100%">'
    + '<h3>📁 Shared Documents</h3>'
    + '<div style="font-size:.85rem;color:var(--muted);margin-bottom:14px;">'
    + 'Upload dokumen di sini agar bisa dipilih dan dicetak oleh mobile user melalui QR link mereka.<br>'
    + 'Format yang didukung: PDF, DOCX, DOC, TXT, JPG, PNG (maks 50MB).'
    + '</div>'
    + '<div id="shared-docs-section"></div>'
    + '</div>';
  renderSharedDocsSection();
}

// ── Shared Docs management ─────────────────────────────────────────────────────
async function renderSharedDocsSection() {
  const container = document.getElementById('shared-docs-section');
  if (!container) return;
  container.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)"><span class="spin"></span></div>';
  try {
    const [docsRes, targetsRes, histRes] = await Promise.all([
      fetch('/api/shared-docs').then(r => r.json()).catch(() => ({ docs: [] })),
      fetch('/api/shared-docs/targets').then(r => r.json()).catch(() => ({ targets: [] })),
      fetch('/api/shared-docs/history').then(r => r.json()).catch(() => ({ history: [] }))
    ]);

    const docs = docsRes.docs || [];
    const targets = targetsRes.targets || [];
    const history = histRes.history || [];

    const rows = docs.length
      ? docs.map(doc => {
          const isPub = doc.targetUser === 'all';
          const targetBadge = isPub 
            ? '<span class="badge-green">🌐 Semua User</span>' 
            : '<span class="badge-amber">🔒 ' + esc(doc.targetUser) + '</span>';
          return '<tr>' +
            '<td style="font-weight:600;color:#f1f5f9">' + esc(doc.name) + '</td>' +
            '<td style="color:var(--muted);font-size:.8rem">' + esc(doc.uploader || 'admin') + '</td>' +
            '<td style="font-size:.8rem">' + targetBadge + '</td>' +
            '<td style="color:var(--muted);font-size:.8rem">' + fmtSize(doc.size) + '</td>' +
            '<td style="color:var(--muted);font-size:.8rem">' + new Date(doc.uploadTime || doc.mtime).toLocaleString() + '</td>' +
            '<td style="display:flex;gap:4px;">' +
              '<a href="/api/shared-docs/download/' + encodeURIComponent(doc.name) + '" class="btn-outline btn-sm" download title="Download">⬇</a>' +
              '<button class="btn-danger btn-sm" onclick="deleteSharedDoc(\\\'' + escJs(doc.name) + '\\\')" title="Hapus">✕</button>' +
            '</td>' +
          '</tr>';
        }).join('')
      : '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:20px">Belum ada dokumen bersama</td></tr>';

    const targetOptions = '<option value="all">🌐 Semua User (Publik)</option>' +
      targets.map(u => '<option value="' + esc(u.username) + '">🔒 ' + esc(u.username) + ' (' + esc(u.role) + ')</option>').join('');

    const histRows = history.length
      ? history.slice(0, 50).map(h => {
          const actionColors = { UPLOAD: '#10b981', DOWNLOAD: '#3b82f6', PRINT: '#8b5cf6', DELETE: '#ef4444' };
          const color = actionColors[h.action] || '#94a3b8';
          return '<tr>' +
            '<td style="color:var(--muted);font-size:.78rem">' + new Date(h.timestamp).toLocaleString() + '</td>' +
            '<td><span style="font-size:.72rem;font-weight:700;color:' + color + ';background:rgba(255,255,255,0.05);padding:2px 6px;border-radius:4px;">' + esc(h.action) + '</span></td>' +
            '<td style="font-weight:600;font-size:.8rem;color:#f1f5f9">' + esc(h.user) + '</td>' +
            '<td style="font-size:.8rem;color:#cbd5e1">' + esc(h.filename) + '</td>' +
            '<td style="font-size:.78rem;color:var(--muted)">' + esc(h.targetUser) + '</td>' +
            '<td style="font-size:.75rem;color:var(--subtle)">' + esc(h.details || '') + '</td>' +
          '</tr>';
        }).join('')
      : '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:14px">Belum ada riwayat aktivitas</td></tr>';

    container.innerHTML =
      '<div style="margin-bottom:20px;background:rgba(15,23,42,0.4);border:1px solid var(--border);border-radius:12px;padding:12px;overflow-x:auto;">' +
        '<table class="data-table" style="width:100%;border-collapse:separate;border-spacing:0;">' +
          '<thead><tr style="background:rgba(255,255,255,0.03)"><th style="padding:10px 12px">Nama File</th><th style="padding:10px 12px">Pengirim</th><th style="padding:10px 12px">Target Penerima</th><th style="padding:10px 12px">Ukuran</th><th style="padding:10px 12px">Waktu Upload</th><th style="padding:10px 12px">Aksi</th></tr></thead>' +
          '<tbody>' + rows + '</tbody>' +
        '</table>' +
        '<div style="margin-top:14px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
          '<input type="file" id="shared-doc-file" accept=".pdf,.doc,.docx,.dot,.dotx,.docm,.rtf,.odt,.txt,.jpg,.jpeg,.png,.xls,.xlsx,.ppt,.pptx" style="flex:1;min-width:200px;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:6px;color:#f1f5f9;font-size:.82rem"/>' +
          '<select id="shared-doc-target" style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:6px 10px;color:#f1f5f9;font-size:.82rem">' +
            targetOptions +
          '</select>' +
          '<button class="btn-primary btn-sm" onclick="uploadSharedDoc()">⬆ Upload Dokumen</button>' +
        '</div>' +
        '<div id="shared-doc-status" style="margin-top:6px;font-size:.78rem"></div>' +
      '</div>' +

      '<h4 style="margin:20px 0 10px;color:#f1f5f9;font-size:1rem;display:flex;align-items:center;gap:8px;">📜 Riwayat Aktivitas Shared Documents</h4>' +
      '<div style="overflow-x:auto;background:rgba(15,23,42,0.4);border:1px solid var(--border);border-radius:12px;padding:12px;">' +
        '<table class="data-table" style="width:100%;font-size:.8rem;border-collapse:separate;border-spacing:0;">' +
          '<thead><tr style="background:rgba(255,255,255,0.03)"><th style="padding:10px 12px">Waktu</th><th style="padding:10px 12px">Aktivitas</th><th style="padding:10px 12px">Pengguna</th><th style="padding:10px 12px">Nama Dokumen</th><th style="padding:10px 12px">Target</th><th style="padding:10px 12px">Detail</th></tr></thead>' +
          '<tbody>' + histRows + '</tbody>' +
        '</table>' +
      '</div>';
  } catch {
    container.innerHTML = '<div style="color:var(--muted);padding:10px">Gagal memuat dokumen bersama</div>';
  }
}

async function uploadSharedDoc() {
  const fileInput = document.getElementById('shared-doc-file');
  const targetSel = document.getElementById('shared-doc-target');
  if (!fileInput || !fileInput.files.length) return;
  const fd = new FormData();
  fd.append('file', fileInput.files[0]);
  if (targetSel) fd.append('targetUser', targetSel.value);
  const statusEl = document.getElementById('shared-doc-status');
  if (statusEl) { statusEl.style.color = 'var(--muted)'; statusEl.textContent = 'Uploading…'; }
  try {
    const r = await fetch('/api/shared-docs', { method:'POST', body: fd });
    const d = await r.json();
    if (d.ok) { 
      if (statusEl) { statusEl.style.color='var(--green,#22c55e)'; statusEl.textContent='✅ Berhasil diunggah untuk ' + d.targetUser + ': ' + d.name; } 
      renderSharedDocsSection(); 
    }
    else { if (statusEl) { statusEl.style.color='var(--red,#ef4444)'; statusEl.textContent = '❌ ' + (d.error||'Gagal mengunggah'); } }
  } catch(e) { if (statusEl) { statusEl.style.color='var(--red,#ef4444)'; statusEl.textContent = '❌ ' + e.message; } }
}

async function deleteSharedDoc(name) {
  if (!confirm('Hapus dokumen bersama: ' + name + '?')) return;
  await fetch('/api/shared-docs/'+encodeURIComponent(name), {method:'DELETE'});
  renderSharedDocsSection();
}

function onUserRoleChange(val) {
  const el = document.getElementById('nu-printer-access');
  if (el) el.style.display = (val === 'user') ? 'block' : 'none';
}

async function addUser() {
  const usernameInput = document.getElementById('nu-username');
  const passwordInput = document.getElementById('nu-password');
  const phoneInput = document.getElementById('nu-phone');
  const username = usernameInput ? usernameInput.value.trim() : '';
  const password = passwordInput ? passwordInput.value : '';
  const phone = phoneInput ? phoneInput.value.trim() : '';
  const role = document.getElementById('nu-role') ? document.getElementById('nu-role').value : 'user';
  const printerAccess = Array.from(document.querySelectorAll('.nu-printer-cb:checked')).map(cb => cb.value);

  const printSuccess = document.getElementById('nu-n-print-succ') ? document.getElementById('nu-n-print-succ').checked : true;
  const printFailed = document.getElementById('nu-n-print-fail') ? document.getElementById('nu-n-print-fail').checked : true;
  const scanSuccess = document.getElementById('nu-n-scan-succ') ? document.getElementById('nu-n-scan-succ').checked : true;
  const scanFailed = document.getElementById('nu-n-scan-fail') ? document.getElementById('nu-n-scan-fail').checked : true;
  const notifications = { printSuccess, scanSuccess, printFailed, scanFailed };

  if (!username || !password) {
    showUsersStatus('Username and password required', 'err');
    showPrintErrorModal({ title: 'Failed', message: 'Username dan Password wajib diisi!' });
    return;
  }

  try {
    const r = await fetch('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, role, printerAccess, phone, notifications })
    });
    const d = await r.json();

    if (d.ok) {
      if (usernameInput) usernameInput.value = '';
      if (passwordInput) passwordInput.value = '';
      if (phoneInput) phoneInput.value = '';
      await renderUsersView();
      showUsersStatus('✅ User created', 'ok');
      showPrintSuccessModal({
        title: 'Berhasil',
        message: 'Akun user <strong>' + esc(username) + '</strong> berhasil dibuat &amp; ditambahkan ke daftar Existing Users!'
      });
    } else {
      showUsersStatus('❌ ' + (d.error || 'Failed'), 'err');
      showPrintErrorModal({
        title: 'Gagal',
        message: 'Gagal membuat user: ' + (d.error || 'Username sudah ada atau data tidak valid.')
      });
    }
  } catch(e) {
    showUsersStatus('❌ ' + e.message, 'err');
    showPrintErrorModal({ title: 'Failed', message: e.message });
  }
}

async function openEditUserModal(username) {
  let users = [];
  try { users = (await fetch('/api/users').then(x => x.json())).users || []; } catch {}
  const target = users.find(u => u.username === username);
  if (!target) return alert('User tidak ditemukan!');

  let printers = [];
  try { printers = (await fetch('/api/printers').then(x => x.json())).data || []; } catch {}

  const currentAccess = new Set(target.printerAccess || []);
  const notifs = target.notifications || { printSuccess: true, scanSuccess: true, printFailed: true, scanFailed: true };

  const old = document.getElementById('edit-user-modal');
  if (old) old.remove();

  const modal = document.createElement('div');
  modal.id = 'edit-user-modal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);backdrop-filter:blur(6px);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;';

  const printerCBs = printers.map(p => {
    const checked = currentAccess.has(String(p.id)) || currentAccess.has(String(p.name)) ? 'checked' : '';
    return '<label style="display:flex;align-items:center;gap:8px;font-size:0.84rem;color:#e2e8f0;background:rgba(255,255,255,0.03);padding:6px 10px;border-radius:6px;border:1px solid rgba(255,255,255,0.05);cursor:pointer;">' +
      '<input type="checkbox" class="eu-printer-cb" value="' + esc(p.id) + '" ' + checked + ' style="width:15px;height:15px;accent-color:var(--blue);"/>' +
      '<span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + esc(p.name) + '</span>' +
    '</label>';
  }).join('') || '<div style="color:var(--muted);font-size:0.85rem;">Tidak ada printer terkonfigurasi</div>';

  modal.innerHTML =
    '<div style="background:#1e293b;color:#f8fafc;border-radius:16px;width:100%;max-width:520px;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);border:1px solid var(--border);overflow:hidden;font-family:system-ui,sans-serif;">' +
      '<div style="padding:18px 24px;border-bottom:1px solid rgba(255,255,255,0.1);display:flex;justify-content:space-between;align-items:center;">' +
        '<h3 style="margin:0;font-size:1.1rem;display:flex;align-items:center;gap:8px;">⚙️ Edit User — ' + esc(username) + '</h3>' +
        '<button onclick="closeEditUserModal()" style="background:none;border:none;color:var(--muted);font-size:1.4rem;cursor:pointer;">✕</button>' +
      '</div>' +
      '<div style="padding:20px 24px;max-height:75vh;overflow-y:auto;">' +
        '<div style="margin-bottom:14px;">' +
          '<label style="display:block;font-size:0.85rem;font-weight:600;margin-bottom:6px;color:#cbd5e1;">No. HP / Telegram Chat ID</label>' +
          '<input id="eu-phone" value="' + esc(target.phone || '') + '" placeholder="081234567890 atau Chat ID" style="width:100%;padding:10px;border-radius:8px;background:rgba(0,0,0,0.25);border:1px solid var(--border);color:#fff;font-size:0.9rem;"/>' +
        '</div>' +

        '<div style="margin-bottom:16px;">' +
          '<label style="display:block;font-size:0.85rem;font-weight:600;margin-bottom:6px;color:#cbd5e1;">📲 Notifikasi Alert Telegram</label>' +
          '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;background:rgba(0,0,0,0.2);padding:10px;border-radius:8px;border:1px solid var(--border);">' +
            '<label style="display:flex;align-items:center;gap:8px;font-size:0.84rem;color:#e2e8f0;cursor:pointer;"><input type="checkbox" id="eu-n-print-succ" ' + (notifs.printSuccess !== false ? 'checked' : '') + ' style="accent-color:#22c55e;"/> 🖨️ Print Success</label>' +
            '<label style="display:flex;align-items:center;gap:8px;font-size:0.84rem;color:#e2e8f0;cursor:pointer;"><input type="checkbox" id="eu-n-print-fail" ' + (notifs.printFailed !== false ? 'checked' : '') + ' style="accent-color:#ef4444;"/> 🖨️ Print Failed</label>' +
            '<label style="display:flex;align-items:center;gap:8px;font-size:0.84rem;color:#e2e8f0;cursor:pointer;"><input type="checkbox" id="eu-n-scan-succ" ' + (notifs.scanSuccess !== false ? 'checked' : '') + ' style="accent-color:#3b82f6;"/> 📷 Scan Success</label>' +
            '<label style="display:flex;align-items:center;gap:8px;font-size:0.84rem;color:#e2e8f0;cursor:pointer;"><input type="checkbox" id="eu-n-scan-fail" ' + (notifs.scanFailed !== false ? 'checked' : '') + ' style="accent-color:#f59e0b;"/> 📷 Scan Failed</label>' +
          '</div>' +
        '</div>' +

        (target.role === 'user' ? (
          '<div style="margin-bottom:16px;">' +
            '<label style="display:block;font-size:0.85rem;font-weight:600;margin-bottom:6px;color:#cbd5e1;">Akses Printer <span style="font-weight:400;color:var(--muted);">(Kosongkan semua jika boleh akses semua printer)</span></label>' +
            '<div style="max-height:120px;overflow-y:auto;background:rgba(0,0,0,0.2);padding:10px;border-radius:8px;border:1px solid var(--border);display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:6px;">' +
              printerCBs +
            '</div>' +
          '</div>'
        ) : '') +
      '</div>' +
      '<div style="padding:16px 24px;border-top:1px solid rgba(255,255,255,0.1);display:flex;justify-content:flex-end;gap:10px;background:rgba(0,0,0,0.15);">' +
        '<button onclick="closeEditUserModal()" style="padding:8px 16px;border-radius:8px;background:transparent;color:var(--subtle);border:1px solid var(--border);cursor:pointer;">Batal</button>' +
        '<button onclick="saveUserEdit(\\\'' + escJs(username) + '\\\')" style="padding:8px 20px;border-radius:8px;background:var(--blue);color:#fff;border:none;font-weight:600;cursor:pointer;">Simpan Perubahan</button>' +
      '</div>' +
    '</div>';

  document.body.appendChild(modal);
}

function closeEditUserModal() {
  const m = document.getElementById('edit-user-modal');
  if (m) m.remove();
}

async function saveUserEdit(username) {
  const phone = (document.getElementById('eu-phone') ? document.getElementById('eu-phone').value : '').trim();
  const printSuccess = document.getElementById('eu-n-print-succ') ? document.getElementById('eu-n-print-succ').checked : true;
  const printFailed = document.getElementById('eu-n-print-fail') ? document.getElementById('eu-n-print-fail').checked : true;
  const scanSuccess = document.getElementById('eu-n-scan-succ') ? document.getElementById('eu-n-scan-succ').checked : true;
  const scanFailed = document.getElementById('eu-n-scan-fail') ? document.getElementById('eu-n-scan-fail').checked : true;
  const printerAccess = Array.from(document.querySelectorAll('.eu-printer-cb:checked')).map(cb => cb.value);

  const notifications = { printSuccess, scanSuccess, printFailed, scanFailed };

  try {
    const r = await fetch('/api/users/' + encodeURIComponent(username), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone, notifications, printerAccess })
    });
    const d = await r.json();
    if (d.ok) {
      closeEditUserModal();
      await renderUsersView();
      showUsersStatus('✅ User ' + username + ' berhasil diperbarui', 'ok');
      showPrintSuccessModal({
        title: 'Berhasil',
        message: 'Perubahan akun user <strong>' + esc(username) + '</strong> berhasil disimpan!'
      });
    } else {
      showUsersStatus('❌ ' + (d.error || 'Failed'), 'err');
      showPrintErrorModal({
        title: 'Gagal',
        message: 'Gagal memperbarui user: ' + (d.error || 'Unknown error')
      });
    }
  } catch (e) {
    showUsersStatus('❌ ' + e.message, 'err');
    showPrintErrorModal({
      title: 'Gagal',
      message: e.message
    });
  }
}

async function toggleUserRole(username, newRole) {
  await fetch('/api/users/'+encodeURIComponent(username), {method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({role:newRole})});
  renderUsersView();
}

async function editUserPrinterAccess(username) {
  let printers=[];
  try { printers = (await fetch('/api/printers').then(x=>x.json())).data||[]; } catch {}
  if (!printers.length) { alert('No printers configured yet.'); return; }
  const list = printers.map((p,i)=>\`\${i+1}. \${p.name}\`).join('\\\\n');
  const input = prompt('Enter comma-separated numbers of printers this user may access:\\\\n'+list+'\\\\n\\\\n(Leave blank to allow ALL printers)');
  if (input === null) return;
  const nums = input.trim() ? input.split(',').map(s=>parseInt(s.trim(),10)).filter(n=>!isNaN(n)&&n>=1&&n<=printers.length) : [];
  const printerAccess = nums.map(n=>printers[n-1].id);
  const r = await fetch('/api/users/'+encodeURIComponent(username), {method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({printerAccess})});
  const d = await r.json();
  if (d.ok) { showUsersStatus('✅ Printer access updated','ok'); renderUsersView(); }
  else showUsersStatus('❌ '+(d.error||'Failed'),'err');
}

async function resetUserPassword(username) {
  const pw = prompt('New password for '+username+':');
  if (!pw) return;
  const r = await fetch('/api/users/'+encodeURIComponent(username), {method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  const d = await r.json();
  showUsersStatus(d.ok?'✅ Password updated':'❌ '+(d.error||'Failed'), d.ok?'ok':'err');
}

async function deleteUser(username) {
  if (!confirm('Delete user '+username+'?')) return;
  const r = await fetch('/api/users/'+encodeURIComponent(username), {method:'DELETE'});
  const d = await r.json();
  if (d.ok) renderUsersView(); else showUsersStatus('❌ '+(d.error||'Failed'),'err');
}

function showUsersStatus(msg, type) {
  const el = document.getElementById('users-status');
  if (el) {
    el.style.display = '';
    el.className = 'settings-status ' + (type === 'ok' ? 'print-status ok' : 'print-status err');
    el.textContent = msg;
  }
  showToast(msg);
}

function showSettingsStatus(msg,type) {
  const el=document.getElementById('settings-status');
  el.style.display=''; el.className='settings-status '+(type==='ok'?'print-status ok':'print-status err'); el.textContent=msg;
}

async function saveTelegramSettings() {
  const body={telegram:{
    enabled:document.getElementById('s-enabled').checked,
    botToken:document.getElementById('s-token').value.trim(),
    chatId:document.getElementById('s-chatid').value.trim(),
    tonerThreshold:Number(document.getElementById('s-threshold').value)||20,
    cooldownMinutes:Number(document.getElementById('s-cooldown').value)||240,
    alertToner:document.getElementById('s-toner').checked,
    alertOffline:document.getElementById('s-offline').checked,
    alertJams:document.getElementById('s-jams').checked,
    alertTrayEmpty:document.getElementById('s-tray').checked,
    alertPrintSuccess:document.getElementById('s-print-succ').checked,
    alertPrintFailed:document.getElementById('s-print-fail').checked,
    alertScanSuccess:document.getElementById('s-scan-succ').checked,
    alertScanFailed:document.getElementById('s-scan-fail').checked,
  }};
  try {
    const r=await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json().catch(()=>({}));
    if (r.ok && d.ok!==false) { showSettingsStatus('✅ Settings saved','ok'); showToast('✅ Settings tersimpan'); }
    else { showSettingsStatus('❌ Failed to save: '+(d.error||r.status),'err'); showToast('❌ Gagal menyimpan: '+(d.error||r.status)); }
  } catch(e) { showSettingsStatus('❌ '+e.message,'err'); showToast('❌ '+e.message); }
}

async function saveNetworkSettings() {
  const body={network:{scanSubnet:document.getElementById('s-subnet').value.trim()}};
  const r=await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json().catch(()=>({}));
  if (r.ok && d.ok!==false) { showSettingsStatus('✅ Network settings saved','ok'); showToast('✅ Default subnet tersimpan'); }
  else { showSettingsStatus('❌ '+(d.error||'Failed to save'),'err'); showToast('❌ Gagal menyimpan'); }
}

async function testTelegram() {
  const botToken=document.getElementById('s-token').value.trim();
  const chatId=document.getElementById('s-chatid').value.trim();
  if (!botToken||!chatId) return showSettingsStatus('⚠ Enter bot token and chat ID first','err');
  showSettingsStatus('Sending…','ok');
  try {
    const r=await fetch('/api/settings/test-telegram',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({botToken,chatId})});
    const d=await r.json();
    if (d.ok) showSettingsStatus('✅ Test message sent — check Telegram','ok');
    else showSettingsStatus('❌ '+(d.error||'Failed'),'err');
  } catch(e) { showSettingsStatus('❌ '+e.message,'err'); }
}

function exportSystemBackup() {
  window.location.href = '/api/backup/export';
  showToast('📥 Mengunduh backup konfigurasi PrintServer...');
}

async function importSystemBackup(input) {
  const file = input.files && input.files[0];
  if (!file) return;
  if (!confirm('Apakah Anda yakin ingin memulihkan (restore) konfigurasi dari file "' + file.name + '"?\\n\\nSemua printer, user, dan settings yang ada akan ditimpa dengan isi file backup ini.')) {
    input.value = '';
    return;
  }
  const statusDiv = document.getElementById('backup-status');
  if (statusDiv) { statusDiv.className = 'settings-status'; statusDiv.textContent = '⏳ Memproses restore konfigurasi...'; }
  try {
    const text = await file.text();
    const backupJson = JSON.parse(text);
    const r = await fetch('/api/backup/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(backupJson)
    });
    const d = await r.json();
    if (r.ok && d.ok) {
      if (statusDiv) { statusDiv.className = 'settings-status ok'; statusDiv.textContent = '✅ ' + d.message; }
      showToast('✅ Konfigurasi berhasil dipulihkan!');
      setTimeout(() => { location.reload(); }, 1500);
    } else {
      if (statusDiv) { statusDiv.className = 'settings-status err'; statusDiv.textContent = '❌ ' + (d.error || 'Gagal memulihkan backup'); }
      showToast('❌ Gagal memulihkan backup');
    }
  } catch(e) {
    if (statusDiv) { statusDiv.className = 'settings-status err'; statusDiv.textContent = '❌ Format file JSON tidak valid: ' + e.message; }
    showToast('❌ Error: ' + e.message);
  } finally {
    input.value = '';
  }
}

// ── Groups view ───────────────────────────────────────────────────────────────
function toggleGrpChip(el) {
  el.classList.toggle('selected');
}

function filterGroupCards(query) {
  const q = (query || '').toLowerCase().trim();
  const cards = document.querySelectorAll('.grp-card');
  cards.forEach(c => {
    const name = c.getAttribute('data-grp-name') || '';
    if (!q || name.includes(q)) {
      c.style.display = 'flex';
    } else {
      c.style.display = 'none';
    }
  });
}

async function renderGroupsView() {
  document.getElementById('view-title').textContent = 'Grouping';
  document.getElementById('view-sub').textContent = 'Organise users and printers into named groups';
  document.getElementById('content').innerHTML = '<div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span></div>';

  let groups=[], users=[], snmpPrinters=[], cupsPrintersList=[];
  try {
    const [gRes, uRes, pRes, cRes] = await Promise.all([
      fetch('/api/groups').then(x=>x.json()).catch(()=>({})),
      fetch('/api/users').then(x=>x.json()).catch(()=>({})),
      fetch('/api/printers').then(x=>x.json()).catch(()=>({})),
      fetch('/api/cups/printers/detail').then(x=>x.json()).catch(()=>({})),
    ]);
    groups = gRes.groups || [];
    users = uRes.users || [];
    snmpPrinters = pRes.data || [];
    cupsPrintersList = cRes.printers || [];
  } catch {}

  const allPrinters = [];
  const seenNames = new Set();
  snmpPrinters.forEach(p => {
    allPrinters.push({ id: String(p.id), name: p.name, desc: p.ip ? 'SNMP (' + p.ip + ')' : 'SNMP' });
    seenNames.add(p.name.toLowerCase());
  });
  cupsPrintersList.forEach(p => {
    if (!seenNames.has(p.name.toLowerCase())) {
      allPrinters.push({ id: p.name, name: p.name, desc: 'CUPS' });
      seenNames.add(p.name.toLowerCase());
    }
  });

  // Calculate statistics
  const totalGroups = groups.length;
  const uniqueUsers = new Set();
  const uniquePrinters = new Set();
  groups.forEach(g => {
    (g.users||[]).forEach(u => uniqueUsers.add(u));
    (g.printers||[]).forEach(p => uniquePrinters.add(String(p).toLowerCase()));
  });

  // Store global references for modal & chip actions
  window._grpData = { users, printers: allPrinters, groups };

  // Generate User chips for Create form
  const createUserChips = users.length ? users.map(u =>
    '<div class="grp-chip-item user-chip-item" data-val="' + esc(u.username) + '" onclick="toggleGrpChip(this)">'
    + '<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>'
    + '<span>' + esc(u.username) + '</span>'
    + '<span class="chip-badge">' + esc(u.role) + '</span>'
    + '</div>'
  ).join('') : '<div style="color:var(--muted);font-size:.8rem">Tidak ada user</div>';

  // Generate Printer chips for Create form
  const createPrinterChips = allPrinters.length ? allPrinters.map(p =>
    '<div class="grp-chip-item printer-chip-item" data-val="' + esc(p.id) + '" onclick="toggleGrpChip(this)">'
    + '<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/></svg>'
    + '<span>' + esc(p.name) + '</span>'
    + '<span class="chip-badge">' + esc(p.desc) + '</span>'
    + '</div>'
  ).join('') : '<div style="color:var(--muted);font-size:.8rem">Tidak ada printer</div>';

  // Build Group Cards
  const groupCards = groups.length ? groups.map(g => {
    const userBadges = (g.users||[]).length ? (g.users||[]).map(u => {
      const uObj = users.find(x => x.username === u);
      const role = uObj ? uObj.role : 'user';
      return '<span class="grp-member-pill user-pill"><svg width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg> ' + esc(u) + ' <small>(' + esc(role) + ')</small></span>';
    }).join('') : '<span style="color:var(--muted);font-size:.78rem">Belum ada user assigned</span>';

    const printerBadges = (g.printers||[]).length ? (g.printers||[]).map(pid => {
      const pObj = allPrinters.find(p => String(p.id).toLowerCase() === String(pid).toLowerCase());
      const pName = pObj ? pObj.name : pid;
      const pDesc = pObj ? pObj.desc : 'Printer';
      return '<span class="grp-member-pill printer-pill"><svg width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/></svg> ' + esc(pName) + ' <small>(' + esc(pDesc) + ')</small></span>';
    }).join('') : '<span style="color:var(--muted);font-size:.78rem">Belum ada printer assigned</span>';

    return '<div class="grp-card" data-grp-name="' + esc(g.name).toLowerCase() + '" data-grp-id="' + g.id + '">'
      + '<div class="grp-card-header">'
        + '<div class="grp-card-title">'
          + '<div class="grp-icon"><svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="7" width="8" height="8" rx="1"/><rect x="14" y="7" width="8" height="8" rx="1"/><line x1="6" y1="3" x2="6" y2="7"/><line x1="18" y1="3" x2="18" y2="7"/><line x1="6" y1="15" x2="6" y2="21"/><line x1="18" y1="15" x2="18" y2="21"/></svg></div>'
          + '<div><h4>' + esc(g.name) + '</h4><div class="grp-meta">' + (g.users||[]).length + ' User &bull; ' + (g.printers||[]).length + ' Printer</div></div>'
        + '</div>'
        + '<div class="grp-card-actions">'
          + '<button class="btn-action edit" onclick="openEditGroup(\\\'' + g.id + '\\\')" title="Edit Group">'
          + '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg> Edit</button>'
          + '<button class="btn-action delete" onclick="deleteGroup(\\\'' + g.id + '\\\')" title="Hapus Group">'
          + '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg> Delete</button>'
        + '</div>'
      + '</div>'
      + '<div class="grp-card-body">'
        + '<div class="grp-section">'
          + '<div class="grp-section-label"><svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg> Anggota User (' + (g.users||[]).length + ')</div>'
          + '<div class="grp-pills-wrap">' + userBadges + '</div>'
        + '</div>'
        + '<div class="grp-section" style="margin-top:12px">'
          + '<div class="grp-section-label"><svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/></svg> Access Printer (' + (g.printers||[]).length + ')</div>'
          + '<div class="grp-pills-wrap">' + printerBadges + '</div>'
        + '</div>'
      + '</div>'
    + '</div>';
  }).join('') : '<div class="grp-empty-state"><div class="grp-empty-icon">&#x1F4C1;</div><h4>Belum Ada Grouping</h4><p>Buat grup baru di bawah untuk mengelompokkan pengguna dan memberikan hak akses ke printer tertentu.</p></div>';

  document.getElementById('content').innerHTML =
    '<!-- Stats Header Cards -->'
    + '<div class="grp-stats-grid">'
      + '<div class="grp-stat-card"><div class="grp-stat-icon blue"><svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="7" width="8" height="8" rx="1"/><rect x="14" y="7" width="8" height="8" rx="1"/><line x1="6" y1="3" x2="6" y2="7"/><line x1="18" y1="3" x2="18" y2="7"/><line x1="6" y1="15" x2="6" y2="21"/><line x1="18" y1="15" x2="18" y2="21"/></svg></div><div><div class="grp-stat-num">' + totalGroups + '</div><div class="grp-stat-label">Total Grouping</div></div></div>'
      + '<div class="grp-stat-card"><div class="grp-stat-icon purple"><svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div><div><div class="grp-stat-num">' + uniqueUsers.size + '</div><div class="grp-stat-label">User Ter-grouping</div></div></div>'
      + '<div class="grp-stat-card"><div class="grp-stat-icon green"><svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/></svg></div><div><div class="grp-stat-num">' + uniquePrinters.size + '</div><div class="grp-stat-label">Printer Ter-assign</div></div></div>'
    + '</div>'
    + '<div class="settings-card grp-form-card">'
      + '<div class="grp-form-header">'
        + '<div class="grp-icon"><svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg></div>'
        + '<div><h3>Tambah Grouping Baru</h3><div class="desc">Kelompokkan user dan tentukan akses printer secara instan</div></div>'
      + '</div>'
      + '<div class="field" style="margin-top:14px"><label>Nama Grouping</label><input id="grp-name" placeholder="Contoh: IT Support, Finance, HRD, Operational" /></div>'
      + '<div class="field-row" style="margin-top:14px">'
        + '<div class="field"><label>Pilih User <span style="color:var(--muted);font-weight:400">(klik untuk memilih)</span></label><div class="grp-chip-container" id="grp-create-users-chips">' + createUserChips + '</div></div>'
        + '<div class="field"><label>Pilih Printer Access <span style="color:var(--muted);font-weight:400">(klik untuk memilih)</span></label><div class="grp-chip-container" id="grp-create-printers-chips">' + createPrinterChips + '</div></div>'
      + '</div>'
      + '<div style="margin-top:16px;display:flex;align-items:center;gap:12px"><button class="btn-primary" onclick="createGroup()"><svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Simpan Grouping Baru</button><div id="grp-status" class="settings-status" style="margin-top:0"></div></div>'
    + '</div>'
    + '<div class="grp-list-header">'
      + '<div class="grp-list-title"><h3>Daftar Grouping Terdaftar (' + groups.length + ')</h3><div class="desc">Daftar grup beserta user &amp; printer yang diberi hak akses</div></div>'
      + '<div class="grp-search-box"><svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg><input type="text" id="grp-search-input" placeholder="Cari nama grup..." oninput="filterGroupCards(this.value)" /></div>'
    + '</div>'
    + '<div class="group-card-grid" id="grp-cards-container">' + groupCards + '</div>';

  // Mount edit modal on body so it always overlays correctly
  let existingModal = document.getElementById('grp-edit-modal');
  if (!existingModal) {
    const modalEl = document.createElement('div');
    modalEl.id = 'grp-edit-modal';
    modalEl.addEventListener('click', function(e){ if(e.target===this) closeEditGroup(); });
    modalEl.innerHTML =
      '<div class="grp-modal-card">'
      + '<div class="grp-modal-header">'
        + '<div style="display:flex;align-items:center;gap:10px">'
          + '<div class="grp-icon"><svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></div>'
          + '<h3 style="margin:0">Edit Grouping</h3>'
        + '</div>'
        + '<button class="grp-modal-close" onclick="closeEditGroup()" title="Tutup">&times;</button>'
      + '</div>'
      + '<input type="hidden" id="edit-grp-id" />'
      + '<div class="field" style="margin-top:18px">'
        + '<label style="font-size:.78rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em">Nama Grouping</label>'
        + '<input id="edit-grp-name" placeholder="Contoh: Finance, IT Support, HRD..." style="margin-top:6px" />'
      + '</div>'
      + '<div class="grp-modal-field-row">'
        + '<div class="field">'
          + '<label style="font-size:.78rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;display:flex;align-items:center;gap:6px">'
            + '<svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg> Pilih User'
          + '</label>'
          + '<div class="grp-chip-container" id="grp-edit-users-chips" style="margin-top:8px"></div>'
        + '</div>'
        + '<div class="field">'
          + '<label style="font-size:.78rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;display:flex;align-items:center;gap:6px">'
            + '<svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/></svg> Pilih Printer Access'
          + '</label>'
          + '<div class="grp-chip-container" id="grp-edit-printers-chips" style="margin-top:8px"></div>'
        + '</div>'
      + '</div>'
      + '<div style="display:flex;gap:10px;margin-top:24px;justify-content:flex-end;padding-top:16px;border-top:1px solid var(--border)">'
        + '<button class="btn-outline" onclick="closeEditGroup()" style="min-width:80px">Batal</button>'
        + '<button class="btn-primary" onclick="saveEditGroup()" style="min-width:140px">'
          + '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg> Simpan Perubahan'
        + '</button>'
      + '</div>'
      + '<div id="grp-edit-status" class="settings-status" style="margin-top:10px"></div>'
      + '</div>';
    document.body.appendChild(modalEl);
  }
}

function showGrpStatus(msg, type, id='grp-status') {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.className = 'settings-status ' + (type === 'ok' ? 'ok-msg' : 'err-msg');
  el.style.display = 'block';
  setTimeout(() => { if (el) el.style.display = 'none'; }, 3500);
}

async function createGroup() {
  const name = document.getElementById('grp-name').value.trim();
  const usersSel = [...document.querySelectorAll('#grp-create-users-chips .grp-chip-item.selected')].map(el => el.getAttribute('data-val'));
  const printSel = [...document.querySelectorAll('#grp-create-printers-chips .grp-chip-item.selected')].map(el => el.getAttribute('data-val'));
  
  if (!name) return showGrpStatus('⚠️ Nama grup wajib diisi','err');
  try {
    const r = await fetch('/api/groups', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ name, users: usersSel, printers: printSel })
    });
    const d = await r.json();
    if (d.ok) {
      showGrpStatus('✅ Grouping berhasil dibuat','ok');
      renderGroupsView();
    } else {
      showGrpStatus('❌ ' + (d.error || 'Gagal membuat grup'), 'err');
    }
  } catch(e) {
    showGrpStatus('❌ ' + e.message, 'err');
  }
}

function openEditGroup(gid) {
  if (!window._grpData || !window._grpData.groups) {
    renderGroupsView().then(() => openEditGroup(gid));
    return;
  }
  const g = (window._grpData.groups || []).find(x => String(x.id) === String(gid));
  if (!g) return;

  document.getElementById('edit-grp-id').value = g.id;
  document.getElementById('edit-grp-name').value = g.name;

  const users = window._grpData.users || [];
  const printers = window._grpData.printers || [];

  const editUserChips = users.map(u => {
    const isSel = (g.users || []).includes(u.username);
    return '<div class="grp-chip-item user-chip-item ' + (isSel ? 'selected' : '') + '" data-val="' + esc(u.username) + '" onclick="toggleGrpChip(this)">'
      + '<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>'
      + '<span>' + esc(u.username) + '</span>'
      + '<span class="chip-badge">' + esc(u.role) + '</span>'
      + '</div>';
  }).join('');

  const editPrinterChips = printers.map(p => {
    const isSel = (g.printers || []).some(pid => String(pid).toLowerCase() === String(p.id).toLowerCase());
    return '<div class="grp-chip-item printer-chip-item ' + (isSel ? 'selected' : '') + '" data-val="' + esc(p.id) + '" onclick="toggleGrpChip(this)">'
      + '<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/></svg>'
      + '<span>' + esc(p.name) + '</span>'
      + '<span class="chip-badge">' + esc(p.desc) + '</span>'
      + '</div>';
  }).join('');

  document.getElementById('grp-edit-users-chips').innerHTML = editUserChips;
  document.getElementById('grp-edit-printers-chips').innerHTML = editPrinterChips;

  const modal = document.getElementById('grp-edit-modal');
  modal.style.display = 'flex';
}

function closeEditGroup() {
  const modal = document.getElementById('grp-edit-modal');
  if (modal) modal.style.display = 'none';
}

async function saveEditGroup() {
  const id = document.getElementById('edit-grp-id').value;
  const name = document.getElementById('edit-grp-name').value.trim();
  const usersSel = [...document.querySelectorAll('#grp-edit-users-chips .grp-chip-item.selected')].map(el => el.getAttribute('data-val'));
  const printSel = [...document.querySelectorAll('#grp-edit-printers-chips .grp-chip-item.selected')].map(el => el.getAttribute('data-val'));

  if (!name) return showGrpStatus('⚠️ Nama grup wajib diisi', 'err', 'grp-edit-status');
  try {
    const r = await fetch('/api/groups/' + encodeURIComponent(id), {
      method: 'PUT',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ name, users: usersSel, printers: printSel })
    });
    const d = await r.json();
    if (d.ok) {
      closeEditGroup();
      renderGroupsView();
    } else {
      showGrpStatus('❌ ' + (d.error || 'Gagal menyimpan perubahan'), 'err', 'grp-edit-status');
    }
  } catch(e) {
    showGrpStatus('❌ ' + e.message, 'err', 'grp-edit-status');
  }
}

async function deleteGroup(gid) {
  if (!confirm('Apakah Anda yakin ingin menghapus grouping ini?')) return;
  try {
    await fetch('/api/groups/' + encodeURIComponent(gid), { method: 'DELETE' });
    renderGroupsView();
  } catch {}
}

// ── Alerts view ───────────────────────────────────────────────────────────────
async function renderAlertsView() {
  document.getElementById('view-title').textContent='Alerts';
  document.getElementById('view-sub').textContent='Active alerts across all printers';
  document.getElementById('content').innerHTML='<div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span></div>';
  let printers=state.data||[];
  if (!printers.length) {
    try { printers=(await fetch('/api/printers').then(x=>x.json())).data||[]; } catch {}
  }
  let html='';
  printers.forEach(p=>{
    (p.alerts||[]).forEach(a=>{
      html+='<div class="alert-item ' + a.severity + '" style="margin-bottom:8px">'
        + '<span>' + (a.severity==='Critical'?'\uD83D\uDD34':a.severity==='Warning'?'\uD83D\DFE1':'\u2139\uFE0F') + '</span>'
        + '<div><strong>' + esc(p.name) + '</strong> &middot; ' + esc(a.desc) + '</div>'
        + '</div>';
    });
  });
  if (!html) html='<div class="no-data" style="padding:60px 20px;text-align:center"><span class="ok-icon">✅</span>No active alerts</div>';
  document.getElementById('content').innerHTML=html;
}

// ── Supplies view ─────────────────────────────────────────────────────────────
async function renderSuppliesView() {
  document.getElementById('view-title').textContent='Supplies';
  document.getElementById('view-sub').textContent='Toner & ink — all printers';
  document.getElementById('content').innerHTML='<div style="text-align:center;padding:40px;color:var(--muted)"><span class="spin"></span></div>';
  // Use live state data if available, otherwise fetch fresh
  let printers=state.data||[];
  if (!printers.length) {
    try { printers=(await fetch('/api/printers').then(x=>x.json())).data||[]; } catch {}
  }
  const html='<div class="printer-grid">'+printers.map(p=>
    '<div class="pcard ' + (p.online?'':'offline') + '">'
    + '<div class="pcard-header">'
    + '<div><div class="pcard-name">&#x1F5A8; ' + esc(p.name) + '</div><div class="pcard-model">' + esc(p.model||p.ip) + '</div></div>'
    + '<span class="badge ' + (p.online?'idle':'offline') + '"><span class="dot ' + (p.online?'on':'off') + '"></span>' + (p.status||'Offline') + '</span>'
    + '</div>'
    + '<div class="pcard-body">' + tonerPanel(p) + '</div>'
    + '</div>'
  ).join('')+'</div>';
  document.getElementById('content').innerHTML=html;
}

// ── Print helpers ─────────────────────────────────────────────────────────────
let printFiles = {};

function dzDrag(e,id){ e.preventDefault(); document.getElementById('dz-'+id).classList.add('drag'); }
function dzLeave(id){ document.getElementById('dz-'+id).classList.remove('drag'); }
function dzDrop(e,id){ e.preventDefault(); dzLeave(id); if(e.dataTransfer.files[0]) dzFile(id,e.dataTransfer.files[0]); }

// ── PDF Preview & Paper Estimator Helper Logic ─────────────────────────────────
let pdfPreviewState = {
  main: { doc: null, pageNum: 1, totalPages: 0, scale: 1.0, rotate: 0, fileType: null }
};

function dzFile(id, f) {
  if (!f) return;
  printFiles[id] = f;
  const labelEl = document.getElementById('dz-label-' + id);
  if (labelEl) labelEl.textContent = '📎 ' + f.name + ' (' + fmtSize(f.size) + ')';

  const emptyEl = document.getElementById('preview-empty-' + id);
  const canvasEl = document.getElementById('pdf-canvas-' + id);
  const imgEl = document.getElementById('img-preview-' + id);
  const officeEl = document.getElementById('preview-office-' + id);

  if (emptyEl) emptyEl.style.display = 'none';

  const ext = f.name.slice(((f.name.lastIndexOf('.') - 1) >>> 0) + 2).toLowerCase();
  const isPdf = f.type === 'application/pdf' || ext === 'pdf';
  const isImg = f.type.startsWith('image/') || ['jpg', 'jpeg', 'png', 'webp', 'bmp'].includes(ext);

  if (isPdf) {
    if (imgEl) imgEl.style.display = 'none';
    if (officeEl) officeEl.style.display = 'none';
    if (canvasEl) canvasEl.style.display = 'block';

    const reader = new FileReader();
    reader.onload = function(e) {
      const typedarray = new Uint8Array(e.target.result);
      if (typeof pdfjsLib === 'undefined') {
        showToast('⚠️ PDF.js library belum dimuat', 'err');
        return;
      }
      pdfjsLib.getDocument({ data: typedarray }).promise.then(pdf => {
        pdfPreviewState[id] = { doc: pdf, pageNum: 1, totalPages: pdf.numPages, scale: 1.0, rotate: 0, fileType: 'pdf' };
        renderPdfPage(id);
        updatePaperSummary(id);
      }).catch(err => {
        console.error('Failed to load PDF preview:', err);
        if (canvasEl) canvasEl.style.display = 'none';
        if (officeEl) {
          officeEl.style.display = 'block';
          document.getElementById('office-file-name-' + id).textContent = f.name;
        }
      });
    };
    reader.readAsArrayBuffer(f);
  } else if (isImg) {
    if (canvasEl) canvasEl.style.display = 'none';
    if (officeEl) officeEl.style.display = 'none';
    if (imgEl) {
      const reader = new FileReader();
      reader.onload = function(e) {
        imgEl.src = e.target.result;
        imgEl.style.display = 'block';
      };
      reader.readAsDataURL(f);
    }
    pdfPreviewState[id] = { doc: null, pageNum: 1, totalPages: 1, scale: 1.0, rotate: 0, fileType: 'img' };
    updatePaperSummary(id);
  } else {
    if (canvasEl) canvasEl.style.display = 'none';
    if (imgEl) imgEl.style.display = 'none';
    if (officeEl) {
      officeEl.style.display = 'block';
      const fileNameEl = document.getElementById('office-file-name-' + id);
      if (fileNameEl) fileNameEl.textContent = '📄 ' + f.name;
    }
    pdfPreviewState[id] = { doc: null, pageNum: 1, totalPages: 1, scale: 1.0, rotate: 0, fileType: 'doc' };
    updatePaperSummary(id);
  }
}

function renderPdfPage(id) {
  const st = pdfPreviewState[id];
  if (!st || !st.doc) return;

  st.doc.getPage(st.pageNum).then(page => {
    const canvas = document.getElementById('pdf-canvas-' + id);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const viewport = page.getViewport({ scale: st.scale, rotation: st.rotate });

    canvas.height = viewport.height;
    canvas.width = viewport.width;

    const renderContext = {
      canvasContext: ctx,
      viewport: viewport
    };
    page.render(renderContext);

    // Update page indicator
    const indicator = document.getElementById('page-indicator-' + id);
    if (indicator) indicator.textContent = st.pageNum + ' / ' + st.totalPages;

    // Update button states
    const btnPrev = document.getElementById('btn-prev-' + id);
    const btnNext = document.getElementById('btn-next-' + id);
    if (btnPrev) btnPrev.disabled = (st.pageNum <= 1);
    if (btnNext) btnNext.disabled = (st.pageNum >= st.totalPages);
  });
}

function changePdfPage(id, delta) {
  const st = pdfPreviewState[id];
  if (!st || !st.doc) return;
  const newPage = st.pageNum + delta;
  if (newPage >= 1 && newPage <= st.totalPages) {
    st.pageNum = newPage;
    renderPdfPage(id);
  }
}

function zoomPdfCanvas(id, delta) {
  const st = pdfPreviewState[id];
  if (!st || !st.doc) return;
  const newScale = Math.min(Math.max(st.scale + delta, 0.4), 2.5);
  st.scale = newScale;
  renderPdfPage(id);
}

function rotatePdfCanvas(id) {
  const st = pdfPreviewState[id];
  if (!st || !st.doc) return;
  st.rotate = (st.rotate + 90) % 360;
  renderPdfPage(id);
}

function updatePaperSummary(id) {
  const st = pdfPreviewState[id] || { totalPages: 0 };
  const pages = st.totalPages || 0;

  const copiesInput = document.getElementById('po-copies-' + id);
  const duplexInput = document.getElementById('po-duplex-' + id);

  const copies = parseInt(copiesInput?.value || '1') || 1;
  const isDuplex = duplexInput?.value && duplexInput.value !== 'none';

  const sheetsPerCopy = isDuplex ? Math.ceil(pages / 2) : pages;
  const totalSheets = sheetsPerCopy * copies;

  const sumPagesEl = document.getElementById('sum-pages-' + id);
  const sumCopiesEl = document.getElementById('sum-copies-' + id);
  const sumSheetsEl = document.getElementById('sum-sheets-' + id);
  const sumWarnEl = document.getElementById('sum-warning-' + id);

  if (sumPagesEl) sumPagesEl.textContent = pages ? pages + ' Halaman' : '0 Halaman';
  if (sumCopiesEl) sumCopiesEl.textContent = copies + 'x';
  if (sumSheetsEl) sumSheetsEl.textContent = totalSheets ? totalSheets + ' Lembar' : '0 Lembar';

  if (sumWarnEl) {
    if (totalSheets > 20) {
      sumWarnEl.innerHTML = '<div class="warning-badge">⚠️ Perhatian: Cetakan ini membutuhkan <strong>' + totalSheets + ' lembar</strong> kertas.</div>';
    } else {
      sumWarnEl.innerHTML = '';
    }
  }
}


async function populatePrinterSelects() {
  await loadCupsPrinters();
  const printers = cupsDetail.printers || [];
  const def = cupsDetail.defaultPrinter;
  const sorted = [...printers].sort((a,b) => {
    const aOn = !a.state.toLowerCase().includes('disabled');
    const bOn = !b.state.toLowerCase().includes('disabled');
    if (aOn !== bOn) return aOn ? -1 : 1;
    if (a.name === def) return -1;
    if (b.name === def) return 1;
    return a.name.localeCompare(b.name);
  });

  const defaultVal = sorted.find(p => !p.state.toLowerCase().includes('disabled'))?.name || def || (sorted[0]?.name || '');

  document.querySelectorAll('[id^="po-printer-"]').forEach(sel => {
    const currentVal = sel.value;
    sel.innerHTML = sorted.length
      ? sorted.map(p => {
          const isOff = p.state.toLowerCase().includes('disabled');
          const statusLabel = isOff ? '🔴 (Offline)' : '🟢 (Online)';
          const isDef = p.name === def ? ' ★ Default' : '';
          return '<option value="'+esc(p.name)+'">'+statusLabel+' '+esc(p.name)+isDef+'</option>';
        }).join('') + '<option value="">-- manual entry --</option>'
      : '<option value="">No CUPS printers found</option>';

    if (currentVal && Array.from(sel.options).some(o => o.value === currentVal)) {
      sel.value = currentVal;
    } else if (defaultVal) {
      sel.value = defaultVal;
    }
  });
}

let printPollTimers = {};

async function submitPrint(id) {
  const file=printFiles[id];
  const printer=document.getElementById('po-printer-'+id)?.value;
  const copies=document.getElementById('po-copies-'+id)?.value||'1';
  const duplex=document.getElementById('po-duplex-'+id)?.value||'none';
  const color=document.getElementById('po-color-'+id)?.value||'';
  if (!file) { showPrintStatus(id,'⚠ Please select a file first','err'); return; }
  if (!printer) { showPrintStatus(id,'⚠ Please select a printer','err'); return; }
  if (printPollTimers[id]) { clearInterval(printPollTimers[id]); delete printPollTimers[id]; }
  showPrintStatus(id,'<span class="spin"></span> Sending to printer…','ok');
  const fd=new FormData();
  fd.append('file',file); fd.append('printer',printer); fd.append('copies',copies); fd.append('duplex',duplex); fd.append('color',color);
  try {
    const r=await fetch('/api/print',{method:'POST',body:fd});
    const d=await r.json();
    if (d.ok) {
      printFiles[id]=null;
      document.getElementById('dz-label-'+id).textContent='Drop file here or click to browse';
      showPrintSuccessModal({
        title: 'Successfully',
        docName: file ? file.name : '',
        printerName: printer,
        jobId: d.jobId || 'queued'
      });
      if (d.jobId) trackPrintJob(id, d.jobId);
      else showPrintStatus(id,'✅ Sent to printer','ok');
    }
    else {
      showPrintStatus(id,'❌ Error: '+esc(d.error),'err');
      showPrintErrorModal({ title: 'Failed', message: d.error || 'Gagal mengirim dokumen ke printer.' });
    }
  } catch(e) {
    showPrintStatus(id,'❌ '+e.message,'err');
    showPrintErrorModal({ title: 'Failed', message: e.message });
  }
}

// Polls the job's status after submission so the user sees Queued → Printing → Completed
// without having to click over to the Print Jobs page.
function trackPrintJob(id, jobId) {
  let ticks=0;
  const poll = async () => {
    ticks++;
    try {
      const r=await fetch('/api/cups/jobs/'+encodeURIComponent(jobId)+'/status');
      const d=await r.json();
      if (d.status==='printing') showPrintStatus(id,'<span class="spin"></span> Printing… Job '+esc(jobId),'ok');
      else if (d.status==='queued') showPrintStatus(id,'<span class="spin"></span> Queued (job '+esc(jobId)+')','ok');
      else if (d.status==='completed') { showPrintStatus(id,'✅ Printed! Job '+esc(jobId),'ok'); stopTrackingPrintJob(id); }
      else { showPrintStatus(id,'✅ Sent! Job '+esc(jobId),'ok'); stopTrackingPrintJob(id); }
    } catch { /* keep polling silently on transient errors */ }
    if (ticks>=40) stopTrackingPrintJob(id); // stop after ~2 minutes
  };
  poll();
  printPollTimers[id]=setInterval(poll, 3000);
}
function stopTrackingPrintJob(id) {
  if (printPollTimers[id]) { clearInterval(printPollTimers[id]); delete printPollTimers[id]; }
}

function showPrintStatus(id,msg,type) {
  const el=document.getElementById('pstatus-'+id);
  if (!el) return;
  el.style.display=''; el.className='print-status '+type; el.innerHTML=msg;
}

// ── CRUD ──────────────────────────────────────────────────────────────────────
function openModal(id) {
  document.getElementById('modal-title').textContent=id?'Edit Printer':'Add Printer';
  document.getElementById('edit-id').value=id||'';
  if (id) {
    const p=state.data.find(x=>String(x.id)===String(id));
    if (p) { document.getElementById('f-name').value=p.name||''; document.getElementById('f-ip').value=p.ip||'';
      document.getElementById('f-brand').value=p.brand||'generic'; document.getElementById('f-community').value=p.community||'public';
      document.getElementById('f-location').value=p.location||''; }
    document.getElementById('f-autoprovision').checked=false;
  } else {
    ['f-name','f-ip','f-location'].forEach(id=>document.getElementById(id).value='');
    document.getElementById('f-brand').value='canon'; document.getElementById('f-community').value='public';
    document.getElementById('f-autoprovision').checked=true;
  }
  document.getElementById('modal-overlay').classList.add('open');
}
function closeModal(){ document.getElementById('modal-overlay').classList.remove('open'); }
document.getElementById('modal-overlay').addEventListener('click',e=>{if(e.target===e.currentTarget)closeModal();});

async function savePrinter() {
  const name=document.getElementById('f-name').value.trim(), ip=document.getElementById('f-ip').value.trim();
  if (!name||!ip) return alert('Name and IP are required');
  const body={name,ip,brand:document.getElementById('f-brand').value,community:document.getElementById('f-community').value.trim()||'public',location:document.getElementById('f-location').value.trim(),alertsEnabled:document.getElementById('f-alerts').checked,autoProvision:document.getElementById('f-autoprovision').checked};
  const editId=document.getElementById('edit-id').value;
  const r = await fetch(editId?'/api/printers/'+editId:'/api/printers',{method:editId?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d = await r.json().catch(()=>({}));
  closeModal(); await load(false);
  if (body.autoProvision && d.provision) {
    const {cups, scan} = d.provision;
    const lines = [];
    lines.push(cups.ok ? '✅ CUPS queue created (' + name + ')' : '❌ CUPS: ' + cups.error);
    lines.push(scan.ok ? '✅ SANE/airscan entry added' : '❌ SANE: ' + scan.error);
    if (!cups.ok || !scan.ok) alert(lines.join('\\\\n') + '\\\\n\\\\nNote: the CUPS/SANE queue name must exactly match "' + name + '" for Print/Scan filtering to work.');
  }
}

async function togglePrinterAlerts(id, enable) {
  await fetch('/api/printers/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({alertsEnabled:enable})});
  load();
}
async function delPrinter(id, name) {
  const pName = name || id;
  if (!confirm('Apakah Anda yakin ingin menghapus printer "' + pName + '"?')) return;
  try {
    const r = await fetch('/api/printers/' + encodeURIComponent(id), { method: 'DELETE' });
    const d = await r.json().catch(() => ({}));
    if (r.ok && d.ok !== false) {
      showToast('✅ Printer "' + pName + '" berhasil dihapus!');
      await load(false);
    } else {
      showToast('❌ Gagal menghapus printer: ' + (d.error || 'Terjadi kesalahan'));
    }
  } catch (err) {
    showToast('❌ Gagal menghapus printer: ' + err.message);
  }
}
function editPrinter(id){ openModal(id); }

function fmtSize(b){ if(b<1024)return b+'B'; if(b<1024*1024)return Math.round(b/1024)+'KB'; return (b/1024/1024).toFixed(1)+'MB'; }
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function escJs(s){ return String(s||'').replace(/'/g,"\\'").replace(/"/g,'\\"'); }

applyRoleUI();
if (window.USER_ROLE!=='admin') { currentView='print'; }
load();
loadCupsPrinters();
// PWA service worker + install prompt
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(()=>{});
let _deferredInstall=null;
window.addEventListener('beforeinstallprompt',e=>{ e.preventDefault(); _deferredInstall=e; document.getElementById('pwa-install-btn').style.display='flex'; });
async function installPWA(){ if(!_deferredInstall)return; _deferredInstall.prompt(); const r=await _deferredInstall.userChoice; if(r.outcome==='accepted') document.getElementById('pwa-install-btn').style.display='none'; _deferredInstall=null; }
</script>
</body>
</html>`;

// ── PWA manifest + service worker ────────────────────────────────────────────
app.get('/manifest.json', (_req,res) => {
  res.json({
    name:'PrintServer', short_name:'PrintServer', start_url:'/',
    display:'standalone', background_color:'#0f172a', theme_color:'#1e293b',
    description:'Printer monitoring dashboard',
    icons:[
      {src:'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect width=%22100%22 height=%22100%22 rx=%2216%22 fill=%22%231e293b%22/><text y=%22.9em%22 font-size=%2280%22>🖨</text></svg>',sizes:'any',type:'image/svg+xml'}
    ]
  });
});
app.get('/sw.js', (_req,res) => {
  res.setHeader('Content-Type','application/javascript');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.send(`
const CACHE='printserver-v8';
self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(keys=>Promise.all(keys.map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',e=>{
  if(e.request.method!=='GET')return;
  const accept = e.request.headers.get('accept')||'';
  if(accept.includes('text/html') || e.request.url.includes('/api/')) {
    return;
  }
  e.respondWith(fetch(e.request).then(r=>{
    if (r.ok && r.status === 200) {
      const clone=r.clone();
      caches.open(CACHE).then(c=>c.put(e.request,clone));
    }
    return r;
  }).catch(()=>caches.match(e.request)));
});
  `);
});




app.listen(PORT, '0.0.0.0', () => {
  console.log('=======================================');
  console.log('  PrintServer v4 -> http://0.0.0.0:'+PORT);
  console.log('  Scan folder  -> '+SCAN_DIR);
  console.log('  Upload dir   -> '+UPLOAD_DIR);
  console.log('  Telegram     -> '+(SETTINGS.telegram.enabled?'enabled':'disabled (configure in Settings tab)'));
  console.log('=======================================');
});
