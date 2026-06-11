'use strict';
/*
 * ╔═══════════════════════════════════════════╗
 * ║  h0zelpanel — PM2 control panel           ║
 * ║  Made by ozitoyy001                          ║
 * ║  github.com/ozitoyy001                       ║
 * ║  MIT License                              ║
 * ╚═══════════════════════════════════════════╝
 */

// ─────────────────────────────────────────────
//  DÉPENDANCES
// ─────────────────────────────────────────────
const path    = require('path');
const express = require('express');
const session = require('express-session');
const crypto  = require('crypto');
const { execFile } = require('child_process');
const os = require('os');

// P3 — chemin .env relatif au fichier, pas hardcodé
require('dotenv').config({ path: path.join(__dirname, '.env') });

// ─────────────────────────────────────────────
//  VALIDATION DE LA CONFIG AU DÉMARRAGE
// ─────────────────────────────────────────────
const PASSWORD = process.env.PANEL_PASSWORD;
if (!PASSWORD || PASSWORD.length < 12) {
  console.error('[FATAL] PANEL_PASSWORD manquant ou trop court (12 car. min)');
  process.exit(1);
}

// P2 — validation du port
const PORT = parseInt(process.env.PANEL_PORT, 10) || 7777;
if (isNaN(PORT) || PORT < 1 || PORT > 65535) {
  console.error('[FATAL] PANEL_PORT invalide:', process.env.PANEL_PORT);
  process.exit(1);
}

// P12 — chemin pm2 configurable pour éviter ENOENT si PATH absent
const PM2_BIN = process.env.PM2_BIN || 'pm2';

// Trust proxy configurable (pour reverse proxy)
const TRUST_PROXY = process.env.TRUST_PROXY || false;
if (TRUST_PROXY) {
  app.set('trust proxy', TRUST_PROXY);
}

// ── Config utilisateur (.env) ──
const PANEL_NAME  = 'h0zelpanel';  // hardcodé (marque du projet)
const SERVER_NAME = process.env.SERVER_NAME || os.hostname();
const PANEL_USER  = process.env.PANEL_USER  || (() => { try { return os.userInfo().username; } catch(e){ return 'user'; } })();
const OS_NAME     = process.env.OS_NAME     || detectOsName();

// Détecte le nom de l'OS (PRETTY_NAME de /etc/os-release, sinon platform)
function detectOsName() {
  try {
    const txt = require('fs').readFileSync('/etc/os-release', 'utf8');
    const m = txt.match(/PRETTY_NAME="?([^"\n]+)"?/);
    if (m) return m[1];
  } catch (e) {}
  return os.type() + ' ' + os.release();
}

// Crédits / liens (configurables pour distribution)
const GITHUB_USER = 'ozitoyy001';
const GITHUB_REPO = 'https://github.com/ozitoyy001/h0zelpanel';
const APP_VERSION = '1.0.0';


// P1 — secret de session stable dérivé du mot de passe
//       (survit aux redémarrages, ne change que si le mdp change)
const SESSION_SECRET = crypto.createHash('sha256').update(PASSWORD).digest('hex');

// ─────────────────────────────────────────────
//  PERSISTANCE (data.json, écriture atomique)
// ─────────────────────────────────────────────
const fs = require('fs');
const DATA_FILE = path.join(__dirname, 'data.json');

function loadData() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch (e) { return { passwordHash: null, pinHash: null, ipWhitelist: [], bruteMax: 5, bruteWindowMin: 15, logins: [], audit: [] }; }
}
let saveTimer = null;
let dirty = false;

function saveData(d) {
  DATA = d; // mise à jour en mémoire
  dirty = true;
  scheduleSave();
  return true;
}

function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    if (!dirty) return;
    dirty = false;
    try {
      const tmp = DATA_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(DATA, null, 2));
      fs.renameSync(tmp, DATA_FILE);
      fs.chmodSync(DATA_FILE, 0o600); // restrict permissions
      return true;
    } catch (e) {
      console.error('[saveData]', e.message);
      return false;
    }
  }, 800); // throttled
}
let DATA = loadData();
// Compat : garantit les champs même sur un ancien data.json
DATA.pinHash       = DATA.pinHash       || null;
DATA.ipWhitelist   = DATA.ipWhitelist   || [];
DATA.bruteMax      = DATA.bruteMax      || 5;
DATA.bruteWindowMin= DATA.bruteWindowMin|| 15;
DATA.logins        = DATA.logins        || [];
DATA.audit         = DATA.audit         || [];

// Hachage scrypt (sel + clé) pour le mot de passe stocké
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const key  = crypto.scryptSync(pw, salt, 32).toString('hex');
  return salt + ':' + key;
}
function verifyPassword(pw, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, key] = stored.split(':');
  const test = crypto.scryptSync(pw, salt, 32).toString('hex');
  const a = Buffer.from(key, 'hex'), b = Buffer.from(test, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Vérifie un mot de passe : hash stocké si présent, sinon .env (compat)
function checkPassword(pw) {
  if (DATA.passwordHash) return verifyPassword(pw, DATA.passwordHash);
  return safeCompare(pw, PASSWORD);
}

// Journal d'audit (garde les 100 dernières entrées)
function audit(action, ip) {
  const clean = cleanIp(ip);
  DATA.audit.unshift({ action, ip: clean, at: Date.now() });
  DATA.audit = DATA.audit.slice(0, 100);
  saveData(DATA);
}
function logLogin(ip, ok) {
  const clean = cleanIp(ip);
  DATA.logins.unshift({ ip: clean, ok, at: Date.now() });
  DATA.logins = DATA.logins.slice(0, 50);
  saveData(DATA);
}

// ─────────────────────────────────────────────
//  APP EXPRESS
// ─────────────────────────────────────────────
const app = express();

// Trust proxy configurable (pour reverse proxy) — placé plus haut
// R1+R2 — headers sécurité (clickjacking, MIME sniffing, CSP basique)
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'");
  next();
});
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(express.json({ limit: '16kb' }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',   // mitigation CSRF principale
    secure: process.env.SECURE_COOKIE === '1',
    maxAge: 12 * 3600 * 1000,
  },
}));

// ─────────────────────────────────────────────
//  ANTI BRUTE-FORCE
// ─────────────────────────────────────────────
const attempts = new Map();

// P5 — nettoyage automatique toutes les 5 min
setInterval(() => {
  const now = Date.now();
  for (const [ip, a] of attempts) {
    if (now - a.first > 15 * 60 * 1000) attempts.delete(ip);
  }
}, 5 * 60 * 1000).unref(); // .unref() : ne bloque pas l'arrêt propre

function tooMany(ip) {
  const a = attempts.get(ip);
  if (!a) return false;
  if (Date.now() - a.first > DATA.bruteWindowMin * 60 * 1000) { attempts.delete(ip); return false; }
  return a.count >= DATA.bruteMax;
}
function recordAttempt(ip) {
  const a = attempts.get(ip) || { count: 0, first: Date.now() };
  a.count++;
  attempts.set(ip, a);
}

// ─────────────────────────────────────────────
//  HELPERS SÉCURITÉ
// ─────────────────────────────────────────────

// P9 — garde explicite sur les valeurs nulles/undefined
function safeCompare(a, b) {
  if (!a || !b) return false;
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// Nettoie les IPs pour éviter XSS
function cleanIp(ip) {
  if (!ip || typeof ip !== 'string') return '?';
  return /^[0-9a-fA-F:.]+$/.test(ip) ? ip : '?';
}

// Middleware d'authentification
function auth(req, res, next) {
  if (req.session && req.session.ok) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'non authentifie' });
  return res.redirect('/login');
}

// P11 — vérification d'origine stricte pour POST sensibles (CSRF)
function checkOrigin(req, res, next) {
  const origin  = req.headers.origin  || '';
  const referer = req.headers.referer || '';
  const host    = req.headers.host    || '';
  const src = origin || referer;
  if (!src) {
    return res.status(403).json({ error: 'origin requis' });
  }
  let srcHost;
  try {
    srcHost = new URL(src).host;
  } catch (e) {
    return res.status(403).json({ error: 'origin invalide' });
  }
  if (srcHost !== host) {
    return res.status(403).json({ error: 'origin invalide' });
  }
  next();
}

// ─────────────────────────────────────────────
//  WRAPPER PM2
// ─────────────────────────────────────────────

// P12 + P13 — chemin configurable, stderr loggué
function pm2cmd(args) {
  return new Promise((resolve, reject) => {
    execFile(PM2_BIN, args, { timeout: 30000, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          if (err.code === 'ENOENT') {
            return reject(new Error(
              'pm2 introuvable. Definir PM2_BIN=/chemin/vers/pm2 dans .env'
            ));
          }
          if (stderr) console.error('[pm2 stderr]', stderr.trim());
          return reject(err);
        }
        resolve(stdout);
      }
    );
  });
}

// ─────────────────────────────────────────────
//  VALIDATION DES INPUTS
// ─────────────────────────────────────────────
const NAME_RE    = /^[a-zA-Z0-9_-]{1,32}$/;
const ACTIONS    = new Set(['start', 'stop', 'restart']);

// P15 — validation du chemin de log (évite path traversal si pm2_env compromis)
function isSafeLogPath(p) {
  if (!p || typeof p !== 'string') return false;
  const resolved = path.resolve(p);
  // Accepte uniquement les chemins sous /home, /root ou /var/log
  return (
    resolved.startsWith('/home/') ||
    resolved.startsWith('/root/') ||
    resolved.startsWith('/var/log/')
  );
}

// ─────────────────────────────────────────────
//  ROUTES
// ─────────────────────────────────────────────

// Vérifie PIN (scrypt) si configuré
function checkPin(pin) {
  if (!DATA.pinHash) return true;            // pas de PIN défini → ok
  return verifyPassword(pin || '', DATA.pinHash);
}

// Middleware whitelist IP (garde-fou : vide = tout autorisé)
function ipAllowed(ip) {
  if (!DATA.ipWhitelist || !DATA.ipWhitelist.length) return true;
  return DATA.ipWhitelist.includes(ip);
}

app.get('/login', (req, res) => res.send(loginHtml('', !!DATA.pinHash)));

app.post('/login', (req, res) => {
  const ip = req.ip;
  // Garde-fou whitelist : on bloque AVANT toute auth
  if (!ipAllowed(ip)) {
    logLogin(ip, false);
    return res.status(403).send(loginHtml('IP non autorisée (' + ip + ').', !!DATA.pinHash));
  }
  if (tooMany(ip)) return res.status(429).send(loginHtml('Trop de tentatives. Réessaie plus tard.', !!DATA.pinHash));
  const okPw  = req.body.password && checkPassword(req.body.password);
  const okPin = checkPin(req.body.pin);
  if (okPw && okPin) {
    req.session.regenerate((err) => {
      if (err) {
        console.error('[login regenerate]', err);
        return res.status(500).send(loginHtml('Erreur session.', !!DATA.pinHash));
      }
      req.session.ok = true;
      logLogin(ip, true);
      res.redirect('/');
    });
    return;
  }
  recordAttempt(ip);
  logLogin(ip, false);
  res.status(401).send(loginHtml('Identifiants incorrects.', !!DATA.pinHash));
});

app.post('/logout', auth, (req, res) =>
  req.session.destroy(() => res.redirect('/login'))
);

// ─── Compte / sécurité (Vague 2) ──────────────
// Changer le mot de passe (vérifie l'ancien, stocke le hash dans data.json)
app.post('/api/account/password', auth, checkOrigin, (req, res) => {
  const { current, next } = req.body;
  if (!checkPassword(current || '')) return res.status(403).json({ error: 'mot de passe actuel incorrect' });
  if (!next || String(next).length < 12) return res.status(400).json({ error: '12 caracteres minimum' });
  DATA.passwordHash = hashPassword(String(next));
  saveData(DATA);
  audit('changement mot de passe', req.ip);
  res.json({ ok: true });
});

// Journal : connexions + actions
app.get('/api/account/log', auth, (_req, res) => {
  res.json({ logins: DATA.logins.slice(0, 20), audit: DATA.audit.slice(0, 20) });
});

// Export de la config (sans secrets)
app.get('/api/account/export', auth, (_req, res) => {
  res.json({
    panelName: PANEL_NAME, serverName: SERVER_NAME, version: APP_VERSION,
    port: PORT, github: GITHUB_REPO, exportedAt: new Date().toISOString(),
  });
});

// Statut sécurité (PIN activé ? whitelist ? brute config ? IP courante)
app.get('/api/account/security', auth, (req, res) => {
  res.json({
    pinSet: !!DATA.pinHash,
    whitelist: DATA.ipWhitelist || [],
    currentIp: req.ip,
    bruteMax: DATA.bruteMax,
    bruteWindowMin: DATA.bruteWindowMin,
  });
});

// Définir / retirer le PIN
app.post('/api/account/pin', auth, checkOrigin, (req, res) => {
  const { pin, current } = req.body;
  if (!checkPassword(current || '')) return res.status(403).json({ error: 'mot de passe requis' });
  if (!pin) { DATA.pinHash = null; saveData(DATA); audit('PIN retiré', req.ip); return res.json({ ok: true, pinSet: false }); }
  if (!/^\d{4,8}$/.test(String(pin))) return res.status(400).json({ error: 'PIN : 4 à 8 chiffres' });
  DATA.pinHash = hashPassword(String(pin));
  saveData(DATA);
  audit('PIN défini', req.ip);
  res.json({ ok: true, pinSet: true });
});

// Whitelist IP (garde-fou : on force l'inclusion de l'IP courante)
app.post('/api/account/whitelist', auth, checkOrigin, (req, res) => {
  let list = Array.isArray(req.body.ips) ? req.body.ips : [];
  list = list.map(s => String(s).trim()).filter(Boolean).slice(0, 20);
  // GARDE-FOU anti-lockout : si la liste est non vide, l'IP courante DOIT y être
  if (list.length && !list.includes(req.ip)) list.push(req.ip);
  DATA.ipWhitelist = list;
  saveData(DATA);
  audit('whitelist IP modifiée', req.ip);
  res.json({ ok: true, whitelist: list });
});

// Config brute-force
app.post('/api/account/brute', auth, checkOrigin, (req, res) => {
  const max = parseInt(req.body.max, 10);
  const win = parseInt(req.body.windowMin, 10);
  if (max >= 3 && max <= 20) DATA.bruteMax = max;
  if (win >= 5 && win <= 120) DATA.bruteWindowMin = win;
  saveData(DATA);
  audit('config brute-force modifiée', req.ip);
  res.json({ ok: true, bruteMax: DATA.bruteMax, bruteWindowMin: DATA.bruteWindowMin });
});

// API : état des process PM2 + métriques système
app.get('/api/status', auth, async (req, res) => {
  try {
    const raw  = await pm2cmd(['jlist']);
    const list = JSON.parse(raw).map(p => ({
      name:     p.name,
      status:   p.pm2_env.status,
      cpu:      p.monit ? p.monit.cpu : 0,
      memMb:    p.monit ? Math.round(p.monit.memory / 1048576) : 0,
      uptimeMs: p.pm2_env.status === 'online'
                  ? Date.now() - p.pm2_env.pm_uptime
                  : 0,
      restarts: p.pm2_env.restart_time,
    }));
    res.json({
      processes: list,
      system: {
        load:       os.loadavg()[0].toFixed(2),
        memUsedMb:  Math.round((os.totalmem() - os.freemem()) / 1048576),
        memTotalMb: Math.round(os.totalmem() / 1048576),
        uptimeH:    Math.floor(os.uptime() / 3600),
        uptimeMin:  Math.floor((os.uptime() % 3600) / 60),
      },
    });
  } catch (e) {
    console.error('[/api/status]', e.message);
    res.status(500).json({ error: 'pm2 indisponible' });
  }
});

// API : lecture des logs d'un process
app.get('/api/logs/:name', auth, async (req, res) => {
  const { name } = req.params;
  if (!NAME_RE.test(name)) return res.status(400).json({ error: 'nom invalide' });

  // P16 — parseInt propre avec fallback explicite
  const rawLines = parseInt(req.query.lines, 10);
  const lines    = Math.min(isNaN(rawLines) ? 100 : rawLines, 300);

  try {
    const raw  = await pm2cmd(['jlist']);
    const proc = JSON.parse(raw).find(p => p.name === name);
    if (!proc) return res.status(404).json({ error: 'process introuvable' });

    // P15 — validation des chemins de log
    const outPath = proc.pm2_env.pm_out_log_path;
    const errPath = proc.pm2_env.pm_err_log_path;
    if (!isSafeLogPath(outPath) && !isSafeLogPath(errPath)) {
      console.warn('[/api/logs] chemin log suspect:', outPath, errPath);
    }

    const tail = (logPath, n) => new Promise(resolve => {
      if (!logPath || !isSafeLogPath(logPath)) return resolve([]);
      execFile('tail', ['-n', String(n), logPath], { timeout: 5000 },
        (err, out) => resolve(err ? [] : out.split('\n').filter(Boolean))
      );
    });

    const [out, err] = await Promise.all([
      tail(outPath, lines),
      tail(errPath, Math.floor(lines / 2)),
    ]);
    res.json({ out, err });
  } catch (e) {
    console.error('[/api/logs]', e.message);
    res.status(500).json({ error: 'lecture logs echouee' });
  }
});

// API : actions sur les process (start/stop/restart)
// P11 — checkOrigin ajouté
app.post('/api/:action/:name', auth, checkOrigin, async (req, res) => {
  const { action, name } = req.params;
  if (!ACTIONS.has(action)) return res.status(400).json({ error: 'action inconnue' });
  if (!NAME_RE.test(name))  return res.status(400).json({ error: 'nom invalide' });
  try {
    await pm2cmd([action, name]);
    audit(action + ' ' + name, req.ip);
    res.json({ ok: true });
  } catch (e) {
    console.error('[/api/action]', action, name, e.message);
    res.status(500).json({ error: 'action echouee' });
  }
});

// Vue plein écran des logs
app.get('/logs/:name', auth, async (req, res) => {
  const { name } = req.params;
  if (!NAME_RE.test(name)) return res.status(400).send('nom invalide');
  const tab = req.query.t === 'err' ? 'err' : 'out';

  try {
    const raw  = await pm2cmd(['jlist']);
    const proc = JSON.parse(raw).find(p => p.name === name);
    if (!proc) return res.status(404).send('process introuvable');

    const logPath = tab === 'err'
      ? proc.pm2_env.pm_err_log_path
      : proc.pm2_env.pm_out_log_path;

    const content = await new Promise(resolve => {
      if (!logPath || !isSafeLogPath(logPath)) return resolve('');
      execFile('tail', ['-n', '300', logPath], { timeout: 5000 },
        (err, out) => resolve(err ? '' : out)
      );
    });

    // P20 — stripping ANSI complet
    const escaped = content
      .replace(/&/g,  '&amp;')
      .replace(/</g,  '&lt;')
      .replace(/>/g,  '&gt;')
      .replace(/\x1b\[[0-9;]*[A-Za-z]/g, '')   // CSI sequences
      .replace(/\x1b[()][AB012]/g, '')           // character sets
      .replace(/\x1b[^\[]/g, '');               // autres escapes

    // P18 — name est validé par NAME_RE avant injection
    res.send(`<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${name} — logs</title>
<style>
*{margin:0;box-sizing:border-box}
body{background:#000;color:#8e8e93;font-family:monospace;font-size:12px;display:flex;flex-direction:column;height:100vh}
header{background:rgba(28,28,30,.9);backdrop-filter:blur(20px);border-bottom:.5px solid rgba(255,255,255,.1);padding:10px 16px;display:flex;align-items:center;gap:8px;flex:none}
.nm{font-size:15px;font-weight:600;color:#fff;font-family:-apple-system,sans-serif}
.tb{font-size:11px;color:#8e8e93;background:rgba(142,142,147,.15);padding:2px 8px;border-radius:6px}
a{margin-left:auto;color:#32ade6;font-size:12px;text-decoration:none;padding:4px 10px;border-radius:6px;background:rgba(50,173,230,.1)}
pre{flex:1;padding:14px 16px;overflow:auto;white-space:pre;line-height:1.6}
pre::-webkit-scrollbar{width:4px;height:4px}
pre::-webkit-scrollbar-thumb{background:rgba(142,142,147,.3);border-radius:2px}
</style></head><body>
<header>
  <span class="nm">${name}</span>
  <span class="tb">${tab}</span>
  <a href="javascript:location.reload()">&#8635; Refresh</a>
</header>
<pre>${escaped}</pre>
<script>document.querySelector("pre").scrollTop = 9999999;</script>
</body></html>`);
  } catch (e) {
    console.error('[/logs]', e.message);
    res.status(500).send('erreur interne');
  }
});

// Page Paramètres
// ─── Contrôle système (whitelisté, sudo requis) ──────
// Services autorisés et leurs commandes EXACTES (jamais d'arbitraire)
const SYS_SERVICES = {
  ufw:        { check: ['ufw', 'status'],                       on: ['ufw', '--force', 'enable'], off: ['ufw', 'disable'] },
  fail2ban:   { check: ['systemctl', 'is-active', 'fail2ban'],  on: ['systemctl', 'start', 'fail2ban'],  off: ['systemctl', 'stop', 'fail2ban'] },
  autoupdate: { check: ['systemctl', 'is-active', 'unattended-upgrades'], on: ['systemctl', 'start', 'unattended-upgrades'], off: ['systemctl', 'stop', 'unattended-upgrades'] },
};

// Actions système ponctuelles (boutons, pas toggles)
const SYS_ACTIONS = {
  reboot:    ['reboot'],
  poweroff:  ['poweroff'],
  dropcache: ['sysctl', '-w', 'vm.drop_caches=3'],
  ntpsync:   ['systemctl', 'restart', 'systemd-timesyncd'],
};

function sudoCmd(argv) {
  return new Promise((resolve) => {
    execFile('sudo', ['-n'].concat(argv), { timeout: 10000 }, (err, stdout, stderr) => {
      resolve({ ok: !err, out: (stdout || '') + (stderr || '') });
    });
  });
}

// Commande simple sans sudo (lecture)
function shCmd(cmd, args) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 8000, maxBuffer: 2 * 1024 * 1024 }, (err, stdout) => {
      resolve(err ? '' : stdout);
    });
  });
}

// Statut des services toggleables
app.get('/api/sys/status', auth, async (_req, res) => {
  const out = {};
  for (const [name, c] of Object.entries(SYS_SERVICES)) {
    const r = await sudoCmd(c.check);
    if (name === 'ufw') out.ufw = /Status:\s*active/i.test(r.out);
    else out[name] = /^active/i.test(r.out.trim());
  }
  res.json(out);
});

// Bascule d'un service
// Step-up sur ufw disable
app.post('/api/sys/:service/:state', auth, checkOrigin, async (req, res) => {
  const { service, state } = req.params;
  const svc = SYS_SERVICES[service];
  if (!svc) return res.status(400).json({ error: 'service inconnu' });
  if (state !== 'on' && state !== 'off') return res.status(400).json({ error: 'etat invalide' });

  if (service === 'ufw' && state === 'off') {
    if (!checkPassword(req.body.confirm || '')) {
      return res.status(403).json({ error: 'mot de passe requis pour désactiver le pare-feu' });
    }
  }

  const r = await sudoCmd(state === 'on' ? svc.on : svc.off);
  if (!r.ok) {
    console.error('[/api/sys]', service, state, r.out.trim());
    return res.status(500).json({ error: 'commande echouee (sudo NOPASSWD configure ?)' });
  }
  res.json({ ok: true });
});

// Action système ponctuelle (reboot, poweroff, dropcache, ntpsync)
// Step-up auth sur actions destructrices
app.post('/api/sysaction/:name', auth, checkOrigin, async (req, res) => {
  const argv = SYS_ACTIONS[req.params.name];
  if (!argv) return res.status(400).json({ error: 'action inconnue' });

  const destructive = ['reboot', 'poweroff'];
  if (destructive.includes(req.params.name)) {
    if (!checkPassword(req.body.confirm || '')) {
      return res.status(403).json({ error: 'mot de passe requis pour cette action' });
    }
  }

  // reboot/poweroff : on répond avant que la machine parte
  if (req.params.name === 'reboot' || req.params.name === 'poweroff') {
    res.json({ ok: true });
    setTimeout(() => sudoCmd(argv), 500);
    return;
  }
  const r = await sudoCmd(argv);
  if (!r.ok) {
    console.error('[/api/sysaction]', req.params.name, r.out.trim());
    return res.status(500).json({ error: 'action echouee (sudo NOPASSWD ?)' });
  }
  res.json({ ok: true });
});

// Infos système détaillées (lecture seule, sans sudo)
// Spécifications matérielles + système (auto-détectées)
app.get('/api/specs', auth, (_req, res) => {
  const cpus = os.cpus() || [];
  // IPs locales non-internes
  const nets = os.networkInterfaces();
  const ips = [];
  for (const name of Object.keys(nets)) {
    for (const ni of nets[name]) {
      if (ni.family === 'IPv4' && !ni.internal) ips.push({ iface: name, ip: ni.address });
    }
  }
  res.json({
    panelName: PANEL_NAME,
    serverName: SERVER_NAME,
    user: PANEL_USER,
    os: OS_NAME,
    hostname: os.hostname(),
    kernel: os.release(),
    arch: os.arch(),
    cpuModel: cpus.length ? cpus[0].model.replace(/\s+/g, ' ').trim() : '—',
    cpuCores: cpus.length,
    ramTotalMb: Math.round(os.totalmem() / 1048576),
    node: process.version,
    port: PORT,
    ips: ips,
    panelVersion: APP_VERSION,
  });
});

app.get('/api/sysinfo', auth, async (_req, res) => {
  try {
    // Disque
    const dfRaw = await shCmd('df', ['-B1', '--output=target,size,used', '-x', 'tmpfs', '-x', 'devtmpfs']);
    const disks = dfRaw.trim().split('\n').slice(1).map(l => {
      const parts = l.trim().split(/\s+/);
      const mount = parts[0], size = parseInt(parts[1]), used = parseInt(parts[2]);
      return { mount, sizeGb: +(size / 1e9).toFixed(1), usedGb: +(used / 1e9).toFixed(1), pct: size ? Math.round(used / size * 100) : 0 };
    }).filter(d => d.sizeGb > 0.5).slice(0, 4);

    // Température CPU
    let temp = null;
    const tRaw = await shCmd('cat', ['/sys/class/thermal/thermal_zone0/temp']);
    if (tRaw && !isNaN(parseInt(tRaw))) temp = Math.round(parseInt(tRaw) / 1000);

    // Swap
    const smem = os.totalmem();
    const swapRaw = await shCmd('sh', ['-c', "free -b | awk '/Swap/{print $2, $3}'"]);
    let swap = null;
    if (swapRaw.trim()) {
      const [tot, usd] = swapRaw.trim().split(/\s+/).map(Number);
      if (tot > 0) swap = { totalMb: Math.round(tot / 1048576), usedMb: Math.round(usd / 1048576), pct: Math.round(usd / tot * 100) };
    }

    // Tailscale (lecture seule)
    let tailscale = null;
    const tsRaw = await shCmd('tailscale', ['status', '--json']);
    if (tsRaw) {
      try { const j = JSON.parse(tsRaw); tailscale = { up: j.BackendState === 'Running', ip: (j.TailscaleIPs || [])[0] || null }; } catch (e) {}
    }

    // Top 5 process
    const topRaw = await shCmd('sh', ['-c', 'ps -eo comm,%cpu,%mem --sort=-%cpu | head -6 | tail -5']);
    const top = topRaw.trim().split('\n').filter(Boolean).map(l => {
      const p = l.trim().split(/\s+/);
      return { name: p[0], cpu: p[1], mem: p[2] };
    });

    res.json({ disks, temp, swap, tailscale, top });
  } catch (e) {
    console.error('[/api/sysinfo]', e.message);
    res.status(500).json({ error: 'sysinfo echoue' });
  }
});

app.get('/settings', auth, (_req, res) => res.send(settingsHtml()));

app.get('/', auth, (_req, res) => res.send(dashHtml()));

// P24 — handler d'erreur global Express
app.use((err, req, res, _next) => {
  console.error('[Express error]', err.message);
  if (req.path.startsWith('/api/')) {
    return res.status(500).json({ error: 'erreur interne' });
  }
  res.status(500).send('erreur interne');
});

// P25 — route 404
app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'not found' });
  res.status(404).redirect('/');
});

// P4 — capture EADDRINUSE et autres erreurs de démarrage
const server = app.listen(PORT, () =>
  console.log('[' + PANEL_NAME + '] actif sur le port ' + PORT)
);
server.on('error', e => {
  if (e.code === 'EADDRINUSE') {
    console.error('[FATAL] Port ' + PORT + ' deja utilise');
  } else {
    console.error('[FATAL] Erreur serveur:', e.message);
  }
  process.exit(1);
});

// ─────────────────────────────────────────────
//  PAGE LOGIN
// ─────────────────────────────────────────────
function loginHtml(msg, showPin) {
  // msg est contrôlé : seules les strings hardcodées sont passées, jamais du user input
  return `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${PANEL_NAME}</title>
<link href="https://fonts.googleapis.com/css2?family=Oxanium:wght@700&display=swap" rel="stylesheet">
<style>
*{margin:0;box-sizing:border-box}
body{background:#000;min-height:100vh;display:grid;place-items:center;font-family:-apple-system,BlinkMacSystemFont,sans-serif}
.bg{position:fixed;inset:0;background:radial-gradient(ellipse at 25% 25%,rgba(94,92,230,.2) 0%,transparent 55%),radial-gradient(ellipse at 75% 75%,rgba(255,55,95,.15) 0%,transparent 55%)}
.w{position:relative;z-index:1;width:100%;max-width:320px;padding:20px}
.logo{font-family:"Oxanium",sans-serif;font-size:26px;font-weight:700;background:linear-gradient(135deg,#5e5ce6,#ff375f);-webkit-background-clip:text;background-clip:text;color:transparent;text-align:center;margin-bottom:4px;letter-spacing:-.02em}
.sub{text-align:center;color:#636366;font-size:11px;margin-bottom:24px}
.card{background:rgba(28,28,30,.8);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:.5px solid rgba(255,255,255,.1);border-radius:20px;padding:22px}
input{width:100%;background:rgba(255,255,255,.06);border:none;border-radius:10px;color:#fff;font-size:15px;padding:12px 14px;outline:none;margin-bottom:12px;font-family:inherit}
input:focus{background:rgba(94,92,230,.1);box-shadow:0 0 0 2px rgba(94,92,230,.4)}
button{width:100%;padding:13px;border:none;border-radius:12px;cursor:pointer;font-weight:600;font-size:15px;color:#fff;background:linear-gradient(135deg,#5e5ce6,#ff375f);font-family:inherit}
button:active{transform:scale(.98)}
.err{color:#ff453a;font-size:12px;margin-top:10px;text-align:center;min-height:16px}
</style></head><body>
<div class="bg"></div>
<div class="w">
  <div class="logo">${PANEL_NAME}</div>
  <div class="sub">${SERVER_NAME}</div>
  <form class="card" method="post" action="/login">
    <input type="password" name="password" placeholder="Mot de passe" autofocus autocomplete="current-password">
    ${showPin ? '<input type="password" name="pin" placeholder="Code PIN" inputmode="numeric" autocomplete="off">' : ''}
    <button type="submit">Se connecter</button>
    <div class="err">${msg}</div>
  </form>
</div>
</body></html>`;
}

// ─────────────────────────────────────────────
//  DASHBOARD
// ─────────────────────────────────────────────
function dashHtml() {
  return `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${PANEL_NAME}</title>
<link href="https://fonts.googleapis.com/css2?family=Oxanium:wght@600;700&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<style>
*{margin:0;box-sizing:border-box}
body{background:#000;color:#fff;font-family:-apple-system,BlinkMacSystemFont,sans-serif;min-height:100vh}
body.light{background:#f2f2f7;color:#1c1c1e}
body.light .sc,body.light .pc{background:rgba(255,255,255,.7);border-color:rgba(0,0,0,.08)}
body.light header{background:rgba(255,255,255,.7);border-bottom-color:rgba(0,0,0,.08)}
.bg{position:fixed;inset:0;z-index:0;background:radial-gradient(ellipse at 20% 10%,rgba(94,92,230,.15) 0%,transparent 50%),radial-gradient(ellipse at 80% 90%,rgba(255,55,95,.1) 0%,transparent 50%)}
body.light .bg{opacity:.5}
body.compact .pc{margin-bottom:4px}
body.compact .ph{padding:7px 12px}
body.compact .sc{padding:8px 11px}
header{position:sticky;top:0;z-index:100;background:rgba(0,0,0,.7);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:.5px solid rgba(255,255,255,.08);padding:0 20px;height:46px;display:flex;align-items:center;gap:10px}
.logo{font-family:"Oxanium",sans-serif;font-size:16px;font-weight:700;background:linear-gradient(135deg,#5e5ce6,#ff375f);-webkit-background-clip:text;background-clip:text;color:transparent}
.dot{width:6px;height:6px;border-radius:50%;background:#30d158;animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(48,209,88,.5)}50%{box-shadow:0 0 0 5px rgba(48,209,88,0)}}
.si{color:#636366;font-size:11px;font-family:"JetBrains Mono",monospace}
.ml{margin-left:auto}
.qb{background:rgba(255,255,255,.06);border:none;color:#636366;border-radius:8px;padding:5px 11px;cursor:pointer;font-size:12px;font-family:inherit}
.qb:hover{background:rgba(255,69,58,.15);color:#ff453a}
main{position:relative;z-index:1;padding:14px 20px;max-width:800px;margin:0 auto}
.gs{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px}
.sc{background:rgba(28,28,30,.7);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:.5px solid rgba(255,255,255,.08);border-radius:14px;padding:11px 13px}
.sl{font-size:9px;color:#636366;font-weight:500;letter-spacing:.04em;text-transform:uppercase;margin-bottom:3px}
.sv{font-size:18px;font-weight:700;letter-spacing:-.02em}
.ss{font-size:9px;color:#636366;margin-top:2px}
.st{font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#636366;margin-bottom:7px;padding-left:2px}
.pc{background:rgba(28,28,30,.7);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:.5px solid rgba(255,255,255,.08);border-radius:14px;margin-bottom:7px;overflow:hidden;transition:border-color .2s}
.pc.new{animation:fadeup .25s ease both}
@keyframes fadeup{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.ph{display:flex;align-items:center;gap:9px;padding:11px 14px}
.d{width:6px;height:6px;border-radius:50%;flex:none}
.online .d{background:#30d158;box-shadow:0 0 0 2px rgba(48,209,88,.2);animation:pulse 2.5s ease-in-out infinite}
.stopped .d{background:#ff453a}
.errored .d{background:#ff9f0a}
.pn{font-size:13px;font-weight:600}
.pm{font-size:10px;color:#636366;margin-left:auto;text-align:right;font-family:"JetBrains Mono",monospace;line-height:1.5}
.pb{display:flex;gap:5px;margin-left:9px}
.btn{background:rgba(255,255,255,.07);border:none;color:rgba(235,235,245,.8);font-size:10px;font-weight:500;padding:5px 10px;border-radius:7px;cursor:pointer;transition:background .15s;white-space:nowrap;font-family:inherit}
.btn:hover{background:rgba(94,92,230,.2);color:#5e5ce6}
.btn.d2:hover{background:rgba(255,69,58,.2);color:#ff453a}
.btn.l{color:#32ade6}.btn.l:hover{background:rgba(50,173,230,.15)}
.btn.la{background:rgba(50,173,230,.12);color:#32ade6}
.btn:disabled{opacity:.3;cursor:wait}
.lp{display:none;border-top:.5px solid rgba(255,255,255,.06);background:rgba(0,0,0,.4)}
.lp.open{display:block}
.lt{display:flex;align-items:center;gap:5px;padding:6px 12px;border-bottom:.5px solid rgba(255,255,255,.06)}
.tab{background:rgba(255,255,255,.05);border:none;color:#636366;font-size:9px;font-weight:500;padding:3px 9px;border-radius:5px;cursor:pointer;font-family:inherit}
.tab.a{background:rgba(94,92,230,.15);color:#5e5ce6}
.rf{background:none;border:none;color:#636366;font-size:11px;padding:3px 7px;border-radius:5px;cursor:pointer;margin-left:auto}
.rf:hover{color:#30d158}
.lb{padding:9px 12px;max-height:200px;overflow-y:auto;overflow-x:auto;font-size:10.5px;line-height:1.55;white-space:pre;color:#636366;font-family:"JetBrains Mono",monospace}
.lb::-webkit-scrollbar{width:2px;height:2px}
.lb::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:1px}
.le{color:#ff453a}.lo{color:#30d158}.lw{color:#ff9f0a}
.empty{color:#636366;text-align:center;padding:30px 0;font-size:12px}
</style>
</head><body>
<div class="bg"></div>
<header>
  <span class="logo">${PANEL_NAME}</span>
  <span class="dot"></span>
  <span class="si" id="si"></span>
  <a href="/settings" class="qb ml" style="text-decoration:none;display:inline-flex;align-items:center">Paramètres</a>
  <form method="post" action="/logout" style="margin-left:6px">
    <button class="qb" type="submit">Quitter</button>
  </form>
</header>
<main>
  <div class="gs">
    <div class="sc"><div class="sl">RAM</div><div class="sv" id="sr">—</div><div class="ss" id="srb">—</div></div>
    <div class="sc"><div class="sl">Load</div><div class="sv" id="sl2">—</div><div class="ss">avg 1 min</div></div>
    <div class="sc"><div class="sl">Uptime</div><div class="sv" id="su">—</div><div class="ss">${SERVER_NAME}</div></div>
    <div class="sc"><div class="sl">Services</div><div class="sv" id="ss">—</div><div class="ss">en ligne</div></div>
  </div>
  <div class="st">Services</div>
  <div id="list"><div class="empty">Chargement...</div></div>
</main>
<script>
// ── état client ──────────────────────────────
var LS = {};   // log state par process : { open, tab }
var KP = {};   // known processes (déjà rendus dans le DOM)

// ── utilitaires ──────────────────────────────
function fU(ms) {
  var s = Math.floor(ms / 1000), h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  var long = false; try { long = localStorage.getItem('opt_uplong') === '1'; } catch(e){}
  if (long) { var d = Math.floor(h/24); return (d>0?d+'j ':'') + (h%24) + 'h' + String(m).padStart(2,'0') + 'm'; }
  return h > 0 ? h + 'h' + String(m).padStart(2, '0') : m + 'min';
}

// Échappement HTML pour affichage dans textContent/innerHTML
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// P21 — échappement pour usage dans attribut HTML (onclick, id, etc.)
function escAttr(s) {
  return String(s)
    .replace(/&/g,  '&amp;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#39;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/\\\\/g, '&#92;');
}

// Conversion ANSI -> HTML coloré (gère les codes \x1b[...m de PM2)
var ANSI_MAP = {
  '30':'#555','31':'#ff453a','32':'#30d158','33':'#ff9f0a','34':'#0a84ff',
  '35':'#bf5af2','36':'#32ade6','37':'#ebebf5','90':'#8e8e93','91':'#ff6961',
  '92':'#5be37d','93':'#ffd426','94':'#409cff','95':'#da8fff','96':'#70d7ff','97':'#fff'
};
function col(l) {
  var out = '', cur = null, buf = '';
  var re = /\\x1b\\[([0-9;]*)m/g, last = 0, m;
  function flush() {
    if (!buf) return;
    var e = esc(buf);
    out += cur ? '<span style="color:' + cur + '">' + e + '</span>' : e;
    buf = '';
  }
  while ((m = re.exec(l)) !== null) {
    buf += l.slice(last, m.index);
    flush();
    var codes = m[1].split(';');
    for (var i = 0; i < codes.length; i++) {
      var c = codes[i];
      if (c === '0' || c === '') cur = null;
      else if (ANSI_MAP[c]) cur = ANSI_MAP[c];
    }
    last = re.lastIndex;
  }
  buf += l.slice(last);
  flush();
  // strip codes ANSI résiduels non-couleur (curseur, etc.)
  out = out.replace(/\\x1b\\[[0-9;]*[A-Za-z]/g, '').replace(/\\x1b[()][AB012]/g, '');
  return out || esc(l);
}

// ── logs ─────────────────────────────────────
async function loadLogs(n, t, sp) {
  var b = document.getElementById('lb-' + n);
  if (!b) return;
  var first = b.dataset.loaded !== '1';
  if (first || sp) b.innerHTML = '<span style="color:#636366">...</span>';
  try {
    var ll = 100; try { ll = parseInt(localStorage.getItem('loglines'))||100; } catch(e){}
    var r = await fetch('/api/logs/' + encodeURIComponent(n) + '?lines=' + ll);
    if (r.status === 401) { location.href = '/login'; return; }
    var d = await r.json();
    var lines = t === 'err' ? d.err : d.out;
    if (!lines || !lines.length) {
      b.innerHTML = '<span style="color:#636366">Aucun log.</span>';
      b.dataset.loaded = '1';
      return;
    }
    var autoscroll = true; try { autoscroll = localStorage.getItem('opt_autoscroll') !== '0'; } catch(e){}
    // Signature légère : nb de lignes + dernière ligne (anti-flicker, peu coûteux)
    var sig = lines.length + '|' + lines[lines.length - 1];
    if (b.dataset.sig === sig) return;
    var atBottom = b.scrollHeight - b.scrollTop - b.clientHeight < 40;
    b.innerHTML = lines.map(col).join('\\n');
    b.dataset.loaded = '1';
    b.dataset.sig = sig;
    if (autoscroll && (atBottom || first)) b.scrollTop = b.scrollHeight;
  } catch (e) {
    b.innerHTML = '<span class="le">Erreur de chargement.</span>';
  }
}

function toggleLogs(n) {
  if (!LS[n]) LS[n] = { open: false, tab: 'out' };
  LS[n].open = !LS[n].open;
  var lp = document.getElementById('lp-' + n);
  var lb = document.getElementById('lbtn-' + n);
  if (lp) lp.classList.toggle('open', LS[n].open);
  if (lb) lb.classList.toggle('la',   LS[n].open);
  if (LS[n].open) loadLogs(n, LS[n].tab);
}

function swTab(n, t) {
  if (!LS[n]) LS[n] = { open: true, tab: t };
  LS[n].tab = t;
  var to = document.getElementById('to-' + n);
  var te = document.getElementById('te-' + n);
  if (to) to.classList.toggle('a', t === 'out');
  if (te) te.classList.toggle('a', t === 'err');
  loadLogs(n, t);
}

function openFS(n) {
  var t = LS[n] ? LS[n].tab : 'out';
  window.open('/logs/' + encodeURIComponent(n) + '?t=' + t, '_blank', 'noopener');
}

// ── actions ──────────────────────────────────
// P21 — on utilise data-* pour ne jamais injecter de valeurs dans onclick
function handleBtn(el) {
  var a = el.dataset.action;
  var n = el.dataset.name;
  if (!a || !n) return;
  // Confirmation seulement si l'option "Confirmer chaque action" est activée
  var confirmAll = false; try { confirmAll = localStorage.getItem('opt_confirmall') === '1'; } catch(e){}
  if (confirmAll && !confirm(a + ' ' + n + ' ?')) return;
  doAction(el, a, n);
}

function beepIfOn(){ try { if(localStorage.getItem('sound')!=='1') return; var c=new (window.AudioContext||window.webkitAudioContext)(),o=c.createOscillator(),g=c.createGain();o.connect(g);g.connect(c.destination);o.frequency.value=660;g.gain.value=.05;o.start();o.stop(c.currentTime+.08);}catch(e){} }
async function doAction(el, a, n) {
  el.disabled = true;
  beepIfOn();
  try {
    await fetch('/api/' + encodeURIComponent(a) + '/' + encodeURIComponent(n),
      { method: 'POST' }
    );
  } catch (e) {
    console.warn('[doAction] erreur reseau:', e);
  }
  // P23 — setTimeout au lieu de setInterval pour éviter le chevauchement
  setTimeout(refresh, 1400);
}

// ── rendu des cartes ─────────────────────────
function mkBtns(p) {
  var n  = escAttr(p.name);
  var on = p.status === 'online';
  var lo = LS[p.name] && LS[p.name].open;

  // P21 — data-action + data-name, pas d'injection dans onclick
  var rb  = '<button class="btn" data-action="restart" data-name="' + n + '" onclick="handleBtn(this)">&#8635;</button>';
  var sb  = '<button class="btn d2" data-action="stop" data-name="' + n + '" onclick="handleBtn(this)">&#9646;</button>';
  var stb = '<button class="btn" data-action="start" data-name="' + n + '" onclick="handleBtn(this)">&#9654; Start</button>';
  var lbc = 'btn l' + (lo ? ' la' : '');
  var lbt = '<button class="' + lbc + '" id="lbtn-' + n + '" data-name="' + n + '" onclick="toggleLogs(this.dataset.name)">&#8801; Logs</button>';
  var fsb = '<button class="btn l" data-name="' + n + '" onclick="openFS(this.dataset.name)">&#10138;</button>';
  return (on ? rb + sb : stb) + lbt + fsb;
}

function cardHtml(p) {
  var n  = escAttr(p.name);
  var on = p.status === 'online';
  var lo = LS[p.name] && LS[p.name].open;
  var tt = LS[p.name] ? LS[p.name].tab : 'out';
  var meta = on
    ? 'up ' + fU(p.uptimeMs) + ' &middot; ' + p.cpu + '% &middot; ' + p.memMb + 'Mo &middot; ' + p.restarts + 'x'
    : esc(p.status);

  return '<div class="ph">'
    + '<span class="d"></span>'
    + '<span class="pn">' + esc(p.name) + '</span>'
    + '<span class="pm" id="meta-' + n + '">' + meta + '</span>'
    + '<span class="pb" id="btns-' + n + '">' + mkBtns(p) + '</span>'
    + '</div>'
    + '<div class="lp' + (lo ? ' open' : '') + '" id="lp-' + n + '">'
    + '<div class="lt">'
    + '<button class="tab' + (tt !== 'err' ? ' a' : '') + '" id="to-' + n + '" data-name="' + n + '" data-tab="out"  onclick="swTab(this.dataset.name,this.dataset.tab)">stdout</button>'
    + '<button class="tab' + (tt === 'err' ? ' a' : '') + '" id="te-' + n + '" data-name="' + n + '" data-tab="err"  onclick="swTab(this.dataset.name,this.dataset.tab)">stderr</button>'
    + '<button class="rf" data-name="' + n + '" data-deftab="out" onclick="loadLogs(this.dataset.name,(LS[this.dataset.name]||{tab:this.dataset.deftab}).tab,true)">&#8635;</button>'
    + '</div>'
    + '<div class="lb" id="lb-' + n + '">Cliquer Logs.</div>'
    + '</div>';
}

function mkCard(p) {
  var div = document.createElement('div');
  div.className = 'pc ' + p.status + ' new';
  div.id        = 'card-' + p.name;
  div.innerHTML = cardHtml(p);
  return div;
}

function updCard(p) {
  var card = document.getElementById('card-' + p.name);
  if (!card) return;
  card.className = 'pc ' + p.status;

  var meta = document.getElementById('meta-' + p.name);
  var on   = p.status === 'online';
  if (meta) {
    meta.innerHTML = on
      ? 'up ' + fU(p.uptimeMs) + ' &middot; ' + p.cpu + '% &middot; ' + p.memMb + 'Mo &middot; ' + p.restarts + 'x'
      : esc(p.status);
  }

  var btns = document.getElementById('btns-' + p.name);
  if (btns && btns.dataset.on !== String(on)) {
    btns.innerHTML    = mkBtns(p);
    btns.dataset.on   = String(on);
  }
}

// ── boucle de rafraîchissement ───────────────
// P23 — setTimeout récursif : évite le chevauchement de requêtes
async function refresh() {
  try {
    var r = await fetch('/api/status');
    if (r.status === 401) { location.href = '/login'; return; }
    var d = await r.json();

    var el;
    el = document.getElementById('sr');  if (el) el.textContent = d.system.memUsedMb + ' Mo';
    el = document.getElementById('srb'); if (el) el.textContent = 'sur ' + d.system.memTotalMb + ' Mo';
    el = document.getElementById('sl2'); if (el) el.textContent = d.system.load;
    el = document.getElementById('su');  if (el) el.textContent = d.system.uptimeH + 'h' + String(d.system.uptimeMin).padStart(2, '0');
    el = document.getElementById('si');  if (el) el.textContent = d.system.memUsedMb + '/' + d.system.memTotalMb + ' Mo';

    var online = d.processes.filter(function(p) { return p.status === 'online'; }).length;
    el = document.getElementById('ss'); if (el) el.textContent = online + '/' + d.processes.length;

    var list = document.getElementById('list');
    if (!list) return;
    if (list.querySelector('.empty')) list.innerHTML = '';

    d.processes.forEach(function(p, i) {
      if (!KP[p.name]) {
        KP[p.name] = true;
        var card = mkCard(p);
        card.style.animationDelay = (i * 50) + 'ms';
        list.appendChild(card);
      } else {
        updCard(p);
      }
    });

    // Mise à jour auto des logs ouverts (silencieuse, sans spinner)
    Object.keys(LS).forEach(function(name){
      if (LS[name] && LS[name].open) loadLogs(name, LS[name].tab, false);
    });
  } catch (e) {
    // P22 — erreur loggée, pas silencieuse
    console.warn('[refresh] erreur:', e.message || e);
  } finally {
    // P23 — on reschedule après la fin (succès ou erreur)
    var rf = 4000; try { rf = (parseInt(localStorage.getItem('refresh'))||4) * 1000; } catch(e){}
    setTimeout(refresh, rf);
  }
}

// applique thème + densité sauvegardés
try {
  if (localStorage.getItem('theme') === 'light') document.body.classList.add('light');
  if (localStorage.getItem('opt_compact') === '1') document.body.classList.add('compact');
} catch(e){}

// déconnexion auto après inactivité
(function(){
  var idleMin = 0; try { idleMin = parseInt(localStorage.getItem('idle'))||0; } catch(e){}
  if (idleMin > 0) {
    var timer;
    function reset(){ clearTimeout(timer); timer = setTimeout(function(){
      fetch('/logout', {method:'POST'}).finally(function(){ location.href='/login'; });
    }, idleMin*60000); }
    ['mousemove','keydown','click','touchstart'].forEach(function(ev){ document.addEventListener(ev, reset, {passive:true}); });
    reset();
  }
})();

refresh(); // premier appel immédiat
</script>
</body></html>`;
}

// ─────────────────────────────────────────────
//  PAGE PARAMÈTRES
// ─────────────────────────────────────────────
function settingsHtml() {
  return `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${PANEL_NAME} — Paramètres</title>
<link href="https://fonts.googleapis.com/css2?family=Oxanium:wght@600;700&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<style>
*{margin:0;box-sizing:border-box}
body{background:#000;color:#fff;font-family:-apple-system,BlinkMacSystemFont,sans-serif;min-height:100vh}
body.light{background:#f2f2f7;color:#1c1c1e}
.bg{position:fixed;inset:0;z-index:0;background:radial-gradient(ellipse at 20% 10%,rgba(94,92,230,.15) 0%,transparent 50%),radial-gradient(ellipse at 80% 90%,rgba(255,55,95,.1) 0%,transparent 50%)}
body.light .bg{opacity:.5}
header{position:sticky;top:0;z-index:100;background:rgba(0,0,0,.7);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:.5px solid rgba(255,255,255,.08);padding:0 20px;height:46px;display:flex;align-items:center;gap:10px}
body.light header{background:rgba(255,255,255,.7);border-bottom-color:rgba(0,0,0,.08)}
.logo{font-family:"Oxanium",sans-serif;font-size:16px;font-weight:700;background:linear-gradient(135deg,#5e5ce6,#ff375f);-webkit-background-clip:text;background-clip:text;color:transparent}
.back{margin-left:auto;background:rgba(255,255,255,.06);border:none;color:#636366;border-radius:8px;padding:5px 11px;cursor:pointer;font-size:12px;text-decoration:none;display:inline-flex;align-items:center;font-family:inherit}
.back:hover{background:rgba(94,92,230,.15);color:#5e5ce6}
main{position:relative;z-index:1;padding:18px 20px;max-width:560px;margin:0 auto}
.st{font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#636366;margin:18px 0 8px;padding-left:2px}
.card{background:rgba(28,28,30,.7);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:.5px solid rgba(255,255,255,.08);border-radius:14px;overflow:hidden}
body.light .card{background:rgba(255,255,255,.7);border-color:rgba(0,0,0,.08)}
.row{display:flex;align-items:center;padding:13px 16px;border-bottom:.5px solid rgba(255,255,255,.06);gap:12px}
body.light .row{border-bottom-color:rgba(0,0,0,.06)}
.row:last-child{border-bottom:none}
.row .k{font-size:13px}
.row .sub{font-size:11px;color:#8e8e93;margin-top:1px}
.row .v{margin-left:auto;font-size:13px;color:#8e8e93;font-family:"JetBrains Mono",monospace}
.grow{flex:1;min-width:0}
/* Toggle switch iOS */
.sw{position:relative;width:44px;height:26px;flex:none;margin-left:auto}
.sw input{opacity:0;width:0;height:0}
.sl{position:absolute;cursor:pointer;inset:0;background:rgba(120,120,128,.32);border-radius:13px;transition:.25s}
.sl:before{content:"";position:absolute;height:22px;width:22px;left:2px;top:2px;background:#fff;border-radius:50%;transition:.25s;box-shadow:0 1px 3px rgba(0,0,0,.3)}
.sw input:checked + .sl{background:#30d158}
.sw input:checked + .sl:before{transform:translateX(18px)}
.sw input:disabled + .sl{opacity:.4;cursor:wait}
/* Slider */
.range{margin-left:auto;width:140px;display:flex;align-items:center;gap:8px}
.range input{flex:1;-webkit-appearance:none;height:4px;border-radius:2px;background:rgba(120,120,128,.32);outline:none}
.range input::-webkit-slider-thumb{-webkit-appearance:none;width:18px;height:18px;border-radius:50%;background:#fff;cursor:pointer;box-shadow:0 1px 3px rgba(0,0,0,.3)}
.range .val{font-size:11px;color:#8e8e93;font-family:"JetBrains Mono",monospace;min-width:28px;text-align:right}
.warn{font-size:11px;color:#ff9f0a;padding:10px 16px;line-height:1.5;background:rgba(255,159,10,.08)}
.abtn{margin-left:auto;background:rgba(94,92,230,.15);border:none;color:#5e5ce6;font-size:12px;font-weight:600;padding:7px 14px;border-radius:8px;cursor:pointer;font-family:inherit;transition:.15s}
.abtn:hover{background:rgba(94,92,230,.25)}
.abtn:disabled{opacity:.4;cursor:wait}
.abtn.danger{background:rgba(255,69,58,.15);color:#ff453a}
.abtn.danger:hover{background:rgba(255,69,58,.25)}
.bar{height:5px;border-radius:3px;background:rgba(120,120,128,.3);overflow:hidden;margin-top:5px}
.bar i{display:block;height:100%;border-radius:3px;background:linear-gradient(90deg,#5e5ce6,#ff375f)}
.bar i.hot{background:linear-gradient(90deg,#ff9f0a,#ff453a)}
.inp{width:100%;background:rgba(255,255,255,.06);border:none;border-radius:9px;color:#fff;font-size:14px;padding:10px 12px;outline:none;font-family:inherit}
body.light .inp{background:rgba(0,0,0,.05);color:#1c1c1e}
.inp:focus{box-shadow:0 0 0 2px rgba(94,92,230,.4)}
.logrow{display:flex;align-items:center;padding:9px 16px;border-bottom:.5px solid rgba(255,255,255,.05);font-size:11px;font-family:"JetBrains Mono",monospace;gap:8px}
.logrow:last-child{border-bottom:none}
.logrow .t{color:#636366;min-width:90px}
.logrow .ok{color:#30d158}.logrow .no{color:#ff453a}
.link{display:flex;align-items:center;padding:14px 16px;border-bottom:.5px solid rgba(255,255,255,.06);text-decoration:none;color:inherit;transition:background .15s}
body.light .link{border-bottom-color:rgba(0,0,0,.06)}
.link:last-child{border-bottom:none}
.link:hover{background:rgba(94,92,230,.1)}
.link .ic{width:26px;height:26px;border-radius:7px;background:rgba(255,255,255,.08);display:grid;place-items:center;margin-right:12px;font-size:15px}
body.light .link .ic{background:rgba(0,0,0,.06)}
.link .t{font-size:14px;font-weight:500}
.link .s{font-size:11px;color:#8e8e93;margin-top:1px}
.link .ar{margin-left:auto;color:#48484a;font-size:18px}
.credit{text-align:center;margin-top:28px;padding:18px}
.credit .by{font-family:"Oxanium",sans-serif;font-size:15px;font-weight:700;background:linear-gradient(135deg,#5e5ce6,#ff375f);-webkit-background-clip:text;background-clip:text;color:transparent}
.credit .tag{font-size:11px;color:#48484a;margin-top:4px}
</style></head><body>
<div class="bg"></div>
<header>
  <span class="logo">${PANEL_NAME}</span>
  <a href="/" class="back">&#8249; Retour</a>
</header>
<main>

  <!-- ════ SERVEUR — SÉCURITÉ ════ -->
  <div class="st">Serveur — Sécurité</div>
  <div class="card">
    <div class="row">
      <div class="grow"><div class="k">Pare-feu (UFW)</div><div class="sub">Bloque les connexions non autorisées</div></div>
      <label class="sw"><input type="checkbox" id="t-ufw" onchange="sysToggle('ufw',this)"><span class="sl"></span></label>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Fail2ban</div><div class="sub">Bannit les IP après tentatives échouées</div></div>
      <label class="sw"><input type="checkbox" id="t-fail2ban" onchange="sysToggle('fail2ban',this)"><span class="sl"></span></label>
    </div>
    <div class="row">
      <div class="grow"><div class="k">MAJ auto sécurité</div><div class="sub">unattended-upgrades</div></div>
      <label class="sw"><input type="checkbox" id="t-autoupdate" onchange="sysToggle('autoupdate',this)"><span class="sl"></span></label>
    </div>
    <div class="warn">&#9888; Commandes système réelles. Règle <b>sudo NOPASSWD</b> requise (voir README).</div>
  </div>

  <!-- ════ SERVEUR — ÉTAT ════ -->
  <div class="st">Serveur — État</div>
  <div class="card" id="sysinfo">
    <div class="row"><span class="k">Chargement...</span></div>
  </div>

  <!-- ════ SERVEUR — ACTIONS ════ -->
  <div class="st">Serveur — Actions</div>
  <div class="card">
    <div class="row">
      <div class="grow"><div class="k">Vider le cache RAM</div><div class="sub">sync + drop_caches</div></div>
      <button class="abtn" onclick="sysAction('dropcache',this)">Exécuter</button>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Synchroniser l'horloge</div><div class="sub">NTP / timesyncd</div></div>
      <button class="abtn" onclick="sysAction('ntpsync',this)">Sync</button>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Redémarrer le serveur</div><div class="sub">Reboot complet</div></div>
      <button class="abtn danger" onclick="confirmReboot(this)">Redémarrer</button>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Éteindre le serveur</div><div class="sub">&#9888; Rallumage physique requis</div></div>
      <button class="abtn danger" onclick="confirmPoweroff(this)">Éteindre</button>
    </div>
  </div>

  <!-- ════ PANEL — AFFICHAGE ════ -->
  <div class="st">Panel — Affichage</div>
  <div class="card">
    <div class="row">
      <div class="grow"><div class="k">Thème clair</div><div class="sub">Bascule fond clair / sombre</div></div>
      <label class="sw"><input type="checkbox" id="t-theme" onchange="setTheme(this.checked)"><span class="sl"></span></label>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Densité compacte</div><div class="sub">Réduit les marges des cartes</div></div>
      <label class="sw"><input type="checkbox" id="t-compact" onchange="setOpt('compact',this.checked)"><span class="sl"></span></label>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Uptime détaillé</div><div class="sub">Format long (heures+minutes)</div></div>
      <label class="sw"><input type="checkbox" id="t-uplong" onchange="setOpt('uplong',this.checked)"><span class="sl"></span></label>
    </div>
  </div>

  <!-- ════ PANEL — COMPORTEMENT ════ -->
  <div class="st">Panel — Comportement</div>
  <div class="card">
    <div class="row">
      <div class="grow"><div class="k">Sons</div><div class="sub">Bip lors des actions</div></div>
      <label class="sw"><input type="checkbox" id="t-sound" onchange="setSound(this.checked)"><span class="sl"></span></label>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Auto-scroll logs</div><div class="sub">Suit le bas des logs</div></div>
      <label class="sw"><input type="checkbox" id="t-autoscroll" onchange="setOpt('autoscroll',this.checked)"><span class="sl"></span></label>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Confirmer chaque action</div><div class="sub">Pas seulement Stop</div></div>
      <label class="sw"><input type="checkbox" id="t-confirmall" onchange="setOpt('confirmall',this.checked)"><span class="sl"></span></label>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Rafraîchissement</div><div class="sub">Fréquence de mise à jour</div></div>
      <div class="range">
        <input type="range" id="r-refresh" min="2" max="15" step="1" oninput="setRefresh(this.value)">
        <span class="val" id="r-val">4s</span>
      </div>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Lignes de logs</div><div class="sub">Nombre chargé à l'ouverture</div></div>
      <div class="range">
        <input type="range" id="r-loglines" min="50" max="300" step="50" oninput="setLogLines(this.value)">
        <span class="val" id="r-llval">100</span>
      </div>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Déconnexion auto</div><div class="sub">Inactivité avant logout</div></div>
      <div class="range">
        <input type="range" id="r-idle" min="0" max="60" step="5" oninput="setIdle(this.value)">
        <span class="val" id="r-idleval">off</span>
      </div>
    </div>
  </div>

  <!-- ════ COMPTE / SÉCURITÉ ════ -->
  <div class="st">Compte</div>
  <div class="card">
    <div class="row" style="flex-direction:column;align-items:stretch;gap:8px">
      <div class="k">Changer le mot de passe</div>
      <input type="password" id="pw-cur"  placeholder="Mot de passe actuel" class="inp">
      <input type="password" id="pw-new"  placeholder="Nouveau (12 car. min)" class="inp">
      <button class="abtn" style="margin-left:0;align-self:flex-start" onclick="changePw(this)">Mettre à jour</button>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Verrouiller le panel</div><div class="sub">Déconnexion immédiate</div></div>
      <button class="abtn danger" onclick="lockPanel()">Verrouiller</button>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Exporter la config</div><div class="sub">JSON (sans secrets)</div></div>
      <button class="abtn" onclick="exportCfg()">Exporter</button>
    </div>
  </div>

  <div class="st">Journal</div>
  <div class="card" id="logbox">
    <div class="row"><span class="k">Chargement...</span></div>
  </div>

  <!-- ════ SÉCURITÉ AVANCÉE ════ -->
  <div class="st">Sécurité avancée</div>
  <div class="card">
    <div class="row" style="flex-direction:column;align-items:stretch;gap:8px">
      <div class="k">Code PIN secondaire <span id="pin-state" class="sub" style="display:inline"></span></div>
      <div class="sub">2e facteur après le mot de passe (4-8 chiffres)</div>
      <input type="password" id="pin-cur" placeholder="Mot de passe actuel" class="inp">
      <input type="password" id="pin-val" placeholder="Nouveau PIN (vide = retirer)" inputmode="numeric" class="inp">
      <button class="abtn" style="margin-left:0;align-self:flex-start" onclick="savePin(this)">Enregistrer le PIN</button>
    </div>
    <div class="row" style="flex-direction:column;align-items:stretch;gap:8px">
      <div class="k">Liste blanche d'IP</div>
      <div class="sub">Vide = toutes autorisées. Ton IP <b id="cur-ip">…</b> est protégée (jamais exclue).</div>
      <input type="text" id="wl-ips" placeholder="IP séparées par des virgules" class="inp">
      <button class="abtn" style="margin-left:0;align-self:flex-start" onclick="saveWl(this)">Enregistrer la whitelist</button>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Tentatives max</div><div class="sub">Avant blocage temporaire</div></div>
      <div class="range">
        <input type="range" id="b-max" min="3" max="20" step="1" oninput="document.getElementById('b-maxv').textContent=this.value">
        <span class="val" id="b-maxv">5</span>
      </div>
    </div>
    <div class="row">
      <div class="grow"><div class="k">Fenêtre de blocage</div><div class="sub">Durée avant remise à zéro</div></div>
      <div class="range">
        <input type="range" id="b-win" min="5" max="120" step="5" oninput="document.getElementById('b-winv').textContent=this.value+'min'">
        <span class="val" id="b-winv">15min</span>
      </div>
    </div>
    <div class="row">
      <div class="grow"></div>
      <button class="abtn" onclick="saveBrute(this)">Appliquer brute-force</button>
    </div>
  </div>

  <!-- ════ PROJET ════ -->
  <div class="st">Projet</div>
  <div class="card">
    <a class="link" href="https://github.com/${GITHUB_USER}" target="_blank" rel="noopener">
      <span class="ic">&#128100;</span>
      <span><div class="t">Profil GitHub</div><div class="s">github.com/${GITHUB_USER}</div></span>
      <span class="ar">&#8250;</span>
    </a>
    <a class="link" href="${GITHUB_REPO}" target="_blank" rel="noopener">
      <span class="ic">&#11088;</span>
      <span><div class="t">Code source</div><div class="s">Voir le repo &middot; donner une étoile</div></span>
      <span class="ar">&#8250;</span>
    </a>
  </div>

  <div class="st">Spécifications</div>
  <div class="card" id="specs">
    <div class="row"><span class="k">Chargement...</span></div>
  </div>

  <div class="credit">
    <div class="by">Made by ${GITHUB_USER}</div>
    <div class="tag">${PANEL_NAME} v${APP_VERSION} &middot; MIT License</div>
  </div>
</main>
<script>
// ── Réglages panel (persistés en localStorage) ──
function lsGet(k, d){ try { var v = localStorage.getItem(k); return v === null ? d : v; } catch(e){ return d; } }
function lsSet(k, v){ try { localStorage.setItem(k, v); } catch(e){} }

function setTheme(on){ document.body.classList.toggle('light', on); lsSet('theme', on ? 'light' : 'dark'); }
function setSound(on){ lsSet('sound', on ? '1' : '0'); if(on) beep(); }
function setRefresh(v){ document.getElementById('r-val').textContent = v + 's'; lsSet('refresh', v); }
function setOpt(k, on){ lsSet('opt_' + k, on ? '1' : '0'); }
function setLogLines(v){ document.getElementById('r-llval').textContent = v; lsSet('loglines', v); }
function setIdle(v){ document.getElementById('r-idleval').textContent = v === '0' ? 'off' : v + 'min'; lsSet('idle', v); }

function beep(){
  try {
    var ctx = new (window.AudioContext||window.webkitAudioContext)();
    var o = ctx.createOscillator(), g = ctx.createGain();
    o.connect(g); g.connect(ctx.destination);
    o.frequency.value = 660; g.gain.value = .05;
    o.start(); o.stop(ctx.currentTime + .08);
  } catch(e){}
}

// Init depuis localStorage
(function(){
  var th = lsGet('theme','dark') === 'light';
  document.getElementById('t-theme').checked = th;
  document.body.classList.toggle('light', th);
  document.getElementById('t-sound').checked = lsGet('sound','0') === '1';
  document.getElementById('t-compact').checked    = lsGet('opt_compact','0') === '1';
  document.getElementById('t-uplong').checked     = lsGet('opt_uplong','0') === '1';
  document.getElementById('t-autoscroll').checked = lsGet('opt_autoscroll','1') === '1';
  document.getElementById('t-confirmall').checked = lsGet('opt_confirmall','0') === '1';
  var rf = lsGet('refresh','4');
  document.getElementById('r-refresh').value = rf;
  document.getElementById('r-val').textContent = rf + 's';
  var ll = lsGet('loglines','100');
  document.getElementById('r-loglines').value = ll;
  document.getElementById('r-llval').textContent = ll;
  var idle = lsGet('idle','0');
  document.getElementById('r-idle').value = idle;
  document.getElementById('r-idleval').textContent = idle === '0' ? 'off' : idle + 'min';
})();

// ── Contrôle serveur : toggles ──
async function loadSysStatus(){
  try {
    var r = await fetch('/api/sys/status');
    if (r.status === 401) { location.href='/login'; return; }
    var d = await r.json();
    document.getElementById('t-ufw').checked = !!d.ufw;
    document.getElementById('t-fail2ban').checked = !!d.fail2ban;
    document.getElementById('t-autoupdate').checked = !!d.autoupdate;
  } catch(e){}
}
async function sysToggle(service, el){
  el.disabled = true;
  var state = el.checked ? 'on' : 'off';
  try {
    var r = await fetch('/api/sys/' + service + '/' + state, { method:'POST' });
    var d = await r.json();
    if (!r.ok) { alert(d.error || 'Échec'); el.checked = !el.checked; }
  } catch(e){ alert('Erreur réseau'); el.checked = !el.checked; }
  el.disabled = false;
}

// ── Contrôle serveur : actions ──
async function sysAction(name, el){
  el.disabled = true;
  var old = el.textContent; el.textContent = '...';
  try {
    var r = await fetch('/api/sysaction/' + name, { method:'POST' });
    var d = await r.json();
    if (!r.ok) alert(d.error || 'Échec');
    else el.textContent = '✓';
  } catch(e){ alert('Erreur réseau'); }
  setTimeout(function(){ el.disabled = false; el.textContent = old; }, 1500);
}
function confirmReboot(el){
  if (confirm('Redémarrer le serveur maintenant ? Le panel sera indisponible ~1 min.')) sysAction('reboot', el);
}
function confirmPoweroff(el){
  if (confirm('ÉTEINDRE le serveur ?\\n\\nIl ne pourra être rallumé que physiquement. Confirmer ?')) {
    if (confirm('Vraiment sûr ? Cette action coupe la machine.')) sysAction('poweroff', el);
  }
}

// ── Infos système (état) ──
async function loadSysInfo(){
  try {
    var r = await fetch('/api/sysinfo');
    if (r.status === 401) { location.href='/login'; return; }
    var d = await r.json();
    var h = '';
    // Disques
    (d.disks||[]).forEach(function(dk){
      var hot = dk.pct > 85 ? ' hot' : '';
      h += '<div class="row"><div class="grow"><div class="k">Disque ' + dk.mount + '</div>'
        + '<div class="sub">' + dk.usedGb + ' / ' + dk.sizeGb + ' Go (' + dk.pct + '%)</div>'
        + '<div class="bar"><i class="' + hot.trim() + '" style="width:' + dk.pct + '%"></i></div></div></div>';
    });
    // Température
    if (d.temp != null) {
      var th = d.temp > 70 ? ' hot' : '';
      h += '<div class="row"><div class="grow"><div class="k">Température CPU</div>'
        + '<div class="sub">' + d.temp + '°C</div>'
        + '<div class="bar"><i class="' + th.trim() + '" style="width:' + Math.min(d.temp,100) + '%"></i></div></div></div>';
    }
    // Swap
    if (d.swap) {
      h += '<div class="row"><div class="grow"><div class="k">Swap</div>'
        + '<div class="sub">' + d.swap.usedMb + ' / ' + d.swap.totalMb + ' Mo (' + d.swap.pct + '%)</div>'
        + '<div class="bar"><i style="width:' + d.swap.pct + '%"></i></div></div></div>';
    }
    // Tailscale (lecture seule)
    if (d.tailscale) {
      h += '<div class="row"><span class="k">Tailscale</span><span class="v">'
        + (d.tailscale.up ? '🟢 ' : '🔴 ') + (d.tailscale.ip || '—') + '</span></div>';
    }
    // Top process
    (d.top||[]).forEach(function(p, i){
      if (i === 0) h += '<div class="row"><span class="k" style="color:#8e8e93;font-size:10px;text-transform:uppercase">Top process</span></div>';
      h += '<div class="row"><span class="k">' + (p.name||'') + '</span><span class="v">'
        + p.cpu + '% cpu · ' + p.mem + '% ram</span></div>';
    });
    document.getElementById('sysinfo').innerHTML = h || '<div class="row"><span class="k">Aucune donnée.</span></div>';
  } catch(e){
    document.getElementById('sysinfo').innerHTML = '<div class="row"><span class="k">Erreur de lecture.</span></div>';
  }
}

// ── Compte ──
async function changePw(el){
  var cur = document.getElementById('pw-cur').value;
  var nw  = document.getElementById('pw-new').value;
  if (!cur || !nw) { alert('Remplis les deux champs.'); return; }
  if (nw.length < 12) { alert('12 caractères minimum.'); return; }
  el.disabled = true;
  try {
    var r = await fetch('/api/account/password', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ current: cur, next: nw })
    });
    var d = await r.json();
    if (r.ok) { alert('Mot de passe modifié. Reconnexion requise.'); location.href='/login'; }
    else alert(d.error || 'Échec');
  } catch(e){ alert('Erreur réseau'); }
  el.disabled = false;
}
function lockPanel(){
  if (!confirm('Verrouiller le panel maintenant ?')) return;
  fetch('/logout', {method:'POST'}).finally(function(){ location.href='/login'; });
}
async function exportCfg(){
  try {
    var r = await fetch('/api/account/export');
    var d = await r.json();
    var blob = new Blob([JSON.stringify(d, null, 2)], {type:'application/json'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'h0zelpanel-config.json';
    a.click();
  } catch(e){ alert('Erreur export'); }
}
async function loadLog(){
  try {
    var r = await fetch('/api/account/log');
    if (r.status === 401) { location.href='/login'; return; }
    var d = await r.json();
    var h = '';
    function fmt(ts){ var dt = new Date(ts); return dt.toLocaleDateString() + ' ' + dt.toTimeString().slice(0,5); }
    if (d.audit && d.audit.length) {
      h += '<div class="row"><span class="k" style="color:#8e8e93;font-size:10px;text-transform:uppercase">Actions</span></div>';
      d.audit.slice(0,8).forEach(function(a){
        h += '<div class="logrow"><span class="t">' + fmt(a.at) + '</span><span>' + a.action + '</span><span style="margin-left:auto;color:#48484a">' + a.ip + '</span></div>';
      });
    }
    if (d.logins && d.logins.length) {
      h += '<div class="row"><span class="k" style="color:#8e8e93;font-size:10px;text-transform:uppercase">Connexions</span></div>';
      d.logins.slice(0,8).forEach(function(l){
        h += '<div class="logrow"><span class="t">' + fmt(l.at) + '</span><span class="' + (l.ok?'ok':'no') + '">' + (l.ok?'réussie':'échouée') + '</span><span style="margin-left:auto;color:#48484a">' + l.ip + '</span></div>';
      });
    }
    document.getElementById('logbox').innerHTML = h || '<div class="row"><span class="k">Aucune entrée.</span></div>';
  } catch(e){
    document.getElementById('logbox').innerHTML = '<div class="row"><span class="k">Erreur.</span></div>';
  }
}

// ── Sécurité avancée ──
async function loadSecurity(){
  try {
    var r = await fetch('/api/account/security');
    if (r.status === 401) { location.href='/login'; return; }
    var d = await r.json();
    document.getElementById('pin-state').textContent = d.pinSet ? '· activé' : '· désactivé';
    document.getElementById('cur-ip').textContent = d.currentIp || '?';
    document.getElementById('wl-ips').value = (d.whitelist||[]).join(', ');
    document.getElementById('b-max').value = d.bruteMax; document.getElementById('b-maxv').textContent = d.bruteMax;
    document.getElementById('b-win').value = d.bruteWindowMin; document.getElementById('b-winv').textContent = d.bruteWindowMin + 'min';
  } catch(e){}
}
async function savePin(el){
  var cur = document.getElementById('pin-cur').value;
  var pin = document.getElementById('pin-val').value;
  if (!cur) { alert('Mot de passe actuel requis.'); return; }
  el.disabled = true;
  try {
    var r = await fetch('/api/account/pin', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ current: cur, pin: pin }) });
    var d = await r.json();
    if (r.ok) { alert(d.pinSet ? 'PIN défini.' : 'PIN retiré.'); document.getElementById('pin-cur').value=''; document.getElementById('pin-val').value=''; loadSecurity(); }
    else alert(d.error || 'Échec');
  } catch(e){ alert('Erreur réseau'); }
  el.disabled = false;
}
async function saveWl(el){
  var raw = document.getElementById('wl-ips').value;
  var ips = raw.split(',').map(function(s){return s.trim();}).filter(Boolean);
  if (ips.length && !confirm('Seules ces IP pourront se connecter (ton IP est ajoutée automatiquement). Continuer ?')) return;
  el.disabled = true;
  try {
    var r = await fetch('/api/account/whitelist', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ ips: ips }) });
    var d = await r.json();
    if (r.ok) { document.getElementById('wl-ips').value = (d.whitelist||[]).join(', '); alert('Whitelist enregistrée.'); }
    else alert(d.error || 'Échec');
  } catch(e){ alert('Erreur réseau'); }
  el.disabled = false;
}
async function saveBrute(el){
  el.disabled = true;
  var max = document.getElementById('b-max').value;
  var win = document.getElementById('b-win').value;
  try {
    var r = await fetch('/api/account/brute', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ max: max, windowMin: win }) });
    if (r.ok) { el.textContent = '✓'; setTimeout(function(){ el.textContent='Appliquer brute-force'; }, 1500); }
    else alert('Échec');
  } catch(e){ alert('Erreur réseau'); }
  el.disabled = false;
}

// ── Spécifications (auto-détectées) ──
async function loadSpecs(){
  try {
    var r = await fetch('/api/specs');
    if (r.status === 401) { location.href='/login'; return; }
    var d = await r.json();
    function row(k, v){ return '<div class="row"><span class="k">' + k + '</span><span class="v">' + (v||'—') + '</span></div>'; }
    var h = '';
    h += row('Serveur', d.serverName);
    h += row('Utilisateur', d.user);
    h += row('OS', d.os);
    h += row('Hostname', d.hostname);
    h += row('Kernel', d.kernel);
    h += row('Architecture', d.arch);
    h += row('CPU', d.cpuModel);
    h += row('Cœurs', d.cpuCores);
    h += row('RAM totale', d.ramTotalMb + ' Mo');
    (d.ips||[]).forEach(function(n){ h += row('IP (' + n.iface + ')', n.ip); });
    h += row('Port panel', d.port);
    h += row('Node.js', d.node);
    h += row('Version panel', 'v' + d.panelVersion);
    document.getElementById('specs').innerHTML = h;
  } catch(e){
    document.getElementById('specs').innerHTML = '<div class="row"><span class="k">Erreur de lecture.</span></div>';
  }
}

loadSpecs();
loadSecurity();
loadSysStatus();
loadSysInfo();
loadLog();
setInterval(loadSysInfo, 8000);
</script>
</body></html>`;
}
