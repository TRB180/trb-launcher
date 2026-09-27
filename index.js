/* ═══════════════════════════════════════════════════════════════
   TRB LAUNCHER — Electron Main Process v6.0
   ═══════════════════════════════════════════════════════════════ */
const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const https = require('https');
const http = require('http');
const net = require('net');
const zlib = require('zlib');
const crypto = require('crypto');
const { execSync } = require('child_process');
const os = require('os');

let loginWindow = null;
let mainWindow = null;
let gameProcess = null;
let currentUser = null;
let rpc = null;
let rpcLang = 'ar';

const ROOT = __dirname;
const MC_ROOT = path.join(ROOT, '.minecraft');
const PROFILES_DIR = path.join(ROOT, 'profiles');
const ACCOUNTS_DIR = path.join(ROOT, 'accounts-data');
const DOWNLOADS_DIR = path.join(ROOT, 'downloads');
const JAVA_DIR = path.join(ROOT, 'java');

const PATHS = {
  login: path.join(ROOT, 'login.html'),
  main: path.join(ROOT, 'index.html'),
  icon: path.join(ROOT, 'trb-icon.png')
};

const DISCORD_CLIENT_ID = '1552770979615346778';
const SESSION_FILE = path.join(ROOT, 'session.json');
const PROFILES_FILE = path.join(ROOT, 'profiles.json');
const ACCOUNTS_FILE = path.join(ROOT, 'accounts.json');
const SETTINGS_FILE = path.join(ROOT, 'settings.json');
const SYNC_FILE = path.join(MC_ROOT, '.trb-account.json');

/* ═══ AUTHLIB INJECTOR ═══ */
const AUTHLIB_VERSION = '1.2.5';
const AUTHLIB_JAR = path.join(ROOT, 'authlib-injector.jar');
const AUTHLIB_URL = `https://github.com/yushijinhun/authlib-injector/releases/download/v${AUTHLIB_VERSION}/authlib-injector-${AUTHLIB_VERSION}.jar`;

let authlibServer = null;
let authlibPort = 0;
let authlibUsers = {};
let authlibCurrentUser = null;

function ensureAuthlibInjector() {
  return new Promise(async (resolve) => {
    if (fs.existsSync(AUTHLIB_JAR) && fs.statSync(AUTHLIB_JAR).size > 100000) return resolve(AUTHLIB_JAR);
    try { if (fs.existsSync(AUTHLIB_JAR)) fs.unlinkSync(AUTHLIB_JAR); } catch(e) {}
    console.log('[Authlib] Downloading...');
    try { await downloadFile(AUTHLIB_URL, AUTHLIB_JAR); resolve(AUTHLIB_JAR); }
    catch(e) { console.error('[Authlib] Failed:', e.message); resolve(null); }
  });
}

function startAuthlibServer() {
  return new Promise((resolve, reject) => {
    if (authlibServer && authlibServer.listening) return resolve(authlibPort);

    authlibServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Access-Control-Allow-Origin', '*');

        if (req.url === '/' || req.url.startsWith('/api/yggdrasil')) {
          res.end(JSON.stringify({
            meta: { serverName: 'TRB Auth', implementationName: 'TRB', implementationVersion: '6.0', feature: { non_email_login: true } },
            skinDomains: [], signaturePublickey: ''
          }));
          return;
        }

        if (req.url === '/authserver/authenticate' && req.method === 'POST') {
          try {
            const data = JSON.parse(body || '{}');
            const username = cleanUsername(data.username || (authlibCurrentUser && authlibCurrentUser.username) || 'Player');
            const uuid = (authlibCurrentUser && authlibCurrentUser.uuid) || genUUID();
            const accessToken = crypto.randomBytes(16).toString('hex');
            const clientToken = data.clientToken || crypto.randomBytes(16).toString('hex');
            authlibUsers[uuid] = { name: username, uuid };
            authlibUsers[uuid.replace(/-/g, '').toLowerCase()] = authlibUsers[uuid];
            authlibUsers[accessToken] = authlibUsers[uuid];
            res.end(JSON.stringify({
              accessToken, clientToken,
              selectedProfile: { id: uuid.replace(/-/g, '').toLowerCase(), name: username, properties: [] },
              availableProfiles: [{ id: uuid.replace(/-/g, '').toLowerCase(), name: username, properties: [] }]
            }));
          } catch(e) { res.statusCode = 400; res.end('{}'); }
          return;
        }

        if (req.url === '/authserver/refresh' && req.method === 'POST') {
          try {
            const data = JSON.parse(body || '{}');
            const user = authlibUsers[data.accessToken];
            const accessToken = crypto.randomBytes(16).toString('hex');
            if (user) { authlibUsers[accessToken] = user; res.end(JSON.stringify({ accessToken, clientToken: data.clientToken || accessToken })); }
            else { res.statusCode = 403; res.end('{}'); }
          } catch(e) { res.statusCode = 400; res.end('{}'); }
          return;
        }

        if (req.url === '/authserver/validate' && req.method === 'POST') {
          try { const data = JSON.parse(body || '{}'); if (authlibUsers[data.accessToken]) { res.statusCode = 204; res.end(); } else { res.statusCode = 403; res.end(); } }
          catch(e) { res.statusCode = 400; res.end(); }
          return;
        }

        if (req.url === '/authserver/invalidate' && req.method === 'POST') {
          try { const d = JSON.parse(body || '{}'); delete authlibUsers[d.accessToken]; } catch(e) {}
          res.statusCode = 204; res.end();
          return;
        }

        if (req.url === '/authserver/signout' && req.method === 'POST') {
          try { const d = JSON.parse(body || '{}'); const u = authlibUsers[d.username]; if (u) delete authlibUsers[u.uuid]; } catch(e) {}
          res.statusCode = 204; res.end();
          return;
        }

        const profileMatch = req.url.match(/^\/sessionserver\/session\/minecraft\/profile\/([a-f0-9]+)/i);
        if (profileMatch) {
          const uuidNoDashes = profileMatch[1].toLowerCase();
          const uuidDashed = uuidNoDashes.replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
          let user = authlibUsers[uuidNoDashes] || authlibUsers[uuidDashed];
          if (!user && authlibCurrentUser) {
            const curNoDash = authlibCurrentUser.uuid.replace(/-/g, '').toLowerCase();
            const curDashed = authlibCurrentUser.uuid.toLowerCase();
            if (curNoDash === uuidNoDashes || curDashed === uuidDashed) user = { name: authlibCurrentUser.username, uuid: authlibCurrentUser.uuid };
          }
          if (user) res.end(JSON.stringify({ id: uuidNoDashes, name: user.name, properties: [] }));
          else { res.statusCode = 204; res.end(); }
          return;
        }

        if (req.url.startsWith('/sessionserver/session/minecraft/hasJoined')) { res.statusCode = 204; res.end(); return; }
        res.statusCode = 404; res.end('{}');
      });
    });

    authlibServer.listen(0, '127.0.0.1', () => {
      authlibPort = authlibServer.address().port;
      console.log('[Authlib] Server on port', authlibPort);
      resolve(authlibPort);
    });
    authlibServer.on('error', reject);
  });
}

async function setupAuthlibForLaunch(username, uuid) {
  try {
    const port = await startAuthlibServer();
    authlibCurrentUser = { username, uuid };
    authlibUsers[uuid] = { name: username, uuid };
    authlibUsers[uuid.replace(/-/g, '').toLowerCase()] = authlibUsers[uuid];
    const jarPath = await ensureAuthlibInjector();
    if (!jarPath) return null;
    const jvmArg = `-javaagent:"${jarPath}"=http://127.0.0.1:${port}`;
    return { jarPath, serverUrl: `http://127.0.0.1:${port}`, port, jvmArg };
  } catch(e) { console.error('[Authlib]', e); return null; }
}

function injectAuthlibIntoVersionJson(versionId, jvmArg) {
  try {
    const versionDir = path.join(MC_ROOT, 'versions', versionId);
    const versionJsonPath = path.join(versionDir, `${versionId}.json`);
    if (!fs.existsSync(versionJsonPath)) return false;
    const versionJson = JSON.parse(fs.readFileSync(versionJsonPath, 'utf8'));
    versionJson.arguments = versionJson.arguments || {};
    if (!versionJson.arguments.game || versionJson.arguments.game.length === 0) {
      versionJson.arguments.game = [
        "--username", "${auth_player_name}", "--version", "${version_name}",
        "--gameDir", "${game_directory}", "--assetsDir", "${assets_root}",
        "--assetIndex", "${assets_index_name}", "--uuid", "${auth_uuid}",
        "--accessToken", "${auth_access_token}", "--clientId", "${clientid}",
        "--xuid", "${auth_xuid}", "--userType", "legacy", "--versionType", "${version_type}"
      ];
    }
    versionJson.arguments.jvm = versionJson.arguments.jvm || [];
    versionJson.arguments.jvm = versionJson.arguments.jvm.filter(arg => typeof arg !== 'string' || !arg.includes('authlib-injector'));
    versionJson.arguments.jvm.unshift(jvmArg);
    fs.writeFileSync(versionJsonPath, JSON.stringify(versionJson, null, 2), 'utf8');
    return true;
  } catch(e) { return false; }
}

/* ═══ DISCORD RPC ═══ */
const RPC_STRINGS = {
  ar: { idle: 'في اللانشر', ready: 'جاهز', launching: 'جاري التشغيل', playing: 'يلعب Minecraft' },
  en: { idle: 'In Launcher', ready: 'Ready', launching: 'Launching', playing: 'Playing Minecraft' }
};

function initDiscordRPC() {
  try {
    const DiscordRPC = require('discord-rpc');
    DiscordRPC.register(DISCORD_CLIENT_ID);
    rpc = new DiscordRPC.Client({ transport: 'ipc' });
    rpc.on('ready', () => { console.log('[RPC] Ready'); setRPCIdle(); });
    rpc.login({ clientId: DISCORD_CLIENT_ID }).catch(() => { rpc = null; });
  } catch(e) {}
}

function setRPCIdle() {
  if (!rpc) return;
  const s = RPC_STRINGS[rpcLang] || RPC_STRINGS.ar;
  const u = (currentUser && currentUser.name) || 'Player';
  rpc.setActivity({ details: s.idle, state: s.ready + ' · ' + u, largeImageKey: 'trb', largeImageText: 'TRB Launcher', instance: false, startTimestamp: Date.now() }).catch(() => {});
}
function setRPCLaunching(p) {
  if (!rpc) return;
  const s = RPC_STRINGS[rpcLang] || RPC_STRINGS.ar;
  const u = (currentUser && currentUser.name) || 'Player';
  rpc.setActivity({ details: s.launching + ' · ' + u, state: 'Minecraft ' + p.version, largeImageKey: 'trb', largeImageText: 'TRB Launcher', instance: false, startTimestamp: Date.now() }).catch(() => {});
}
function setRPCPlaying(p) {
  if (!rpc) return;
  const s = RPC_STRINGS[rpcLang] || RPC_STRINGS.ar;
  const u = (currentUser && currentUser.name) || 'Player';
  rpc.setActivity({ details: s.playing + ' ' + p.version, state: u + ' · ' + (p.loader || 'vanilla'), largeImageKey: 'trb', largeImageText: 'TRB Launcher', instance: false, startTimestamp: Date.now() }).catch(() => {});
}
function clearRPC() { if (rpc) rpc.clearActivity().catch(() => {}); }

ipcMain.on('set-rpc-lang', (e, lang) => { rpcLang = lang === 'en' ? 'en' : 'ar'; setRPCIdle(); });

/* ═══ HELPERS ═══ */
function readJSON(file, fallback = {}) {
  try { if (!fs.existsSync(file)) return fallback; return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch(e) { return fallback; }
}

function httpGetJSON(url) {
  return new Promise((resolve) => {
    const opts = { headers: { 'User-Agent': 'TRB-Launcher/1.0' } };
    https.get(url, opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { resolve(null); } });
    }).on('error', () => resolve(null));
  });
}

function downloadFile(url, dest, retries = 3) {
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const file = fs.createWriteStream(dest);
      const opts = { headers: { 'User-Agent': 'TRB-Launcher/6.0' } };
      https.get(url, opts, (res) => {
        if (res.statusCode === 302 || res.statusCode === 301) {
          file.close();
          try { fs.unlinkSync(dest); } catch(e) {}
          return downloadFile(res.headers.location, dest, retries).then(resolve).catch(reject);
        }
        if (res.statusCode !== 200) {
          file.close();
          try { fs.unlinkSync(dest); } catch(e) {}
          if (retries > 0) { setTimeout(() => downloadFile(url, dest, retries - 1).then(resolve).catch(reject), 1000); return; }
          return reject(new Error('HTTP ' + res.statusCode));
        }
        res.pipe(file);
        file.on('finish', () => file.close(resolve));
      }).on('error', (err) => {
        file.close();
        try { fs.unlinkSync(dest); } catch(e) {}
        if (retries > 0) { setTimeout(() => downloadFile(url, dest, retries - 1).then(resolve).catch(reject), 1000); return; }
        reject(err);
      });
    };
    attempt();
  });
}

function getFolderSize(folder) {
  let size = 0;
  try {
    for (const f of fs.readdirSync(folder)) {
      const p = path.join(folder, f);
      const stat = fs.statSync(p);
      if (stat.isDirectory()) size += getFolderSize(p);
      else size += stat.size;
    }
  } catch(e) {}
  return size;
}

function ensureDirectories() {
  try {
    [MC_ROOT, PROFILES_DIR, ACCOUNTS_DIR, DOWNLOADS_DIR, JAVA_DIR].forEach(d => {
      if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    });
    const pp = path.join(MC_ROOT, 'launcher_profiles.json');
    if (!fs.existsSync(pp)) fs.writeFileSync(pp, JSON.stringify({ profiles: {}, settings: {}, version: 3 }, null, 2), 'utf8');
  } catch(e) {}
}

function cleanUsername(name) {
  const c = String(name || 'Player').replace(/[^A-Za-z0-9_]/g, '').slice(0, 16);
  return c.length >= 3 ? c : 'Player';
}

function isValidUUID(s) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s || ''); }

function genUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

/* ═══ PNG GENERATOR ═══ */
function createSolidPng(w, h, r, g, b, alpha) {
  try {
    const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
    function crc32(buf) {
      const table = [];
      for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); table[n] = c; }
      let crc = 0xFFFFFFFF;
      for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
      return (crc ^ 0xFFFFFFFF) >>> 0;
    }
    function chunk(type, data) {
      const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
      const typeBuf = Buffer.from(type, 'ascii');
      const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
      return Buffer.concat([len, typeBuf, data, crc]);
    }
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4);
    ihdr[8] = 8; ihdr[9] = 6;
    const rawData = Buffer.alloc((w * 4 + 1) * h);
    let offset = 0;
    for (let y = 0; y < h; y++) {
      rawData[offset++] = 0;
      for (let x = 0; x < w; x++) { rawData[offset++] = r; rawData[offset++] = g; rawData[offset++] = b; rawData[offset++] = Math.round(alpha * 255); }
    }
    const compressed = zlib.deflateSync(rawData);
    return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', compressed), chunk('IEND', Buffer.alloc(0))]);
  } catch(e) { return null; }
}

/* ═══ PACK FORMAT ═══ */
function getPackFormat(mcVersion) {
  const v = String(mcVersion || '1.21.1');
  const parts = v.split('.').map(n => parseInt(n, 10));
  const M = parts[0], m = parts[1] || 0, p = parts[2] || 0;
  if (M === 1) {
    if (m >= 6 && m <= 8) return 1;
    if (m === 9 || m === 10) return 2;
    if (m === 11 || m === 12) return 3;
    if (m === 13 || m === 14) return 4;
    if (m === 15) return 5;
    if (m === 16 && p === 0) return 5;
    if (m === 16) return 6;
    if (m === 17) return 7;
    if (m === 18) return 8;
    if (m === 19 && p <= 2) return 9;
    if (m === 19 && p === 3) return 12;
    if (m === 19) return 13;
    if (m === 20 && p <= 1) return 15;
    if (m === 20 && p === 2) return 18;
    if (m === 20 && p <= 4) return 22;
    if (m === 20) return 32;
    if (m === 21 && p <= 1) return 34;
    if (m === 21 && p <= 3) return 42;
    if (m === 21 && p === 4) return 46;
    if (m === 21) return 55;
    if (m >= 22) return 65;
  }
  return 34;
}

function getSupportedFormats() { return { min_inclusive: 1, max_inclusive: 999 }; }

/* ═══ PROFILE DIRS ═══ */
function getProfileDir(profileId) {
  if (!profileId) return MC_ROOT;
  const dir = path.join(PROFILES_DIR, profileId);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}
function getProfileModsDir(profileId) {
  const base = getProfileDir(profileId);
  const modsDir = path.join(base, 'mods');
  if (!fs.existsSync(modsDir)) fs.mkdirSync(modsDir, { recursive: true });
  return modsDir;
}
function getProfileResourcePacksDir(profileId) {
  const base = getProfileDir(profileId);
  const rpDir = path.join(base, 'resourcepacks');
  if (!fs.existsSync(rpDir)) fs.mkdirSync(rpDir, { recursive: true });
  return rpDir;
}

/* ═══ SESSION ═══ */
function loadSavedSession() {
  try {
    if (!fs.existsSync(SESSION_FILE)) return null;
    const data = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8'));
    if (data.remember && data.savedAt && Date.now() - data.savedAt > 30 * 24 * 60 * 60 * 1000) { fs.unlinkSync(SESSION_FILE); return null; }
    if (!data.name) return null;
    return data;
  } catch(e) { return null; }
}
function saveSession(user, remember) {
  try {
    if (remember) fs.writeFileSync(SESSION_FILE, JSON.stringify({ ...user, remember: true, savedAt: Date.now() }, null, 2), 'utf8');
    else if (fs.existsSync(SESSION_FILE)) fs.unlinkSync(SESSION_FILE);
  } catch(e) {}
}
function loadSyncedAccount() {
  try { if (!fs.existsSync(SYNC_FILE)) return null; return JSON.parse(fs.readFileSync(SYNC_FILE, 'utf8')); }
  catch(e) { return null; }
}

/* ═══ IPC — SESSION ═══ */
ipcMain.handle('save-session', async (e, { user, remember }) => { saveSession(user, remember); return { success: true }; });
ipcMain.handle('clear-session', async () => { try { if (fs.existsSync(SESSION_FILE)) fs.unlinkSync(SESSION_FILE); return { success: true }; } catch(e) { return { success: false }; } });

/* ═══ IPC — PROFILES ═══ */
ipcMain.handle('save-profiles', async (e, data) => {
  try { const arr = Array.isArray(data) ? data : (data && data.profiles) || []; fs.writeFileSync(PROFILES_FILE, JSON.stringify(arr, null, 2), 'utf8'); return { success: true }; }
  catch(e) { return { success: false, error: e.message }; }
});
ipcMain.handle('load-profiles', async () => { const data = readJSON(PROFILES_FILE, null); return { success: !!data, data }; });

/* ═══ IPC — ACCOUNTS ═══ */
ipcMain.handle('save-accounts', async (e, data) => {
  try { const arr = Array.isArray(data) ? data : (data && data.accounts) || []; fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(arr, null, 2), 'utf8'); return { success: true }; }
  catch(e) { return { success: false, error: e.message }; }
});
ipcMain.handle('load-accounts', async () => { const data = readJSON(ACCOUNTS_FILE, null); return { success: !!data, data }; });

ipcMain.handle('sync-account-with-game', async (e, { accountName, profileId }) => {
  try {
    const clean = cleanUsername(accountName);
    if (!fs.existsSync(MC_ROOT)) fs.mkdirSync(MC_ROOT, { recursive: true });
    fs.writeFileSync(SYNC_FILE, JSON.stringify({ username: clean, originalName: accountName, profileId: profileId || null, syncedAt: Date.now(), mode: 'offline' }, null, 2), 'utf8');
    currentUser = { name: clean, type: 'cracked' };
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('user-data', currentUser);
    setRPCIdle();
    return { success: true, username: clean };
  } catch(e) { return { success: false, error: e.message }; }
});

/* ═══ APPLY CUSTOMIZATION ═══ */
ipcMain.handle('apply-customization', async (e, { profileId, mcVersion, loader, customization }) => {
  try {
    if (!profileId) return { success: false, error: 'No profileId' };
    if (!customization) return { success: false, error: 'No customization' };

    const packFormat = getPackFormat(mcVersion);
    console.log('[Pack]', profileId, '| MC:', mcVersion, '| Format:', packFormat);

    const profileDir = getProfileDir(profileId);
    const locations = [profileDir];
    if (path.resolve(profileDir) !== path.resolve(MC_ROOT)) locations.push(MC_ROOT);
    const results = { files: [], packFormat, locations: [] };

    for (const loc of locations) {
      const rpDir = path.join(loc, 'resourcepacks');
      const optFile = path.join(loc, 'options.txt');
      if (!fs.existsSync(rpDir)) fs.mkdirSync(rpDir, { recursive: true });

      const packDir = path.join(rpDir, 'TRB-Pack');
      if (!fs.existsSync(packDir)) fs.mkdirSync(packDir, { recursive: true });
      results.locations.push(loc);

      const packMeta = {
        pack: {
          pack_format: packFormat,
          supported_formats: getSupportedFormats(),
          description: 'TRB Launcher Pack · Made with love'
        }
      };
      fs.writeFileSync(path.join(packDir, 'pack.mcmeta'), JSON.stringify(packMeta, null, 2), 'utf8');

      if (!fs.existsSync(path.join(packDir, 'pack.png'))) {
        const iconPng = createSolidPng(64, 64, 27, 217, 106, 1);
        if (iconPng) fs.writeFileSync(path.join(packDir, 'pack.png'), iconPng);
      }

      if (customization.logo && customization.logo.data) {
        const base64 = customization.logo.data.split(',')[1];
        if (base64) {
          const buf = Buffer.from(base64, 'base64');
          const targets = [
            ['assets','minecraft','textures','gui','title','minecraft.png'],
            ['assets','minecraft','textures','gui','title','logo.png'],
            ['assets','minecraft','textures','gui','title','edition.png']
          ];
          for (const parts of targets) {
            const dir = path.join(packDir, ...parts.slice(0, -1));
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(path.join(dir, parts[parts.length - 1]), buf);
          }
          if (!results.files.includes('logo')) results.files.push('logo');
        }
      }

      if (customization.panorama && customization.panorama.data) {
        const panoDir = path.join(packDir, 'assets','minecraft','textures','gui','title','background');
        if (!fs.existsSync(panoDir)) fs.mkdirSync(panoDir, { recursive: true });
        const base64 = customization.panorama.data.split(',')[1];
        if (base64) {
          const buf = Buffer.from(base64, 'base64');
          for (let i = 0; i <= 5; i++) fs.writeFileSync(path.join(panoDir, `panorama_${i}.png`), buf);
          if (!results.files.includes('panorama')) results.files.push('panorama');
        }
      }

      if (customization.fastclientMode) {
        const bgDir = path.join(packDir, 'assets','minecraft','textures','gui');
        if (!fs.existsSync(bgDir)) fs.mkdirSync(bgDir, { recursive: true });
        const titleBg = path.join(bgDir, 'title', 'background');
        if (!fs.existsSync(titleBg)) fs.mkdirSync(titleBg, { recursive: true });

        const overlay = createSolidPng(64, 64, 0, 0, 0, 0.5);
        if (overlay) fs.writeFileSync(path.join(titleBg, 'panorama_overlay.png'), overlay);

        const menuBg = createSolidPng(16, 16, 8, 8, 16, 0.92);
        if (menuBg) {
          fs.writeFileSync(path.join(bgDir, 'menu_background.png'), menuBg);
          fs.writeFileSync(path.join(bgDir, 'menu_list_background.png'), menuBg);
          fs.writeFileSync(path.join(bgDir, 'options_background.png'), menuBg);
        }
        if (!results.files.includes('fastclient')) results.files.push('fastclient');
      }

      if (customization.loadingBg && customization.loadingBg.data) {
        const bgDir = path.join(packDir, 'assets','minecraft','textures','gui');
        if (!fs.existsSync(bgDir)) fs.mkdirSync(bgDir, { recursive: true });
        const base64 = customization.loadingBg.data.split(',')[1];
        if (base64) {
          fs.writeFileSync(path.join(bgDir, 'options_background.png'), Buffer.from(base64, 'base64'));
          if (!results.files.includes('loading-bg')) results.files.push('loading-bg');
        }
      }

      if (customization.splash && customization.splash.length > 0) {
        const textDir = path.join(packDir, 'assets','minecraft','texts');
        if (!fs.existsSync(textDir)) fs.mkdirSync(textDir, { recursive: true });
        fs.writeFileSync(path.join(textDir, 'splashes.txt'), customization.splash.join('\n'), 'utf8');
        if (!results.files.includes('splash')) results.files.push('splash');
      }

      let options = {};
      if (fs.existsSync(optFile)) {
        const lines = fs.readFileSync(optFile, 'utf8').split('\n');
        lines.forEach(line => {
          const idx = line.indexOf(':');
          if (idx > 0) { const k = line.slice(0, idx).trim(); const v = line.slice(idx + 1).trim(); if (k) options[k] = v; }
        });
      }

      let packs = [];
      try { packs = JSON.parse(options.resourcePacks || '[]'); if (!Array.isArray(packs)) packs = []; } catch(e) { packs = []; }
      packs = packs.filter(p => p !== 'file/TRB-Pack');
      packs.unshift('file/TRB-Pack');
      options.resourcePacks = JSON.stringify(packs);

      let incomp = [];
      try { incomp = JSON.parse(options.incompatibleResourcePacks || '[]'); if (!Array.isArray(incomp)) incomp = []; } catch(e) { incomp = []; }
      incomp = incomp.filter(p => p !== 'file/TRB-Pack');
      incomp.unshift('file/TRB-Pack');
      options.incompatibleResourcePacks = JSON.stringify(incomp);

      const newOptions = Object.keys(options).map(k => `${k}:${options[k]}`).join('\n');
      fs.writeFileSync(optFile, newOptions, 'utf8');
    }

    return { success: true, applied: results };
  } catch(err) { return { success: false, error: err.message }; }
});

/* ═══ DELETE FOLDERS ═══ */
ipcMain.handle('delete-account-folder', async (e, { accountId }) => {
  try {
    if (accountId) { const accDir = path.join(ACCOUNTS_DIR, accountId); if (fs.existsSync(accDir)) fs.rmSync(accDir, { recursive: true, force: true }); }
    if (fs.existsSync(SYNC_FILE)) { try { fs.unlinkSync(SYNC_FILE); } catch(e) {} }
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});

ipcMain.handle('delete-profile-folder', async (e, { profileId }) => {
  try {
    if (!profileId) return { success: false, error: 'No profileId' };
    const dir = path.join(PROFILES_DIR, profileId);
    if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});

/* ═══ FABRIC LOADER ═══ */
async function installFabricLoader(mcVersion) {
  try {
    const versionsDir = path.join(MC_ROOT, 'versions');
    if (!fs.existsSync(versionsDir)) fs.mkdirSync(versionsDir, { recursive: true });

    try {
      for (const v of fs.readdirSync(versionsDir)) {
        if (v.startsWith('fabric-loader-') && v.endsWith(mcVersion)) fs.rmSync(path.join(versionsDir, v), { recursive: true, force: true });
      }
    } catch(e) {}

    const loaderList = await httpGetJSON('https://meta.fabricmc.net/v2/versions/loader');
    if (!loaderList || !loaderList.length) return { success: false, error: 'Failed to fetch Fabric' };
    const loaderVersion = loaderList[0].version;
    const fabricVersionId = `fabric-loader-${loaderVersion}-${mcVersion}`;
    const fabricDir = path.join(versionsDir, fabricVersionId);
    const fabricJsonPath = path.join(fabricDir, `${fabricVersionId}.json`);
    const fabricJarPath = path.join(fabricDir, `${fabricVersionId}.jar`);

    const vanillaDir = path.join(versionsDir, mcVersion);
    const vanillaJar = path.join(vanillaDir, `${mcVersion}.jar`);
    const vanillaJsonPath = path.join(vanillaDir, `${mcVersion}.json`);
    if (!fs.existsSync(vanillaJar) || !fs.existsSync(vanillaJsonPath)) return { success: false, error: 'need-vanilla-first' };

    if (!fs.existsSync(fabricDir)) fs.mkdirSync(fabricDir, { recursive: true });

    const profile = await httpGetJSON(`https://meta.fabricmc.net/v2/versions/loader/${mcVersion}/${loaderVersion}/profile/json`);
    if (!profile || !profile.id) return { success: false, error: 'Failed profile' };

    profile.id = fabricVersionId;
    profile.inheritsFrom = mcVersion;

    const vanillaData = JSON.parse(fs.readFileSync(vanillaJsonPath, 'utf8'));
    const fields = ['assetIndex','assets','downloads','javaVersion','logging','type','complianceLevel','minimumLauncherVersion','releaseTime','time','mainClass','arguments','minecraftArguments'];
    for (const f of fields) if (vanillaData[f] !== undefined && profile[f] === undefined) profile[f] = vanillaData[f];

    const vanillaLibs = vanillaData.libraries || [];
    const fabricLibs = profile.libraries || [];
    const names = new Set(vanillaLibs.map(l => l.name));
    const merged = [...vanillaLibs];
    for (const fl of fabricLibs) if (!names.has(fl.name)) merged.push(fl);

    profile.libraries = merged.map(lib => {
      if (lib.downloads && lib.downloads.artifact && lib.downloads.artifact.url) return lib;
      if (lib.name && (!lib.downloads || !lib.downloads.artifact)) {
        const parts = lib.name.split(':');
        if (parts.length >= 3) {
          const group = parts[0], artifact = parts[1], version = parts[2];
          const groupPath = group.replace(/\./g, '/');
          const fileName = `${artifact}-${version}.jar`;
          const mavenUrl = group.startsWith('net.fabricmc') || group.startsWith('org.spongepowered')
            ? `https://maven.fabricmc.net/${groupPath}/${artifact}/${version}/${fileName}`
            : `https://libraries.minecraft.net/${groupPath}/${artifact}/${version}/${fileName}`;
          lib.downloads = lib.downloads || {};
          lib.downloads.artifact = { path: `${groupPath}/${artifact}/${version}/${fileName}`, url: mavenUrl, size: 0, sha1: '' };
        }
      }
      return lib;
    });

    profile.arguments = profile.arguments || {};
    if (!profile.arguments.game || profile.arguments.game.length === 0) {
      if (vanillaData.arguments && vanillaData.arguments.game) profile.arguments.game = vanillaData.arguments.game;
    }

    fs.writeFileSync(fabricJsonPath, JSON.stringify(profile, null, 2), 'utf8');
    fs.copyFileSync(vanillaJar, fabricJarPath);
    return { success: true, versionId: fabricVersionId, loaderVersion };
  } catch(e) { return { success: false, error: e.message }; }
}

/* ═══ QUILT LOADER ═══ */
async function installQuiltLoader(mcVersion) {
  try {
    const versionsDir = path.join(MC_ROOT, 'versions');
    if (!fs.existsSync(versionsDir)) fs.mkdirSync(versionsDir, { recursive: true });

    try {
      for (const v of fs.readdirSync(versionsDir)) {
        if (v.startsWith('quilt-loader-') && v.endsWith(mcVersion)) fs.rmSync(path.join(versionsDir, v), { recursive: true, force: true });
      }
    } catch(e) {}

    const loaderList = await httpGetJSON('https://meta.quiltmc.org/v3/versions/loader');
    if (!loaderList || !loaderList.length) return { success: false, error: 'Failed Quilt' };
    const loaderVersion = loaderList[0].version;
    const quiltVersionId = `quilt-loader-${loaderVersion}-${mcVersion}`;
    const quiltDir = path.join(versionsDir, quiltVersionId);
    const quiltJsonPath = path.join(quiltDir, `${quiltVersionId}.json`);
    const quiltJarPath = path.join(quiltDir, `${quiltVersionId}.jar`);

    const vanillaDir = path.join(versionsDir, mcVersion);
    const vanillaJar = path.join(vanillaDir, `${mcVersion}.jar`);
    const vanillaJsonPath = path.join(vanillaDir, `${mcVersion}.json`);
    if (!fs.existsSync(vanillaJar) || !fs.existsSync(vanillaJsonPath)) return { success: false, error: 'need-vanilla-first' };

    if (!fs.existsSync(quiltDir)) fs.mkdirSync(quiltDir, { recursive: true });

    const profile = await httpGetJSON(`https://meta.quiltmc.org/v3/versions/loader/${mcVersion}/${loaderVersion}/profile/json`);
    if (!profile || !profile.id) return { success: false, error: 'Failed profile' };

    profile.id = quiltVersionId;
    profile.inheritsFrom = mcVersion;

    const vanillaData = JSON.parse(fs.readFileSync(vanillaJsonPath, 'utf8'));
    const fields = ['assetIndex','assets','downloads','javaVersion','logging','type','mainClass','arguments','minecraftArguments'];
    for (const f of fields) if (vanillaData[f] !== undefined && profile[f] === undefined) profile[f] = vanillaData[f];

    const vanillaLibs = vanillaData.libraries || [];
    const quiltLibs = profile.libraries || [];
    const names = new Set(vanillaLibs.map(l => l.name));
    for (const ql of quiltLibs) if (!names.has(ql.name)) vanillaLibs.push(ql);

    profile.libraries = vanillaLibs.map(lib => {
      if (lib.downloads && lib.downloads.artifact && lib.downloads.artifact.url) return lib;
      if (lib.name && (!lib.downloads || !lib.downloads.artifact)) {
        const parts = lib.name.split(':');
        if (parts.length >= 3) {
          const group = parts[0], artifact = parts[1], version = parts[2];
          const groupPath = group.replace(/\./g, '/');
          const fileName = `${artifact}-${version}.jar`;
          const mavenUrl = group.startsWith('org.quiltmc')
            ? `https://maven.quiltmc.org/repository/release/${groupPath}/${artifact}/${version}/${fileName}`
            : `https://libraries.minecraft.net/${groupPath}/${artifact}/${version}/${fileName}`;
          lib.downloads = lib.downloads || {};
          lib.downloads.artifact = { path: `${groupPath}/${artifact}/${version}/${fileName}`, url: mavenUrl, size: 0, sha1: '' };
        }
      }
      return lib;
    });

    profile.arguments = profile.arguments || {};
    if (!profile.arguments.game || profile.arguments.game.length === 0) {
      if (vanillaData.arguments && vanillaData.arguments.game) profile.arguments.game = vanillaData.arguments.game;
    }

    fs.writeFileSync(quiltJsonPath, JSON.stringify(profile, null, 2), 'utf8');
    fs.copyFileSync(vanillaJar, quiltJarPath);
    return { success: true, versionId: quiltVersionId, loaderVersion };
  } catch(e) { return { success: false, error: e.message }; }
}

/* ═══ JAVA DETECTION ═══ */
function pickJavaForVersion(mcVersion) {
  const s = String(mcVersion || '');
  if (s.startsWith('26.')) return 21;
  const parts = s.split('.');
  const major = parseInt(parts[0], 10) || 1;
  const minor = parseInt(parts[1], 10) || 0;
  const patch = parseInt(parts[2], 10) || 0;
  if (major === 1 && minor === 21) return 21;
  if (major === 1 && minor === 20 && patch >= 5) return 21;
  if (major === 1 && minor >= 17 && minor <= 20) return 17;
  return 8;
}

function findJava(mcVersion) {
  const dirs = [
    JAVA_DIR,
    'C:\\Java', 'C:\\Program Files\\Java', 'C:\\Program Files\\Eclipse Adoptium',
    'C:\\Program Files\\Microsoft', 'C:\\Program Files\\BellSoft', 'C:\\Program Files\\Zulu',
    'C:\\Program Files\\Amazon Corretto', 'C:\\Program Files\\Azul',
    'C:\\Program Files (x86)\\Java', '/usr/lib/jvm', '/Library/Java/JavaVirtualMachines'
  ];
  const candidates = [];

  for (const dir of dirs) {
    try {
      if (!fs.existsSync(dir)) continue;
      for (const entry of fs.readdirSync(dir)) {
        const full = path.join(dir, entry);
        const paths = [path.join(full, 'bin', 'java.exe'), path.join(full, 'bin', 'java'), path.join(full, 'Contents', 'Home', 'bin', 'java')];
        for (const p of paths) if (fs.existsSync(p)) candidates.push(p);
      }
    } catch(e) {}
  }

  try {
    const which = execSync('where java', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    which.split('\n').map(l => l.trim()).filter(Boolean).forEach(p => { if (fs.existsSync(p) && !candidates.includes(p)) candidates.push(p); });
  } catch(e) {}

  if (candidates.length === 0) return null;

  function getVer(p) {
    try {
      const out = execSync(`"${p}" -version 2>&1`, { encoding: 'utf8', timeout: 5000 });
      const m = out.match(/version "([^"]+)"/);
      if (!m) return 0;
      const v = m[1];
      if (v.startsWith('1.')) return parseInt(v.split('.')[1], 10);
      return parseInt(v.split('.')[0], 10);
    } catch(e) { return 0; }
  }

  const scored = candidates.map(p => ({ path: p, version: getVer(p) }));
  const wanted = pickJavaForVersion(mcVersion);
  const exact = scored.filter(s => s.version === wanted);
  if (exact.length > 0) return exact[0].path;
  const higher = scored.filter(s => s.version >= wanted).sort((a, b) => a.version - b.version);
  if (higher.length > 0) return higher[0].path;
  scored.sort((a, b) => b.version - a.version);
  return scored[0].path;
}

/* ═══ LAUNCH GAME ═══ */
ipcMain.handle('launch-game', async (event, config) => {
  const send = (type, payload) => {
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('launch-progress', { type, ...payload });
  };

  try {
    const { version, loader, ram, username, uuid, profileName, profileId } = config;

    console.log('═══════════════════════════');
    console.log('[LAUNCH]', profileName, '|', version, '|', loader);
    console.log('═══════════════════════════');

    let finalUsername = cleanUsername(username);
    if (finalUsername === 'Player' || !username) {
      const synced = loadSyncedAccount();
      if (synced && synced.username) finalUsername = cleanUsername(synced.username);
    }
    if (finalUsername === 'Player' && currentUser && currentUser.name) finalUsername = cleanUsername(currentUser.name);

    const safeUuid = isValidUUID(uuid) ? uuid : genUUID();
    if (currentUser) currentUser.name = finalUsername;
    setRPCLaunching({ name: profileName || 'Profile', version, loader, ram });

    send('status', { message: 'Verifying Java...' });
    await new Promise(r => setTimeout(r, 400));

    let finalVersion = version || '1.21.1';

    if (loader && loader.toLowerCase() === 'fabric') {
      send('status', { message: 'Preparing Fabric...' });
      const r = await installFabricLoader(finalVersion);
      if (r.success) { finalVersion = r.versionId; send('status', { message: 'Fabric ready' }); }
      else if (r.error === 'need-vanilla-first') send('status', { message: 'Downloading vanilla...' });
    } else if (loader && loader.toLowerCase() === 'quilt') {
      send('status', { message: 'Preparing Quilt...' });
      const r = await installQuiltLoader(finalVersion);
      if (r.success) { finalVersion = r.versionId; send('status', { message: 'Quilt ready' }); }
    }

    let javaPath = findJava(version);

// Auto-download Java if not found
if (!javaPath) {
  send('status', { message: 'Java not found. Auto-downloading...' });
  console.log('[Launch] Java missing — attempting auto-download...');
  
  try {
    const major = getJavaMajorForMc(version);
    const platform = os.platform() === 'win32' ? 'windows' : (os.platform() === 'darwin' ? 'mac' : 'linux');
    const arch = os.arch() === 'arm64' ? 'aarch64' : 'x64';
    
    const release = await getAdoptiumRelease(major, platform, arch);
    if (!release || !release.downloadUrl) {
      return { success: false, error: 'Java not installed and download failed.' };
    }
    
    send('status', { message: `Downloading Java ${major}...` });
    
    const targetDir = path.join(JAVA_DIR, getJavaDirName(major));
    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });
    if (!fs.existsSync(DOWNLOADS_DIR)) fs.mkdirSync(DOWNLOADS_DIR, { recursive: true });
    
    const archivePath = path.join(DOWNLOADS_DIR, release.fileName);
    await downloadFile(release.downloadUrl, archivePath);
    
    send('status', { message: 'Extracting Java...' });
    
    if (release.fileName.endsWith('.zip')) {
      const AdmZip = require('adm-zip');
      const zip = new AdmZip(archivePath);
      zip.extractAllTo(targetDir, true);
    } else if (release.fileName.endsWith('.tar.gz') || release.fileName.endsWith('.tgz')) {
      execSync(`tar -xzf "${archivePath}" -C "${targetDir}"`, { stdio: 'ignore' });
    }
    
    try { fs.unlinkSync(archivePath); } catch(e) {}
    
    javaPath = findLocalJava(major);
    if (!javaPath) {
      return { success: false, error: 'Java downloaded but not found after extract.' };
    }
    
    send('status', { message: 'Java installed: ' + release.version });
    console.log('[Launch] Auto-installed Java:', javaPath);
  } catch(e) {
    return { success: false, error: 'Auto-download failed: ' + e.message };
  }
}

        const settings = readJSON(SETTINGS_FILE, {});
        const customJvmArgs = settings.jvmArgs || '';
    
    if (customJvmArgs) opts.overrides.customArgs = customJvmArgs.split(/\s+/).filter(Boolean);
        let Client;
    try { Client = require('minecraft-launcher-core').Client; }
    catch(e) { return { success: false, error: 'Please run: npm install minecraft-launcher-core' }; }

    const launcher = new Client();
    const profileGameDir = profileId ? getProfileDir(profileId) : MC_ROOT;

    const opts = {
      authorization: { access_token: safeUuid, client_token: safeUuid, uuid: safeUuid, name: finalUsername, user_properties: '{}', meta: { type: 'legacy', demo: false, online: false } },
      root: MC_ROOT,
      version: { number: finalVersion, type: 'release' },
      memory: { max: (ram || '4') + 'G', min: '2G' },
      javaPath,
      overrides: { detached: false, gameDirectory: profileGameDir }
    };

    if (customJvmArgs) opts.overrides.customArgs = customJvmArgs.split(/\s+/).filter(Boolean);

    launcher.on('debug', e => console.log('[MC-DEBUG]', e));
    launcher.on('data', e => { console.log('[MC]', e); send('status', { message: String(e).slice(0, 200) }); });
    launcher.on('download-status', e => { const pct = e.total ? Math.round((e.current / e.total) * 100) : 0; send('download', { message: `Downloading ${e.name || 'file'}`, percent: pct }); });
    launcher.on('progress', e => { const pct = e.total ? Math.round((e.task / e.total) * 100) : 0; send('progress', { message: 'Verifying...', percent: pct }); });
    launcher.on('close', code => {
      send('close', { code });
      gameProcess = null;
      setRPCIdle();
      
      setTimeout(() => {
        try {
          const profileDir = profileId ? getProfileDir(profileId) : MC_ROOT;
          const logPaths = [
            path.join(profileDir, 'logs', 'latest.log'),
            path.join(MC_ROOT, 'logs', 'latest.log')
          ];
          
          let logContent = '';
          let foundLog = '';
          for (const lp of logPaths) {
            if (fs.existsSync(lp)) {
              const stat = fs.statSync(lp);
              if (Date.now() - stat.mtimeMs < 120000) {
                logContent = fs.readFileSync(lp, 'utf8');
                foundLog = lp;
                break;
              }
            }
          }
          
          if (logContent) {
            const indicators = ['---- Minecraft Crash Report ----', 'Exception in thread "main"', 'FATAL ERROR', 'A fatal error has been detected', 'outofmemoryerror', 'the game crashed'];
            const lowerLog = logContent.toLowerCase();
            const hasCrash = indicators.some(ind => lowerLog.includes(ind.toLowerCase()));
            
            if (hasCrash || (code !== 0 && code !== null && code !== undefined)) {
              console.log('[Crash] Detected! Code:', code);
              if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.webContents.send('game-crashed', { exitCode: code || -1, profileId, logPath: foundLog });
              }
            }
          }
        } catch(e) { console.error('[Crash Check]', e.message); }
      }, 1500);
});
    launcher.on('error', err => send('error', { message: err.message || 'Error' }));

    send('status', { message: 'Downloading game files...' });
    gameProcess = await launcher.launch(opts);
    setRPCPlaying({ name: profileName || 'Profile', version, loader, ram });
    return { success: true, message: 'Launched', pid: gameProcess?.pid || null, username: finalUsername };
  } catch(err) {
    console.error('[LAUNCH ERROR]', err);
    send('error', { message: err.message });
    setRPCIdle();
    return { success: false, error: err.message };
  }
});

ipcMain.on('kill-game', () => {
  try {
    if (gameProcess && !gameProcess.killed) {
      gameProcess.kill('SIGTERM');
      setTimeout(() => { try { if (gameProcess && !gameProcess.killed) gameProcess.kill('SIGKILL'); } catch(e) {} }, 2000);
      gameProcess = null;
      setRPCIdle();
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('game-closed');
    }
  } catch(e) {}
});

/* ═══ MOD INSTALL ═══ */
ipcMain.handle('install-mod', async (event, { projectId, slug, mcVersion, loader, profileId }) => {
  try {
    const modsDir = getProfileModsDir(profileId);
    const versions = await httpGetJSON(`https://api.modrinth.com/v2/project/${projectId}/version`);
    if (!versions || versions.length === 0) return { success: false, error: 'No versions available' };

    const wantVersion = mcVersion || '1.21.1';
    const wantLoader = (loader || 'fabric').toLowerCase();
    let chosen = null;

    for (const v of versions) {
      const gv = v.game_versions || [];
      const ld = (v.loaders || []).map(x => x.toLowerCase());
      if (gv.includes(wantVersion) && ld.includes(wantLoader)) { chosen = v; break; }
    }
    if (!chosen && wantLoader !== 'vanilla') {
      const loaderMatches = versions.filter(v => (v.loaders || []).map(x => x.toLowerCase()).includes(wantLoader));
      if (loaderMatches.length) {
        loaderMatches.sort((a, b) => {
          const aMatch = (a.game_versions || []).includes(wantVersion) ? 1 : 0;
          const bMatch = (b.game_versions || []).includes(wantVersion) ? 1 : 0;
          return bMatch - aMatch;
        });
        chosen = loaderMatches[0];
      }
    }
    if (!chosen) chosen = versions[0];
    if (!chosen || !chosen.files || chosen.files.length === 0) return { success: false, error: 'No compatible file found' };

    const file = chosen.files.find(f => f.primary) || chosen.files[0];
    const destPath = path.join(modsDir, file.filename);
    await downloadFile(file.url, destPath);
    return { success: true, filename: file.filename, version: chosen.version_number, gameVersion: chosen.game_versions[0] };
  } catch(err) { return { success: false, error: err.message }; }
});

ipcMain.handle('uninstall-mod', async (event, { filename, profileId }) => {
  try {
    const modsDir = getProfileModsDir(profileId);
    const target = path.join(modsDir, filename);
    if (fs.existsSync(target)) fs.unlinkSync(target);
    return { success: true };
  } catch(err) { return { success: false, error: err.message }; }
});

ipcMain.handle('list-installed-mods', async (event, { profileId }) => {
  try {
    const modsDir = getProfileModsDir(profileId);
    return { success: true, mods: fs.readdirSync(modsDir).filter(f => f.endsWith('.jar')) };
  } catch(err) { return { success: false, error: err.message, mods: [] }; }
});

/* ═══ RESOURCE PACK INSTALL ═══ */
ipcMain.handle('install-resourcepack', async (event, { projectId, slug, mcVersion, profileId }) => {
  try {
    const rpDir = profileId ? getProfileResourcePacksDir(profileId) : path.join(MC_ROOT, 'resourcepacks');
    if (!fs.existsSync(rpDir)) fs.mkdirSync(rpDir, { recursive: true });

    const versions = await httpGetJSON(`https://api.modrinth.com/v2/project/${projectId}/version`);
    if (!versions || !versions.length) return { success: false, error: 'No versions available' };

    let chosen = null;
    if (mcVersion) {
      for (const v of versions) { if ((v.game_versions || []).includes(mcVersion)) { chosen = v; break; } }
    }
    if (!chosen) chosen = versions[0];
    if (!chosen.files || !chosen.files.length) return { success: false, error: 'No files' };

    const file = chosen.files.find(f => f.filename.endsWith('.zip')) || chosen.files[0];
    await downloadFile(file.url, path.join(rpDir, file.filename));
    return { success: true, filename: file.filename, version: chosen.version_number };
  } catch(err) { return { success: false, error: err.message }; }
});

ipcMain.handle('list-resourcepacks', async (event, { profileId }) => {
  try {
    const rpDir = profileId ? getProfileResourcePacksDir(profileId) : path.join(MC_ROOT, 'resourcepacks');
    if (!fs.existsSync(rpDir)) return { success: true, packs: [] };
    const packs = fs.readdirSync(rpDir).map(f => {
      const p = path.join(rpDir, f);
      const stat = fs.statSync(p);
      return { name: f, size: stat.isDirectory() ? getFolderSize(p) : stat.size, isDirectory: stat.isDirectory() };
    });
    return { success: true, packs };
  } catch(err) { return { success: false, error: err.message, packs: [] }; }
});

ipcMain.handle('delete-resourcepack', async (event, { filename, profileId }) => {
  try {
    const rpDir = profileId ? getProfileResourcePacksDir(profileId) : path.join(MC_ROOT, 'resourcepacks');
    const target = path.join(rpDir, filename);
    if (fs.existsSync(target)) {
      const stat = fs.statSync(target);
      if (stat.isDirectory()) fs.rmSync(target, { recursive: true, force: true });
      else fs.unlinkSync(target);
    }
    return { success: true };
  } catch(err) { return { success: false, error: err.message }; }
});

/* ═══ INSTALL MODPACK FULL ═══ */
ipcMain.handle('install-modpack-full', async (e, { projectId, mcVersion, loader, profileName }) => {
  try {
    const send = (type, payload) => { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('launch-progress', { type, ...payload }); };

    send('status', { message: 'Fetching modpack info...' });
    const project = await httpGetJSON(`https://api.modrinth.com/v2/project/${projectId}`);
    if (!project) return { success: false, error: 'Project not found' };

    const versions = await httpGetJSON(`https://api.modrinth.com/v2/project/${projectId}/version`);
    if (!versions || !versions.length) return { success: false, error: 'No versions available' };

    let chosen = null;
    const wantLoader = (loader || 'fabric').toLowerCase();
    for (const v of versions) {
      const gv = v.game_versions || [];
      const ld = (v.loaders || []).map(x => x.toLowerCase());
      if (mcVersion && gv.includes(mcVersion) && ld.includes(wantLoader)) { chosen = v; break; }
    }
    if (!chosen) chosen = versions[0];

    const file = chosen.files && (chosen.files.find(f => f.primary) || chosen.files[0]);
    if (!file) return { success: false, error: 'No file available' };

    const profileId = 'mp_' + projectId.slice(0, 8) + '_' + Date.now();
    const profileDir = getProfileDir(profileId);

    send('status', { message: 'Downloading ' + project.title + '...' });
    if (!fs.existsSync(DOWNLOADS_DIR)) fs.mkdirSync(DOWNLOADS_DIR, { recursive: true });
    const packPath = path.join(DOWNLOADS_DIR, file.filename);
    await downloadFile(file.url, packPath);

    send('status', { message: 'Extracting...' });
    try { const AdmZip = require('adm-zip'); const zip = new AdmZip(packPath); zip.extractAllTo(profileDir, true); }
    catch(e) { console.error('[Extract]', e); }

    let iconPath = null;
    if (project.icon_url) {
      try { const iconFile = path.join(profileDir, 'icon.png'); await downloadFile(project.icon_url, iconFile); iconPath = 'file:///' + iconFile.replace(/\\/g, '/'); } catch(e) {}
    }

    return {
      success: true,
      profile: {
        id: profileId,
        name: profileName || project.title,
        version: chosen.game_versions[0] || mcVersion || '1.21.1',
        loader: chosen.loaders[0] || loader || 'fabric',
        ram: '6',
        icon: iconPath,
        description: project.description,
        projectId,
        slug: project.slug,
        modpackVersion: chosen.version_number,
        size: (file.size / 1024 / 1024).toFixed(1) + ' MB',
        downloadedAt: Date.now(),
        folderPath: profileDir,
        mods: [], packs: [], playtime: 0, launches: 0, lastPlayed: null, color: '#1bd96a'
      }
    };
  } catch(err) { return { success: false, error: err.message }; }
});

/* ═══ SYSTEM ═══ */
ipcMain.handle('install-fabric', async (event, { version }) => await installFabricLoader(version || '1.21.1'));

ipcMain.handle('get-system-info', async () => ({
  success: true,
  platform: os.platform(),
  arch: os.arch(),
  cpus: os.cpus().length,
  totalMem: Math.round(os.totalmem() / (1024 ** 3)),
  freeMem: Math.round(os.freemem() / (1024 ** 3)),
  javaPath: findJava('1.21.1') || 'Not found'
}));

ipcMain.handle('get-mojang-versions', async () => {
  try {
    const data = await httpGetJSON('https://launchermeta.mojang.com/mc/game/version_manifest_v2.json');
    if (!data || !data.versions) return { success: false, error: 'Failed to fetch' };
    const releases = data.versions.filter(v => v.type === 'release').map(v => ({ id: v.id, type: v.type, released: v.releaseTime, url: v.url }));
    return { success: true, versions: releases };
  } catch(err) { return { success: false, error: err.message }; }
});

/* ═══ SHELL ═══ */
ipcMain.on('open-external', (e, url) => shell.openExternal(url));

ipcMain.on('open-mc-folder', (e, folder) => {
  const map = { mods: ['mods'], resourcepacks: ['resourcepacks'], shaderpacks: ['shaderpacks'], saves: ['saves'], screenshots: ['screenshots'], root: [], logs: ['logs'], versions: ['versions'], profiles: ['../profiles'] };
  const sub = map[folder] || [folder];
  const target = path.join(MC_ROOT, ...sub);
  if (!fs.existsSync(target)) fs.mkdirSync(target, { recursive: true });
  shell.openPath(target);
});

ipcMain.on('open-folder', (e, folder) => {
  const target = path.join(MC_ROOT, folder);
  if (!fs.existsSync(target)) fs.mkdirSync(target, { recursive: true });
  shell.openPath(target);
});

/* ═══ DEV PANEL ═══ */
ipcMain.handle('dev-get-info', async () => {
  try {
    let versions = [];
    const vd = path.join(MC_ROOT, 'versions');
    if (fs.existsSync(vd)) versions = fs.readdirSync(vd);
    const profiles = readJSON(PROFILES_FILE, []);
    const accounts = readJSON(ACCOUNTS_FILE, []);
    return {
      success: true,
      stats: {
        versions: versions.length,
        profiles: Array.isArray(profiles) ? profiles.length : 0,
        mcSize: fs.existsSync(MC_ROOT) ? getFolderSize(MC_ROOT) : 0,
        accounts: Array.isArray(accounts) ? accounts.length : 0
      }
    };
  } catch(e) { return { success: false, error: e.message }; }
});

ipcMain.handle('dev-clear-cache', async () => {
  try {
    const cd = path.join(MC_ROOT, 'cache');
    if (fs.existsSync(cd)) fs.rmSync(cd, { recursive: true, force: true });
    const ld = path.join(MC_ROOT, 'logs');
    if (fs.existsSync(ld)) fs.rmSync(ld, { recursive: true, force: true });
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});

/* ═══ PING SERVER ═══ */
ipcMain.handle('ping-server', async (e, { host, port }) => {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch(e) {}
      resolve({ success: true, online: ok, ping: ok ? (Date.now() - start) : null });
    };
    socket.setTimeout(3000);
    socket.on('connect', () => finish(true));
    socket.on('timeout', () => finish(false));
    socket.on('error', () => finish(false));
    try { socket.connect(port || 25565, host); }
    catch(e) { finish(false); }
  });
});

/* ═══ SETTINGS ═══ */
ipcMain.handle('save-settings', async (e, data) => { try { fs.writeFileSync(SETTINGS_FILE, JSON.stringify(data, null, 2), 'utf8'); return { success: true }; } catch(e) { return { success: false, error: e.message }; } });
ipcMain.handle('load-settings', async () => { try { if (!fs.existsSync(SETTINGS_FILE)) return { success: true, data: {} }; return { success: true, data: JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')) }; } catch(e) { return { success: false, error: e.message }; } });

/* ═══ WORLDS ═══ */
ipcMain.handle('list-worlds', async (event, { profileId } = {}) => {
  try {
    const profileDir = profileId ? getProfileDir(profileId) : MC_ROOT;
    const dir = path.join(profileDir, 'saves');
    if (!fs.existsSync(dir)) return { success: true, worlds: [] };
    const worlds = fs.readdirSync(dir, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => {
      const p = path.join(dir, d.name);
      return { name: d.name, size: getFolderSize(p), modified: fs.statSync(p).mtime };
    });
    return { success: true, worlds };
  } catch(err) { return { success: false, error: err.message, worlds: [] }; }
});

ipcMain.handle('delete-world', async (event, { name, profileId }) => {
  try {
    const profileDir = profileId ? getProfileDir(profileId) : MC_ROOT;
    const target = path.join(profileDir, 'saves', name);
    if (fs.existsSync(target)) fs.rmSync(target, { recursive: true, force: true });
    return { success: true };
  } catch(err) { return { success: false, error: err.message }; }
});

ipcMain.handle('list-screenshots', async (event, { profileId } = {}) => {
  try {
    const profileDir = profileId ? getProfileDir(profileId) : MC_ROOT;
    const dir = path.join(profileDir, 'screenshots');
    if (!fs.existsSync(dir)) return { success: true, screenshots: [] };
    const files = fs.readdirSync(dir).filter(f => f.match(/\.(png|jpg|jpeg)$/i)).map(f => ({
      name: f, url: 'file:///' + path.join(dir, f).replace(/\\/g, '/'), size: fs.statSync(path.join(dir, f)).size, modified: fs.statSync(path.join(dir, f)).mtime
    })).sort((a, b) => b.modified - a.modified);
    return { success: true, screenshots: files };
  } catch(err) { return { success: false, error: err.message, screenshots: [] }; }
});

/* ═══ WINDOWS ═══ */
function createLoginWindow() {
  loginWindow = new BrowserWindow({
    width: 980, height: 720, minWidth: 900, minHeight: 660,
    frame: false, resizable: false, center: true,
    backgroundColor: '#05070b', icon: PATHS.icon,
    webPreferences: { nodeIntegration: true, contextIsolation: false }
  });
  loginWindow.loadFile(PATHS.login);
  loginWindow.setMenuBarVisibility(false);
  loginWindow.on('closed', () => { loginWindow = null; if (!mainWindow) app.quit(); });
}

function createMainWindow(user) {
  if (user) currentUser = user;
  mainWindow = new BrowserWindow({
    width: 1440, height: 900, minWidth: 1200, minHeight: 720,
    frame: false, show: false,
    backgroundColor: '#05070b', icon: PATHS.icon,
    webPreferences: { nodeIntegration: true, contextIsolation: false }
  });
  mainWindow.loadFile(PATHS.main);
  mainWindow.setMenuBarVisibility(false);
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (loginWindow && !loginWindow.isDestroyed()) loginWindow.close();
    setRPCIdle();
  });
  mainWindow.webContents.on('did-finish-load', () => { if (currentUser) mainWindow.webContents.send('user-data', currentUser); });
  mainWindow.on('closed', () => { mainWindow = null; });
}

/* ═══ APP READY ═══ */
app.whenReady().then(() => {
  console.log('');
  console.log('═════════════════════════════════════════════');
  console.log('   TRB LAUNCHER v1.0');
  console.log('   ROOT:', ROOT);
  console.log('═════════════════════════════════════════════');
  console.log('');

  ensureDirectories();
  initDiscordRPC();
  startAuthlibServer().catch(e => console.error('[Authlib]', e));

  const synced = loadSyncedAccount();
  if (synced && synced.username) currentUser = { name: synced.username, type: 'cracked' };

  const session = loadSavedSession();
  if (session && session.remember) {
    currentUser = session;
    if (synced && synced.username) currentUser.name = synced.username;
    createMainWindow(currentUser);
  } else {
    createLoginWindow();
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      const s = loadSavedSession();
      if (s && s.remember) createMainWindow(s);
      else createLoginWindow();
    }
  });
});

app.on('window-all-closed', () => {
  clearRPC();
  if (authlibServer) { try { authlibServer.close(); } catch(e) {} }
  if (process.platform !== 'darwin') app.quit();
});

/* ═══ WINDOW CONTROLS + AUTH ═══ */
ipcMain.on('window-minimize', (e) => { const w = BrowserWindow.fromWebContents(e.sender); if (w) w.minimize(); });
ipcMain.on('window-maximize', (e) => { const w = BrowserWindow.fromWebContents(e.sender); if (!w) return; w.isMaximized() ? w.unmaximize() : w.maximize(); });
ipcMain.on('window-close', (e) => { const w = BrowserWindow.fromWebContents(e.sender); if (w) w.close(); });

ipcMain.on('login-success', (event, user) => {
  currentUser = user || { name: 'Player', type: 'cracked' };
  if (!mainWindow || mainWindow.isDestroyed()) createMainWindow(currentUser);
  else { mainWindow.show(); mainWindow.focus(); if (loginWindow && !loginWindow.isDestroyed()) loginWindow.close(); }
  setRPCIdle();
});

ipcMain.on('logout', () => {
  currentUser = null;
  setRPCIdle();
  if (mainWindow && !mainWindow.isDestroyed()) { mainWindow.close(); mainWindow = null; }
  setTimeout(() => { if (!loginWindow || loginWindow.isDestroyed()) createLoginWindow(); }, 200);
});
/* ═══ AUTO JAVA DOWNLOAD ═══ */
const ADOPTIUM_API = 'https://api.adoptium.net/v3';

async function getAdoptiumRelease(javaVersion, platform = 'windows', arch = 'x64') {
  try {
    const url = `${ADOPTIUM_API}/assets/latest/${javaVersion}/hotspot?architecture=${arch}&image_type=jdk&os=${platform}&vendor=eclipse`;
    const data = await httpGetJSON(url);
    if (!data || !Array.isArray(data) || data.length === 0) return null;
    const release = data[0];
    const binary = release.binary || {};
    const pkg = binary.package || {};
    return {
      version: release.version?.semver || 'unknown',
      releaseName: release.release_name,
      downloadUrl: pkg.link,
      fileName: pkg.name,
      size: pkg.size
    };
  } catch(e) {
    console.error('[AutoJava] Fetch failed:', e.message);
    return null;
  }
}

function getJavaMajorForMc(mcVersion) {
  const s = String(mcVersion || '');
  if (s.startsWith('26.')) return 21;
  const parts = s.split('.');
  const major = parseInt(parts[0], 10) || 1;
  const minor = parseInt(parts[1], 10) || 0;
  const patch = parseInt(parts[2], 10) || 0;
  if (major === 1 && minor === 21) return 21;
  if (major === 1 && minor === 20 && patch >= 5) return 21;
  if (major === 1 && minor >= 17 && minor <= 20) return 17;
  return 8;
}

function getJavaDirName(major) {
  return `jdk-${major}`;
}

function findLocalJava(major) {
  try {
    const dir = path.join(JAVA_DIR, getJavaDirName(major));
    if (!fs.existsSync(dir)) return null;
    const entries = fs.readdirSync(dir);
    for (const entry of entries) {
      const full = path.join(dir, entry);
      const candidates = [
        path.join(full, 'bin', 'java.exe'),
        path.join(full, 'bin', 'java'),
        path.join(full, 'Contents', 'Home', 'bin', 'java')
      ];
      for (const c of candidates) {
        if (fs.existsSync(c)) return c;
      }
    }
    const directExe = path.join(dir, 'bin', 'java.exe');
    if (fs.existsSync(directExe)) return directExe;
    const directExe2 = path.join(dir, 'bin', 'java');
    if (fs.existsSync(directExe2)) return directExe2;
  } catch(e) {}
  return null;
}

ipcMain.handle('auto-download-java', async (event, { mcVersion }) => {
  const send = (type, payload) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('launch-progress', { type, ...payload });
    }
  };

  try {
    const major = getJavaMajorForMc(mcVersion);
    console.log('[AutoJava] Required: Java', major, 'for MC', mcVersion);

    // Check local first
    const local = findLocalJava(major);
    if (local) {
      console.log('[AutoJava] Found local:', local);
      return { success: true, alreadyExists: true, javaPath: local };
    }

    // Check system
    const systemJava = findJava(mcVersion);
    if (systemJava) {
      console.log('[AutoJava] Found system:', systemJava);
      return { success: true, alreadyExists: true, javaPath: systemJava };
    }

    // Need to download
    send('status', { message: `Java ${major} not found. Downloading...` });
    console.log('[AutoJava] Downloading Java', major, 'from Adoptium...');

    const platform = os.platform() === 'win32' ? 'windows' : (os.platform() === 'darwin' ? 'mac' : 'linux');
    const arch = os.arch() === 'arm64' ? 'aarch64' : 'x64';

    const release = await getAdoptiumRelease(major, platform, arch);
    if (!release || !release.downloadUrl) {
      return { success: false, error: 'Failed to fetch Java from Adoptium' };
    }

    send('status', { message: `Downloading ${release.fileName}...` });

    const targetDir = path.join(JAVA_DIR, getJavaDirName(major));
    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

    const archivePath = path.join(DOWNLOADS_DIR, release.fileName);
    if (!fs.existsSync(DOWNLOADS_DIR)) fs.mkdirSync(DOWNLOADS_DIR, { recursive: true });

    await downloadFile(release.downloadUrl, archivePath);
    send('status', { message: 'Extracting Java...' });

    // Extract using tar (built-in on Win10+) or unzip
    try {
      if (release.fileName.endsWith('.zip')) {
        const AdmZip = require('adm-zip');
        const zip = new AdmZip(archivePath);
        zip.extractAllTo(targetDir, true);
      } else if (release.fileName.endsWith('.tar.gz') || release.fileName.endsWith('.tgz')) {
        execSync(`tar -xzf "${archivePath}" -C "${targetDir}"`, { stdio: 'ignore' });
      } else if (release.fileName.endsWith('.tar.gz')) {
        execSync(`tar -xzf "${archivePath}" -C "${targetDir}"`, { stdio: 'ignore' });
      }
    } catch(e) {
      console.error('[AutoJava] Extract failed:', e.message);
      return { success: false, error: 'Extract failed: ' + e.message };
    }

    // Clean archive
    try { fs.unlinkSync(archivePath); } catch(e) {}

    // Find java.exe in the extracted folder
    const javaPath = findLocalJava(major);
    if (!javaPath) {
      return { success: false, error: 'Java extracted but binary not found' };
    }

    send('status', { message: `Java ${major} installed!` });
    console.log('[AutoJava] Installed:', javaPath);
    return { success: true, downloaded: true, javaPath, version: release.version };
  } catch(e) {
    console.error('[AutoJava] Error:', e);
    return { success: false, error: e.message };
  }
});
/* ═══ CRASH REPORTER ═══ */
function analyzeCrashLog(logContent) {
  const lines = String(logContent || '').split('\n');
  const text = logContent.toLowerCase();
  const issues = [];

  if (text.includes('outofmemoryerror') || text.includes('java heap space')) {
    issues.push({
      type: 'ram',
      title: 'Not enough RAM',
      desc: 'The game ran out of memory. Increase RAM allocation in profile settings.',
      severity: 'high'
    });
  }
  if (text.includes('nosuchmethoderror') || text.includes('noclassdeffounderror')) {
    issues.push({
      type: 'missing-lib',
      title: 'Missing library or mod dependency',
      desc: 'A mod needs another mod/library that is not installed. Check mod requirements.',
      severity: 'high'
    });
  }
  if (text.includes('mod resolution') || text.includes('incompatible mods')) {
    issues.push({
      type: 'mod-conflict',
      title: 'Mod conflict detected',
      desc: 'Two or more mods are incompatible. Remove recently added mods.',
      severity: 'high'
    });
  }
  if (text.includes('unsupportedclassversionerror')) {
    issues.push({
      type: 'java-version',
      title: 'Wrong Java version',
      desc: 'The Java version does not match the game version. Try Java 21 for 1.21+.',
      severity: 'high'
    });
  }
  if (text.includes('glfw error') || text.includes('opengl')) {
    issues.push({
      type: 'graphics',
      title: 'Graphics driver issue',
      desc: 'Update your GPU drivers or check shader settings.',
      severity: 'medium'
    });
  }
  if (text.includes('failed to download') || text.includes('connection timed out')) {
    issues.push({
      type: 'network',
      title: 'Network error',
      desc: 'Game files could not be downloaded. Check your internet connection.',
      severity: 'medium'
    });
  }
  if (text.includes('exception in thread') && issues.length === 0) {
    issues.push({
      type: 'unknown',
      title: 'Unknown error',
      desc: 'Check the full log below for details.',
      severity: 'low'
    });
  }

  return {
    issues,
    lastLines: lines.slice(-50).join('\n'),
    lineCount: lines.length
  };
}

ipcMain.handle('check-crash', async (event, { profileId }) => {
  try {
    const profileDir = profileId ? getProfileDir(profileId) : MC_ROOT;
    const possibleLogs = [
      path.join(profileDir, 'logs', 'latest.log'),
      path.join(MC_ROOT, 'logs', 'latest.log'),
      path.join(profileDir, 'crash-reports'),
      path.join(MC_ROOT, 'crash-reports')
    ];

    let logContent = '';
    let logPath = '';

    // Try latest.log first
    for (const p of possibleLogs) {
      if (fs.existsSync(p) && fs.statSync(p).isFile()) {
        logContent = fs.readFileSync(p, 'utf8');
        logPath = p;
        break;
      }
    }

    // Try latest crash report
    if (!logContent) {
      for (const dir of [path.join(profileDir, 'crash-reports'), path.join(MC_ROOT, 'crash-reports')]) {
        if (fs.existsSync(dir) && fs.statSync(dir).isDirectory()) {
          const files = fs.readdirSync(dir).filter(f => f.endsWith('.txt')).sort().reverse();
          if (files.length > 0) {
            logPath = path.join(dir, files[0]);
            logContent = fs.readFileSync(logPath, 'utf8');
            break;
          }
        }
      }
    }

    if (!logContent) {
      return { success: false, error: 'No log file found' };
    }

    const analysis = analyzeCrashLog(logContent);
    return {
      success: true,
      logPath,
      ...analysis
    };
  } catch(e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('detect-crash', async (event, { profileId, exitCode }) => {
  try {
    const profileDir = profileId ? getProfileDir(profileId) : MC_ROOT;
    const logPath = path.join(profileDir, 'logs', 'latest.log');
    const altLog = path.join(MC_ROOT, 'logs', 'latest.log');
    const finalPath = fs.existsSync(logPath) ? logPath : (fs.existsSync(altLog) ? altLog : null);
    if (!finalPath) return { success: false, crashed: false };

    const stat = fs.statSync(finalPath);
    const recent = Date.now() - stat.mtimeMs < 60000; // modified in last minute
    
    if (exitCode !== 0 && exitCode !== undefined && exitCode !== null) {
      return { success: true, crashed: true, exitCode, logPath: finalPath };
    }
    if (recent && exitCode !== 0) {
      return { success: true, crashed: true, exitCode, logPath: finalPath };
    }
    return { success: true, crashed: false };
  } catch(e) {
    return { success: false, error: e.message };
  }
});
/* ═══ VERSION MANAGER ═══ */
ipcMain.handle('list-versions', async () => {
  try {
    const versionsDir = path.join(MC_ROOT, 'versions');
    if (!fs.existsSync(versionsDir)) return { success: true, versions: [] };
    const versions = [];
    for (const name of fs.readdirSync(versionsDir)) {
      const dir = path.join(versionsDir, name);
      try {
        const stat = fs.statSync(dir);
        if (!stat.isDirectory()) continue;
        const hasJar = fs.existsSync(path.join(dir, `${name}.jar`));
        const hasJson = fs.existsSync(path.join(dir, `${name}.json`));
        if (!hasJar && !hasJson) continue;
        versions.push({
          name,
          size: getFolderSize(dir),
          modified: stat.mtime.getTime(),
          hasJar,
          hasJson
        });
      } catch(e) {}
    }
    versions.sort((a, b) => b.modified - a.modified);
    return { success: true, versions };
  } catch(e) { return { success: false, error: e.message, versions: [] }; }
});

ipcMain.handle('delete-version', async (e, { name }) => {
  try {
    if (!name) return { success: false, error: 'No version name' };
    const target = path.join(MC_ROOT, 'versions', name);
    if (!fs.existsSync(target)) return { success: false, error: 'Version not found' };
    fs.rmSync(target, { recursive: true, force: true });
    console.log('[Version] Deleted:', name);
    return { success: true };
  } catch(e) { return { success: false, error: e.message }; }
});
/* ═══ GLOBAL HANDLERS ═══ */
process.on('uncaughtException', (error) => console.error('Uncaught:', error));
process.on('unhandledRejection', (reason) => console.error('Unhandled:', reason));

console.log('');
console.log('╔═══════════════════════════════════════════╗');
console.log('║   TRB Launcher — Main Process Ready       ║');
console.log('║   [OK] Full IPC handlers                  ║');
console.log('║   [OK] Resource Pack (all versions)       ║');
console.log('║   [OK] Fabric + Quilt loaders             ║');
console.log('║   [OK] Modrinth mods                      ║');
console.log('║   [OK] Authlib injector                   ║');
console.log('║   [OK] Discord RPC                        ║');
console.log('║   [OK] Developer panel                    ║');
console.log('╚═══════════════════════════════════════════╝');
console.log('');