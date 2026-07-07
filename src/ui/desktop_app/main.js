const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs   = require('fs');

// ── Paths ──────────────────────────────────────────────────────────────────
const DB_PATH   = path.join(__dirname, '../../../data/system_monitor.db');
const HTML_PATH = path.join(__dirname, '../web/index.html');

// ── Username resolution from /etc/passwd ──────────────────────────────────
let passwdCache = null;
function uidToUsername(uid) {
    try {
        if (!passwdCache) passwdCache = fs.readFileSync('/etc/passwd', 'utf8');
        const line = passwdCache.split('\n').find(l => {
            const p = l.split(':');
            return p.length >= 3 && parseInt(p[2], 10) === uid;
        });
        return line ? line.split(':')[0] : `UID:${uid}`;
    } catch {
        return `UID:${uid}`;
    }
}

// ── IPC handler — reads SQLite directly, no HTTP layer ────────────────────
ipcMain.handle('db:get-data', () => {
    // Lazy-require so the module can be rebuilt without restarting
    let Database;
    try {
        Database = require('better-sqlite3');
    } catch (e) {
        console.error('[DB] better-sqlite3 not available:', e.message);
        return { net_stats: [], flows: [], file_writes: [], priv_esc: [] };
    }

    if (!fs.existsSync(DB_PATH)) {
        return { net_stats: [], flows: [], file_writes: [], priv_esc: [] };
    }

    try {
        const db = new Database(DB_PATH, { readonly: true, fileMustExist: true });

        const net_stats = db.prepare(`
            SELECT pid, MAX(comm) as comm, COUNT(*) as conns,
                   SUM(tx_packets) as tx_pkts, SUM(rx_packets) as rx_pkts
            FROM udp_flows
            GROUP BY pid
            ORDER BY SUM(tx_packets + rx_packets) DESC
        `).all();

        const flows = db.prepare(`
            SELECT * FROM udp_flows
            ORDER BY (tx_packets + rx_packets) DESC
        `).all();

        const file_writes = db.prepare(`
            SELECT * FROM file_writes
            ORDER BY bytes_written DESC
        `).all();

        const priv_esc = db.prepare(`
            SELECT * FROM priv_esc
            ORDER BY escalation_count DESC
        `).all().map(row => ({
            ...row,
            username: uidToUsername(row.old_uid)
        }));

        db.close();
        return { net_stats, flows, file_writes, priv_esc };

    } catch (err) {
        console.error('[DB] Query error:', err.message);
        return { net_stats: [], flows: [], file_writes: [], priv_esc: [] };
    }
});

// ── Window ─────────────────────────────────────────────────────────────────
let mainWindow;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        backgroundColor: '#0c0e13',
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
        },
        title: 'Unified EDR Monitor',
        show: false
    });

    mainWindow.setMenuBarVisibility(false);

    // Load the HTML directly as a local file — no HTTP server needed
    mainWindow.loadFile(HTML_PATH);
    mainWindow.once('ready-to-show', () => mainWindow.show());
    mainWindow.on('closed', () => { mainWindow = null; });
}

app.on('ready', createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});
