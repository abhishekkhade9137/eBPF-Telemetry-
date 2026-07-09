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

// --- Threat Configuration ---
let threatConfig = {
    suspiciousNames: ['nc', 'ncat', 'netcat', 'bash', 'sh', 'curl', 'wget'],
    ioThresholdMB: 50,
    networkThresholdPkts: 1000,
    filesTouchedThreshold: 100
};

ipcMain.handle('config:update', (event, newConfig) => {
    threatConfig = { ...threatConfig, ...newConfig };
    return { success: true };
});

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

        // --- Aggregation for UI (Moved from Frontend) ---
        const commMap = {};
        const ensure = (pid, comm) => {
            const name = comm || 'unknown';
            if (!commMap[name]) {
                commMap[name] = { comm: name, pids: new Set(), flows: 0, tx: 0, rx: 0, writes: 0, bytes: 0, filesTouched: 0, privEsc: false };
            }
            if (pid) commMap[name].pids.add(pid);
        };
        flows.forEach(f => {
            ensure(f.pid, f.comm);
            commMap[f.comm || 'unknown'].flows++;
            commMap[f.comm || 'unknown'].tx += f.tx_packets;
            commMap[f.comm || 'unknown'].rx += f.rx_packets;
        });
        file_writes.forEach(w => {
            ensure(w.pid, w.comm);
            commMap[w.comm || 'unknown'].writes += w.write_calls;
            commMap[w.comm || 'unknown'].bytes  += w.bytes_written;
            commMap[w.comm || 'unknown'].filesTouched += 1;
        });
        priv_esc.forEach(p => {
            ensure(p.pid, p.comm);
            commMap[p.comm || 'unknown'].privEsc = true;
        });

        const procList = Object.values(commMap).map(p => ({
            ...p,
            pids: Array.from(p.pids)
        })).sort((a, b) => (b.tx + b.rx) - (a.tx + a.rx));

        // Evaluate Threats
        const threats = [];

        Object.values(commMap).forEach(p => {
            let reasons = [];
            let severity = 'Low';

            if (p.privEsc) {
                reasons.push('Triggered Privilege Escalation (SetUID change) event.');
                severity = 'High';
            }

            if (threatConfig.suspiciousNames.includes(p.comm) && (p.flows > 0 || p.tx > 0 || p.rx > 0)) {
                reasons.push(`Suspicious binary '${p.comm}' is making network connections (Possible reverse shell or exfiltration).`);
                severity = severity === 'High' ? 'High' : 'Medium';
            }

            if (p.bytes > threatConfig.ioThresholdMB * 1024 * 1024 && (p.tx > threatConfig.networkThresholdPkts || p.rx > threatConfig.networkThresholdPkts)) {
                reasons.push('High volume of File I/O combined with heavy network traffic.');
                severity = severity === 'High' ? 'High' : 'Medium';
            }

            if (p.filesTouched > threatConfig.filesTouchedThreshold) {
                reasons.push(`Rapidly modifying a large number of files (${p.filesTouched} files touched - Possible Ransomware).`);
                severity = severity === 'High' ? 'High' : 'Medium';
            }

            if (reasons.length > 0) {
                threats.push({
                    comm: p.comm,
                    pids: Array.from(p.pids),
                    severity,
                    reasons
                });
            }
        });
        
        // Sort threats: High first
        threats.sort((a, b) => (a.severity === 'High' ? -1 : (b.severity === 'High' ? 1 : 0)));

        const cleanCommMap = {};
        procList.forEach(p => cleanCommMap[p.comm] = p);

        db.close();
        return { net_stats, flows, file_writes, priv_esc, commMap: cleanCommMap, procList, threats };

    } catch (err) {
        console.error('[DB] Query error:', err.message);
        return { net_stats: [], flows: [], file_writes: [], priv_esc: [], commMap: {}, procList: [], threats: [] };
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
