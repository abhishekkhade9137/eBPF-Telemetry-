document.addEventListener('DOMContentLoaded', () => {

    // ═══════════════════════════════════════════════════════
    //  STATE
    // ═══════════════════════════════════════════════════════
    let latestData   = { flows: [], file_writes: [], priv_esc: [], net_stats: [] };
    let currentPid   = null;
    let sortState    = {};            // { tableId: { col, dir, type } }
    let activeSubTab = 'detail-network';
    let activeSection = 'processes';

    // ─── Keyed-row tracking: tableId → Map<key, tr> ────────
    // Lets us patch only changed cells instead of rebuilding the whole table.
    const rowMaps = {};

    // ═══════════════════════════════════════════════════════
    //  NAVIGATION – main tabs
    // ═══════════════════════════════════════════════════════
    const navItems  = document.querySelectorAll('.nav-item');
    const sections  = document.querySelectorAll('.section');
    const pageTitle = document.getElementById('page-title');
    const btnBack   = document.getElementById('btn-back');

    const sectionTitles = {
        'processes':      'Per Process View',
        'process-detail': 'Process Detail',
        'global-network': 'Global Network Flows',
        'global-io':      'Global File I/O',
        'global-priv':    'Global Privilege Escalations',
    };

    function showSection(id) {
        activeSection = id;
        sections.forEach(s => s.classList.remove('active'));
        document.getElementById(id).classList.add('active');
        pageTitle.textContent = sectionTitles[id] || id;

        if (id === 'process-detail') {
            btnBack.classList.remove('hidden');
            navItems.forEach(n => n.classList.remove('active'));
        } else {
            btnBack.classList.add('hidden');
            navItems.forEach(n => n.classList.toggle('active', n.dataset.target === id));
        }
    }

    navItems.forEach(item => {
        item.addEventListener('click', e => {
            e.preventDefault();
            currentPid = null;
            showSection(item.dataset.target);
        });
    });

    btnBack.addEventListener('click', () => {
        currentPid = null;
        showSection('processes');
    });

    // ═══════════════════════════════════════════════════════
    //  NAVIGATION – sub-tabs
    // ═══════════════════════════════════════════════════════
    document.querySelectorAll('.sub-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            activeSubTab = tab.dataset.subtab;
            applySubTab(activeSubTab);
        });
    });

    function applySubTab(id) {
        document.querySelectorAll('.sub-tab').forEach(t =>
            t.classList.toggle('active', t.dataset.subtab === id));
        document.querySelectorAll('.sub-section').forEach(s =>
            s.classList.toggle('active', s.id === id));
    }

    // ═══════════════════════════════════════════════════════
    //  SORT ENGINE — persistent across refreshes
    // ═══════════════════════════════════════════════════════
    function sortRows(tbody, col, dir, type) {
        Array.from(tbody.rows)
            .sort((a, b) => {
                const av = a.cells[col]?.textContent.trim() || '';
                const bv = b.cells[col]?.textContent.trim() || '';
                if (type === 'num') {
                    return dir === 'asc'
                        ? (parseFloat(av) || 0) - (parseFloat(bv) || 0)
                        : (parseFloat(bv) || 0) - (parseFloat(av) || 0);
                }
                return dir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
            })
            .forEach(r => tbody.appendChild(r));
    }

    function reapplySort(tableId) {
        const state = sortState[tableId];
        if (!state) return;
        const table = document.getElementById(tableId);
        if (!table) return;
        table.querySelectorAll('.sort-icon').forEach(i => i.textContent = '⇅');
        const activeTh = table.querySelector(`th[data-col="${state.col}"]`);
        if (activeTh) activeTh.querySelector('.sort-icon').textContent = state.dir === 'asc' ? '▲' : '▼';
        sortRows(table.querySelector('tbody'), state.col, state.dir, state.type);
    }

    function makeSortable(tableId) {
        const table = document.getElementById(tableId);
        if (!table) return;
        table.querySelectorAll('th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const col  = parseInt(th.dataset.col);
                const type = th.dataset.type;
                const prev = sortState[tableId] || {};
                const dir  = (prev.col === col && prev.dir === 'asc') ? 'desc' : 'asc';
                sortState[tableId] = { col, dir, type };
                table.querySelectorAll('.sort-icon').forEach(i => i.textContent = '⇅');
                th.querySelector('.sort-icon').textContent = dir === 'asc' ? '▲' : '▼';
                sortRows(table.querySelector('tbody'), col, dir, type);
            });
        });
    }

    [
        'table-processes',
        'table-global-network', 'table-global-io', 'table-global-priv',
        'table-detail-network', 'table-detail-io', 'table-detail-priv',
    ].forEach(makeSortable);

    // ═══════════════════════════════════════════════════════
    //  SEARCH FILTER (persists across refreshes)
    // ═══════════════════════════════════════════════════════
    function applySearch() {
        const q = document.getElementById('proc-search').value.trim().toLowerCase();
        document.querySelectorAll('#table-processes tbody tr').forEach(tr => {
            tr.style.display = (!q || tr.textContent.toLowerCase().includes(q)) ? '' : 'none';
        });
    }
    document.getElementById('proc-search').addEventListener('input', applySearch);

    // ═══════════════════════════════════════════════════════
    //  HELPERS
    // ═══════════════════════════════════════════════════════
    function fmtBytes(b) {
        if (!b) return '0 B';
        if (b < 1024) return b + ' B';
        if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
        return (b / 1048576).toFixed(2) + ' MB';
    }

    function fmtTime(ms) {
        if (!ms) return '—';
        const d = new Date(ms);
        const pad = n => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ` +
               `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    }

    function renderEmpty(tableId, msg) {
        const tbody = document.querySelector(`#${tableId} tbody`);
        if (!tbody) return;
        const cols = document.querySelectorAll(`#${tableId} th`).length;
        tbody.innerHTML = `<tr><td colspan="${cols}" class="empty-state">
            <span class="icon">◌</span>${msg}</td></tr>`;
        // Reset row map since we wiped the tbody
        rowMaps[tableId] = new Map();
    }

    // ═══════════════════════════════════════════════════════
    //  KEYED DIFF RENDERER — NO full wipe, NO scroll jump
    // ═══════════════════════════════════════════════════════
    /**
     * Diff-patches a tbody using a stable key per row.
     *
     * @param {string}   tableId
     * @param {Array}    rows        – data rows to display
     * @param {Function} keyFn       – (row) => unique string key
     * @param {Function} cellsFn     – (row) => array of {html, raw} per cell
     *                                   `html` is innerHTML, `raw` is the text used
     *                                   for dirty-check (omit to always use html)
     * @param {Function} [onNew]     – optional callback(tr, row) after a new <tr> is inserted
     */
    function patchTable(tableId, rows, keyFn, cellsFn, onNew) {
        const tbody = document.querySelector(`#${tableId} tbody`);
        if (!tbody) return;

        if (!rowMaps[tableId]) rowMaps[tableId] = new Map();
        const map = rowMaps[tableId];

        if (!rows.length) {
            // Preserve empty-state only if already shown
            if (tbody.querySelector('.empty-state')) return;
            renderEmpty(tableId, 'No data yet');
            return;
        }

        // Remove stale empty-state row if present
        const emptyRow = tbody.querySelector('.empty-state');
        if (emptyRow) {
            emptyRow.closest('tr').remove();
            map.clear();
        }

        const newKeys = new Set();

        rows.forEach((row, idx) => {
            const key = keyFn(row);
            newKeys.add(key);
            const cells = cellsFn(row);

            if (map.has(key)) {
                // ── Existing row: patch only changed cells ──────────
                const tr = map.get(key);
                cells.forEach((cell, ci) => {
                    const td = tr.cells[ci];
                    if (!td) return;
                    const dirty = cell.raw !== undefined
                        ? td.dataset.raw !== String(cell.raw)
                        : td.innerHTML !== cell.html;
                    if (dirty) {
                        td.innerHTML = cell.html;
                        if (cell.raw !== undefined) td.dataset.raw = String(cell.raw);
                    }
                });
            } else {
                // ── New row: create and insert ──────────────────────
                const tr = document.createElement('tr');
                cells.forEach(cell => {
                    const td = document.createElement('td');
                    td.innerHTML = cell.html;
                    if (cell.raw !== undefined) td.dataset.raw = String(cell.raw);
                    tr.appendChild(td);
                });
                tbody.appendChild(tr);
                map.set(key, tr);
                if (onNew) onNew(tr, row);
            }
        });

        // Remove rows whose keys are no longer present
        for (const [key, tr] of map) {
            if (!newKeys.has(key)) {
                tr.remove();
                map.delete(key);
            }
        }

        // Re-apply sort only if we added/removed rows (order may have changed)
        reapplySort(tableId);
    }

    // ═══════════════════════════════════════════════════════
    //  BUILD PROCESS MAP  (single call per update cycle)
    // ═══════════════════════════════════════════════════════
    function buildPidMap(data) {
        const map = {};
        const ensure = (pid, comm) => {
            if (!map[pid]) map[pid] = { pid, comm, flows: 0, tx: 0, rx: 0, writes: 0, bytes: 0, privEsc: false };
        };
        data.flows.forEach(f => {
            ensure(f.pid, f.comm);
            map[f.pid].flows++;
            map[f.pid].tx += f.tx_packets;
            map[f.pid].rx += f.rx_packets;
        });
        data.file_writes.forEach(w => {
            ensure(w.pid, w.comm);
            map[w.pid].writes += w.write_calls;
            map[w.pid].bytes  += w.bytes_written;
        });
        data.priv_esc.forEach(p => {
            ensure(p.pid, p.comm);
            map[p.pid].privEsc = true;
        });
        return map;
    }

    // ═══════════════════════════════════════════════════════
    //  PROCESS DETAIL VIEW
    // ═══════════════════════════════════════════════════════
    function openProcessDetail(pid, resetSubTab, pidMap) {
        currentPid = pid;
        const data = latestData;
        const p    = pidMap[pid];
        if (!p) return;

        document.getElementById('detail-avatar').textContent = p.comm[0]?.toUpperCase() || '?';
        document.getElementById('detail-name').textContent   = p.comm;
        document.getElementById('detail-pid').textContent    = `PID ${p.pid}`;
        document.getElementById('d-flows').textContent  = p.flows;
        document.getElementById('d-tx').textContent     = p.tx;
        document.getElementById('d-rx').textContent     = p.rx;
        document.getElementById('d-writes').textContent = p.writes;
        document.getElementById('d-bytes').textContent  = fmtBytes(p.bytes);

        if (resetSubTab) activeSubTab = 'detail-network';
        applySubTab(activeSubTab);

        // Network flows for this PID
        const pidFlows = data.flows.filter(f => f.pid === pid);
        patchTable(
            'table-detail-network',
            pidFlows,
            f => `${f.local_ip}:${f.local_port}-${f.remote_ip}:${f.remote_port}`,
            f => [
                { html: `<code>${f.local_ip}</code>`,  raw: f.local_ip },
                { html: `${f.local_port}`,             raw: f.local_port },
                { html: `<code>${f.remote_ip}</code>`, raw: f.remote_ip },
                { html: `${f.remote_port}`,            raw: f.remote_port },
                { html: `${f.tx_packets}`,             raw: f.tx_packets },
                { html: `${f.rx_packets}`,             raw: f.rx_packets },
            ]
        );

        // File I/O for this PID
        const pidIO = data.file_writes.filter(w => w.pid === pid);
        patchTable(
            'table-detail-io',
            pidIO,
            w => `${w.pid}-${w.fd}`,
            w => [
                { html: `${w.fd}`,                raw: w.fd },
                { html: `${w.write_calls}`,        raw: w.write_calls },
                { html: `${fmtBytes(w.bytes_written)}`, raw: w.bytes_written },
            ]
        );

        // Privilege escalations for this PID
        const pidPriv = data.priv_esc.filter(pr => pr.pid === pid);
        if (pidPriv.length) {
            patchTable(
                'table-detail-priv',
                pidPriv,
                pr => `${pr.pid}-${pr.old_uid}-${pr.new_uid}`,
                pr => [
                    { html: `<span class="user-badge">${pr.username}</span>`, raw: pr.username },
                    { html: `${pr.old_uid}`,           raw: pr.old_uid },
                    { html: `<span style="color:var(--danger);font-weight:700">${pr.new_uid}</span>`, raw: pr.new_uid },
                    { html: `${pr.escalation_count}`,  raw: pr.escalation_count },
                    { html: `<span class="ts-cell">${fmtTime(pr.first_seen)}</span>`, raw: pr.first_seen },
                    { html: `<span class="ts-cell">${fmtTime(pr.last_seen)}</span>`,  raw: pr.last_seen },
                ]
            );
        } else {
            renderEmpty('table-detail-priv', 'No privilege escalations for this process');
        }

        showSection('process-detail');
    }

    // ═══════════════════════════════════════════════════════
    //  UPDATE ALL VIEWS  — one pidMap, no full rebuilds
    // ═══════════════════════════════════════════════════════
    function updateAll(data) {
        latestData = data;

        // Build the pid aggregation map ONCE per cycle
        const pidMap = buildPidMap(data);

        // ── Top-bar stats (text node patches, no layout) ──────
        document.getElementById('stat-procs').textContent = Object.keys(pidMap).length;
        document.getElementById('stat-flows').textContent = data.flows.length;
        document.getElementById('stat-io').textContent    = data.file_writes.reduce((a, w) => a + w.write_calls, 0);
        document.getElementById('stat-priv').textContent  = data.priv_esc.reduce((a, p) => a + p.escalation_count, 0);

        // ── Per-process table (keyed diff, no scroll reset) ───
        if (activeSection !== 'process-detail') {
            const procList = Object.values(pidMap).sort((a, b) => (b.tx + b.rx) - (a.tx + a.rx));
            patchTable(
                'table-processes',
                procList,
                p => String(p.pid),
                p => [
                    { html: `<span class="tag">${p.pid}</span>`, raw: p.pid },
                    { html: `<strong>${p.comm}</strong>`,        raw: p.comm },
                    { html: `${p.flows}`,   raw: p.flows },
                    { html: `${p.tx}`,      raw: p.tx },
                    { html: `${p.rx}`,      raw: p.rx },
                    { html: `${p.writes}`,  raw: p.writes },
                    { html: `${fmtBytes(p.bytes)}`, raw: p.bytes },
                    { html: p.privEsc
                        ? '<span class="badge-danger">⚠ YES</span>'
                        : '<span class="badge-ok">✓ No</span>',   raw: p.privEsc ? 1 : 0 },
                    { html: `<button class="btn-detail">Inspect →</button>`, raw: p.pid },
                ],
                (tr, p) => {
                    // Wire up click handlers only once, when the row is NEW
                    tr.classList.add('clickable');
                    tr.querySelector('.btn-detail').addEventListener('click', e => {
                        e.stopPropagation();
                        openProcessDetail(p.pid, true, buildPidMap(latestData));
                    });
                    tr.addEventListener('click', () => openProcessDetail(p.pid, true, buildPidMap(latestData)));
                }
            );
            applySearch(); // restore search filter
        }

        // ── Refresh detail view live without resetting tab/scroll
        if (currentPid !== null) {
            openProcessDetail(currentPid, false, pidMap);
        }

        // ── Global tabs — only render when visible ────────────
        if (activeSection === 'global-network') {
            patchTable(
                'table-global-network',
                data.flows,
                f => `${f.pid}-${f.local_ip}:${f.local_port}-${f.remote_ip}:${f.remote_port}`,
                f => [
                    { html: `<span class="tag">${f.pid}</span>`, raw: f.pid },
                    { html: `${f.comm}`,                         raw: f.comm },
                    { html: `<code>${f.local_ip}</code>`,        raw: f.local_ip },
                    { html: `${f.local_port}`,                   raw: f.local_port },
                    { html: `<code>${f.remote_ip}</code>`,       raw: f.remote_ip },
                    { html: `${f.remote_port}`,                  raw: f.remote_port },
                    { html: `${f.tx_packets}`,                   raw: f.tx_packets },
                    { html: `${f.rx_packets}`,                   raw: f.rx_packets },
                ]
            );
        }

        if (activeSection === 'global-io') {
            patchTable(
                'table-global-io',
                data.file_writes,
                w => `${w.pid}-${w.fd}`,
                w => [
                    { html: `<span class="tag">${w.pid}</span>`, raw: w.pid },
                    { html: `${w.comm}`,                         raw: w.comm },
                    { html: `${w.fd}`,                           raw: w.fd },
                    { html: `${w.write_calls}`,                  raw: w.write_calls },
                    { html: `${fmtBytes(w.bytes_written)}`,      raw: w.bytes_written },
                ]
            );
        }

        if (activeSection === 'global-priv') {
            if (data.priv_esc.length) {
                patchTable(
                    'table-global-priv',
                    data.priv_esc,
                    p => `${p.pid}-${p.old_uid}-${p.new_uid}`,
                    p => [
                        { html: `<span class="tag">${p.pid}</span>`,                         raw: p.pid },
                        { html: `${p.comm}`,                                                 raw: p.comm },
                        { html: `<span class="user-badge">${p.username}</span>`,             raw: p.username },
                        { html: `${p.old_uid}`,                                              raw: p.old_uid },
                        { html: `<span style="color:var(--danger);font-weight:700">${p.new_uid}</span>`, raw: p.new_uid },
                        { html: `${p.escalation_count}`,                                     raw: p.escalation_count },
                        { html: `<span class="ts-cell">${fmtTime(p.first_seen)}</span>`,     raw: p.first_seen },
                        { html: `<span class="ts-cell">${fmtTime(p.last_seen)}</span>`,      raw: p.last_seen },
                    ]
                );
            } else {
                renderEmpty('table-global-priv', 'No privilege escalations detected');
            }
        }
    }

    // ═══════════════════════════════════════════════════════
    //  DATA FETCH
    //  • Reads SQLite via Electron IPC, or falls back to HTTP
    //  • Skips fetch when the window is hidden (page not visible)
    //  • Uses Page Visibility API to avoid polling in background
    // ═══════════════════════════════════════════════════════
    let fetchPending = false;

    async function fetchData() {
        if (fetchPending) return;          // don't pile up requests
        if (document.hidden) return;       // don't waste IPC / HTTP when tab hidden

        fetchPending = true;
        try {
            let data;
            if (window.electronAPI) {
                data = await window.electronAPI.getData();
            } else {
                const res = await fetch('/api/data');
                data = await res.json();
            }
            updateAll(data);
            document.getElementById('status-text').textContent = 'Live';
        } catch (err) {
            document.getElementById('status-text').textContent = 'Offline';
            console.error('Data error:', err);
        } finally {
            fetchPending = false;
        }
    }

    fetchData();
    setInterval(fetchData, 2000);

    // Re-fetch immediately when user returns to the tab (no stale-data lag)
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) fetchData();
    });
});
