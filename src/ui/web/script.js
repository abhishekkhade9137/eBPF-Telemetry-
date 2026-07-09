document.addEventListener('DOMContentLoaded', () => {

    // ═══════════════════════════════════════════════════════
    //  STATE
    // ═══════════════════════════════════════════════════════
    let latestData   = { flows: [], file_writes: [], priv_esc: [], net_stats: [] };
    let currentComm  = null;
    let sortState    = {};            // { tableId: { col, dir, type } }
    let activeSubTab = 'detail-network';
    let activeSection = 'processes';
    let tableLimits  = {};

    function resetLimits(prefix) {
        Object.keys(tableLimits).forEach(k => {
            if (k.startsWith(prefix)) tableLimits[k] = 50;
        });
    }

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
        'threats':        'Detected Threats',
        'settings':       'Settings',
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
            currentComm = null;
            resetLimits('table-global');
            resetLimits('table-processes');
            showSection(item.dataset.target);
        });
    });

    btnBack.addEventListener('click', () => {
        currentComm = null;
        resetLimits('table-processes');
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
        'table-threats'
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

    function updateLoadMoreButton(tableId, totalRows, limit) {
        let btn = document.getElementById(`btn-load-more-${tableId}`);
        if (!btn) {
            btn = document.createElement('button');
            btn.id = `btn-load-more-${tableId}`;
            btn.className = 'btn-load-more';
            const table = document.getElementById(tableId);
            const container = table.closest('.table-container');
            container.parentNode.insertBefore(btn, container.nextSibling);
            
            btn.addEventListener('click', () => {
                tableLimits[tableId] = (tableLimits[tableId] || 50) + 50;
                if (latestData) updateAll(latestData);
            });
        }
        if (totalRows > limit) {
            btn.style.display = 'block';
            btn.innerHTML = `Load 50 More <span>(Showing ${limit} of ${totalRows})</span>`;
        } else {
            btn.style.display = 'none';
        }
    }

    /**
     * Diff-patches a tbody using a stable key per row.
     *
     * @param {string}   tableId
     * @param {Array}    rows        – data rows to display
     * @param {Function} keyFn       – (row) => unique string key
     * @param {Function} rawFn       – (row) => array of raw primitive values for dirty checking
     * @param {Function} htmlFn      – (row, colIndex) => string of HTML to render if dirty
     * @param {Function} [onNew]     – optional callback(tr, row) after a new <tr> is inserted
     */
    function patchTable(tableId, rows, keyFn, rawFn, htmlFn, onNew) {
        const tbody = document.querySelector(`#${tableId} tbody`);
        if (!tbody) return;

        if (!rowMaps[tableId]) rowMaps[tableId] = new Map();
        const map = rowMaps[tableId];

        if (!tableLimits[tableId]) tableLimits[tableId] = 50;
        const limit = tableLimits[tableId];
        const totalRows = rows.length;
        const visibleRows = rows.slice(0, limit);

        if (!visibleRows.length) {
            // Preserve empty-state only if already shown
            if (tbody.querySelector('.empty-state')) return;
            renderEmpty(tableId, 'No data yet');
            updateLoadMoreButton(tableId, 0, limit);
            return;
        }

        // Remove stale empty-state row if present
        const emptyRow = tbody.querySelector('.empty-state');
        if (emptyRow) {
            emptyRow.closest('tr').remove();
            map.clear();
        }

        const newKeys = new Set();

        visibleRows.forEach((row, idx) => {
            const key = keyFn(row);
            newKeys.add(key);
            const raws = rawFn(row);

            if (map.has(key)) {
                // ── Existing row: patch only changed cells ──────────
                const tr = map.get(key);
                raws.forEach((rawVal, ci) => {
                    const td = tr.cells[ci];
                    if (!td) return;
                    if (td.dataset.raw !== String(rawVal)) {
                        td.innerHTML = htmlFn(row, ci);
                        td.dataset.raw = String(rawVal);
                    }
                });
            } else {
                // ── New row: create and insert ──────────────────────
                const tr = document.createElement('tr');
                raws.forEach((rawVal, ci) => {
                    const td = document.createElement('td');
                    td.innerHTML = htmlFn(row, ci);
                    td.dataset.raw = String(rawVal);
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

        updateLoadMoreButton(tableId, totalRows, limit);
    }


    // ═══════════════════════════════════════════════════════
    //  PROCESS DETAIL VIEW
    // ═══════════════════════════════════════════════════════
    function openProcessDetail(comm, resetSubTab, commMap) {
        currentComm = comm;
        const data = latestData;
        const p    = commMap[comm];
        if (!p) return;

        document.getElementById('detail-avatar').textContent = p.comm[0]?.toUpperCase() || '?';
        document.getElementById('detail-name').textContent   = p.comm;
        
        const pidsText = p.pids.length > 5 ? 
            `${p.pids.slice(0,5).join(', ')}... (${p.pids.length} total)` : 
            p.pids.join(', ');
        document.getElementById('detail-pid').textContent    = `PIDs: ${pidsText}`;

        document.getElementById('d-flows').textContent  = p.flows;
        document.getElementById('d-tx').textContent     = p.tx;
        document.getElementById('d-rx').textContent     = p.rx;
        document.getElementById('d-writes').textContent = p.writes;
        document.getElementById('d-bytes').textContent  = fmtBytes(p.bytes);

        if (resetSubTab) {
            activeSubTab = 'detail-network';
            resetLimits('table-detail');
        }
        applySubTab(activeSubTab);

        // Network flows for this COMM
        const commFlows = data.flows.filter(f => f.comm === comm);
        patchTable(
            'table-detail-network',
            commFlows,
            f => `${f.pid}-${f.local_ip}:${f.local_port}-${f.remote_ip}:${f.remote_port}`,
            f => [ f.pid, f.local_ip, f.local_port, f.remote_ip, f.remote_port, f.tx_packets, f.rx_packets ],
            (f, i) => {
                switch(i) {
                    case 0: return `<span class="tag">${f.pid}</span> <code>${f.local_ip}</code>`;
                    case 1: return `${f.local_port}`;
                    case 2: return `<code>${f.remote_ip}</code>`;
                    case 3: return `${f.remote_port}`;
                    case 4: return `${f.tx_packets}`;
                    case 5: return `${f.rx_packets}`;
                }
            }
        );

        // File I/O for this COMM
        const commIO = data.file_writes.filter(w => w.comm === comm);
        patchTable(
            'table-detail-io',
            commIO,
            w => `${w.pid}-${w.fd}`,
            w => [ w.pid, w.fd, w.write_calls, w.bytes_written ],
            (w, i) => {
                switch(i) {
                    case 0: return `<span class="tag">${w.pid}</span> ${w.fd}`;
                    case 1: return `${w.write_calls}`;
                    case 2: return `${fmtBytes(w.bytes_written)}`;
                }
            }
        );

        // Privilege escalations for this COMM
        const commPriv = data.priv_esc.filter(pr => pr.comm === comm);
        if (commPriv.length) {
            patchTable(
                'table-detail-priv',
                commPriv,
                pr => `${pr.pid}-${pr.old_uid}-${pr.new_uid}`,
                pr => [ pr.pid, pr.username, pr.old_uid, pr.new_uid, pr.escalation_count, pr.first_seen, pr.last_seen ],
                (pr, i) => {
                    switch(i) {
                        case 0: return `<span class="tag">${pr.pid}</span> <span class="user-badge">${pr.username}</span>`;
                        case 1: return `${pr.old_uid}`;
                        case 2: return `<span style="color:var(--danger);font-weight:700">${pr.new_uid}</span>`;
                        case 3: return `${pr.escalation_count}`;
                        case 4: return `<span class="ts-cell">${fmtTime(pr.first_seen)}</span>`;
                        case 5: return `<span class="ts-cell">${fmtTime(pr.last_seen)}</span>`;
                    }
                }
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

        const commMap = data.commMap || {};
        const procList = data.procList || [];

        // ── Top-bar stats (text node patches, no layout) ──────
        document.getElementById('stat-procs').textContent = Object.keys(commMap).length;
        document.getElementById('stat-flows').textContent = data.flows.length;
        document.getElementById('stat-io').textContent    = data.file_writes.reduce((a, w) => a + w.write_calls, 0);
        document.getElementById('stat-priv').textContent  = data.priv_esc.reduce((a, p) => a + p.escalation_count, 0);

        // ── Per-process table (keyed diff, no scroll reset) ───
        if (activeSection !== 'process-detail') {
            patchTable(
                'table-processes',
                procList,
                p => p.comm,
                p => [ p.pids.join(','), p.comm, p.flows, p.tx, p.rx, p.writes, p.bytes, p.privEsc ? 1 : 0, p.comm ],
                (p, i) => {
                    switch(i) {
                        case 0: 
                            const pidText = p.pids.length === 1 ? p.pids[0] : `${p.pids.length} PIDs`;
                            return `<span class="tag">${pidText}</span>`;
                        case 1: return `<strong>${p.comm}</strong>`;
                        case 2: return `${p.flows}`;
                        case 3: return `${p.tx}`;
                        case 4: return `${p.rx}`;
                        case 5: return `${p.writes}`;
                        case 6: return `${fmtBytes(p.bytes)}`;
                        case 7: return p.privEsc ? '<span class="badge-danger">⚠ YES</span>' : '<span class="badge-ok">✓ No</span>';
                        case 8: return `<button class="btn-detail">Inspect →</button>`;
                    }
                },
                (tr, p) => {
                    // Wire up click handlers only once, when the row is NEW
                    tr.classList.add('clickable');
                    tr.querySelector('.btn-detail').addEventListener('click', e => {
                        e.stopPropagation();
                        openProcessDetail(p.comm, true, latestData.commMap);
                    });
                    tr.addEventListener('click', () => openProcessDetail(p.comm, true, latestData.commMap));
                }
            );
            applySearch(); // restore search filter
        }

        // ── Refresh detail view live without resetting tab/scroll
        if (currentComm !== null) {
            openProcessDetail(currentComm, false, commMap);
        }

        // ── Global tabs — only render when visible ────────────
        if (activeSection === 'global-network') {
            patchTable(
                'table-global-network',
                data.flows,
                f => `${f.pid}-${f.local_ip}:${f.local_port}-${f.remote_ip}:${f.remote_port}`,
                f => [ f.pid, f.comm, f.local_ip, f.local_port, f.remote_ip, f.remote_port, f.tx_packets, f.rx_packets ],
                (f, i) => {
                    switch(i) {
                        case 0: return `<span class="tag">${f.pid}</span>`;
                        case 1: return `${f.comm}`;
                        case 2: return `<code>${f.local_ip}</code>`;
                        case 3: return `${f.local_port}`;
                        case 4: return `<code>${f.remote_ip}</code>`;
                        case 5: return `${f.remote_port}`;
                        case 6: return `${f.tx_packets}`;
                        case 7: return `${f.rx_packets}`;
                    }
                }
            );
        }

        if (activeSection === 'global-io') {
            patchTable(
                'table-global-io',
                data.file_writes,
                w => `${w.pid}-${w.fd}`,
                w => [ w.pid, w.comm, w.fd, w.write_calls, w.bytes_written ],
                (w, i) => {
                    switch(i) {
                        case 0: return `<span class="tag">${w.pid}</span>`;
                        case 1: return `${w.comm}`;
                        case 2: return `${w.fd}`;
                        case 3: return `${w.write_calls}`;
                        case 4: return `${fmtBytes(w.bytes_written)}`;
                    }
                }
            );
        }

        if (activeSection === 'global-priv') {
            if (data.priv_esc.length) {
                patchTable(
                    'table-global-priv',
                    data.priv_esc,
                    p => `${p.pid}-${p.old_uid}-${p.new_uid}`,
                    p => [ p.pid, p.comm, p.username, p.old_uid, p.new_uid, p.escalation_count, p.first_seen, p.last_seen ],
                    (p, i) => {
                        switch(i) {
                            case 0: return `<span class="tag">${p.pid}</span>`;
                            case 1: return `${p.comm}`;
                            case 2: return `<span class="user-badge">${p.username}</span>`;
                            case 3: return `${p.old_uid}`;
                            case 4: return `<span style="color:var(--danger);font-weight:700">${p.new_uid}</span>`;
                            case 5: return `${p.escalation_count}`;
                            case 6: return `<span class="ts-cell">${fmtTime(p.first_seen)}</span>`;
                            case 7: return `<span class="ts-cell">${fmtTime(p.last_seen)}</span>`;
                        }
                    }
                );
            } else {
                renderEmpty('table-global-priv', 'No privilege escalations detected');
            }
        }

        if (activeSection === 'threats') {
            const threats = data.threats || [];
            if (threats.length) {
                patchTable(
                    'table-threats',
                    threats,
                    t => t.comm,
                    t => [ t.comm, t.pids.join(','), t.severity, t.reasons.join('; '), t.comm ],
                    (t, i) => {
                        switch(i) {
                            case 0: return `<strong>${t.comm}</strong>`;
                            case 1: return `<span class="tag">${t.pids.length === 1 ? t.pids[0] : t.pids.length + ' PIDs'}</span>`;
                            case 2: return `<span class="${t.severity === 'High' ? 'badge-danger' : 'tag'}">${t.severity}</span>`;
                            case 3: return `<span style="color:var(--text-secondary);font-size:12px">${t.reasons.join('<br>')}</span>`;
                            case 4: return `<button class="btn-detail">Inspect →</button>`;
                        }
                    },
                    (tr, t) => {
                        tr.classList.add('clickable');
                        tr.querySelector('.btn-detail').addEventListener('click', e => {
                            e.stopPropagation();
                            openProcessDetail(t.comm, true, latestData.commMap);
                        });
                        tr.addEventListener('click', () => openProcessDetail(t.comm, true, latestData.commMap));
                    }
                );
            } else {
                renderEmpty('table-threats', 'No threats detected on the system.');
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

    // ═══════════════════════════════════════════════════════
    //  SETTINGS CONFIGURATION
    // ═══════════════════════════════════════════════════════
    const btnSaveSettings = document.getElementById('btn-save-settings');
    if (btnSaveSettings) {
        btnSaveSettings.addEventListener('click', async () => {
            const namesVal = document.getElementById('config-names').value;
            const ioVal = parseInt(document.getElementById('config-io').value, 10);
            const netVal = parseInt(document.getElementById('config-net').value, 10);
            const filesVal = parseInt(document.getElementById('config-files').value, 10);

            const names = namesVal.split(',').map(s => s.trim()).filter(Boolean);

            const newConfig = {
                suspiciousNames: names,
                ioThresholdMB: isNaN(ioVal) ? 50 : ioVal,
                networkThresholdPkts: isNaN(netVal) ? 1000 : netVal,
                filesTouchedThreshold: isNaN(filesVal) ? 100 : filesVal
            };

            if (window.electronAPI && window.electronAPI.updateConfig) {
                await window.electronAPI.updateConfig(newConfig);
            }

            const msg = document.getElementById('settings-msg');
            msg.style.opacity = '1';
            setTimeout(() => msg.style.opacity = '0', 2000);
            
            // Force data refresh to apply new rules immediately
            fetchData();
        });
    }
});
