document.addEventListener('DOMContentLoaded', () => {

    // ═══════════════════════════════════════════════════════
    //  STATE
    // ═══════════════════════════════════════════════════════
    let latestData   = { flows: [], file_writes: [], priv_esc: [], net_stats: [] };
    let currentPid   = null;
    let sortState    = {};            // { tableId: { col, dir, type } }
    let activeSubTab = 'detail-network';
    let activeSection = 'processes';

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
    //  SCROLL PRESERVATION
    // ═══════════════════════════════════════════════════════
    function saveScrolls() {
        return {
            content: document.querySelector('.content-area')?.scrollTop ?? 0,
            sub:     document.querySelector('.sub-content')?.scrollTop  ?? 0,
        };
    }

    function restoreScrolls(saved) {
        requestAnimationFrame(() => {
            const ca = document.querySelector('.content-area');
            const sc = document.querySelector('.sub-content');
            if (ca) ca.scrollTop = saved.content;
            if (sc) sc.scrollTop = saved.sub;
        });
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

    // Re-apply stored sort to a table after it has been rebuilt
    function reapplySort(tableId) {
        const state = sortState[tableId];
        if (!state) return;
        const table = document.getElementById(tableId);
        if (!table) return;

        // Update sort icons to reflect current state
        table.querySelectorAll('.sort-icon').forEach(i => i.textContent = '⇅');
        const activeTh = table.querySelector(`th[data-col="${state.col}"]`);
        if (activeTh) {
            activeTh.querySelector('.sort-icon').textContent = state.dir === 'asc' ? '▲' : '▼';
        }

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

                // Persist the sort choice
                sortState[tableId] = { col, dir, type };

                // Update icons
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
    }

    // Build rows then immediately re-apply any active sort for this table
    function renderTable(tableId, rows, rowBuilder) {
        const tbody = document.querySelector(`#${tableId} tbody`);
        if (!tbody) return;
        if (!rows.length) { renderEmpty(tableId, 'No data yet'); return; }
        tbody.innerHTML = '';
        rows.forEach(row => {
            const tr = document.createElement('tr');
            tr.innerHTML = rowBuilder(row);
            tbody.appendChild(tr);
        });
        // KEY FIX: re-apply the saved sort so every refresh keeps the column order
        reapplySort(tableId);
    }

    // ═══════════════════════════════════════════════════════
    //  BUILD PROCESS MAP
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
    function openProcessDetail(pid, resetSubTab) {
        currentPid = pid;
        const data   = latestData;
        const pidMap = buildPidMap(data);
        const p      = pidMap[pid];
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

        const pidFlows = data.flows.filter(f => f.pid === pid);
        renderTable('table-detail-network', pidFlows, f => `
            <td><code>${f.local_ip}</code></td>
            <td>${f.local_port}</td>
            <td><code>${f.remote_ip}</code></td>
            <td>${f.remote_port}</td>
            <td>${f.tx_packets}</td>
            <td>${f.rx_packets}</td>
        `);

        const pidIO = data.file_writes.filter(w => w.pid === pid);
        renderTable('table-detail-io', pidIO, w => `
            <td>${w.fd}</td>
            <td>${w.write_calls}</td>
            <td>${fmtBytes(w.bytes_written)}</td>
        `);

        const pidPriv = data.priv_esc.filter(pr => pr.pid === pid);
        if (pidPriv.length) {
            renderTable('table-detail-priv', pidPriv, pr => `
                <td><span class="user-badge">${pr.username}</span></td>
                <td>${pr.old_uid}</td>
                <td style="color:var(--danger);font-weight:700">${pr.new_uid}</td>
                <td>${pr.escalation_count}</td>
                <td class="ts-cell">${fmtTime(pr.first_seen)}</td>
                <td class="ts-cell">${fmtTime(pr.last_seen)}</td>
            `);
        } else {
            renderEmpty('table-detail-priv', 'No privilege escalations for this process');
        }

        showSection('process-detail');
    }

    // ═══════════════════════════════════════════════════════
    //  UPDATE ALL VIEWS
    // ═══════════════════════════════════════════════════════
    function updateAll(data) {
        latestData = data;
        const scrolls = saveScrolls();

        // Top-bar stats
        document.getElementById('stat-procs').textContent = Object.keys(buildPidMap(data)).length;
        document.getElementById('stat-flows').textContent = data.flows.length;
        document.getElementById('stat-io').textContent    = data.file_writes.reduce((a, w) => a + w.write_calls, 0);
        document.getElementById('stat-priv').textContent  = data.priv_esc.reduce((a, p) => a + p.escalation_count, 0);

        // Per Process list — only rebuild when not in detail view
        if (activeSection !== 'process-detail') {
            const pidMap   = buildPidMap(data);
            const procList = Object.values(pidMap).sort((a, b) => (b.tx + b.rx) - (a.tx + a.rx));
            const procBody = document.querySelector('#table-processes tbody');
            procBody.innerHTML = '';
            procList.forEach(p => {
                const tr = document.createElement('tr');
                tr.className = 'clickable';
                tr.innerHTML = `
                    <td><span class="tag">${p.pid}</span></td>
                    <td><strong>${p.comm}</strong></td>
                    <td>${p.flows}</td>
                    <td>${p.tx}</td>
                    <td>${p.rx}</td>
                    <td>${p.writes}</td>
                    <td>${fmtBytes(p.bytes)}</td>
                    <td>${p.privEsc ? '<span class="badge-danger">⚠ YES</span>' : '<span class="badge-ok">✓ No</span>'}</td>
                    <td><button class="btn-detail">Inspect →</button></td>
                `;
                tr.querySelector('.btn-detail').addEventListener('click', e => {
                    e.stopPropagation();
                    openProcessDetail(p.pid, true);
                });
                tr.addEventListener('click', () => openProcessDetail(p.pid, true));
                procBody.appendChild(tr);
            });
            if (!procList.length) renderEmpty('table-processes', 'No processes captured yet');
            reapplySort('table-processes');  // restore sort after rebuild
            applySearch();                   // restore search filter after rebuild
        }

        // Refresh detail view live without resetting tab/scroll
        if (currentPid !== null) {
            openProcessDetail(currentPid, false);
        }

        // Global tabs — only render when visible
        if (activeSection === 'global-network') {
            renderTable('table-global-network', data.flows, f => `
                <td><span class="tag">${f.pid}</span></td>
                <td>${f.comm}</td>
                <td><code>${f.local_ip}</code></td>
                <td>${f.local_port}</td>
                <td><code>${f.remote_ip}</code></td>
                <td>${f.remote_port}</td>
                <td>${f.tx_packets}</td>
                <td>${f.rx_packets}</td>
            `);
        }

        if (activeSection === 'global-io') {
            renderTable('table-global-io', data.file_writes, w => `
                <td><span class="tag">${w.pid}</span></td>
                <td>${w.comm}</td>
                <td>${w.fd}</td>
                <td>${w.write_calls}</td>
                <td>${fmtBytes(w.bytes_written)}</td>
            `);
        }

        if (activeSection === 'global-priv') {
            if (data.priv_esc.length) {
                renderTable('table-global-priv', data.priv_esc, p => `
                    <td><span class="tag">${p.pid}</span></td>
                    <td>${p.comm}</td>
                    <td><span class="user-badge">${p.username}</span></td>
                    <td>${p.old_uid}</td>
                    <td style="color:var(--danger);font-weight:700">${p.new_uid}</td>
                    <td>${p.escalation_count}</td>
                    <td class="ts-cell">${fmtTime(p.first_seen)}</td>
                    <td class="ts-cell">${fmtTime(p.last_seen)}</td>
                `);
            } else {
                renderEmpty('table-global-priv', 'No privilege escalations detected');
            }
        }

        restoreScrolls(scrolls);
    }

    // ═══════════════════════════════════════════════════════
    //  DATA FETCH — reads SQLite via Electron IPC (no HTTP server)
    // ═══════════════════════════════════════════════════════
    async function fetchData() {
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
        }
    }

    fetchData();
    setInterval(fetchData, 2000);
});
