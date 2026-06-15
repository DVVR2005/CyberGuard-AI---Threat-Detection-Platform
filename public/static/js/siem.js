// ============================================================
// CyberGuard AI - SIEM Event Monitoring Module
// ============================================================

Router.register('siem', renderSIEM);

let siemEventsList = [];

function renderSIEM() {
    const content = document.getElementById('page-content');
    content.innerHTML = `
        <div class="page-header">
            <div>
                <h1>SIEM Event Monitoring</h1>
                <p class="text-muted">Real-time enterprise threat logging and security event correlation.</p>
            </div>
            <div class="header-actions">
                <button class="btn btn-secondary" onclick="fetchSIEMLogs()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px;">
                        <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
                    </svg>
                    Refresh
                </button>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-body">
                <div class="row g-3">
                    <div class="col-md-6">
                        <div class="search-input-wrapper">
                            <input type="text" id="siem-search" class="form-control" placeholder="Search events by type, description, or IP..." onkeyup="handleSIEMSearch(event)">
                        </div>
                    </div>
                    <div class="col-md-4">
                        <select id="siem-severity-filter" class="form-select" onchange="fetchSIEMLogs()">
                            <option value="">All Severities</option>
                            <option value="Critical">Critical</option>
                            <option value="High">High</option>
                            <option value="Medium">Medium</option>
                            <option value="Low">Low</option>
                        </select>
                    </div>
                    <div class="col-md-2">
                        <button class="btn btn-primary w-100" onclick="fetchSIEMLogs()">Search</button>
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">Security Event Logs</h5>
                <span class="badge bg-info" id="siem-live-indicator">● LIVE FEED ACTIVE</span>
            </div>
            <div class="table-responsive">
                <table class="table table-hover align-middle mb-0">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Event Type</th>
                            <th>Severity</th>
                            <th>Source IP</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody id="siem-logs-table-body">
                        <tr>
                            <td colspan="5" class="text-center py-4 text-muted">
                                <span class="spinner-border spinner-border-sm me-2"></span>Loading security events...
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    `;

    fetchSIEMLogs();
}

async function fetchSIEMLogs() {
    const searchVal = document.getElementById('siem-search')?.value || '';
    const severityVal = document.getElementById('siem-severity-filter')?.value || '';
    const tbody = document.getElementById('siem-logs-table-body');
    if (!tbody) return;

    try {
        const url = `/api/siem?q=${encodeURIComponent(searchVal)}&severity=${encodeURIComponent(severityVal)}`;
        const data = await api(url);
        siemEventsList = data.events;
        displaySIEMLogs();
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger py-4">${err.message}</td></tr>`;
    }
}

function displaySIEMLogs() {
    const tbody = document.getElementById('siem-logs-table-body');
    if (!tbody) return;

    if (siemEventsList.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-muted">No security events found.</td></tr>`;
        return;
    }

    tbody.innerHTML = siemEventsList.map(ev => `
        <tr>
            <td class="text-nowrap text-muted" style="font-family: var(--font-mono); font-size: 0.85rem;">
                ${formatDateTime(ev.created_at)}
            </td>
            <td>
                <span class="fw-semibold text-light">${escapeHtml(ev.event_type)}</span>
            </td>
            <td>
                <span class="badge ${getSeverityClass(ev.severity)}">${ev.severity}</span>
            </td>
            <td class="text-nowrap" style="font-family: var(--font-mono); color: var(--accent-cyan);">
                ${escapeHtml(ev.source_ip || 'N/A')}
            </td>
            <td class="text-muted" style="max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(ev.description)}">
                ${escapeHtml(ev.description)}
            </td>
        </tr>
    `).join('');
}

function handleSIEMSearch(e) {
    if (e.key === 'Enter') {
        fetchSIEMLogs();
    }
}

// Subscribe to real-time websocket additions
window.addEventListener('siem-event-added', (e) => {
    const newEvent = e.detail;
    // Add to list and refresh UI if we are currently looking at SIEM panel
    if (document.getElementById('siem-logs-table-body')) {
        siemEventsList.unshift(newEvent);
        displaySIEMLogs();
    }
});
