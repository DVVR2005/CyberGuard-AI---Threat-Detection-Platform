/* ============================================================
   CyberGuard AI - Admin Panel Module
   User management, audit logs, platform analytics
   ============================================================ */

Router.register('admin', renderAdminPanel);

async function renderAdminPanel() {
    const content = document.getElementById('page-content');

    if (!Auth.isAdmin()) {
        content.innerHTML = `
            <div class="access-denied">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--accent-red)" stroke-width="1.5">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                    <path d="M7 11V7a5 5 0 0110 0v4"/>
                </svg>
                <h2>Access Denied</h2>
                <p>You need administrator privileges to access this page.</p>
                <button class="btn btn-primary" onclick="Router.navigate('dashboard')">Back to Dashboard</button>
            </div>
        `;
        return;
    }

    content.innerHTML = `
        <div class="page-header">
            <h1>Admin Panel</h1>
            <p class="page-subtitle">Platform administration & user management</p>
        </div>

        <!-- Admin Stats -->
        <div class="kpi-grid" id="admin-stats-grid">
            <div class="kpi-card kpi-cyan">
                <div class="kpi-icon">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
                        <circle cx="9" cy="7" r="4"/>
                        <path d="M23 21v-2a4 4 0 00-3-3.87"/>
                        <path d="M16 3.13a4 4 0 010 7.75"/>
                    </svg>
                </div>
                <div class="kpi-info">
                    <span class="kpi-label">Total Users</span>
                    <span class="kpi-value" id="admin-total-users">--</span>
                </div>
            </div>
            <div class="kpi-card kpi-green">
                <div class="kpi-icon">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                    </svg>
                </div>
                <div class="kpi-info">
                    <span class="kpi-label">Total Scans</span>
                    <span class="kpi-value" id="admin-total-scans">--</span>
                </div>
            </div>
            <div class="kpi-card kpi-amber">
                <div class="kpi-icon">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                </div>
                <div class="kpi-info">
                    <span class="kpi-label">Vulnerabilities</span>
                    <span class="kpi-value" id="admin-total-vulns">--</span>
                </div>
            </div>
            <div class="kpi-card kpi-red">
                <div class="kpi-icon">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                        <polyline points="14 2 14 8 20 8"/>
                    </svg>
                </div>
                <div class="kpi-info">
                    <span class="kpi-label">Total Reports</span>
                    <span class="kpi-value" id="admin-total-reports">--</span>
                </div>
            </div>
        </div>

        <!-- Admin Tabs -->
        <div class="admin-tabs">
            <button class="admin-tab active" data-tab="users" onclick="switchAdminTab('users')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
                    <circle cx="9" cy="7" r="4"/>
                </svg>
                Users
            </button>
            <button class="admin-tab" data-tab="scans" onclick="switchAdminTab('scans')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
                </svg>
                Scans
            </button>
            <button class="admin-tab" data-tab="audit" onclick="switchAdminTab('audit')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                    <line x1="16" y1="13" x2="8" y2="13"/>
                    <line x1="16" y1="17" x2="8" y2="17"/>
                </svg>
                Audit Logs
            </button>
        </div>

        <!-- Tab Content -->
        <div class="card" style="margin-top: 0; border-top-left-radius: 0; border-top-right-radius: 0;">
            <div id="admin-tab-content">
                <div class="text-center text-muted p-4">Loading...</div>
            </div>
        </div>

        <!-- Confirmation Modal -->
        <div id="admin-modal" class="modal-overlay" style="display:none;">
            <div class="modal-card">
                <h3 id="modal-title">Confirm Action</h3>
                <p id="modal-message">Are you sure?</p>
                <div class="modal-actions">
                    <button class="btn btn-ghost" onclick="closeAdminModal()">Cancel</button>
                    <button class="btn btn-danger" id="modal-confirm-btn">Confirm</button>
                </div>
            </div>
        </div>
    `;

    loadAdminData();
}

let adminData = { users: [], scans: [], logs: [] };

async function loadAdminData() {
    try {
        const [statsRes, usersRes, scansRes, logsRes] = await Promise.all([
            api('/api/admin/stats'),
            api('/api/admin/users'),
            api('/api/admin/scans'),
            api('/api/admin/audit-logs')
        ]);

        // Populate stats
        const s = statsRes.stats;
        setTextIfExists('admin-total-users', s.total_users);
        setTextIfExists('admin-total-scans', s.total_scans);
        setTextIfExists('admin-total-vulns', s.total_vulnerabilities);
        setTextIfExists('admin-total-reports', s.total_reports);

        adminData.users = usersRes.users || [];
        adminData.scans = scansRes.scans || [];
        adminData.logs = logsRes.logs || [];

        // Render default tab (users)
        switchAdminTab('users');

    } catch (err) {
        Toast.show('Failed to load admin data: ' + err.message, 'error');
        console.error(err);
    }
}

function setTextIfExists(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value ?? '--';
}

function switchAdminTab(tab) {
    // Update tab active state
    document.querySelectorAll('.admin-tab').forEach(t => {
        t.classList.toggle('active', t.dataset.tab === tab);
    });

    const container = document.getElementById('admin-tab-content');
    if (!container) return;

    switch (tab) {
        case 'users':
            renderUsersTab(container);
            break;
        case 'scans':
            renderScansTab(container);
            break;
        case 'audit':
            renderAuditTab(container);
            break;
    }
}

function renderUsersTab(container) {
    const users = adminData.users;
    container.innerHTML = `
        <div class="table-responsive">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Scans</th>
                        <th>Joined</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${users.length === 0 ? '<tr><td colspan="7" class="text-center text-muted">No users found</td></tr>' :
                        users.map(u => `
                            <tr>
                                <td>
                                    <div class="user-cell">
                                        <div class="avatar-sm">${u.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)}</div>
                                        <span>${u.name}</span>
                                    </div>
                                </td>
                                <td class="text-muted">${u.email}</td>
                                <td><span class="badge ${u.role === 'admin' ? 'badge-info' : 'badge-low'}">${u.role}</span></td>
                                <td><span class="badge ${u.status === 'active' ? 'badge-safe' : 'badge-critical'}">${u.status}</span></td>
                                <td>${u.scan_count || 0}</td>
                                <td class="text-muted">${formatDate(u.created_at)}</td>
                                <td>
                                    <div class="action-btns">
                                        ${u.status === 'active' ?
                                            `<button class="btn btn-ghost btn-sm btn-warning-text" onclick="toggleUserStatus(${u.id}, 'suspended')" title="Suspend">
                                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                    <circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                                                </svg>
                                            </button>` :
                                            `<button class="btn btn-ghost btn-sm btn-success-text" onclick="toggleUserStatus(${u.id}, 'active')" title="Activate">
                                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                    <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                                                    <polyline points="22 4 12 14.01 9 11.01"/>
                                                </svg>
                                            </button>`
                                        }
                                        <button class="btn btn-ghost btn-sm btn-danger-text" onclick="confirmDeleteUser(${u.id}, '${u.name}')" title="Delete">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                <polyline points="3 6 5 6 21 6"/>
                                                <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                                            </svg>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        `).join('')
                    }
                </tbody>
            </table>
        </div>
    `;
}

function renderScansTab(container) {
    const scans = adminData.scans;
    container.innerHTML = `
        <div class="table-responsive">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Target URL</th>
                        <th>User</th>
                        <th>Risk Score</th>
                        <th>Vulnerabilities</th>
                        <th>Status</th>
                        <th>Date</th>
                    </tr>
                </thead>
                <tbody>
                    ${scans.length === 0 ? '<tr><td colspan="6" class="text-center text-muted">No scans found</td></tr>' :
                        scans.map(s => `
                            <tr>
                                <td>
                                    <span class="scan-url-text">${s.target_url}</span>
                                </td>
                                <td class="text-muted">${s.user_name || s.user_email || 'Unknown'}</td>
                                <td>
                                    <span class="risk-score-badge" style="color: ${getScoreColor(s.risk_score || 0)};">
                                        ${s.risk_score != null ? s.risk_score.toFixed(1) : 'N/A'}
                                    </span>
                                </td>
                                <td>${s.vulnerability_count || 0}</td>
                                <td><span class="badge badge-info">${s.status}</span></td>
                                <td class="text-muted">${formatDate(s.created_at)}</td>
                            </tr>
                        `).join('')
                    }
                </tbody>
            </table>
        </div>
    `;
}

function renderAuditTab(container) {
    const logs = adminData.logs;
    container.innerHTML = `
        <div class="table-responsive">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>User</th>
                        <th>Action</th>
                        <th>Details</th>
                        <th>IP Address</th>
                    </tr>
                </thead>
                <tbody>
                    ${logs.length === 0 ? '<tr><td colspan="5" class="text-center text-muted">No audit logs found</td></tr>' :
                        logs.map(log => `
                            <tr>
                                <td class="text-muted" style="white-space: nowrap;">${formatDateTime(log.created_at)}</td>
                                <td>${log.user_email || 'System'}</td>
                                <td><span class="badge badge-info">${log.action}</span></td>
                                <td class="text-secondary">${log.details || '—'}</td>
                                <td class="text-muted">${log.ip_address || '—'}</td>
                            </tr>
                        `).join('')
                    }
                </tbody>
            </table>
        </div>
    `;
}

async function toggleUserStatus(userId, newStatus) {
    try {
        await api(`/api/admin/users/${userId}`, {
            method: 'PUT',
            body: { status: newStatus }
        });
        Toast.show(`User ${newStatus === 'active' ? 'activated' : 'suspended'} successfully`, 'success');
        // Refresh
        const usersRes = await api('/api/admin/users');
        adminData.users = usersRes.users || [];
        switchAdminTab('users');
    } catch (err) {
        Toast.show('Failed to update user: ' + err.message, 'error');
    }
}

function confirmDeleteUser(userId, userName) {
    const modal = document.getElementById('admin-modal');
    const title = document.getElementById('modal-title');
    const message = document.getElementById('modal-message');
    const confirmBtn = document.getElementById('modal-confirm-btn');

    title.textContent = 'Delete User';
    message.textContent = `Are you sure you want to permanently delete "${userName}"? This action cannot be undone.`;
    confirmBtn.onclick = () => deleteUser(userId);
    modal.style.display = 'flex';
}

function closeAdminModal() {
    const modal = document.getElementById('admin-modal');
    if (modal) modal.style.display = 'none';
}

async function deleteUser(userId) {
    closeAdminModal();
    try {
        await api(`/api/admin/users/${userId}`, { method: 'DELETE' });
        Toast.show('User deleted successfully', 'success');
        const usersRes = await api('/api/admin/users');
        adminData.users = usersRes.users || [];
        switchAdminTab('users');

        // Refresh stats
        const statsRes = await api('/api/admin/stats');
        const s = statsRes.stats;
        setTextIfExists('admin-total-users', s.total_users);
    } catch (err) {
        Toast.show('Failed to delete user: ' + err.message, 'error');
    }
}
