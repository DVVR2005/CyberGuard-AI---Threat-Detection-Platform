// ============================================================
// CyberGuard AI - Core Application Module
// ============================================================

// API Configuration
const API_BASE = ''; // Same origin

// ============================================================
// Authentication State Management
// ============================================================
const Auth = {
    getToken() { return localStorage.getItem('cyberguard_token'); },
    setToken(token) { localStorage.setItem('cyberguard_token', token); },
    getUser() { return JSON.parse(localStorage.getItem('cyberguard_user') || 'null'); },
    setUser(user) { localStorage.setItem('cyberguard_user', JSON.stringify(user)); },
    isAuthenticated() { return !!this.getToken(); },
    isAdmin() { const u = this.getUser(); return u && u.role === 'admin'; },
    logout() {
        localStorage.removeItem('cyberguard_token');
        localStorage.removeItem('cyberguard_user');
        Router.navigate('login');
    },
    getUserInitials() {
        const u = this.getUser();
        if (!u || !u.name) return '?';
        return u.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
    }
};

// ============================================================
// API Wrapper with Auth & Error Handling
// ============================================================
async function api(endpoint, options = {}) {
    const config = {
        headers: { 'Content-Type': 'application/json' },
        ...options
    };
    if (Auth.getToken()) {
        config.headers['Authorization'] = `Bearer ${Auth.getToken()}`;
    }
    if (options.body && typeof options.body === 'object') {
        config.body = JSON.stringify(options.body);
    }
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, config);
        if (response.status === 401) {
            Auth.logout();
            throw new Error('Session expired. Please log in again.');
        }
        // Handle PDF/blob responses
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/pdf')) {
            if (!response.ok) throw new Error('Failed to download file');
            return response.blob();
        }
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || data.message || 'Request failed');
        }
        return data;
    } catch (err) {
        if (err.name === 'TypeError' && err.message === 'Failed to fetch') {
            throw new Error('Network error. Please check your connection.');
        }
        throw err;
    }
}

// ============================================================
// Toast Notification System
// ============================================================
const Toast = {
    container: null,
    init() {
        this.container = document.createElement('div');
        this.container.id = 'toast-container';
        document.body.appendChild(this.container);
    },
    show(message, type = 'info', duration = 4000) {
        if (!this.container) this.init();
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        const icons = {
            success: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>',
            error: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
            warning: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M12 9v4"/><path d="M12 17h.01"/></svg>',
            info: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>'
        };
        toast.innerHTML = `
            <div class="toast-icon">${icons[type] || icons.info}</div>
            <div class="toast-message">${message}</div>
            <div class="toast-progress"><div class="toast-progress-bar"></div></div>
        `;
        this.container.appendChild(toast);
        // Animate progress bar
        const bar = toast.querySelector('.toast-progress-bar');
        bar.style.transition = `width ${duration}ms linear`;
        requestAnimationFrame(() => {
            requestAnimationFrame(() => { bar.style.width = '0%'; });
        });
        setTimeout(() => {
            toast.classList.add('toast-exit');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }
};

// ============================================================
// SPA Router
// ============================================================
const Router = {
    routes: {},
    register(hash, handler) { this.routes[hash] = handler; },
    navigate(hash) {
        window.location.hash = hash;
    },
    getCurrentRoute() { return window.location.hash.slice(1) || 'dashboard'; },
    init() {
        window.addEventListener('hashchange', () => this.handleRoute());
        this.handleRoute();
    },
    handleRoute() {
        const route = this.getCurrentRoute();

        // Auth check
        if (!Auth.isAuthenticated() && route !== 'login' && route !== 'register') {
            this.navigate('login');
            return;
        }
        if (Auth.isAuthenticated() && (route === 'login' || route === 'register')) {
            this.navigate('dashboard');
            return;
        }

        // Show/hide containers
        const authContainer = document.getElementById('auth-container');
        const dashContainer = document.getElementById('dashboard-container');
        if (!Auth.isAuthenticated()) {
            authContainer.style.display = 'flex';
            dashContainer.style.display = 'none';
        } else {
            authContainer.style.display = 'none';
            dashContainer.style.display = 'flex';
            updateSidebar();
            initWebSockets();
        }

        // Call route handler
        const handler = this.routes[route];
        if (handler) {
            const content = document.getElementById('page-content');
            if (content) {
                content.classList.remove('page-enter');
                void content.offsetWidth; // Trigger reflow
                content.classList.add('page-enter');
            }
            handler();
        }
    }
};

// ============================================================
// Real-time WebSocket Alerting
// ============================================================
let socket = null;
function initWebSockets() {
    if (window.io && Auth.isAuthenticated() && !socket) {
        try {
            socket = io();
            socket.on('scan_started', (data) => {
                Toast.show(`[Scan Alert] ${data.message}`, 'info');
                // Dispatch alert event to components
                window.dispatchEvent(new CustomEvent('scan-state-change', { detail: data }));
            });
            socket.on('scan_completed', (data) => {
                Toast.show(`[Scan Success] ${data.message}`, 'success');
                window.dispatchEvent(new CustomEvent('scan-state-change', { detail: data }));
            });
            socket.on('scan_failed', (data) => {
                Toast.show(`[Scan Error] ${data.message}`, 'error');
                window.dispatchEvent(new CustomEvent('scan-state-change', { detail: data }));
            });
            socket.on('siem_alert', (data) => {
                Toast.show(`[SIEM Log] ${data.message}`, 'warning');
                window.dispatchEvent(new CustomEvent('siem-event-added', { detail: data }));
            });
        } catch (e) {
            console.warn("WebSocket connection failure:", e);
        }
    }
}

// ============================================================
// Sidebar Management
// ============================================================
function updateSidebar() {
    const user = Auth.getUser();
    if (!user) return;

    // Update user info
    const initialsEl = document.getElementById('user-initials');
    const nameEl = document.getElementById('user-name');
    const roleEl = document.getElementById('user-role');

    if (initialsEl) initialsEl.textContent = Auth.getUserInitials();
    if (nameEl) nameEl.textContent = user.name;
    if (roleEl) {
        roleEl.textContent = user.role;
        roleEl.className = `role-badge role-${user.role}`;
    }

    // Update workspace name
    const workspaceEl = document.getElementById('current-workspace-name');
    if (workspaceEl) {
        workspaceEl.textContent = user.tenant_name || 'Default Org';
    }

    // Show/hide admin and SIEM nav items
    const adminNav = document.getElementById('nav-admin');
    if (adminNav) adminNav.style.display = Auth.isAdmin() ? 'flex' : 'none';

    const siemNav = document.getElementById('nav-siem');
    if (siemNav) {
        siemNav.style.display = (user.role === 'admin' || user.role === 'analyst') ? 'flex' : 'none';
    }

    // Update active nav item
    const route = Router.getCurrentRoute();
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.route === route);
    });
}

// ============================================================
// Utility / Format Helpers
// ============================================================
function formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    const d = new Date(dateStr);
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

function formatDateTime(dateStr) {
    if (!dateStr) return 'N/A';
    const d = new Date(dateStr);
    return d.toLocaleDateString('en-US', {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit'
    });
}

function getSeverityClass(severity) {
    const s = (severity || '').toLowerCase();
    if (s === 'critical') return 'badge-critical';
    if (s === 'high') return 'badge-high';
    if (s === 'medium') return 'badge-medium';
    if (s === 'low') return 'badge-low';
    return 'badge-info';
}

function getGradeClass(grade) {
    if (!grade) return '';
    if (grade.startsWith('A')) return 'grade-a';
    if (grade === 'B') return 'grade-b';
    if (grade === 'C') return 'grade-c';
    return 'grade-d';
}

function getScoreColor(score) {
    if (score <= 20) return 'var(--accent-green)';
    if (score <= 40) return 'var(--accent-cyan)';
    if (score <= 60) return 'var(--accent-amber)';
    return 'var(--accent-red)';
}

// Convert scores from 0-1 range to percentage
function formatPercent(val) {
    if (val === undefined || val === null) return '0.00%';
    const floatVal = parseFloat(val);
    return (floatVal * 100).toFixed(2) + '%';
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ============================================================
// Theme Management
// ============================================================
const ThemeManager = {
    init() {
        const savedTheme = localStorage.getItem('cyberguard_theme') || 'cyber-glow';
        this.setTheme(savedTheme);

        const select = document.getElementById('theme-select');
        if (select) {
            select.value = savedTheme;
            select.addEventListener('change', (e) => {
                this.setTheme(e.target.value);
            });
        }
    },
    setTheme(themeName) {
        // Remove previous theme classes
        document.body.className = '';
        // Apply new theme class
        document.body.classList.add(`theme-${themeName}`);
        localStorage.setItem('cyberguard_theme', themeName);
    }
};

// ============================================================
// Initialization
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    Toast.init();
    ThemeManager.init();

    // Setup sidebar nav clicks
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            Router.navigate(item.dataset.route);
            // Close mobile sidebar if open
            document.getElementById('sidebar')?.classList.remove('sidebar-open');
        });
    });

    // Logout button
    document.getElementById('logout-btn')?.addEventListener('click', () => {
        Auth.logout();
        if (socket) {
            socket.disconnect();
            socket = null;
        }
        Toast.show('Logged out successfully', 'success');
    });

    // Mobile sidebar toggle
    document.getElementById('sidebar-toggle')?.addEventListener('click', () => {
        document.getElementById('sidebar')?.classList.toggle('sidebar-open');
    });

    // Close sidebar on overlay click (mobile)
    document.addEventListener('click', (e) => {
        const sidebar = document.getElementById('sidebar');
        const toggle = document.getElementById('sidebar-toggle');
        if (sidebar?.classList.contains('sidebar-open') &&
            !sidebar.contains(e.target) &&
            !toggle?.contains(e.target)) {
            sidebar.classList.remove('sidebar-open');
        }
    });

    Router.init();
});
