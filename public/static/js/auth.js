// ============================================================
// CyberGuard AI - Authentication Module
// ============================================================

// Register routes
Router.register('login', renderLogin);
Router.register('register', renderRegister);

// ============================================================
// Login Page
// ============================================================
function renderLogin() {
    const container = document.getElementById('auth-container');
    container.innerHTML = `
        <div class="auth-bg"></div>
        <div class="auth-card">
            <div class="auth-logo">
                <div class="auth-logo-icon">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="#06b6d4" stroke-width="1.5" fill="rgba(6,182,212,0.06)"/>
                        <path d="M9 12l2 2 4-4" stroke="#10b981" stroke-width="2"/>
                    </svg>
                </div>
                <h1 class="auth-title">CyberGuard AI</h1>
                <p class="auth-subtitle">Threat Detection Platform</p>
            </div>
            <form id="login-form" class="auth-form">
                <div class="form-group">
                    <label for="login-email">Email Address</label>
                    <input type="email" id="login-email" placeholder="admin@cyberguard.ai" required autocomplete="email">
                </div>
                <div class="form-group">
                    <label for="login-password">Password</label>
                    <div class="password-input-wrapper">
                        <input type="password" id="login-password" placeholder="Enter your password" required autocomplete="current-password">
                        <button type="button" class="password-toggle" onclick="togglePassword('login-password', this)">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                <circle cx="12" cy="12" r="3"/>
                            </svg>
                        </button>
                    </div>
                </div>
                <div class="form-row" style="margin-bottom:20px;">
                    <label class="checkbox-label">
                        <input type="checkbox" id="remember-me"> Remember me
                    </label>
                </div>
                <div id="login-error" class="form-error" style="display:none"></div>
                <button type="submit" class="btn btn-primary btn-block" id="login-btn">
                    <span class="btn-text">Sign In</span>
                    <span class="btn-loader" style="display:none"></span>
                </button>
            </form>
            <div class="auth-footer">
                <p>Don't have an account? <a href="#register" class="auth-link">Create Account</a></p>
            </div>
            <div class="auth-demo-info">
                <p><strong>Demo Credentials</strong></p>
                <p>Admin: admin@cyberguard.ai / Admin@123</p>
                <p>Analyst: analyst@cyberguard.ai / Analyst@123</p>
                <p>User: user@cyberguard.ai / User@123</p>
            </div>
        </div>
    `;

    document.getElementById('login-form').addEventListener('submit', handleLogin);
}

async function handleLogin(e) {
    e.preventDefault();
    const btn = document.getElementById('login-btn');
    const errorDiv = document.getElementById('login-error');

    btn.disabled = true;
    btn.querySelector('.btn-text').style.display = 'none';
    btn.querySelector('.btn-loader').style.display = 'inline-block';
    errorDiv.style.display = 'none';

    try {
        const data = await api('/api/auth/login', {
            method: 'POST',
            body: {
                email: document.getElementById('login-email').value,
                password: document.getElementById('login-password').value
            }
        });
        Auth.setToken(data.token);
        Auth.setUser(data.user);
        Toast.show(`Welcome back, ${data.user.name}!`, 'success');
        Router.navigate('dashboard');
    } catch (err) {
        errorDiv.textContent = err.message;
        errorDiv.style.display = 'block';
    } finally {
        btn.disabled = false;
        btn.querySelector('.btn-text').style.display = 'inline';
        btn.querySelector('.btn-loader').style.display = 'none';
    }
}

// ============================================================
// Register Page
// ============================================================
function renderRegister() {
    const container = document.getElementById('auth-container');
    container.innerHTML = `
        <div class="auth-bg"></div>
        <div class="auth-card">
            <div class="auth-logo">
                <div class="auth-logo-icon">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="#06b6d4" stroke-width="1.5" fill="rgba(6,182,212,0.06)"/>
                        <path d="M9 12l2 2 4-4" stroke="#10b981" stroke-width="2"/>
                    </svg>
                </div>
                <h1 class="auth-title">CyberGuard AI</h1>
                <p class="auth-subtitle">Create your account</p>
            </div>
            <form id="register-form" class="auth-form">
                <div class="form-group">
                    <label for="reg-name">Full Name</label>
                    <input type="text" id="reg-name" placeholder="John Doe" required>
                </div>
                <div class="form-group">
                    <label for="reg-email">Email Address</label>
                    <input type="email" id="reg-email" placeholder="you@example.com" required>
                </div>
                <div class="form-row form-row-2">
                    <div class="form-group">
                        <label for="reg-password">Password</label>
                        <input type="password" id="reg-password" placeholder="Min 8 characters" required minlength="8">
                    </div>
                    <div class="form-group">
                        <label for="reg-confirm">Confirm Password</label>
                        <input type="password" id="reg-confirm" placeholder="Repeat password" required>
                    </div>
                </div>
                <div class="form-group">
                    <label for="reg-tenant">Organization / Tenant Name</label>
                    <input type="text" id="reg-tenant" placeholder="e.g. Acme Corp (Optional)">
                </div>
                <div class="form-group">
                    <label for="reg-role">Role</label>
                    <select id="reg-role">
                        <option value="user">Standard User</option>
                        <option value="analyst" selected>Security Analyst</option>
                        <option value="admin">Administrator</option>
                    </select>
                </div>
                <div id="register-error" class="form-error" style="display:none"></div>
                <button type="submit" class="btn btn-primary btn-block" id="register-btn">
                    <span class="btn-text">Create Account</span>
                    <span class="btn-loader" style="display:none"></span>
                </button>
            </form>
            <div class="auth-footer">
                <p>Already have an account? <a href="#login" class="auth-link">Sign In</a></p>
            </div>
        </div>
    `;

    document.getElementById('register-form').addEventListener('submit', handleRegister);
}

async function handleRegister(e) {
    e.preventDefault();
    const password = document.getElementById('reg-password').value;
    const confirm = document.getElementById('reg-confirm').value;
    const errorDiv = document.getElementById('register-error');
    const btn = document.getElementById('register-btn');

    if (password !== confirm) {
        errorDiv.textContent = 'Passwords do not match';
        errorDiv.style.display = 'block';
        return;
    }
    if (password.length < 8) {
        errorDiv.textContent = 'Password must be at least 8 characters';
        errorDiv.style.display = 'block';
        return;
    }

    btn.disabled = true;
    btn.querySelector('.btn-text').style.display = 'none';
    btn.querySelector('.btn-loader').style.display = 'inline-block';
    errorDiv.style.display = 'none';

    try {
        const data = await api('/api/auth/register', {
            method: 'POST',
            body: {
                name: document.getElementById('reg-name').value,
                email: document.getElementById('reg-email').value,
                password: password,
                confirm_password: confirm,
                role: document.getElementById('reg-role').value,
                tenant_name: document.getElementById('reg-tenant').value
            }
        });
        Auth.setToken(data.token);
        Auth.setUser(data.user);
        Toast.show('Account created successfully!', 'success');
        Router.navigate('dashboard');
    } catch (err) {
        errorDiv.textContent = err.message;
        errorDiv.style.display = 'block';
    } finally {
        btn.disabled = false;
        btn.querySelector('.btn-text').style.display = 'inline';
        btn.querySelector('.btn-loader').style.display = 'none';
    }
}

// ============================================================
// Password Toggle
// ============================================================
function togglePassword(inputId, btn) {
    const input = document.getElementById(inputId);
    const svg = btn.querySelector('svg');
    if (input.type === 'password') {
        input.type = 'text';
        svg.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';
    } else {
        input.type = 'password';
        svg.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
    }
}
