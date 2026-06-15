/* ============================================================
   CyberGuard AI - Profile Settings Module
   ============================================================ */

Router.register('profile', renderProfile);

async function renderProfile() {
    const user = Auth.getUser();
    if (!user) {
        Router.navigate('login');
        return;
    }

    const content = document.getElementById('page-content');
    content.innerHTML = `
        <div class="page-header">
            <h1>Profile Settings</h1>
            <p class="page-subtitle">Manage your personal details and account security</p>
        </div>

        <div class="profile-grid">
            <!-- Account Summary Card -->
            <div class="card profile-info-card">
                <h3 class="card-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2" style="margin-right: 8px; vertical-align: middle;">
                        <circle cx="12" cy="12" r="10"/>
                        <path d="M12 16v-4"/>
                        <path d="M12 8h.01"/>
                    </svg>
                    Account Summary
                </h3>
                <div class="profile-avatar-large">
                    <span>${Auth.getUserInitials()}</span>
                </div>
                <div class="profile-summary-details">
                    <div class="summary-item">
                        <span class="summary-label">Name</span>
                        <span class="summary-value" id="profile-sum-name">${escapeHtml(user.name)}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Email Address</span>
                        <span class="summary-value">${escapeHtml(user.email)}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Role</span>
                        <span class="summary-value">
                            <span class="role-badge role-${user.role}">${user.role.toUpperCase()}</span>
                        </span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Current Workspace</span>
                        <span class="summary-value text-accent-cyan">${escapeHtml(user.tenant_name || 'Default Org')}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Account Status</span>
                        <span class="summary-value text-accent-green">Active</span>
                    </div>
                </div>
            </div>

            <!-- Update Settings Form -->
            <div class="card profile-form-card">
                <h3 class="card-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-purple)" stroke-width="2" style="margin-right: 8px; vertical-align: middle;">
                        <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
                        <path d="M18.5 2.5a2.121 2.121 0 113 3L12 15l-4 1 1-4 9.5-9.5z"/>
                    </svg>
                    Edit Profile Details
                </h3>
                <form id="profile-settings-form" class="cyber-form">
                    <div class="form-group">
                        <label for="profile-name">Full Name</label>
                        <input type="text" id="profile-name" class="form-input" value="${escapeHtml(user.name)}" required>
                    </div>

                    <h4 style="margin: 24px 0 12px; color: var(--accent-cyan); font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">
                        Change Password
                    </h4>
                    <p class="text-secondary" style="font-size: 12px; margin-bottom: 16px;">Leave password fields blank if you do not wish to update your password.</p>

                    <div class="form-group">
                        <label for="profile-current-pw">Current Password</label>
                        <div class="password-input-wrapper">
                            <input type="password" id="profile-current-pw" class="form-input" placeholder="••••••••">
                            <button type="button" class="password-toggle" onclick="togglePassword('profile-current-pw', this)">
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                    <circle cx="12" cy="12" r="3"/>
                                </svg>
                            </button>
                        </div>
                    </div>

                    <div class="form-row form-row-2">
                        <div class="form-group">
                            <label for="profile-new-pw">New Password</label>
                            <div class="password-input-wrapper">
                                <input type="password" id="profile-new-pw" class="form-input" placeholder="Min 8 characters">
                                <button type="button" class="password-toggle" onclick="togglePassword('profile-new-pw', this)">
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                        <circle cx="12" cy="12" r="3"/>
                                    </svg>
                                </button>
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="profile-confirm-pw">Confirm New Password</label>
                            <div class="password-input-wrapper">
                                <input type="password" id="profile-confirm-pw" class="form-input" placeholder="Repeat new password">
                                <button type="button" class="password-toggle" onclick="togglePassword('profile-confirm-pw', this)">
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                        <circle cx="12" cy="12" r="3"/>
                                    </svg>
                                </button>
                            </div>
                        </div>
                    </div>

                    <div id="profile-error" class="form-error" style="display:none; margin-bottom: 16px;"></div>
                    <div id="profile-success" class="form-success" style="display:none; margin-bottom: 16px;"></div>

                    <button type="submit" class="btn btn-primary" id="save-profile-btn" style="margin-top: 12px; min-width: 150px;">
                        <span class="btn-text">Save Changes</span>
                        <span class="btn-loader" style="display:none"></span>
                    </button>
                </form>
            </div>
        </div>
    `;

    document.getElementById('profile-settings-form').addEventListener('submit', handleProfileUpdate);
}

async function handleProfileUpdate(e) {
    e.preventDefault();
    const saveBtn = document.getElementById('save-profile-btn');
    const errorDiv = document.getElementById('profile-error');
    const successDiv = document.getElementById('profile-success');

    const name = document.getElementById('profile-name').value.trim();
    const currentPassword = document.getElementById('profile-current-pw').value;
    const newPassword = document.getElementById('profile-new-pw').value;
    const confirmPassword = document.getElementById('profile-confirm-pw').value;

    errorDiv.style.display = 'none';
    successDiv.style.display = 'none';

    // Verify fields if password update is requested
    if (newPassword || currentPassword) {
        if (!currentPassword) {
            errorDiv.textContent = 'Current password is required to change password';
            errorDiv.style.display = 'block';
            return;
        }
        if (newPassword.length < 8) {
            errorDiv.textContent = 'New password must be at least 8 characters';
            errorDiv.style.display = 'block';
            return;
        }
        if (newPassword !== confirmPassword) {
            errorDiv.textContent = 'New passwords do not match';
            errorDiv.style.display = 'block';
            return;
        }
    }

    saveBtn.disabled = true;
    saveBtn.querySelector('.btn-text').style.display = 'none';
    saveBtn.querySelector('.btn-loader').style.display = 'inline-block';

    try {
        const body = { name };
        if (newPassword) {
            body.current_password = currentPassword;
            body.new_password = newPassword;
        }

        const data = await api('/api/auth/profile', {
            method: 'PUT',
            body: body
        });

        // Update local state
        Auth.setUser(data.user);
        updateSidebar();

        // Update summary values dynamically
        document.getElementById('profile-sum-name').textContent = data.user.name;

        // Reset password fields
        document.getElementById('profile-current-pw').value = '';
        document.getElementById('profile-new-pw').value = '';
        document.getElementById('profile-confirm-pw').value = '';

        successDiv.textContent = 'Profile updated successfully!';
        successDiv.style.display = 'block';
        Toast.show('Profile updated successfully!', 'success');

    } catch (err) {
        errorDiv.textContent = err.message;
        errorDiv.style.display = 'block';
    } finally {
        saveBtn.disabled = false;
        saveBtn.querySelector('.btn-text').style.display = 'inline';
        saveBtn.querySelector('.btn-loader').style.display = 'none';
    }
}
