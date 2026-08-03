// Profile Page
// User profile management, MFA, password change

import { API } from '../api.js';
import { UI } from '../ui.js';
import { Auth } from '../auth.js';

export const ProfilePage = {
  async render() {
    const main = document.getElementById('appMain');
    if (!main) return;

    // Get current user
    const user = Auth.getCurrentUser ? await Auth.getCurrentUser() : MALINFO.currentUser;

    main.innerHTML = `
      <div class="page-header">
        <div>
          <h1>Profile</h1>
          <p>Manage your account settings and preferences</p>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:300px 1fr;gap:1.5rem;">
        <!-- Profile Sidebar -->
        <div class="card" style="text-align:center;padding:2rem;">
          <div class="user-avatar" style="width:80px;height:80px;font-size:28px;margin:0 auto 1rem;">${user?.full_name?.split(' ').map(n => n[0]).join('').toUpperCase() || 'MI'}</div>
          <h2 style="margin:0 0 0.5rem;">${UI.escapeHtml(user?.full_name || 'Unknown')}</h2>
          <p style="color:var(--text-muted);margin:0 0 0.5rem;">@${UI.escapeHtml(user?.username || 'unknown')}</p>
          <span class="pill" style="background:var(--panel-raised);color:var(--text-secondary);">${UI.escapeHtml(user?.role || 'viewer')}</span>
          <p style="margin-top:1rem;font-size:12px;color:var(--text-muted)">Member since ${user?.created_at ? UI.formatDate(user.created_at) : 'Unknown'}</p>
        </div>

        <!-- Profile Content -->
        <div>
          <div class="tabs">
            <button class="tab-btn active" data-tab="account">Account</button>
            <button class="tab-btn" data-tab="security">Security</button>
            <button class="tab-btn" data-tab="sessions">Sessions</button>
            <button class="tab-btn" data-tab="api-keys">API Keys</button>
          </div>

          <div class="tab-content active" id="tab-account">
            <div class="card">
              <div class="card-header"><h2>Account Information</h2></div>
              <form id="accountForm">
                <div class="form-row">
                  <div class="form-group">
                    <label>Full Name</label>
                    <input type="text" name="full_name" value="${UI.escapeHtml(user?.full_name || '')}" required style="width:100%;">
                  </div>
                  <div class="form-group">
                    <label>Email</label>
                    <input type="email" name="email" value="${UI.escapeHtml(user?.email || '')}" required style="width:100%;">
                  </div>
                </div>
                <div class="form-group">
                  <label>Username</label>
                  <input type="text" value="${UI.escapeHtml(user?.username || '')}" disabled style="width:100%;background:var(--panel);color:var(--text-muted);">
                  <small style="color:var(--text-muted)">Username cannot be changed</small>
                </div>
                <div class="form-actions">
                  <button type="submit" class="btn btn-primary">Save Changes</button>
                </div>
              </form>
            </div>
          </div>

          <div class="tab-content" id="tab-security">
            <div class="card">
              <div class="card-header"><h2>Change Password</h2></div>
              <form id="passwordForm">
                <div class="form-group">
                  <label>Current Password</label>
                  <input type="password" name="current_password" required style="width:100%;">
                </div>
                <div class="form-row">
                  <div class="form-group">
                    <label>New Password</label>
                    <input type="password" name="new_password" required minlength="12" style="width:100%;">
                    <small style="color:var(--text-muted)">Minimum 12 characters</small>
                  </div>
                  <div class="form-group">
                    <label>Confirm New Password</label>
                    <input type="password" name="confirm_password" required style="width:100%;">
                  </div>
                </div>
                <div class="form-actions">
                  <button type="submit" class="btn btn-primary">Change Password</button>
                </div>
              </form>
            </div>

            <div class="card" style="margin-top:1.5rem;">
              <div class="card-header"><h2>Two-Factor Authentication (MFA)</h2></div>
              <div id="mfaSection">
                ${user?.mfa_enabled ? this.renderMFAEnabled() : this.renderMFADisabled()}
              </div>
            </div>
          </div>

          <div class="tab-content" id="tab-sessions">
            <div class="card">
              <div class="card-header"><h2>Active Sessions</h2></div>
              <div id="sessionsTable">${UI.showLoading()}</div>
            </div>
          </div>

          <div class="tab-content" id="tab-api-keys">
            <div class="card">
              <div class="card-header">
                <h2>API Keys</h2>
                <button class="btn btn-primary btn-sm" id="createApiKeyBtn">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="12" y1="5" x2="12" y2="19"></line>
                    <line x1="5" y1="12" x2="19" y2="12"></line>
                  </svg>
                  Create Key
                </button>
              </div>
              <div id="apiKeysTable">${UI.showLoading()}</div>
            </div>
          </div>
        </div>
      </div>
    `;

    this.setupEventListeners();
    await this.loadSessions();
    await this.loadAPIKeys();
  },

  renderMFAEnabled() {
    return `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:1rem;background:var(--safe-dim);border:1px solid var(--safe);border-radius:var(--radius);">
        <div>
          <strong style="color:var(--safe)">MFA Enabled</strong>
          <p style="margin:0.25rem 0 0;color:var(--text-secondary);font-size:13px;">Your account is protected with two-factor authentication</p>
        </div>
        <button class="btn btn-ghost danger" id="disableMFABtn">Disable MFA</button>
      </div>
    `;
  },

  renderMFADisabled() {
    return `
      <div style="padding:1rem;">
        <p style="color:var(--text-secondary);margin-bottom:1rem;">Add an extra layer of security to your account with time-based one-time passwords (TOTP).</p>
        <button class="btn btn-primary" id="setupMFABtn">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
          Enable MFA
        </button>
      </div>
    `;
  },

  setupEventListeners() {
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
      });
    });

    // Account form
    document.getElementById('accountForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData);

      const submitBtn = e.target.querySelector('button[type="submit"]');
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span class="spinner spinner-sm"></span> Saving...';

      try {
        await API.updateProfile(data);
        UI.toast('Profile updated', 'success');
        MALINFO.currentUser = { ...MALINFO.currentUser, ...data };
        UI.updateUserDisplay(MALINFO.currentUser);
      } catch (error) {
        UI.toast(`Failed to update profile: ${error.message}`, 'error');
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Save Changes';
      }
    });

    // Password form
    document.getElementById('passwordForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData);

      if (data.new_password !== data.confirm_password) {
        UI.toast('Passwords do not match', 'error');
        return;
      }

      const submitBtn = e.target.querySelector('button[type="submit"]');
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span class="spinner spinner-sm"></span> Changing...';

      try {
        await API.changePassword(data.current_password, data.new_password);
        UI.toast('Password changed. Please log in again.', 'success');
        setTimeout(() => {
          Auth.logout();
          window.location.hash = 'login';
        }, 1500);
      } catch (error) {
        UI.toast(`Failed to change password: ${error.message}`, 'error');
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Change Password';
      }
    });

    // MFA setup
    document.getElementById('setupMFABtn')?.addEventListener('click', () => this.setupMFA());
    document.getElementById('disableMFABtn')?.addEventListener('click', () => this.disableMFA());

    // API Keys
    document.getElementById('createApiKeyBtn')?.addEventListener('click', () => this.showCreateAPIKeyModal());
  },

  async setupMFA() {
    try {
      const result = await API.setupMFA();
      
      const modalHtml = `
        <div class="modal-overlay open" id="mfaSetupModal" style="position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:2000;">
          <div class="modal" style="max-width:500px;">
            <div class="modal-header">
              <h3 class="modal-title">Setup Two-Factor Authentication</h3>
              <button class="modal-close" onclick="document.getElementById('mfaSetupModal').remove()">&times;</button>
            </div>
            <div class="modal-body">
              <p style="margin-bottom:1rem;">Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password, etc.)</p>
              <div style="text-align:center;margin:1rem 0;">
                <img src="${result.qr_code_uri}" alt="MFA QR Code" style="max-width:100%;border:1px solid var(--line);border-radius:var(--radius);">
              </div>
              <div style="background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:1rem;margin-bottom:1rem;font-family:var(--font-mono);font-size:14px;text-align:center;">
                Secret: <strong>${result.secret}</strong>
              </div>
              <p style="font-size:12px;color:var(--text-muted);margin-bottom:1rem;">Save the secret key in a safe place for recovery.</p>
              <div class="form-group">
                <label>Enter 6-digit code from authenticator app</label>
                <input type="text" id="mfaVerifyCode" maxlength="6" placeholder="123456" style="width:100%;text-align:center;letter-spacing:0.5em;font-size:18px;">
              </div>
              <div class="form-actions">
                <button type="button" class="btn" onclick="document.getElementById('mfaSetupModal').remove()">Cancel</button>
                <button type="button" class="btn btn-primary" id="verifyMFABtn">Verify & Enable</button>
              </div>
            </div>
          </div>
        </div>
      `;

      document.body.insertAdjacentHTML('beforeend', modalHtml);

      document.getElementById('verifyMFABtn')?.addEventListener('click', async () => {
        const code = document.getElementById('mfaVerifyCode').value.trim();
        if (!code || code.length !== 6) {
          UI.toast('Enter 6-digit code', 'warning');
          return;
        }

        const btn = document.getElementById('verifyMFABtn');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner spinner-sm"></span> Verifying...';

        try {
          await API.verifyMFA(code);
          UI.toast('MFA enabled successfully', 'success');
          document.getElementById('mfaSetupModal').remove();
          
          // Update UI
          const mfaSection = document.getElementById('mfaSection');
          if (mfaSection) mfaSection.innerHTML = this.renderMFAEnabled();
          this.setupEventListeners(); // Re-bind disable button
        } catch (error) {
          UI.toast(`Verification failed: ${error.message}`, 'error');
        } finally {
          btn.disabled = false;
          btn.textContent = 'Verify & Enable';
        }
      });
    } catch (error) {
      UI.toast(`Failed to setup MFA: ${error.message}`, 'error');
    }
  },

  async disableMFA() {
    if (!confirm('Disable two-factor authentication? This reduces your account security.')) return;

    try {
      await API.disableMFA();
      UI.toast('MFA disabled', 'success');
      
      const mfaSection = document.getElementById('mfaSection');
      if (mfaSection) mfaSection.innerHTML = this.renderMFADisabled();
      this.setupEventListeners(); // Re-bind setup button
    } catch (error) {
      UI.toast(`Failed to disable MFA: ${error.message}`, 'error');
    }
  },

  async loadSessions() {
    const container = document.getElementById('sessionsTable');
    if (!container) return;

    // Note: Would need backend endpoint for user sessions
    container.innerHTML = UI.showEmptyState('', 'Session management endpoint not yet implemented', '🔐');
  },

  async loadAPIKeys() {
    const container = document.getElementById('apiKeysTable');
    if (!container) return;

    try {
      const keys = await API.getAPIKeys();
      this.renderAPIKeys(keys);
    } catch (error) {
      container.innerHTML = UI.showEmptyState('', 'Failed to load API keys', '⚠');
    }
  },

  renderAPIKeys(keys) {
    const container = document.getElementById('apiKeysTable');
    if (!container) return;

    if (!keys.length) {
      container.innerHTML = UI.showEmptyState('', 'No API keys created yet');
      return;
    }

    container.innerHTML = UI.renderTable(
      [
        { field: 'name', label: 'Name' },
        { field: 'prefix', label: 'Prefix', render: v => `<code class="mono">${v}...</code>` },
        { field: 'permissions', label: 'Permissions', render: v => v.length ? v.map(p => UI.createTag(p)).join(' ') : '<span style="color:var(--text-muted)">None</span>' },
        { field: 'is_active', label: 'Status', render: v => v ? UI.createPill('Active', 'safe') : UI.createPill('Revoked', 'warning') },
        { field: 'expires_at', label: 'Expires', render: v => v ? UI.formatRelativeTime(v) : 'Never' },
        { field: 'last_used', label: 'Last Used', render: v => v ? UI.formatRelativeTime(v) : 'Never' },
        { field: 'created_at', label: 'Created', render: v => UI.formatRelativeTime(v) },
        { field: 'id', label: 'Actions', render: (v, r) => `
          <button class="btn btn-sm btn-ghost danger" onclick="MALINFO.pages.profile.revokeAPIKey('${v}', '${UI.escapeHtml(r.name)}')" title="Revoke">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="15" y1="9" x2="9" y2="15"></line>
              <line x1="9" y1="9" x2="15" y2="15"></line>
            </svg>
          </button>
        ` },
      ],
      keys,
      { emptyMessage: 'No API keys found' }
    );
  },

  showCreateAPIKeyModal() {
    const modalHtml = `
      <div class="modal-overlay open" id="createApiKeyModal" style="position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:2000;">
        <div class="modal" style="max-width:500px;">
          <div class="modal-header">
            <h3 class="modal-title">Create API Key</h3>
            <button class="modal-close" onclick="document.getElementById('createApiKeyModal').remove()">&times;</button>
          </div>
          <div class="modal-body">
            <form id="createApiKeyForm">
              <div class="form-group">
                <label>Key Name</label>
                <input type="text" name="name" required placeholder="e.g., CI/CD Pipeline" style="width:100%;">
              </div>
              <div class="form-group">
                <label>Permissions (one per line)</label>
                <textarea name="permissions" rows="4" placeholder="sample:upload
sample:view_own
report:view_own" style="width:100%;font-family:var(--font-mono);font-size:12px;"></textarea>
                <small style="color:var(--text-muted)">Leave empty for default permissions based on your role</small>
              </div>
              <div class="form-group">
                <label>Expires In (days, optional)</label>
                <input type="number" name="expires_days" min="1" max="365" placeholder="30" style="width:100%;">
              </div>
              <div class="form-actions">
                <button type="button" class="btn" onclick="document.getElementById('createApiKeyModal').remove()">Cancel</button>
                <button type="submit" class="btn btn-primary">Create Key</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    document.getElementById('createApiKeyForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      const name = formData.get('name');
      const permissions = formData.get('permissions')?.split('\n').filter(p => p.trim()) || [];
      const expiresDays = formData.get('expires_days') ? parseInt(formData.get('expires_days')) : null;

      const submitBtn = e.target.querySelector('button[type="submit"]');
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span class="spinner spinner-sm"></span> Creating...';

      try {
        const result = await API.createAPIKey(name, permissions, expiresDays);
        
        // Show the key (only time it's visible!)
        const modalHtml = `
          <div class="modal-overlay open" id="apiKeyCreatedModal" style="position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:2000;">
            <div class="modal" style="max-width:600px;">
              <div class="modal-header">
                <h3 class="modal-title">API Key Created</h3>
              </div>
              <div class="modal-body">
                <div style="background:var(--danger-dim);border:1px solid var(--danger);border-radius:var(--radius);padding:1rem;margin-bottom:1rem;color:var(--danger);">
                  <strong>Important:</strong> This is the only time the full key will be shown. Copy and store it securely.
                </div>
                <div style="font-family:var(--font-mono);font-size:14px;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:1rem;word-break:break-all;">
                  ${result.key}
                </div>
                <button class="btn btn-primary" style="width:100%;" onclick="navigator.clipboard.writeText('${result.key}');UI.toast('Copied to clipboard','success');document.getElementById('apiKeyCreatedModal').remove();">Copy & Close</button>
              </div>
            </div>
          </div>
        `;

        document.getElementById('createApiKeyModal').remove();
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        
        this.loadAPIKeys();
      } catch (error) {
        UI.toast(`Failed to create API key: ${error.message}`, 'error');
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create Key';
      }
    });
  },

  async revokeAPIKey(keyId, name) {
    if (!confirm(`Revoke API key "${name}"?`)) return;

    try {
      await API.revokeAPIKey(keyId);
      UI.toast('API key revoked', 'success');
      this.loadAPIKeys();
    } catch (error) {
      UI.toast(`Failed to revoke API key: ${error.message}`, 'error');
    }
  },

  refresh() {
    this.loadSessions();
    this.loadAPIKeys();
  },
};