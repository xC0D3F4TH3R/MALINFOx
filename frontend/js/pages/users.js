// User Management Page (Admin only)
// Manage users, roles, and API keys

import { API } from '../api.js';
import { UI } from '../ui.js';

export const UsersPage = {
  currentTab: 'users',

  async render() {
    const main = document.getElementById('appMain');
    if (!main) return;

    main.innerHTML = `
      <div class="page-header">
        <div>
          <h1>User Management</h1>
          <p>Manage user accounts, roles, and API access</p>
        </div>
        <div class="page-header-actions">
          <button class="btn btn-primary" id="createUserBtn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="12" y1="5" x2="12" y2="19"></line>
              <line x1="5" y1="12" x2="19" y2="12"></line>
            </svg>
            Add User
          </button>
        </div>
      </div>

      <div class="tabs">
        <button class="tab-btn active" data-tab="users">Users</button>
        <button class="tab-btn" data-tab="api-keys">API Keys</button>
      </div>

      <div class="tab-content active" id="tab-users">
        <div class="card">
          <div id="usersTable">${UI.showLoading()}</div>
        </div>
      </div>

      <div class="tab-content" id="tab-api-keys">
        <div class="card">
          <div id="apiKeysTable">${UI.showLoading()}</div>
        </div>
      </div>
    `;

    this.setupEventListeners();
    await this.loadUsers();
    await this.loadAPIKeys();
  },

  setupEventListeners() {
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
        this.currentTab = btn.dataset.tab;
      });
    });

    // Create user button
    document.getElementById('createUserBtn')?.addEventListener('click', () => this.showCreateUserModal());
  },

  async loadUsers() {
    const container = document.getElementById('usersTable');
    if (!container) return;

    container.innerHTML = UI.showLoading();

    try {
      const users = await API.getUsers({ limit: 100 });
      this.renderUsers(users);
    } catch (error) {
      container.innerHTML = UI.showEmptyState('', 'Failed to load users', '⚠');
    }
  },

  renderUsers(users) {
    const container = document.getElementById('usersTable');
    if (!container) return;

    if (!users.length) {
      container.innerHTML = UI.showEmptyState('', 'No users found');
      return;
    }

    container.innerHTML = UI.renderTable(
      [
        { field: 'username', label: 'Username' },
        { field: 'full_name', label: 'Full Name' },
        { field: 'email', label: 'Email' },
        { field: 'role', label: 'Role', render: v => UI.createTag(v) },
        { field: 'is_active', label: 'Status', render: v => v ? UI.createPill('Active', 'safe') : UI.createPill('Inactive', 'warning') },
        { field: 'mfa_enabled', label: 'MFA', render: v => v ? UI.createPill('Enabled', 'safe') : UI.createPill('Disabled', 'warning') },
        { field: 'last_login', label: 'Last Login', render: v => v ? UI.formatRelativeTime(v) : 'Never' },
        { field: 'created_at', label: 'Created', render: v => UI.formatRelativeTime(v) },
        { field: 'id', label: 'Actions', render: (v, r) => `
          <div style="display:flex;gap:0.25rem;">
            <button class="btn btn-sm btn-ghost" onclick="MALINFO.pages.users.editUser('${v}')" title="Edit">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
              </svg>
            </button>
            <button class="btn btn-sm btn-ghost danger" onclick="MALINFO.pages.users.deleteUser('${v}', '${UI.escapeHtml(r.username)}')" title="Delete">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="3 6 5 6 21 6"></polyline>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
              </svg>
            </button>
          </div>
        ` },
      ],
      users,
      { emptyMessage: 'No users found' }
    );
  },

  async loadAPIKeys() {
    const container = document.getElementById('apiKeysTable');
    if (!container) return;

    container.innerHTML = UI.showLoading();

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
      container.innerHTML = UI.showEmptyState('', 'No API keys found. Create one to enable programmatic access.');
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
          <button class="btn btn-sm btn-ghost danger" onclick="MALINFO.pages.users.revokeAPIKey('${v}', '${UI.escapeHtml(r.name)}')" title="Revoke">
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

  showCreateUserModal() {
    const modalHtml = `
      <div class="modal-overlay open" id="createUserModal" style="position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:2000;">
        <div class="modal" style="max-width:500px;">
          <div class="modal-header">
            <h3 class="modal-title">Create User</h3>
            <button class="modal-close" onclick="document.getElementById('createUserModal').remove()">&times;</button>
          </div>
          <div class="modal-body">
            <form id="createUserForm">
              <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required minlength="3" maxlength="64" style="width:100%;">
              </div>
              <div class="form-group">
                <label>Email</label>
                <input type="email" name="email" required style="width:100%;">
              </div>
              <div class="form-group">
                <label>Full Name</label>
                <input type="text" name="full_name" required style="width:100%;">
              </div>
              <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required minlength="12" style="width:100%;">
                <small style="color:var(--text-muted)">Minimum 12 characters</small>
              </div>
              <div class="form-group">
                <label>Role</label>
                <select name="role" style="width:100%;">
                  <option value="viewer">Viewer</option>
                  <option value="operator">Operator</option>
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div class="form-actions">
                <button type="button" class="btn" onclick="document.getElementById('createUserModal').remove()">Cancel</button>
                <button type="submit" class="btn btn-primary">Create User</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modalHtml);

    document.getElementById('createUserForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      const userData = Object.fromEntries(formData);

      const submitBtn = e.target.querySelector('button[type="submit"]');
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span class="spinner spinner-sm"></span> Creating...';

      try {
        await API.createUser(userData);
        UI.toast('User created successfully', 'success');
        document.getElementById('createUserModal').remove();
        this.loadUsers();
      } catch (error) {
        UI.toast(`Failed to create user: ${error.message}`, 'error');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create User';
      }
    });
  },

  async editUser(userId) {
    try {
      const user = await API.getUser(userId);
      
      const modalHtml = `
        <div class="modal-overlay open" id="editUserModal" style="position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:2000;">
          <div class="modal" style="max-width:500px;">
            <div class="modal-header">
              <h3 class="modal-title">Edit User: ${UI.escapeHtml(user.username)}</h3>
              <button class="modal-close" onclick="document.getElementById('editUserModal').remove()">&times;</button>
            </div>
            <div class="modal-body">
              <form id="editUserForm">
                <div class="form-group">
                  <label>Email</label>
                  <input type="email" name="email" value="${UI.escapeHtml(user.email)}" style="width:100%;">
                </div>
                <div class="form-group">
                  <label>Full Name</label>
                  <input type="text" name="full_name" value="${UI.escapeHtml(user.full_name)}" style="width:100%;">
                </div>
                <div class="form-group">
                  <label>Role</label>
                  <select name="role" style="width:100%;">
                    <option value="viewer" ${user.role === 'viewer' ? 'selected' : ''}>Viewer</option>
                    <option value="operator" ${user.role === 'operator' ? 'selected' : ''}>Operator</option>
                    <option value="analyst" ${user.role === 'analyst' ? 'selected' : ''}>Analyst</option>
                    <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option>
                  </select>
                </div>
                <div class="form-group">
                  <label>
                    <input type="checkbox" name="is_active" ${user.is_active ? 'checked' : ''}> Active
                  </label>
                </div>
                <div class="form-actions">
                  <button type="button" class="btn" onclick="document.getElementById('editUserModal').remove()">Cancel</button>
                  <button type="submit" class="btn btn-primary">Save Changes</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      `;

      document.body.insertAdjacentHTML('beforeend', modalHtml);

      document.getElementById('editUserForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const updateData = {};
        
        for (const [key, value] of formData.entries()) {
          if (key === 'is_active') {
            updateData[key] = value === 'on';
          } else {
            updateData[key] = value;
          }
        }

        const submitBtn = e.target.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner spinner-sm"></span> Saving...';

        try {
          await API.updateUser(userId, updateData);
          UI.toast('User updated successfully', 'success');
          document.getElementById('editUserModal').remove();
          this.loadUsers();
        } catch (error) {
          UI.toast(`Failed to update user: ${error.message}`, 'error');
          submitBtn.disabled = false;
          submitBtn.textContent = 'Save Changes';
        }
      });
    } catch (error) {
      UI.toast(`Failed to load user: ${error.message}`, 'error');
    }
  },

  async deleteUser(userId, username) {
    if (!confirm(`Delete user "${username}"? This action cannot be undone.`)) return;

    try {
      await API.deleteUser(userId);
      UI.toast('User deleted', 'success');
      this.loadUsers();
    } catch (error) {
      UI.toast(`Failed to delete user: ${error.message}`, 'error');
    }
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
    if (this.currentTab === 'users') this.loadUsers();
    else this.loadAPIKeys();
  },
};