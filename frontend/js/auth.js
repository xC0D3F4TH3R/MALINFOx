// MALINFO Authentication Module
// Handles user authentication, token management, and session state

export const Auth = {
  // Get stored access token
  getToken() {
    return localStorage.getItem('malinfo_access_token');
  },

  // Get stored refresh token
  getRefreshToken() {
    return localStorage.getItem('malinfo_refresh_token');
  },

  // Store tokens
  setTokens(accessToken, refreshToken) {
    localStorage.setItem('malinfo_access_token', accessToken);
    localStorage.setItem('malinfo_refresh_token', refreshToken);
  },

  // Clear tokens
  clearTokens() {
    localStorage.removeItem('malinfo_access_token');
    localStorage.removeItem('malinfo_refresh_token');
  },

  // Get current user from API
  async getCurrentUser() {
    const token = this.getToken();
    if (!token) return null;

    try {
      const response = await fetch('/api/auth/me', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (!response.ok) {
        if (response.status === 401) {
          // Try to refresh token
          const refreshed = await this.refreshAccessToken();
          if (refreshed) {
            return this.getCurrentUser();
          }
        }
        return null;
      }
      
      return await response.json();
    } catch (error) {
      console.error('[Auth] Failed to get current user:', error);
      return null;
    }
  },

  // Refresh access token
  async refreshAccessToken() {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) return false;

    try {
      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      
      if (!response.ok) {
        this.clearTokens();
        return false;
      }
      
      const data = await response.json();
      this.setTokens(data.access_token, data.refresh_token);
      return true;
    } catch (error) {
      console.error('[Auth] Token refresh failed:', error);
      this.clearTokens();
      return false;
    }
  },

  // Login
  async login(username, password, mfaCode = null, rememberMe = false) {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, mfa_code: mfaCode, remember_me: rememberMe }),
    });
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Login failed' }));
      throw new Error(error.detail);
    }
    
    const data = await response.json();
    this.setTokens(data.access_token, data.refresh_token);
    return data;
  },

  // Logout
  async logout() {
    const token = this.getToken();
    if (token) {
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        });
      } catch (error) {
        console.error('[Auth] Logout request failed:', error);
      }
    }
    this.clearTokens();
  },

  // Check if user has permission
  hasPermission(user, permission) {
    if (!user) return false;
    
    const rolePermissions = {
      admin: ['*'],
      analyst: [
        'sample:upload', 'sample:view_all', 'sample:view_own', 'sample:reanalyze',
        'sandbox:trigger', 'sandbox:view',
        'report:view_all', 'report:view_own', 'report:export',
        'monitor:view', 'threat_intel:view', 'audit:view',
      ],
      operator: [
        'sample:upload', 'sample:view_own', 'sample:reanalyze',
        'sandbox:trigger', 'sandbox:view',
        'report:view_own', 'report:export',
      ],
      viewer: [
        'sample:view_own', 'report:view_own',
      ],
      citizen: [
        'public:report',
      ],
    };
    
    const permissions = rolePermissions[user.role] || [];
    return permissions.includes('*') || permissions.includes(permission);
  },

  // Check if user has role
  hasRole(user, ...roles) {
    if (!user) return false;
    return roles.includes(user.role);
  },

  // Update user display in UI
  updateUserDisplay(user) {
    const avatar = document.getElementById('userAvatar');
    const name = document.getElementById('userName');
    const dropdownName = document.getElementById('dropdownUserName');
    const dropdownRole = document.getElementById('dropdownUserRole');
    
    if (avatar) {
      avatar.textContent = user.full_name?.split(' ').map(n => n[0]).join('').toUpperCase() || 'MI';
    }
    if (name) name.textContent = user.full_name || user.username;
    if (dropdownName) dropdownName.textContent = user.full_name || user.username;
    if (dropdownRole) dropdownRole.textContent = user.role;
  },
};