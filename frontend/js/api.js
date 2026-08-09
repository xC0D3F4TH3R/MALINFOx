// MALINFO API Client
// Handles all backend communication with authentication, error handling, and caching

export const API = {
  baseURL: '',
  token: null,
  csrfToken: null,
  cache: new Map(),
  cacheTTL: 30000, // 30 seconds

  // Initialize API base URL
  init() {
    // Auto-detect API base URL
    if (window.MALINFO_API_BASE) {
      this.baseURL = window.MALINFO_API_BASE;
    } else if (window.location.port === '8080') {
      this.baseURL = `${window.location.protocol}//${window.location.hostname}:8000/api`;
    } else {
      this.baseURL = '/api';
    }
    console.log('[MALINFO API] Base URL:', this.baseURL);

    // Fetch CSRF token on init
    this.fetchCsrfToken();
  },

  // Fetch CSRF token from backend
  async fetchCsrfToken() {
    try {
      const response = await fetch(`${this.baseURL}/csrf-token`, {
        credentials: 'include', // Important for cookies
      });
      if (response.ok) {
        const data = await response.json();
        this.csrfToken = data.csrf_token;
        console.log('[MALINFO API] CSRF token fetched');
      }
    } catch (error) {
      console.warn('[MALINFO API] Failed to fetch CSRF token:', error);
    }
  },

  // Set auth token (kept for backwards compatibility)
  setToken(token) {
    this.token = token;
  },

  // Get auth token - now reads from cookie if available
  getToken() {
    // Try memory first, then cookie (httpOnly cookies can't be read from JS)
    // The token is sent automatically with credentials: 'include'
    return this.token;
  },

  // Clear token (for logout)
  clearToken() {
    this.token = null;
    localStorage.removeItem('malinfo_access_token');
    localStorage.removeItem('malinfo_refresh_token');
  },

  // Build headers
  getHeaders(includeAuth = true) {
    const headers = {
      'Content-Type': 'application/json',
    };
    // Note: With httpOnly cookies, we don't need to manually add Authorization header
    // The browser sends cookies automatically with credentials: 'include'
    // But we keep the token for API key auth
    if (includeAuth && this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    // Add CSRF token for state-changing operations
    if (this.csrfToken) {
      headers['X-CSRF-Token'] = this.csrfToken;
    }
    return headers;
  },

  // Core request method - always use credentials: 'include' for cookies
  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: this.getHeaders(options.auth !== false),
      credentials: 'include', // Critical for httpOnly cookies
      ...options,
    };

    // Handle FormData (don't set Content-Type)
    if (config.body instanceof FormData) {
      delete config.headers['Content-Type'];
    }

    try {
      const response = await fetch(url, config);
      
      // Handle token refresh on 401
      if (response.status === 401 && options.auth !== false) {
        const refreshed = await this.refreshToken();
        if (refreshed) {
          // Retry with new token
          config.headers = this.getHeaders(true);
          return this.request(endpoint, options);
        } else {
          // Redirect to login
          window.location.hash = 'login';
          throw new Error('Authentication expired');
        }
      }

      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: response.statusText }));
        throw new Error(error.detail || `HTTP ${response.status}`);
      }

      // Handle empty responses
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return await response.json();
      }
      return await response.text();
    } catch (error) {
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error('Cannot connect to backend. Is the API server running?');
      }
      throw error;
    }
  },

  // GET request
  async get(endpoint, params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const url = queryString ? `${endpoint}?${queryString}` : endpoint;
    
    // Check cache
    const cacheKey = `GET:${url}`;
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      return cached.data;
    }

    const data = await this.request(url, { method: 'GET' });
    
    // Cache successful responses
    this.cache.set(cacheKey, { data, timestamp: Date.now() });
    return data;
  },

  // POST request
  async post(endpoint, data, options = {}) {
    this.invalidateCache(endpoint);
    return this.request(endpoint, {
      method: 'POST',
      body: data instanceof FormData ? data : JSON.stringify(data),
      ...options,
    });
  },

  // PUT request
  async put(endpoint, data) {
    this.invalidateCache(endpoint);
    return this.request(endpoint, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  // PATCH request
  async patch(endpoint, data) {
    this.invalidateCache(endpoint);
    return this.request(endpoint, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  },

  // DELETE request
  async delete(endpoint) {
    this.invalidateCache(endpoint);
    return this.request(endpoint, { method: 'DELETE' });
  },

  // Invalidate cache for endpoint
  invalidateCache(pattern) {
    for (const key of this.cache.keys()) {
      if (key.includes(pattern)) {
        this.cache.delete(key);
      }
    }
  },

  // Clear all cache
  clearCache() {
    this.cache.clear();
  },

  // =========================================================================
  // Authentication
  // =========================================================================

  async login(username, password, mfaCode = null, rememberMe = false) {
    const data = await this.post('/auth/login', { username, password, mfa_code: mfaCode, remember_me: rememberMe });
    // Tokens are now in httpOnly cookies, but we store access_token in memory for API key fallback
    this.setToken(data.access_token);
    return data;
  },

  async refreshToken() {
    // Refresh token is in httpOnly cookie, sent automatically
    try {
      const data = await this.post('/auth/refresh', {}, { auth: false });
      this.setToken(data.access_token);
      return true;
    } catch (error) {
      this.clearToken();
      return false;
    }
  },

  async logout() {
    try {
      await this.post('/auth/logout');
    } finally {
      this.clearToken();
    }
  },

  async getCurrentUser() {
    return this.get('/auth/me');
  },

  async updateProfile(data) {
    return this.patch('/auth/me', data);
  },

  async changePassword(currentPassword, newPassword) {
    return this.post('/auth/change-password', { current_password: currentPassword, new_password: newPassword });
  },

  // MFA
  async setupMFA() {
    return this.post('/auth/mfa/setup');
  },

  async verifyMFA(code) {
    return this.post('/auth/mfa/verify', { mfa_code: code });
  },

  async disableMFA() {
    return this.post('/auth/mfa/disable');
  },

  // =========================================================================
  // Samples / Upload
  // =========================================================================

  async uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    return this.request('/upload', {
      method: 'POST',
      body: formData,
      auth: true,
    });
  },

  async getSamples(params = {}) {
    return this.get('/reports', params);
  },

  async getSample(sampleId) {
    return this.get(`/reports/${sampleId}`);
  },

  async getSampleReport(sampleId) {
    return this.get(`/reports/${sampleId}/html`);
  },

  async downloadReport(sampleId) {
    const response = await fetch(`${this.baseURL}/reports/${sampleId}/download`, {
      headers: this.getHeaders(),
      credentials: 'include',
    });
    if (!response.ok) throw new Error('Failed to download report');
    return response.blob();
  },

  async reanalyzeSample(sampleId) {
    return this.post(`/reports/${sampleId}/reanalyze`);
  },

  async deleteSample(sampleId) {
    return this.delete(`/reports/${sampleId}`);
  },

  // =========================================================================
  // Sandbox
  // =========================================================================

  async triggerSandbox(sampleId, profile = null) {
    return this.post('/sandbox/detonate', { sample_id: sampleId, profile });
  },

  async getSandboxStatus(taskId) {
    return this.get(`/sandbox/status/${taskId}`);
  },

  async getSandboxReport(taskId) {
    return this.get(`/sandbox/report/${taskId}`);
  },

  async getSandboxProfiles() {
    return this.get('/sandbox/profiles');
  },

  // =========================================================================
  // Monitoring
  // =========================================================================

  async getMonitoringStatus() {
    return this.get('/monitoring/status');
  },

  async getTransfers(params = {}) {
    return this.get('/monitoring/transfers', params);
  },

  async getTransfer(eventId) {
    return this.get(`/monitoring/transfers/${eventId}`);
  },

  async reanalyzeTransfer(eventId) {
    return this.post(`/monitoring/transfers/${eventId}/reanalyze`);
  },

  async getNetworkFlows(params = {}) {
    return this.get('/monitoring/network/flows', params);
  },

  async getMonitoringStats() {
    return this.get('/monitoring/stats');
  },

  // =========================================================================
  // Threat Intelligence
  // =========================================================================

  async getThreatIntelProviders() {
    return this.get('/threat-intel/providers');
  },

  async lookupHash(hash) {
    return this.post('/threat-intel/lookup/hash/' + hash);
  },

  async lookupIP(ip) {
    return this.post('/threat-intel/lookup/ip/' + ip);
  },

  async lookupDomain(domain) {
    return this.post('/threat-intel/lookup/domain/' + domain);
  },

  async lookupURL(url) {
    return this.post('/threat-intel/lookup/url', { url });
  },

  async enrichSample(sampleId) {
    return this.post(`/threat-intel/enrich/sample/${sampleId}`);
  },

  async enrichBulk(iocs) {
    return this.post('/threat-intel/enrich/bulk', { iocs });
  },

  // =========================================================================
  // User Management (Admin)
  // =========================================================================

  async createUser(userData) {
    return this.post('/auth/users', userData);
  },

  async getUsers(params = {}) {
    return this.get('/auth/users', params);
  },

  async getUser(userId) {
    return this.get(`/auth/users/${userId}`);
  },

  async updateUser(userId, data) {
    return this.patch(`/auth/users/${userId}`, data);
  },

  async deleteUser(userId) {
    return this.delete(`/auth/users/${userId}`);
  },

  // API Keys
  async createAPIKey(name, permissions = [], expiresDays = null) {
    return this.post('/auth/api-keys', { name, permissions, expires_days: expiresDays });
  },

  async getAPIKeys() {
    return this.get('/auth/api-keys');
  },

  async revokeAPIKey(keyId) {
    return this.delete(`/auth/api-keys/${keyId}`);
  },

  // =========================================================================
  // Audit Logs
  // =========================================================================

  async getAuditLogs(params = {}) {
    return this.get('/audit/logs', params);
  },

  // =========================================================================
  // Search
  // =========================================================================

  async search(query, params = {}) {
    return this.get('/search', { q: query, ...params });
  },

  // =========================================================================
  // VM Orchestrator
  // =========================================================================

  async getISOs() {
    return this.get('/vm/isos');
  },

  async deleteISO(name) {
    return this.delete(`/vm/isos/${encodeURIComponent(name)}`);
  },

  async getVMTemplates() {
    return this.get('/vm/templates');
  },

  async getVMTemplate(templateId) {
    return this.get(`/vm/templates/${templateId}`);
  },

  async createVMTemplate(data) {
    return this.post('/vm/templates', data);
  },

  async deleteVMTemplate(templateId) {
    return this.delete(`/vm/templates/${templateId}`);
  },

  async rebuildVMTemplate(templateId) {
    return this.post(`/vm/templates/${templateId}/rebuild`);
  },

  async submitVMAnalysis(sampleId, templateId, options = {}) {
    return this.post('/vm/analyze', { sample_id: sampleId, template_id: templateId, ...options });
  },

  async getVMTasks(params = {}) {
    return this.get('/vm/tasks', params);
  },

  async getVMTask(taskId) {
    return this.get(`/vm/tasks/${taskId}`);
  },

  async getVMTaskReport(taskId, format = 'json') {
    return this.get(`/vm/tasks/${taskId}/report`, { format });
  },

  async cancelVMTask(taskId) {
    return this.post(`/vm/tasks/${taskId}/cancel`);
  },

  // =========================================================================
  // Health Check
  // =========================================================================

  async healthCheck() {
    return this.get('/health', {}, { auth: false });
  },
};

// Initialize on import
API.init();