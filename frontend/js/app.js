// MALINFO Frontend Application
// Modular architecture with routing, state management, and real-time updates

import { API } from './api.js';
import { Auth } from './auth.js';
import { UI } from './ui.js';
import { Dashboard } from './pages/dashboard.js';
import { SamplesPage } from './pages/samples.js';
import { SandboxPage } from './pages/sandbox.js';
import { ReportsPage } from './pages/reports.js';
import { MonitoringPage } from './pages/monitoring.js';
import { NetworkPage } from './pages/network.js';
import { ThreatIntelPage } from './pages/threat-intel.js';
import { IOCsPage } from './pages/iocs.js';
import { UsersPage } from './pages/users.js';
import { AuditPage } from './pages/audit.js';
import { VMPage } from './pages/vm.js';
import { ProfilePage } from './pages/profile.js';

// Application State
const App = {
  currentPage: 'dashboard',
  currentUser: null,
  ws: null,
  wsReconnectAttempts: 0,
  maxReconnectAttempts: 10,
  
  // Page components registry
  pages: {
    dashboard: Dashboard,
    samples: SamplesPage,
    sandbox: SandboxPage,
    reports: ReportsPage,
    monitoring: MonitoringPage,
    network: NetworkPage,
    'threat-intel': ThreatIntelPage,
    iocs: IOCsPage,
    users: UsersPage,
    audit: AuditPage,
    vm: VMPage,
    profile: ProfilePage,
  },

  // Initialize application
  async init() {
    console.log('[MALINFO] Initializing application...');
    
    // Initialize UI utilities
    UI.init();
    
    // Check authentication
    await this.checkAuth();
    
    // Setup event listeners
    this.setupEventListeners();
    
    // Initialize WebSocket for real-time updates
    this.initWebSocket();
    
    // Handle initial route
    this.handleRoute(window.location.hash.slice(1) || 'dashboard');
    
    // Handle browser back/forward
    window.addEventListener('hashchange', () => {
      this.handleRoute(window.location.hash.slice(1) || 'dashboard');
    });
    
    console.log('[MALINFO] Application initialized');
  },

  // Check authentication status
  async checkAuth() {
    try {
      const user = await Auth.getCurrentUser();
      if (user) {
        this.currentUser = user;
        UI.updateUserDisplay(user);
        this.updateNavigationForRole(user.role);
      } else {
        // Redirect to login if not authenticated
        if (!window.location.hash.includes('login')) {
          window.location.hash = 'login';
        }
      }
    } catch (error) {
      console.error('[MALINFO] Auth check failed:', error);
      window.location.hash = 'login';
    }
  },

  // Update navigation based on user role
  updateNavigationForRole(role) {
    const adminOnly = ['users', 'audit', 'settings'];
    const analystOnly = ['sandbox', 'monitoring', 'network', 'threat-intel', 'iocs', 'vm'];
    
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
      const page = item.dataset.page;
      let visible = true;
      
      if (adminOnly.includes(page) && role !== 'admin') {
        visible = false;
      } else if (analystOnly.includes(page) && !['admin', 'analyst'].includes(role)) {
        visible = false;
      }
      
      item.style.display = visible ? 'flex' : 'none';
    });
  },

  // Setup global event listeners
  setupEventListeners() {
    // Navigation clicks
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const page = item.dataset.page;
        if (item.style.display !== 'none') {
          this.navigateTo(page);
        }
      });
    });

    // Mobile menu toggle
    const menuToggle = document.getElementById('menuToggle');
    const sidebar = document.getElementById('appSidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    menuToggle?.addEventListener('click', () => {
      const isOpen = sidebar.classList.toggle('open');
      overlay.classList.toggle('open', isOpen);
      menuToggle.setAttribute('aria-expanded', isOpen);
    });
    
    overlay?.addEventListener('click', () => {
      sidebar.classList.remove('open');
      overlay.classList.remove('open');
      menuToggle.setAttribute('aria-expanded', 'false');
    });

    // Logout
    document.getElementById('logoutBtn')?.addEventListener('click', async (e) => {
      e.preventDefault();
      await Auth.logout();
      this.currentUser = null;
      window.location.hash = 'login';
      window.location.reload();
    });

    // Upload modal
    this.setupUploadModal();

    // Global search
    const searchInput = document.getElementById('globalSearch');
    let searchDebounce;
    searchInput?.addEventListener('input', (e) => {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(() => {
        this.handleGlobalSearch(e.target.value);
      }, 300);
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      // Ctrl/Cmd + K for search
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        searchInput?.focus();
      }
      // Escape to close modals
      if (e.key === 'Escape') {
        UI.closeAllModals();
        sidebar.classList.remove('open');
        overlay.classList.remove('open');
      }
    });
  },

  // Setup upload modal
  setupUploadModal() {
    const modal = document.getElementById('uploadModal');
    const dropzone = document.getElementById('modalDropzone');
    const fileInput = document.getElementById('modalFileInput');
    const cancelBtn = document.getElementById('cancelUpload');
    const confirmBtn = document.getElementById('confirmUpload');
    
    let selectedFile = null;

    // Dropzone events
    dropzone?.addEventListener('click', () => fileInput?.click());
    dropzone?.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });
    dropzone?.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone?.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length) {
        this.handleFileSelect(e.dataTransfer.files[0]);
      }
    });
    
    fileInput?.addEventListener('change', (e) => {
      if (e.target.files.length) {
        this.handleFileSelect(e.target.files[0]);
      }
    });

    cancelBtn?.addEventListener('click', () => {
      UI.closeModal('uploadModal');
      selectedFile = null;
      fileInput.value = '';
      this.updateDropzoneUI(dropzone, null);
      confirmBtn.disabled = true;
    });

    confirmBtn?.addEventListener('click', async () => {
      if (selectedFile) {
        confirmBtn.disabled = true;
        confirmBtn.innerHTML = '<span class="spinner spinner-sm"></span> Uploading...';
        try {
          await API.uploadFile(selectedFile);
          UI.toast('Sample uploaded and queued for analysis', 'success');
          UI.closeModal('uploadModal');
          selectedFile = null;
          fileInput.value = '';
          this.updateDropzoneUI(dropzone, null);
          confirmBtn.disabled = true;
          // Refresh current page if it's samples or dashboard
          if (['dashboard', 'samples'].includes(this.currentPage)) {
            this.pages[this.currentPage].refresh?.();
          }
        } catch (error) {
          UI.toast(`Upload failed: ${error.message}`, 'error');
          confirmBtn.disabled = false;
          confirmBtn.textContent = 'Upload & Analyze';
        }
      }
    });

    this.updateDropzoneUI = (dz, file) => {
      if (file) {
        dz.innerHTML = `
          <div class="icon" style="color:var(--safe)">✓</div>
          <div class="primary" style="color:var(--safe)">${file.name}</div>
          <div class="secondary">${UI.formatBytes(file.size)} • ${file.type || 'Unknown type'}</div>
        `;
      } else {
        dz.innerHTML = `
          <div class="icon">&#8593;</div>
          <div class="primary">Drop file here, or click to browse</div>
          <div class="secondary">Any file type — executables, documents, archives, mobile apps. Max 250 MB.</div>
        `;
      }
    };

    this.handleFileSelect = (file) => {
      if (file.size > 250 * 1024 * 1024) {
        UI.toast('File exceeds 250 MB limit', 'error');
        return;
      }
      selectedFile = file;
      this.updateDropzoneUI(dropzone, file);
      confirmBtn.disabled = false;
      confirmBtn.textContent = 'Upload & Analyze';
    };
  },

  // Navigate to page
  navigateTo(page) {
    window.location.hash = page;
  },

  // Handle route change
  async handleRoute(route) {
    // Check authentication for protected routes
    const publicRoutes = ['login'];
    if (!publicRoutes.includes(route) && !this.currentUser) {
      window.location.hash = 'login';
      return;
    }

    // Update active nav item
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.page === route);
    });

    // Close mobile sidebar
    document.getElementById('appSidebar')?.classList.remove('open');
    document.getElementById('sidebarOverlay')?.classList.remove('open');

    // Load page component
    const pageComponent = this.pages[route];
    if (pageComponent) {
      this.currentPage = route;
      try {
        await pageComponent.render();
        // Update page title
        document.title = `MALINFO — ${route.charAt(0).toUpperCase() + route.slice(1).replace('-', ' ')}`;
      } catch (error) {
        console.error(`[MALINFO] Failed to render page ${route}:`, error);
        UI.toast(`Failed to load ${route} page`, 'error');
      }
    } else {
      console.warn(`[MALINFO] Unknown page: ${route}`);
      this.handleRoute('dashboard');
    }
  },

  // Initialize WebSocket for real-time updates
  initWebSocket() {
    if (!window.location.protocol.startsWith('http')) return;

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/api/ws`;

    this.connectWebSocket(wsUrl);
  },

  connectWebSocket(url) {
    try {
      this.ws = new WebSocket(url);
      
      this.ws.onopen = () => {
        console.log('[MALINFO] WebSocket connected');
        this.wsReconnectAttempts = 0;
        // Authenticate WebSocket
        if (Auth.getToken()) {
          this.ws.send(JSON.stringify({
            type: 'auth',
            token: Auth.getToken()
          }));
        }
      };

      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.handleWebSocketMessage(message);
        } catch (error) {
          console.error('[MALINFO] WebSocket message parse error:', error);
        }
      };

      this.ws.onclose = () => {
        console.log('[MALINFO] WebSocket disconnected');
        this.scheduleReconnect(url);
      };

      this.ws.onerror = (error) => {
        console.error('[MALINFO] WebSocket error:', error);
      };
    } catch (error) {
      console.error('[MALINFO] WebSocket connection failed:', error);
      this.scheduleReconnect(url);
    }
  },

  scheduleReconnect(url) {
    if (this.wsReconnectAttempts >= this.maxReconnectAttempts) {
      console.log('[MALINFO] Max reconnect attempts reached');
      return;
    }
    
    const delay = Math.min(1000 * Math.pow(2, this.wsReconnectAttempts), 30000);
    this.wsReconnectAttempts++;
    
    setTimeout(() => {
      console.log(`[MALINFO] Reconnecting WebSocket (attempt ${this.wsReconnectAttempts})...`);
      this.connectWebSocket(url);
    }, delay);
  },

  handleWebSocketMessage(message) {
    switch (message.type) {
      case 'analysis_update':
        this.handleAnalysisUpdate(message.data);
        break;
      case 'transfer_detected':
        this.handleTransferDetected(message.data);
        break;
      case 'network_alert':
        this.handleNetworkAlert(message.data);
        break;
      case 'notification':
        UI.toast(message.data.message, message.data.level || 'info');
        break;
      case 'stats_update':
        this.updateDashboardStats(message.data);
        break;
      default:
        console.log('[MALINFO] Unknown WS message type:', message.type);
    }
  },

  handleAnalysisUpdate(data) {
    // Update UI if on relevant page
    if (this.pages[this.currentPage]?.handleAnalysisUpdate) {
      this.pages[this.currentPage].handleAnalysisUpdate(data);
    }
    // Show toast for completions
    if (data.status === 'complete') {
      const verdict = data.verdict;
      const level = verdict === 'malicious' ? 'error' : verdict === 'suspicious' ? 'warning' : 'success';
      UI.toast(`Analysis complete: ${data.filename} — ${verdict}`, level);
    }
  },

  handleTransferDetected(data) {
    UI.toast(`File transfer detected: ${data.filename}`, 'warning');
    if (this.pages.monitoring?.handleNewTransfer) {
      this.pages.monitoring.handleNewTransfer(data);
    }
    // Update badge
    const badge = document.getElementById('transferBadge');
    if (badge) {
      badge.style.display = 'inline-flex';
      badge.textContent = parseInt(badge.textContent || '0') + 1;
    }
  },

  handleNetworkAlert(data) {
    UI.toast(`Network alert: ${data.description}`, 'warning');
  },

  updateDashboardStats(data) {
    if (this.currentPage === 'dashboard' && this.pages.dashboard?.updateStats) {
      this.pages.dashboard.updateStats(data);
    }
    // Update stat cards in header if visible
    Object.entries(data).forEach(([key, value]) => {
      const el = document.getElementById(`stat-${key}`);
      if (el) el.textContent = value;
    });
  },

  // Handle global search
  async handleGlobalSearch(query) {
    if (!query || query.length < 2) return;
    
    try {
      const results = await API.search(query);
      UI.showSearchResults(results, query);
    } catch (error) {
      console.error('Search failed:', error);
    }
  },
};

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});

// Export for global access
window.MALINFO = App;