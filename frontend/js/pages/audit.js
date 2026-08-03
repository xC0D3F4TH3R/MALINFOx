// Audit Logs Page (Admin only)
// View and search audit trail

import { API } from '../api.js';
import { UI } from '../ui.js';

export const AuditPage = {
  currentFilters: {
    action: '',
    user: '',
    result: '',
    page: 1,
    limit: 50,
  },

  async render() {
    const main = document.getElementById('appMain');
    if (!main) return;

    main.innerHTML = `
      <div class="page-header">
        <div>
          <h1>Audit Logs</h1>
          <p>System audit trail for compliance and security monitoring</p>
        </div>
      </div>

      <div class="card">
        <div class="form-row" style="margin-bottom:0.5rem;">
          <div class="form-group" style="flex:1;">
            <input type="search" id="auditSearch" placeholder="Search by action, user, IP..." style="width:100%;">
          </div>
          <div class="form-group" style="width:150px;">
            <select id="auditResultFilter" style="width:100%;">
              <option value="">All Results</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
              <option value="error">Error</option>
            </select>
          </div>
          <div class="form-group" style="width:150px;">
            <select id="auditSeverityFilter" style="width:100%;">
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
            </select>
          </div>
        </div>
      </div>

      <div class="card">
        <div id="auditTable">${UI.showLoading()}</div>
        
        <div id="auditPagination" style="display:flex;justify-content:center;align-items:center;gap:1rem;margin-top:1rem;padding-top:1rem;border-top:1px solid var(--line);">
          <button class="btn btn-sm" id="prevAuditPage" disabled>Previous</button>
          <span id="auditPageInfo" class="mono">Page 1</span>
          <button class="btn btn-sm" id="nextAuditPage" disabled>Next</button>
        </div>
      </div>
    `;

    this.setupEventListeners();
    await this.loadAuditLogs();
  },

  setupEventListeners() {
    const searchInput = document.getElementById('auditSearch');
    const resultFilter = document.getElementById('auditResultFilter');
    const severityFilter = document.getElementById('auditSeverityFilter');
    const prevBtn = document.getElementById('prevAuditPage');
    const nextBtn = document.getElementById('nextAuditPage');

    let searchDebounce;
    searchInput?.addEventListener('input', (e) => {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(() => {
        this.currentFilters.search = e.target.value;
        this.currentFilters.page = 1;
        this.loadAuditLogs();
      }, 300);
    });

    resultFilter?.addEventListener('change', (e) => {
      this.currentFilters.result = e.target.value;
      this.currentFilters.page = 1;
      this.loadAuditLogs();
    });

    severityFilter?.addEventListener('change', (e) => {
      this.currentFilters.severity = e.target.value;
      this.currentFilters.page = 1;
      this.loadAuditLogs();
    });

    prevBtn?.addEventListener('click', () => {
      if (this.currentFilters.page > 1) {
        this.currentFilters.page--;
        this.loadAuditLogs();
      }
    });

    nextBtn?.addEventListener('click', () => {
      this.currentFilters.page++;
      this.loadAuditLogs();
    });
  },

  async loadAuditLogs() {
    const container = document.getElementById('auditTable');
    if (!container) return;

    container.innerHTML = UI.showLoading();

    try {
      // Note: Would need backend endpoint for audit logs
      // For now, show placeholder
      container.innerHTML = UI.showEmptyState(
        '',
        'Audit log endpoint not yet implemented',
        '📋'
      );
    } catch (error) {
      console.error('[Audit] Load failed:', error);
      container.innerHTML = UI.showEmptyState('', 'Failed to load audit logs', '⚠');
    }
  },

  updatePagination(hasMore) {
    const prevBtn = document.getElementById('prevAuditPage');
    const nextBtn = document.getElementById('nextAuditPage');
    const pageInfo = document.getElementById('auditPageInfo');

    if (prevBtn) prevBtn.disabled = this.currentFilters.page <= 1;
    if (nextBtn) nextBtn.disabled = !hasMore;
    if (pageInfo) pageInfo.textContent = `Page ${this.currentFilters.page}`;
  },

  refresh() {
    this.loadAuditLogs();
  },
};