// Monitoring Page
// Real-time file transfer monitoring and analysis

import { API } from '../api.js';
import { UI } from '../ui.js';

export const MonitoringPage = {
  currentFilters: {
    verdict: '',
    page: 1,
    limit: 50,
  },

  async render() {
    const main = document.getElementById('appMain');
    if (!main) return;

    main.innerHTML = `
      <div class="page-header">
        <div>
          <h1>File Transfer Monitoring</h1>
          <p>Real-time detection and analysis of file transfers</p>
        </div>
        <div class="page-header-actions">
          <button class="btn btn-primary" id="refreshMonitoringBtn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="23 4 23 10 17 10"></polyline>
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
            </svg>
            Refresh
          </button>
        </div>
      </div>

      <div class="stat-grid" id="monitoringStats">
        <div class="stat-card">
          <div class="label">Total Transfers</div>
          <div class="value" id="stat-total-transfers">—</div>
        </div>
        <div class="stat-card">
          <div class="label">Analyzed</div>
          <div class="value" id="stat-analyzed">—</div>
        </div>
        <div class="stat-card">
          <div class="label">Malicious</div>
          <div class="value danger" id="stat-monitoring-malicious">—</div>
        </div>
        <div class="stat-card">
          <div class="label">Queue</div>
          <div class="value" id="stat-queue">—</div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2>Transfer Events</h2>
          <div style="display:flex;gap:0.5rem;">
            <select id="monitoringVerdictFilter" style="width:auto;">
              <option value="">All Verdicts</option>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="clean">Clean</option>
              <option value="pending">Pending</option>
              <option value="error">Error</option>
            </select>
          </div>
        </div>
        <div id="transfersTable">${UI.showLoading()}</div>
        
        <div id="monitoringPagination" style="display:flex;justify-content:center;align-items:center;gap:1rem;margin-top:1rem;padding-top:1rem;border-top:1px solid var(--line);">
          <button class="btn btn-sm" id="prevMonitoringPage" disabled>Previous</button>
          <span id="monitoringPageInfo" class="mono">Page 1</span>
          <button class="btn btn-sm" id="nextMonitoringPage" disabled>Next</button>
        </div>
      </div>
    `;

    this.setupEventListeners();
    await this.loadData();
  },

  setupEventListeners() {
    const verdictFilter = document.getElementById('monitoringVerdictFilter');
    const refreshBtn = document.getElementById('refreshMonitoringBtn');
    const prevBtn = document.getElementById('prevMonitoringPage');
    const nextBtn = document.getElementById('nextMonitoringPage');

    verdictFilter?.addEventListener('change', (e) => {
      this.currentFilters.verdict = e.target.value;
      this.currentFilters.page = 1;
      this.loadTransfers();
    });

    refreshBtn?.addEventListener('click', () => this.loadData());

    prevBtn?.addEventListener('click', () => {
      if (this.currentFilters.page > 1) {
        this.currentFilters.page--;
        this.loadTransfers();
      }
    });

    nextBtn?.addEventListener('click', () => {
      this.currentFilters.page++;
      this.loadTransfers();
    });
  },

  async loadData() {
    await Promise.all([
      this.loadStats(),
      this.loadTransfers(),
    ]);
  },

  async loadStats() {
    try {
      const stats = await API.getMonitoringStats();
      
      document.getElementById('stat-total-transfers').textContent = stats.total_events || 0;
      document.getElementById('stat-analyzed').textContent = stats.analyzed || 0;
      document.getElementById('stat-monitoring-malicious').textContent = stats.verdicts?.malicious || 0;
      document.getElementById('stat-queue').textContent = stats.queue_size || 0;
    } catch (error) {
      console.error('[Monitoring] Stats load failed:', error);
    }
  },

  async loadTransfers() {
    const container = document.getElementById('transfersTable');
    if (!container) return;

    container.innerHTML = UI.showLoading();

    try {
      const params = {
        limit: this.currentFilters.limit,
        offset: (this.currentFilters.page - 1) * this.currentFilters.limit,
        verdict: this.currentFilters.verdict,
      };

      const transfers = await API.getTransfers(params);
      this.renderTransfers(transfers);
      this.updatePagination(transfers.length === this.currentFilters.limit);
    } catch (error) {
      console.error('[Monitoring] Transfers load failed:', error);
      container.innerHTML = UI.showEmptyState('', 'Monitoring not enabled or failed to load', '📡');
    }
  },

  renderTransfers(transfers) {
    const container = document.getElementById('transfersTable');
    if (!container) return;

    if (!transfers.length) {
      container.innerHTML = UI.showEmptyState('', 'No transfer events recorded');
      return;
    }

    container.innerHTML = UI.renderTable(
      [
        { field: 'timestamp', label: 'Time', render: v => UI.formatRelativeTime(v) },
        { field: 'source_path', label: 'Source Path', truncate: true },
        { field: 'dest_path', label: 'Destination', truncate: true },
        { field: 'transfer_type', label: 'Type', render: v => UI.createTag(v) },
        { field: 'file_size', label: 'Size', render: v => UI.formatBytes(v) },
        { field: 'file_hash', label: 'SHA256', render: v => `<code class="mono">${v?.slice(0, 16)}…</code>` },
        { field: 'process_name', label: 'Process' },
        { field: 'user', label: 'User' },
        { field: 'verdict', label: 'Verdict', render: v => UI.createPill(v, v) },
        { field: 'risk_score', label: 'Risk', render: v => `<span class="mono">${v}</span>` },
        { field: 'event_id', label: 'Actions', render: (v, r) => `
          <div style="display:flex;gap:0.25rem;">
            <button class="btn btn-sm btn-ghost" onclick="MALINFO.pages.monitoring.viewTransfer('${v}')" title="View Details">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                <circle cx="12" cy="12" r="3"></circle>
              </svg>
            </button>
            <button class="btn btn-sm btn-ghost" onclick="MALINFO.pages.monitoring.reanalyzeTransfer('${v}')" title="Re-analyze">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="23 4 23 10 17 10"></polyline>
                <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
              </svg>
            </button>
          </div>
        ` },
      ],
      transfers,
      { emptyMessage: 'No transfers found' }
    );
  },

  updatePagination(hasMore) {
    const prevBtn = document.getElementById('prevMonitoringPage');
    const nextBtn = document.getElementById('nextMonitoringPage');
    const pageInfo = document.getElementById('monitoringPageInfo');

    if (prevBtn) prevBtn.disabled = this.currentFilters.page <= 1;
    if (nextBtn) nextBtn.disabled = !hasMore;
    if (pageInfo) pageInfo.textContent = `Page ${this.currentFilters.page}`;
  },

  async viewTransfer(eventId) {
    try {
      const transfer = await API.getTransfer(eventId);
      
      // Show modal with details
      const modalHtml = `
        <div class="modal-overlay open" id="transferDetailModal" style="position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:2000;">
          <div class="modal" style="max-width:800px;max-height:80vh;overflow:auto;">
            <div class="modal-header">
              <h3 class="modal-title">Transfer Details: ${UI.escapeHtml(transfer.event?.source_path || eventId)}</h3>
              <button class="modal-close" onclick="document.getElementById('transferDetailModal').remove()">&times;</button>
            </div>
            <div class="modal-body">
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
                <div>
                  <h4 style="color:var(--text-secondary);margin-bottom:0.5rem;">Event Info</h4>
                  <table style="width:100%;font-size:13px;">
                    <tr><td style="color:var(--text-muted)">Event ID</td><td class="mono">${UI.escapeHtml(transfer.event?.event_id)}</td></tr>
                    <tr><td style="color:var(--text-muted)">Time</td><td>${UI.formatDate(transfer.event?.timestamp)}</td></tr>
                    <tr><td style="color:var(--text-muted)">Source</td><td>${UI.escapeHtml(transfer.event?.source_path)}</td></tr>
                    <tr><td style="color:var(--text-muted)">Destination</td><td>${UI.escapeHtml(transfer.event?.dest_path)}</td></tr>
                    <tr><td style="color:var(--text-muted)">Type</td><td>${UI.createTag(transfer.event?.transfer_type)}</td></tr>
                    <tr><td style="color:var(--text-muted)">Size</td><td>${UI.formatBytes(transfer.event?.file_size)}</td></tr>
                    <tr><td style="color:var(--text-muted)">Process</td><td>${UI.escapeHtml(transfer.event?.process_name)}</td></tr>
                    <tr><td style="color:var(--text-muted)">User</td><td>${UI.escapeHtml(transfer.event?.user)}</td></tr>
                  </table>
                </div>
                <div>
                  <h4 style="color:var(--text-secondary);margin-bottom:0.5rem;">Analysis Result</h4>
                  <table style="width:100%;font-size:13px;">
                    <tr><td style="color:var(--text-muted)">Analyzed</td><td>${transfer.event?.analyzed ? 'Yes' : 'No'}</td></tr>
                    <tr><td style="color:var(--text-muted)">Verdict</td><td>${UI.createPill(transfer.event?.verdict, transfer.event?.verdict)}</td></tr>
                    <tr><td style="color:var(--text-muted)">Risk Score</td><td><span class="mono">${transfer.event?.risk_score}</span></td></tr>
                    <tr><td style="color:var(--text-muted)">Sample ID</td><td class="mono">${transfer.analysis?.sample_id || 'N/A'}</td></tr>
                  </table>
                </div>
              </div>
              ${transfer.analysis?.static_report ? `
                <details class="collapsible" style="margin-top:1rem;">
                  <summary>Static Analysis Details</summary>
                  <div class="content">
                    <pre style="max-height:300px;">${UI.escapeHtml(JSON.stringify(transfer.analysis.static_report, null, 2))}</pre>
                  </div>
                </details>
              ` : ''}
            </div>
          </div>
        </div>
      `;
      
      document.body.insertAdjacentHTML('beforeend', modalHtml);
    } catch (error) {
      UI.toast(`Failed to load transfer details: ${error.message}`, 'error');
    }
  },

  async reanalyzeTransfer(eventId) {
    if (!confirm('Re-analyze this transfer?')) return;
    
    try {
      await API.reanalyzeTransfer(eventId);
      UI.toast('Re-analysis queued', 'success');
      this.loadTransfers();
    } catch (error) {
      UI.toast(`Re-analysis failed: ${error.message}`, 'error');
    }
  },

  handleNewTransfer(data) {
    // Add to top of table if on first page
    if (this.currentFilters.page === 1) {
      this.loadTransfers();
    }
    // Update stats
    this.loadStats();
  },

  refresh() {
    this.loadData();
  },
};