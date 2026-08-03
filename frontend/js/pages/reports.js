// Reports Page
// Detailed analysis reports viewing and management

import { API } from '../api.js';
import { UI } from '../ui.js';

export const ReportsPage = {
  currentFilters: {
    search: '',
    verdict: '',
    page: 1,
    limit: 25,
  },

  async render() {
    const main = document.getElementById('appMain');
    if (!main) return;

    main.innerHTML = `
      <div class="page-header">
        <div>
          <h1>Reports</h1>
          <p>View and export detailed analysis reports</p>
        </div>
      </div>

      <div class="card">
        <div class="form-row" style="margin-bottom:0.5rem;">
          <div class="form-group" style="flex:1;">
            <input type="search" id="reportSearch" placeholder="Search by filename, hash, verdict..." style="width:100%;">
          </div>
          <div class="form-group" style="width:200px;">
            <select id="reportVerdictFilter" style="width:100%;">
              <option value="">All Verdicts</option>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="clean">Clean</option>
              <option value="unknown">Unknown</option>
            </select>
          </div>
        </div>
      </div>

      <div class="card">
        <div id="reportsTable">${UI.showLoading()}</div>
        
        <div id="reportPagination" style="display:flex;justify-content:center;align-items:center;gap:1rem;margin-top:1rem;padding-top:1rem;border-top:1px solid var(--line);">
          <button class="btn btn-sm" id="prevReportPage" disabled>Previous</button>
          <span id="reportPageInfo" class="mono">Page 1</span>
          <button class="btn btn-sm" id="nextReportPage" disabled>Next</button>
        </div>
      </div>
    `;

    this.setupEventListeners();
    await this.loadReports();
  },

  setupEventListeners() {
    const searchInput = document.getElementById('reportSearch');
    const verdictFilter = document.getElementById('reportVerdictFilter');
    const prevBtn = document.getElementById('prevReportPage');
    const nextBtn = document.getElementById('nextReportPage');

    let searchDebounce;
    searchInput?.addEventListener('input', (e) => {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(() => {
        this.currentFilters.search = e.target.value;
        this.currentFilters.page = 1;
        this.loadReports();
      }, 300);
    });

    verdictFilter?.addEventListener('change', (e) => {
      this.currentFilters.verdict = e.target.value;
      this.currentFilters.page = 1;
      this.loadReports();
    });

    prevBtn?.addEventListener('click', () => {
      if (this.currentFilters.page > 1) {
        this.currentFilters.page--;
        this.loadReports();
      }
    });

    nextBtn?.addEventListener('click', () => {
      this.currentFilters.page++;
      this.loadReports();
    });
  },

  async loadReports() {
    const container = document.getElementById('reportsTable');
    if (!container) return;

    container.innerHTML = UI.showLoading();

    try {
      const params = {
        limit: this.currentFilters.limit,
        offset: (this.currentFilters.page - 1) * this.currentFilters.limit,
      };

      const samples = await API.getSamples(params);
      
      let filtered = samples;
      
      if (this.currentFilters.search) {
        const query = this.currentFilters.search.toLowerCase();
        filtered = filtered.filter(s => 
          s.original_filename?.toLowerCase().includes(query) ||
          s.sha256?.toLowerCase().includes(query) ||
          s.verdict?.toLowerCase().includes(query)
        );
      }

      if (this.currentFilters.verdict) {
        filtered = filtered.filter(s => s.verdict === this.currentFilters.verdict);
      }

      this.renderReports(filtered);
      this.updatePagination(filtered.length === this.currentFilters.limit);
    } catch (error) {
      console.error('[Reports] Load failed:', error);
      container.innerHTML = UI.showEmptyState('', 'Failed to load reports', '⚠');
    }
  },

  renderReports(reports) {
    const container = document.getElementById('reportsTable');
    if (!container) return;

    if (!reports.length) {
      container.innerHTML = UI.showEmptyState('', 'No reports match your filters');
      return;
    }

    container.innerHTML = UI.renderTable(
      [
        { field: 'original_filename', label: 'File', render: (v, r) => `
          <div style="font-weight:500">${UI.escapeHtml(v)}</div>
          <div class="mono" style="font-size:11px;color:var(--text-muted)">${r.sha256?.slice(0, 24)}…</div>
        ` },
        { field: 'file_type', label: 'Type' },
        { field: 'target_os', label: 'Target OS', render: v => UI.createTag(v) },
        { field: 'verdict', label: 'Verdict', render: v => UI.createPill(v, v) },
        { field: 'risk_score', label: 'Risk', render: v => `<span class="mono">${v}</span>` },
        { field: 'created_at', label: 'Analyzed', render: v => UI.formatRelativeTime(v) },
        { field: 'id', label: 'Actions', render: (v, r) => `
          <div style="display:flex;gap:0.5rem;">
            <button class="btn btn-sm btn-ghost" onclick="MALINFO.pages.reports.viewReport('${v}')" title="View Report">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                <circle cx="12" cy="12" r="3"></circle>
              </svg>
            </button>
            <button class="btn btn-sm btn-ghost" onclick="MALINFO.pages.reports.downloadReport('${v}')" title="Download JSON">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="7 10 12 15 17 10"></polyline>
                <line x1="12" y1="15" x2="12" y2="3"></line>
              </svg>
            </button>
            <button class="btn btn-sm btn-ghost" onclick="MALINFO.pages.reports.reanalyzeSample('${v}')" title="Re-analyze">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="23 4 23 10 17 10"></polyline>
                <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
              </svg>
            </button>
          </div>
        ` },
      ],
      reports,
      { emptyMessage: 'No reports found' }
    );
  },

  updatePagination(hasMore) {
    const prevBtn = document.getElementById('prevReportPage');
    const nextBtn = document.getElementById('nextReportPage');
    const pageInfo = document.getElementById('reportPageInfo');

    if (prevBtn) prevBtn.disabled = this.currentFilters.page <= 1;
    if (nextBtn) nextBtn.disabled = !hasMore;
    if (pageInfo) pageInfo.textContent = `Page ${this.currentFilters.page}`;
  },

  async viewReport(sampleId) {
    try {
      const html = await API.getSampleReport(sampleId);
      // Open in new window/tab
      const win = window.open('', '_blank');
      win.document.write(html);
      win.document.close();
    } catch (error) {
      UI.toast(`Failed to load report: ${error.message}`, 'error');
    }
  },

  async downloadReport(sampleId) {
    try {
      const blob = await API.downloadReport(sampleId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `malinfo_report_${sampleId}.json`;
      a.click();
      URL.revokeObjectURL(url);
      UI.toast('Report downloaded', 'success');
    } catch (error) {
      UI.toast(`Download failed: ${error.message}`, 'error');
    }
  },

  async reanalyzeSample(sampleId) {
    if (!confirm('Re-analyze this sample? This will re-run static analysis and sandbox if enabled.')) return;
    
    try {
      UI.toast('Re-analysis queued', 'success');
      await API.reanalyzeSample(sampleId);
      this.loadReports();
    } catch (error) {
      UI.toast(`Re-analysis failed: ${error.message}`, 'error');
    }
  },

  refresh() {
    this.loadReports();
  },
};