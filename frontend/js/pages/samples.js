// Samples Page
// Sample listing, search, and management

import { API } from '../api.js';
import { UI } from '../ui.js';

export const SamplesPage = {
  currentFilters: {
    search: '',
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
          <h1>Samples</h1>
          <p>Browse and manage analyzed samples</p>
        </div>
        <div class="page-header-actions">
          <button class="btn btn-primary" id="uploadSampleBtn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="12" y1="5" x2="12" y2="19"></line>
              <line x1="5" y1="12" x2="19" y2="12"></line>
            </svg>
            Upload Sample
          </button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2>Filters</h2>
        </div>
        <div class="form-row" style="margin-bottom:0.5rem;">
          <div class="form-group" style="flex:1;">
            <input type="search" id="sampleSearch" placeholder="Search by filename, hash, type..." style="width:100%;">
          </div>
          <div class="form-group" style="width:200px;">
            <select id="verdictFilter" style="width:100%;">
              <option value="">All Verdicts</option>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="clean">Clean</option>
              <option value="unknown">Unknown</option>
            </select>
          </div>
          <div class="form-group" style="width:150px;">
            <select id="limitSelect" style="width:100%;">
              <option value="25">25 per page</option>
              <option value="50" selected>50 per page</option>
              <option value="100">100 per page</option>
            </select>
          </div>
        </div>
      </div>

      <div class="card">
        <div id="samplesTable">
          ${UI.showLoading()}
        </div>
        
        <div id="pagination" style="display:flex;justify-content:center;align-items:center;gap:1rem;margin-top:1rem;padding-top:1rem;border-top:1px solid var(--line);">
          <button class="btn btn-sm" id="prevPage" disabled>Previous</button>
          <span id="pageInfo" class="mono">Page 1</span>
          <button class="btn btn-sm" id="nextPage" disabled>Next</button>
        </div>
      </div>
    `;

    // Setup event listeners
    this.setupEventListeners();
    await this.loadSamples();
  },

  setupEventListeners() {
    const searchInput = document.getElementById('sampleSearch');
    const verdictFilter = document.getElementById('verdictFilter');
    const limitSelect = document.getElementById('limitSelect');
    const uploadBtn = document.getElementById('uploadSampleBtn');
    const prevBtn = document.getElementById('prevPage');
    const nextBtn = document.getElementById('nextPage');

    // Debounced search
    let searchDebounce;
    searchInput?.addEventListener('input', (e) => {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(() => {
        this.currentFilters.search = e.target.value;
        this.currentFilters.page = 1;
        this.loadSamples();
      }, 300);
    });

    verdictFilter?.addEventListener('change', (e) => {
      this.currentFilters.verdict = e.target.value;
      this.currentFilters.page = 1;
      this.loadSamples();
    });

    limitSelect?.addEventListener('change', (e) => {
      this.currentFilters.limit = parseInt(e.target.value);
      this.currentFilters.page = 1;
      this.loadSamples();
    });

    uploadBtn?.addEventListener('click', () => {
      UI.showModal('uploadModal');
    });

    prevBtn?.addEventListener('click', () => {
      if (this.currentFilters.page > 1) {
        this.currentFilters.page--;
        this.loadSamples();
      }
    });

    nextBtn?.addEventListener('click', () => {
      this.currentFilters.page++;
      this.loadSamples();
    });
  },

  async loadSamples() {
    const container = document.getElementById('samplesTable');
    if (!container) return;

    container.innerHTML = UI.showLoading();

    try {
      const params = {
        limit: this.currentFilters.limit,
        offset: (this.currentFilters.page - 1) * this.currentFilters.limit,
      };

      // Note: Backend doesn't support search/verdict filters yet, so we filter client-side
      const samples = await API.getSamples(params);
      
      let filtered = samples;
      
      if (this.currentFilters.search) {
        const query = this.currentFilters.search.toLowerCase();
        filtered = filtered.filter(s => 
          s.original_filename?.toLowerCase().includes(query) ||
          s.sha256?.toLowerCase().includes(query) ||
          s.file_type?.toLowerCase().includes(query)
        );
      }

      if (this.currentFilters.verdict) {
        filtered = filtered.filter(s => s.verdict === this.currentFilters.verdict);
      }

      this.renderSamples(filtered);
      this.updatePagination(filtered.length === this.currentFilters.limit);
    } catch (error) {
      console.error('[Samples] Load failed:', error);
      container.innerHTML = UI.showEmptyState('', 'Failed to load samples', '⚠');
    }
  },

  renderSamples(samples) {
    const container = document.getElementById('samplesTable');
    if (!container) return;

    if (!samples.length) {
      container.innerHTML = UI.showEmptyState('', 'No samples match your filters');
      return;
    }

    container.innerHTML = UI.renderTable(
      [
        { field: 'original_filename', label: 'File', render: (v, r) => `
          <div style="font-weight:500">${UI.escapeHtml(v)}</div>
          <div class="mono" style="font-size:11px;color:var(--text-muted)">${r.sha256?.slice(0, 24)}…</div>
        ` },
        { field: 'file_type', label: 'Type' },
        { field: 'file_size', label: 'Size', render: v => UI.formatBytes(v) },
        { field: 'target_os', label: 'Target OS', render: v => UI.createTag(v) },
        { field: 'verdict', label: 'Verdict', render: v => UI.createPill(v, v) },
        { field: 'risk_score', label: 'Risk', render: v => `<span class="mono">${v}</span>` },
        { field: 'status', label: 'Status', render: v => UI.createTag(v.replace('_', ' ')) },
        { field: 'created_at', label: 'Submitted', render: v => UI.formatRelativeTime(v) },
      ],
      samples,
      { clickable: true, keyField: 'id', emptyMessage: 'No samples found' }
    );
  },

  updatePagination(hasMore) {
    const prevBtn = document.getElementById('prevPage');
    const nextBtn = document.getElementById('nextPage');
    const pageInfo = document.getElementById('pageInfo');

    if (prevBtn) prevBtn.disabled = this.currentFilters.page <= 1;
    if (nextBtn) nextBtn.disabled = !hasMore;
    if (pageInfo) pageInfo.textContent = `Page ${this.currentFilters.page}`;
  },

  async onRowClick(sampleId) {
    window.location.hash = `samples/${sampleId}`;
  },

  refresh() {
    this.loadSamples();
  },
};