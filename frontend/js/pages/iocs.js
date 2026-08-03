// IOC Database Page
// Search and manage Indicators of Compromise

import { API } from '../api.js';
import { UI } from '../ui.js';

export const IOCsPage = {
  currentFilters: {
    type: '',
    search: '',
    page: 1,
    limit: 50,
  },

  async render() {
    const main = document.getElementById('appMain');
    if (!main) return;

    main.innerHTML = `
      <div class="page-header">
        <div>
          <h1>IOC Database</h1>
          <p>Search and manage Indicators of Compromise across all analyses</p>
        </div>
      </div>

      <div class="card">
        <div class="form-row" style="margin-bottom:0.5rem;">
          <div class="form-group" style="flex:1;">
            <input type="search" id="iocSearch" placeholder="Search IOCs by value..." style="width:100%;">
          </div>
          <div class="form-group" style="width:200px;">
            <select id="iocTypeFilter" style="width:100%;">
              <option value="">All Types</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="c2">C2 Server</option>
              <option value="mutex">Mutex</option>
              <option value="registry_key">Registry Key</option>
              <option value="email">Email</option>
            </select>
          </div>
        </div>
      </div>

      <div class="card">
        <div id="iocsTable">${UI.showLoading()}</div>
        
        <div id="iocPagination" style="display:flex;justify-content:center;align-items:center;gap:1rem;margin-top:1rem;padding-top:1rem;border-top:1px solid var(--line);">
          <button class="btn btn-sm" id="prevIocPage" disabled>Previous</button>
          <span id="iocPageInfo" class="mono">Page 1</span>
          <button class="btn btn-sm" id="nextIocPage" disabled>Next</button>
        </div>
      </div>
    `;

    this.setupEventListeners();
    await this.loadIOCs();
  },

  setupEventListeners() {
    const searchInput = document.getElementById('iocSearch');
    const typeFilter = document.getElementById('iocTypeFilter');
    const prevBtn = document.getElementById('prevIocPage');
    const nextBtn = document.getElementById('nextIocPage');

    let searchDebounce;
    searchInput?.addEventListener('input', (e) => {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(() => {
        this.currentFilters.search = e.target.value;
        this.currentFilters.page = 1;
        this.loadIOCs();
      }, 300);
    });

    typeFilter?.addEventListener('change', (e) => {
      this.currentFilters.type = e.target.value;
      this.currentFilters.page = 1;
      this.loadIOCs();
    });

    prevBtn?.addEventListener('click', () => {
      if (this.currentFilters.page > 1) {
        this.currentFilters.page--;
        this.loadIOCs();
      }
    });

    nextBtn?.addEventListener('click', () => {
      this.currentFilters.page++;
      this.loadIOCs();
    });
  },

  async loadIOCs() {
    const container = document.getElementById('iocsTable');
    if (!container) return;

    container.innerHTML = UI.showLoading();

    try {
      // Get samples and extract IOCs (since we don't have a dedicated IOC endpoint yet)
      const samples = await API.getSamples({ limit: 500 });
      
      let allIOCs = [];
      samples.forEach(sample => {
        if (sample.iocs) {
          sample.iocs.forEach(ioc => {
            allIOCs.push({
              ...ioc,
              sample_id: sample.id,
              sample_name: sample.original_filename,
              sample_verdict: sample.verdict,
              sample_date: sample.created_at,
            });
          });
        }
      });

      // Filter
      let filtered = allIOCs;
      
      if (this.currentFilters.search) {
        const query = this.currentFilters.search.toLowerCase();
        filtered = filtered.filter(ioc => 
          ioc.value?.toLowerCase().includes(query)
        );
      }

      if (this.currentFilters.type) {
        filtered = filtered.filter(ioc => ioc.ioc_type === this.currentFilters.type);
      }

      // Sort by date descending
      filtered.sort((a, b) => new Date(b.sample_date) - new Date(a.sample_date));

      // Paginate
      const start = (this.currentFilters.page - 1) * this.currentFilters.limit;
      const paginated = filtered.slice(start, start + this.currentFilters.limit);

      this.renderIOCs(paginated);
      this.updatePagination(filtered.length > start + this.currentFilters.limit);
    } catch (error) {
      console.error('[IOCs] Load failed:', error);
      container.innerHTML = UI.showEmptyState('', 'Failed to load IOCs', '⚠');
    }
  },

  renderIOCs(iocs) {
    const container = document.getElementById('iocsTable');
    if (!container) return;

    if (!iocs.length) {
      container.innerHTML = UI.showEmptyState('', 'No IOCs match your filters');
      return;
    }

    container.innerHTML = UI.renderTable(
      [
        { field: 'ioc_type', label: 'Type', render: v => UI.createTag(v) },
        { field: 'value', label: 'Value', truncate: true, render: v => `<code class="mono">${UI.escapeHtml(v)}</code>` },
        { field: 'confidence', label: 'Confidence', render: v => `<span class="mono">${(v * 100).toFixed(0)}%</span>` },
        { field: 'sample_name', label: 'Sample', truncate: true },
        { field: 'sample_verdict', label: 'Sample Verdict', render: v => UI.createPill(v, v) },
        { field: 'sample_date', label: 'First Seen', render: v => UI.formatRelativeTime(v) },
        { field: 'sample_id', label: 'Actions', render: (v, r) => `
          <button class="btn btn-sm btn-ghost" onclick="MALINFO.pages.iocs.lookupIOC('${r.ioc_type}', '${r.value}')" title="Threat Intel Lookup">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="11" cy="11" r="8"></circle>
              <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
          </button>
        ` },
      ],
      iocs,
      { emptyMessage: 'No IOCs found' }
    );
  },

  updatePagination(hasMore) {
    const prevBtn = document.getElementById('prevIocPage');
    const nextBtn = document.getElementById('nextIocPage');
    const pageInfo = document.getElementById('iocPageInfo');

    if (prevBtn) prevBtn.disabled = this.currentFilters.page <= 1;
    if (nextBtn) nextBtn.disabled = !hasMore;
    if (pageInfo) pageInfo.textContent = `Page ${this.currentFilters.page}`;
  },

  async lookupIOC(type, value) {
    // Navigate to threat intel page with pre-filled lookup
    window.location.hash = 'threat-intel';
    // Wait for page to load then trigger lookup
    setTimeout(() => {
      const typeSelect = document.getElementById('lookupType');
      const valueInput = document.getElementById('lookupValue');
      const lookupBtn = document.getElementById('lookupBtn');
      
      if (typeSelect && valueInput && lookupBtn) {
        typeSelect.value = type;
        valueInput.value = value;
        lookupBtn.click();
      }
    }, 100);
  },

  refresh() {
    this.loadIOCs();
  },
};