// Threat Intelligence Page
// IOC lookup and enrichment across multiple providers

import { API } from '../api.js';
import { UI } from '../ui.js';

export const ThreatIntelPage = {
  activeTab: 'lookup',

  async render() {
    const main = document.getElementById('appMain');
    if (!main) return;

    main.innerHTML = `
      <div class="page-header">
        <div>
          <h1>Threat Intelligence</h1>
          <p>IOC enrichment across VirusTotal, OTX, AbuseIPDB, MISP and more</p>
        </div>
      </div>

      <div class="tabs">
        <button class="tab-btn active" data-tab="lookup">IOC Lookup</button>
        <button class="tab-btn" data-tab="enrich">Sample Enrichment</button>
        <button class="tab-btn" data-tab="bulk">Bulk Enrichment</button>
        <button class="tab-btn" data-tab="providers">Providers</button>
      </div>

      <div class="tab-content active" id="tab-lookup">
        ${this.renderLookupTab()}
      </div>

      <div class="tab-content" id="tab-enrich">
        <div class="card">
          <div class="card-header"><h2>Enrich Sample IOCs</h2></div>
          <div class="form-group">
            <label>Sample ID</label>
            <input type="text" id="enrichSampleId" placeholder="Enter sample UUID" style="width:100%;max-width:400px;">
          </div>
          <div class="form-actions">
            <button class="btn btn-primary" id="enrichSampleBtn">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="16 18 22 12 16 6"></polyline>
                <polyline points="8 6 2 12 8 18"></polyline>
              </svg>
              Enrich IOCs
            </button>
          </div>
          <div id="enrichResult" style="margin-top:1.5rem;"></div>
        </div>
      </div>

      <div class="tab-content" id="tab-bulk">
        <div class="card">
          <div class="card-header"><h2>Bulk IOC Enrichment</h2></div>
          <div class="form-group">
            <label>IOCs (JSON array)</label>
            <textarea id="bulkIocsInput" rows="10" placeholder='[{"ioc_type": "ip", "value": "1.2.3.4", "confidence": 0.8}, {"ioc_type": "domain", "value": "example.com"}]' style="width:100%;font-family:var(--font-mono);font-size:12px;"></textarea>
          </div>
          <div class="form-actions">
            <button class="btn btn-primary" id="bulkEnrichBtn">Enrich All</button>
          </div>
          <div id="bulkEnrichResult" style="margin-top:1.5rem;"></div>
        </div>
      </div>

      <div class="tab-content" id="tab-providers">
        <div class="card">
          <div class="card-header"><h2>Configured Providers</h2></div>
          <div id="providersTable">${UI.showLoading()}</div>
        </div>
      </div>
    `;

    this.setupEventListeners();
    await this.loadProviders();
  },

  renderLookupTab() {
    return `
      <div class="card">
        <div class="card-header"><h2>Single IOC Lookup</h2></div>
        <div class="form-row" style="margin-bottom:1rem;">
          <div class="form-group">
            <label>IOC Type</label>
            <select id="lookupType" style="width:100%;">
              <option value="hash">Hash (MD5/SHA1/SHA256)</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
            </select>
          </div>
          <div class="form-group" style="flex:2;">
            <label>Value</label>
            <input type="text" id="lookupValue" placeholder="Enter IOC value" style="width:100%;">
          </div>
        </div>
        <div class="form-actions">
          <button class="btn btn-primary" id="lookupBtn">Lookup</button>
        </div>
        <div id="lookupResult" style="margin-top:1.5rem;"></div>
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
        this.activeTab = btn.dataset.tab;
      });
    });

    // Lookup
    document.getElementById('lookupBtn')?.addEventListener('click', () => this.doLookup());

    // Enrich sample
    document.getElementById('enrichSampleBtn')?.addEventListener('click', () => this.enrichSample());

    // Bulk enrich
    document.getElementById('bulkEnrichBtn')?.addEventListener('click', () => this.bulkEnrich());

    // Enter key support
    document.getElementById('lookupValue')?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.doLookup();
    });

    document.getElementById('enrichSampleId')?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.enrichSample();
    });
  },

  async loadProviders() {
    const container = document.getElementById('providersTable');
    if (!container) return;

    try {
      const data = await API.getThreatIntelProviders();
      
      container.innerHTML = UI.renderTable(
        [
          { field: 'name', label: 'Provider' },
          { field: 'rate_limit', label: 'Rate Limit (req/s)' },
          { field: 'has_api_key', label: 'Configured', render: v => v ? UI.createPill('Yes', 'safe') : UI.createPill('No', 'warning') },
        ],
        data.providers || [],
        { emptyMessage: 'No threat intelligence providers configured' }
      );
    } catch (error) {
      container.innerHTML = UI.showEmptyState('', 'Failed to load providers', '⚠');
    }
  },

  async doLookup() {
    const type = document.getElementById('lookupType').value;
    const value = document.getElementById('lookupValue').value.trim();
    const resultContainer = document.getElementById('lookupResult');

    if (!value) {
      UI.toast('Please enter an IOC value', 'warning');
      return;
    }

    resultContainer.innerHTML = UI.showLoading();

    try {
      let result;
      switch (type) {
        case 'hash':
          result = await API.lookupHash(value);
          break;
        case 'ip':
          result = await API.lookupIP(value);
          break;
        case 'domain':
          result = await API.lookupDomain(value);
          break;
        case 'url':
          result = await API.lookupURL(value);
          break;
      }

      resultContainer.innerHTML = this.renderEnrichedResult(result);
    } catch (error) {
      resultContainer.innerHTML = `
        <div style="background:var(--danger-dim);border:1px solid var(--danger);border-radius:var(--radius);padding:1rem;color:var(--danger);">
          Lookup failed: ${UI.escapeHtml(error.message)}
        </div>
      `;
    }
  },

  async enrichSample() {
    const sampleId = document.getElementById('enrichSampleId').value.trim();
    const resultContainer = document.getElementById('enrichResult');

    if (!sampleId) {
      UI.toast('Please enter a sample ID', 'warning');
      return;
    }

    resultContainer.innerHTML = UI.showLoading();

    try {
      const result = await API.enrichSample(sampleId);
      resultContainer.innerHTML = this.renderEnrichmentResult(result);
    } catch (error) {
      resultContainer.innerHTML = `
        <div style="background:var(--danger-dim);border:1px solid var(--danger);border-radius:var(--radius);padding:1rem;color:var(--danger);">
          Enrichment failed: ${UI.escapeHtml(error.message)}
        </div>
      `;
    }
  },

  async bulkEnrich() {
    const input = document.getElementById('bulkIocsInput').value.trim();
    const resultContainer = document.getElementById('bulkEnrichResult');

    if (!input) {
      UI.toast('Please enter IOCs as JSON array', 'warning');
      return;
    }

    let iocs;
    try {
      iocs = JSON.parse(input);
      if (!Array.isArray(iocs)) throw new Error('Input must be an array');
    } catch (error) {
      UI.toast('Invalid JSON format', 'error');
      return;
    }

    if (iocs.length > 100) {
      UI.toast('Maximum 100 IOCs per request', 'warning');
      return;
    }

    resultContainer.innerHTML = UI.showLoading();

    try {
      const result = await API.enrichBulk(iocs);
      resultContainer.innerHTML = this.renderBulkResult(result.enriched);
    } catch (error) {
      resultContainer.innerHTML = `
        <div style="background:var(--danger-dim);border:1px solid var(--danger);border-radius:var(--radius);padding:1rem;color:var(--danger);">
          Bulk enrichment failed: ${UI.escapeHtml(error.message)}
        </div>
      `;
    }
  },

  renderEnrichedResult(result) {
    if (!result) return '<p style="color:var(--text-muted)">No results</p>';

    const consensus = result.consensus_malicious ? 'MALICIOUS' : 'CLEAN';
    const consensusClass = result.consensus_malicious ? 'danger' : 'safe';

    return `
      <div style="border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;">
        <div style="background:var(--panel-raised);padding:1rem;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;">
          <div>
            <strong>${UI.escapeHtml(result.ioc_type.toUpperCase())}: ${UI.escapeHtml(result.value)}</strong>
            <span class="mono" style="margin-left:1rem;color:var(--text-muted)">Confidence: ${(result.aggregated_confidence * 100).toFixed(1)}%</span>
          </div>
          <span class="pill ${consensusClass}">${consensus}</span>
        </div>
        <div style="padding:1rem;">
          <h4 style="margin-bottom:0.75rem;color:var(--text-secondary)">Source Results</h4>
          ${result.sources.map(src => `
            <div style="padding:0.75rem;border:1px solid var(--line);border-radius:var(--radius);margin-bottom:0.5rem;background:var(--panel-raised);">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                <strong>${src.source}</strong>
                ${src.malicious ? UI.createPill('Malicious', 'danger') : UI.createPill('Clean', 'safe')}
              </div>
              <div style="font-size:12px;color:var(--text-secondary);display:flex;gap:1rem;flex-wrap:wrap;">
                <span>Threat Level: <strong>${src.threat_level}</strong></span>
                <span>Confidence: <strong>${(src.confidence * 100).toFixed(1)}%</strong></span>
              </div>
              ${src.tags.length ? `<div style="margin-top:0.5rem;">${src.tags.map(t => UI.createTag(t)).join(' ')}</div>` : ''}
              ${src.families.length ? `<div style="margin-top:0.5rem;">Families: ${src.families.map(f => UI.createTag(f)).join(' ')}</div>` : ''}
              ${src.error ? `<div style="margin-top:0.5rem;color:var(--danger);">Error: ${UI.escapeHtml(src.error)}</div>` : ''}
            </div>
          `).join('')}
        </div>
      </div>
    `;
  },

  renderEnrichmentResult(result) {
    if (!result || !result.enriched) {
      return '<p style="color:var(--text-muted)">No IOCs to enrich</p>';
    }

    return `
      <div>
        <h4 style="margin-bottom:1rem;color:var(--text-secondary)">Sample: ${UI.escapeHtml(result.sample_id)} (${result.enriched.length} IOCs enriched)</h4>
        ${result.enriched.map(r => this.renderEnrichedResult(r)).join('')}
      </div>
    `;
  },

  renderBulkResult(enriched) {
    if (!enriched || !enriched.length) {
      return '<p style="color:var(--text-muted)">No results</p>';
    }

    return `
      <div style="display:grid;gap:1rem;">
        ${enriched.map(r => this.renderEnrichedResult(r)).join('')}
      </div>
    `;
  },

  refresh() {
    this.loadProviders();
  },
};