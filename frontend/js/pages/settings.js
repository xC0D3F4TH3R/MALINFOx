// Settings Page (Admin only)
// System configuration and settings

import { API } from '../api.js';
import { UI } from '../ui.js';

export const SettingsPage = {
  async render() {
    const main = document.getElementById('appMain');
    if (!main) return;

    main.innerHTML = `
      <div class="page-header">
        <div>
          <h1>Settings</h1>
          <p>System configuration and deployment settings</p>
        </div>
      </div>

      <div class="tabs">
        <button class="tab-btn active" data-tab="general">General</button>
        <button class="tab-btn" data-tab="sandbox">Sandbox</button>
        <button class="tab-btn" data-tab="monitoring">Monitoring</button>
        <button class="tab-btn" data-tab="threat-intel">Threat Intel</button>
        <button class="tab-btn" data-tab="security">Security</button>
      </div>

      <div class="tab-content active" id="tab-general">
        <div class="card">
          <div class="card-header"><h2>General Settings</h2></div>
          <div class="form-row">
            <div class="form-group">
              <label>Application Name</label>
              <input type="text" id="settingAppName" value="MALINFO" style="width:100%;">
            </div>
            <div class="form-group">
              <label>Environment</label>
              <select id="settingEnvironment" style="width:100%;">
                <option value="development">Development</option>
                <option value="staging">Staging</option>
                <option value="production">Production</option>
              </select>
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>Max Upload Size (MB)</label>
              <input type="number" id="settingMaxUpload" value="250" min="1" max="2048" style="width:100%;">
            </div>
            <div class="form-group">
              <label>Debug Mode</label>
              <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;">
                <input type="checkbox" id="settingDebug"> Enabled
              </label>
            </div>
          </div>
          <div class="form-actions">
            <button class="btn btn-primary" id="saveGeneralSettings">Save Changes</button>
          </div>
        </div>
      </div>

      <div class="tab-content" id="tab-sandbox">
        <div class="card">
          <div class="card-header"><h2>Sandbox Configuration</h2></div>
          <div class="form-group">
            <label>
              <input type="checkbox" id="settingSandboxEnabled"> Enable Sandbox Integration
            </label>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>Sandbox API URL</label>
              <input type="url" id="settingSandboxUrl" placeholder="http://cape-controller:8000" style="width:100%;">
            </div>
            <div class="form-group">
              <label>API Token</label>
              <input type="password" id="settingSandboxToken" placeholder="Optional API token" style="width:100%;">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>Poll Interval (seconds)</label>
              <input type="number" id="settingSandboxPoll" value="15" min="5" max="300" style="width:100%;">
            </div>
            <div class="form-group">
              <label>Timeout (seconds)</label>
              <input type="number" id="settingSandboxTimeout" value="600" min="60" max="3600" style="width:100%;">
            </div>
          </div>
          <div class="form-actions">
            <button class="btn btn-primary" id="saveSandboxSettings">Save Changes</button>
          </div>
        </div>
      </div>

      <div class="tab-content" id="tab-monitoring">
        <div class="card">
          <div class="card-header"><h2>Monitoring Configuration</h2></div>
          <div class="form-group">
            <label>
              <input type="checkbox" id="settingMonitorEnabled"> Enable File Transfer Monitoring
            </label>
          </div>
          <div class="form-group">
            <label>Watch Paths (one per line)</label>
            <textarea id="settingMonitorPaths" rows="5" placeholder="/var/mail
/home/*/Downloads
/tmp" style="width:100%;font-family:var(--font-mono);font-size:12px;"></textarea>
          </div>
          <div class="form-group">
            <label>
              <input type="checkbox" id="settingMonitorNetwork"> Enable Network Monitoring
            </label>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>Network Interface</label>
              <input type="text" id="settingMonitorInterface" value="any" style="width:100%;">
            </div>
            <div class="form-group">
              <label>BPF Filter</label>
              <input type="text" id="settingMonitorFilter" value="tcp or udp" style="width:100%;">
            </div>
          </div>
          <div class="form-group">
            <label>
              <input type="checkbox" id="settingMonitorAutoAnalyze" checked> Auto-analyze detected files
            </label>
          </div>
          <div class="form-actions">
            <button class="btn btn-primary" id="saveMonitoringSettings">Save Changes</button>
          </div>
        </div>
      </div>

      <div class="tab-content" id="tab-threat-intel">
        <div class="card">
          <div class="card-header"><h2>Threat Intelligence API Keys</h2></div>
          <div class="form-row">
            <div class="form-group">
              <label>VirusTotal API Key</label>
              <input type="password" id="settingVTKey" placeholder="VirusTotal API key" style="width:100%;">
            </div>
            <div class="form-group">
              <label>OTX API Key</label>
              <input type="password" id="settingOTXKey" placeholder="AlienVault OTX API key" style="width:100%;">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>AbuseIPDB API Key</label>
              <input type="password" id="settingAbuseIPDBKey" placeholder="AbuseIPDB API key" style="width:100%;">
            </div>
            <div class="form-group">
              <label>MISP URL</label>
              <input type="url" id="settingMISPUrl" placeholder="https://misp.example.com" style="width:100%;">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>MISP API Key</label>
              <input type="password" id="settingMISPKey" placeholder="MISP API key" style="width:100%;">
            </div>
            <div class="form-group">
              <label>
                <input type="checkbox" id="settingMISPVerifySSL" checked> Verify SSL
              </label>
            </div>
          </div>
          <div class="form-actions">
            <button class="btn btn-primary" id="saveThreatIntelSettings">Save Changes</button>
          </div>
        </div>
      </div>

      <div class="tab-content" id="tab-security">
        <div class="card">
          <div class="card-header"><h2>Security Settings</h2></div>
          <div class="form-row">
            <div class="form-group">
              <label>Access Token Expiry (minutes)</label>
              <input type="number" id="settingTokenExpiry" value="480" min="15" max="1440" style="width:100%;">
            </div>
            <div class="form-group">
              <label>Refresh Token Expiry (days)</label>
              <input type="number" id="settingRefreshExpiry" value="30" min="1" max="365" style="width:100%;">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>Max Failed Login Attempts</label>
              <input type="number" id="settingMaxFailed" value="5" min="3" max="20" style="width:100%;">
            </div>
            <div class="form-group">
              <label>Account Lockout (minutes)</label>
              <input type="number" id="settingLockout" value="15" min="5" max="120" style="width:100%;">
            </div>
          </div>
          <div class="form-group">
            <label>Allowed Origins (CORS) - one per line</label>
            <textarea id="settingAllowedOrigins" rows="4" placeholder="https://malinfo.example.gov
https://malinfo.internal" style="width:100%;font-family:var(--font-mono);font-size:12px;"></textarea>
          </div>
          <div class="form-group">
            <label>
              <input type="checkbox" id="settingRateLimit" checked> Enable Rate Limiting
            </label>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>Rate Limit (requests)</label>
              <input type="number" id="settingRateLimitReq" value="100" min="10" max="10000" style="width:100%;">
            </div>
            <div class="form-group">
              <label>Rate Limit Window (seconds)</label>
              <input type="number" id="settingRateLimitWindow" value="60" min="10" max="3600" style="width:100%;">
            </div>
          </div>
          <div class="form-actions">
            <button class="btn btn-primary" id="saveSecuritySettings">Save Changes</button>
          </div>
        </div>
      </div>
    `;

    this.setupEventListeners();
    await this.loadSettings();
  },

  setupEventListeners() {
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
      });
    });

    // Save buttons
    document.getElementById('saveGeneralSettings')?.addEventListener('click', () => this.saveSettings('general'));
    document.getElementById('saveSandboxSettings')?.addEventListener('click', () => this.saveSettings('sandbox'));
    document.getElementById('saveMonitoringSettings')?.addEventListener('click', () => this.saveSettings('monitoring'));
    document.getElementById('saveThreatIntelSettings')?.addEventListener('click', () => this.saveSettings('threat-intel'));
    document.getElementById('saveSecuritySettings')?.addEventListener('click', () => this.saveSettings('security'));
  },

  async loadSettings() {
    try {
      const health = await API.healthCheck();
      
      // Populate from health check or defaults
      document.getElementById('settingEnvironment').value = health.environment || 'development';
      document.getElementById('settingSandboxEnabled').checked = health.sandbox_enabled || false;
      document.getElementById('settingMonitorEnabled').checked = health.monitoring_enabled || false;
    } catch (error) {
      console.error('[Settings] Failed to load settings:', error);
    }
  },

  async saveSettings(tab) {
    UI.toast('Settings saved (backend endpoint needed)', 'info');
    // Would need backend endpoints to persist settings
  },

  refresh() {
    this.loadSettings();
  },
};