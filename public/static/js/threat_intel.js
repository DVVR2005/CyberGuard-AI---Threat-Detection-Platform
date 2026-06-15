/* ============================================================
   CyberGuard AI - Threat Intelligence Module
   CVE Feed, Domain Reputation, Global Threat Status
   ============================================================ */

Router.register('threat-intel', renderThreatIntel);

async function renderThreatIntel() {
    const content = document.getElementById('page-content');
    content.innerHTML = `
        <div class="page-header">
            <h1>Threat Intelligence</h1>
            <p class="page-subtitle">Global threat monitoring & domain reputation analysis</p>
        </div>

        <!-- Global Threat Level -->
        <div class="threat-level-banner" id="threat-level-banner">
            <div class="threat-level-left">
                <div class="threat-level-icon" id="threat-level-icon">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <path d="M12 8v4M12 16h.01"/>
                    </svg>
                </div>
                <div>
                    <div class="threat-level-label">Global Threat Level</div>
                    <div class="threat-level-value" id="threat-level-text">Loading...</div>
                </div>
            </div>
            <div class="threat-level-stats">
                <div class="threat-stat">
                    <span class="threat-stat-value" id="active-threats">--</span>
                    <span class="threat-stat-label">Active Threats</span>
                </div>
                <div class="threat-stat">
                    <span class="threat-stat-value" id="recent-cves-count">--</span>
                    <span class="threat-stat-label">Recent CVEs</span>
                </div>
                <div class="threat-stat">
                    <span class="threat-stat-value" id="threat-updated">--</span>
                    <span class="threat-stat-label">Last Updated</span>
                </div>
            </div>
        </div>

        <!-- Top Threat Categories -->
        <div class="threat-categories-grid" id="threat-categories">
        </div>

        <!-- Domain Reputation Lookup -->
        <div class="card" style="margin-bottom: 24px;">
            <h3 class="card-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2" style="margin-right: 8px; vertical-align: middle;">
                    <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
                </svg>
                Domain Reputation Lookup
            </h3>
            <div class="domain-lookup-row">
                <input type="text" id="domain-input" class="form-input" placeholder="Enter domain (e.g. example.com)" />
                <button class="btn btn-primary" id="domain-check-btn" onclick="checkDomainReputation()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                    Check Reputation
                </button>
            </div>
            <div id="domain-result" style="display:none; margin-top: 20px;"></div>
        </div>

        <!-- CVE Feed Table -->
        <div class="card">
            <div class="card-header-row" style="flex-wrap: wrap; gap: 16px; align-items: center; justify-content: space-between;">
                <h3 class="card-title" style="margin-bottom: 0;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-amber)" stroke-width="2" style="margin-right: 8px; vertical-align: middle;">
                        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                    Latest CVE Advisories
                </h3>
            </div>
            
            <!-- Upgraded filter grid -->
            <div class="cve-filters-grid" style="margin: 20px 0;">
                <div class="filter-col">
                    <label class="form-label" style="font-weight: 500; font-size: 0.85rem; color: var(--text-muted); display: block; margin-bottom: 6px;">Search CVEs</label>
                    <input type="text" id="cve-search-input" class="form-input" placeholder="CVE-ID, product, keyword..." oninput="debouncedSearchCVEs()" style="width: 100%;" />
                </div>
                <div class="filter-col">
                    <label class="form-label" style="font-weight: 500; font-size: 0.85rem; color: var(--text-muted); display: block; margin-bottom: 6px;">Severity</label>
                    <select id="cve-severity-filter" class="form-select" onchange="loadFilteredCVEs()" style="width: 100%;">
                        <option value="">All Severities</option>
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                    </select>
                </div>
                <div class="filter-col">
                    <label class="form-label" style="font-weight: 500; font-size: 0.85rem; color: var(--text-muted); display: block; margin-bottom: 6px;">Min CVSS: <span id="cvss-val-display" style="font-weight: bold; color: var(--accent-amber);">0.0</span></label>
                    <input type="range" id="cve-cvss-slider" min="0" max="10" step="0.1" value="0.0" class="form-range" oninput="document.getElementById('cvss-val-display').textContent=this.value; loadFilteredCVEs();" style="width: 100%;" />
                </div>
                <div class="filter-col">
                    <label class="form-label" style="font-weight: 500; font-size: 0.85rem; color: var(--text-muted); display: block; margin-bottom: 6px;">Min EPSS Prob: <span id="epss-val-display" style="font-weight: bold; color: var(--accent-cyan);">0%</span></label>
                    <input type="range" id="cve-epss-slider" min="0" max="1" step="0.01" value="0.0" class="form-range" oninput="document.getElementById('epss-val-display').textContent=(this.value*100).toFixed(0)+'%'; loadFilteredCVEs();" style="width: 100%;" />
                </div>
                <div class="filter-col">
                    <label class="form-label" style="font-weight: 500; font-size: 0.85rem; color: var(--text-muted); display: block; margin-bottom: 6px;">Sort By</label>
                    <select id="cve-sort-filter" class="form-select" onchange="loadFilteredCVEs()" style="width: 100%;">
                        <option value="cvss_score">CVSS Score</option>
                        <option value="epss_score">EPSS Score</option>
                        <option value="published_date">Publication Date</option>
                        <option value="cve_id">CVE ID</option>
                    </select>
                </div>
            </div>

            <div class="table-responsive">
                <table class="data-table" id="cve-table">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Title</th>
                            <th>Severity</th>
                            <th>CVSS</th>
                            <th>EPSS Score</th>
                            <th>EPSS Percentile</th>
                            <th>Published</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody id="cve-tbody">
                        <tr><td colspan="8" class="text-center">Loading CVE data...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    `;

    loadThreatData();
}

let allCVEs = [];
let cveSearchTimeout = null;

function formatEPSSScore(val) {
    if (val === undefined || val === null) return '0.00%';
    const score = parseFloat(val);
    return (score * 100).toFixed(2) + '%';
}

function formatEPSSPercentile(val) {
    if (val === undefined || val === null) return '0.00%';
    const pct = parseFloat(val);
    if (pct <= 1.0) {
        return (pct * 100).toFixed(2) + '%';
    }
    return pct.toFixed(2) + '%';
}

function debouncedSearchCVEs() {
    clearTimeout(cveSearchTimeout);
    cveSearchTimeout = setTimeout(() => {
        loadFilteredCVEs();
    }, 300);
}

async function loadFilteredCVEs() {
    const q = document.getElementById('cve-search-input').value.trim();
    const severity = document.getElementById('cve-severity-filter').value;
    const min_cvss = document.getElementById('cve-cvss-slider').value;
    const min_epss = document.getElementById('cve-epss-slider').value;
    const sort_by = document.getElementById('cve-sort-filter').value;

    const tbody = document.getElementById('cve-tbody');

    try {
        const queryParams = new URLSearchParams();
        if (q) queryParams.append('q', q);
        if (severity) queryParams.append('severity', severity);
        if (min_cvss && parseFloat(min_cvss) > 0) queryParams.append('min_cvss', min_cvss);
        if (min_epss && parseFloat(min_epss) > 0) queryParams.append('min_epss', min_epss);
        if (sort_by) queryParams.append('sort_by', sort_by);
        
        queryParams.append('limit', '50');

        const cveData = await api(`/api/threat-intel/cves?${queryParams.toString()}`);
        allCVEs = cveData.cves || [];
        renderCVETable(allCVEs);
    } catch (err) {
        Toast.show('Failed to load filtered CVE data', 'error');
        console.error(err);
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-red">Error loading CVEs</td></tr>';
        }
    }
}

async function loadThreatData() {
    try {
        const [globalData, cveData] = await Promise.all([
            api('/api/threat-intel/global-status'),
            api('/api/threat-intel/cves')
        ]);

        // Render global threat level
        const g = globalData.global;
        const levelColors = {
            'Low': 'var(--accent-green)',
            'Moderate': 'var(--accent-cyan)',
            'Elevated': 'var(--accent-amber)',
            'High': 'var(--accent-red)',
            'Critical': 'var(--accent-red)'
        };
        const color = levelColors[g.threat_level] || 'var(--accent-amber)';

        const banner = document.getElementById('threat-level-banner');
        if (banner) banner.style.borderColor = color;

        const icon = document.getElementById('threat-level-icon');
        if (icon) icon.style.color = color;

        const textEl = document.getElementById('threat-level-text');
        if (textEl) {
            textEl.textContent = g.threat_level;
            textEl.style.color = color;
        }

        const at = document.getElementById('active-threats');
        if (at) at.textContent = (g.active_threats || 0).toLocaleString();

        const rc = document.getElementById('recent-cves-count');
        if (rc) rc.textContent = g.recent_cves_count || 0;

        const tu = document.getElementById('threat-updated');
        if (tu) tu.textContent = formatDate(g.last_updated);

        // Render top threat categories
        if (g.top_threat_categories && g.top_threat_categories.length > 0) {
            const catGrid = document.getElementById('threat-categories');
            if (catGrid) {
                const catColors = ['var(--accent-red)', 'var(--accent-amber)', 'var(--accent-purple)', 'var(--accent-cyan)', 'var(--accent-green)'];
                catGrid.innerHTML = g.top_threat_categories.slice(0, 5).map((cat, i) => `
                    <div class="threat-cat-card" style="border-left: 3px solid ${catColors[i % catColors.length]};">
                        <div class="threat-cat-count" style="color: ${catColors[i % catColors.length]};">${cat.count}</div>
                        <div class="threat-cat-name">${cat.category}</div>
                    </div>
                `).join('');
            }
        }

        // Render CVEs
        allCVEs = cveData.cves || [];
        renderCVETable(allCVEs);

    } catch (err) {
        Toast.show('Failed to load threat intelligence data', 'error');
        console.error(err);
    }
}

function renderCVETable(cves) {
    const tbody = document.getElementById('cve-tbody');
    if (!tbody) return;

    if (cves.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No CVEs found</td></tr>';
        return;
    }

    tbody.innerHTML = cves.map(cve => `
        <tr class="cve-row">
            <td>
                <span class="cve-id">${cve.cve_id}</span>
            </td>
            <td>
                <div class="cve-title">${cve.title}</div>
            </td>
            <td>
                <span class="badge ${getSeverityClass(cve.severity)}">${cve.severity}</span>
            </td>
            <td>
                <span class="cvss-score" style="color: ${getCVSSColor(cve.cvss_score)}; font-weight: 600;">${cve.cvss_score}</span>
            </td>
            <td>
                <span class="epss-score" style="color: var(--accent-cyan); font-weight: 500;">${formatEPSSScore(cve.epss_score)}</span>
            </td>
            <td>
                <span class="epss-percentile" style="color: var(--text-muted); font-size: 0.9rem;">${formatEPSSPercentile(cve.epss_percentile)}</span>
            </td>
            <td class="text-muted" style="font-size: 0.9rem;">${formatDate(cve.published_date)}</td>
            <td>
                <button class="btn btn-ghost btn-sm" onclick="toggleCVEDetail(this, '${encodeURIComponent(JSON.stringify(cve))}')">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="6 9 12 15 18 9"/>
                    </svg>
                </button>
            </td>
        </tr>
    `).join('');
}

function toggleCVEDetail(btn, encodedCve) {
    const row = btn.closest('tr');
    const existing = row.nextElementSibling;
    if (existing && existing.classList.contains('cve-detail-row')) {
        existing.remove();
        return;
    }

    const cve = JSON.parse(decodeURIComponent(encodedCve));
    
    // Parse references
    let refs = [];
    if (Array.isArray(cve.references)) {
        refs = cve.references;
    } else if (cve.references_json) {
        try {
            refs = typeof cve.references_json === 'string' ? JSON.parse(cve.references_json) : cve.references_json;
        } catch(e) {
            refs = [cve.references_json];
        }
    }
    if (!Array.isArray(refs)) {
        refs = [refs];
    }

    // Parse affected products
    let products = [];
    if (Array.isArray(cve.affected_products)) {
        products = cve.affected_products;
    } else if (cve.affected_products) {
        products = [cve.affected_products];
    }

    const detailRow = document.createElement('tr');
    detailRow.className = 'cve-detail-row';
    detailRow.innerHTML = `
        <td colspan="8">
            <div class="cve-detail-content">
                <p class="cve-description">${cve.description || 'No description available.'}</p>
                <div class="cve-detail-grid">
                    <div>
                        <strong>Affected Products:</strong>
                        <ul class="cve-products">
                            ${products.map(p => `<li>${p}</li>`).join('') || '<li>N/A</li>'}
                        </ul>
                    </div>
                    <div>
                        <strong>References:</strong>
                        <ul class="cve-refs">
                            ${refs.map(r => `<li><a href="${r}" target="_blank" class="text-cyan">${r}</a></li>`).join('') || '<li>N/A</li>'}
                        </ul>
                    </div>
                </div>
            </div>
        </td>
    `;
    row.after(detailRow);
}

function filterCVEs() {
    loadFilteredCVEs();
}

function getCVSSColor(score) {
    if (score >= 9.0) return 'var(--accent-red)';
    if (score >= 7.0) return 'var(--accent-amber)';
    if (score >= 4.0) return '#eab308';
    return 'var(--accent-green)';
}

async function checkDomainReputation() {
    const domainInput = document.getElementById('domain-input');
    const resultDiv = document.getElementById('domain-result');
    const btn = document.getElementById('domain-check-btn');
    const domain = domainInput.value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');

    if (!domain || domain.length < 3) {
        Toast.show('Please enter a valid domain', 'warning');
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="btn-loader"></span> Checking...';
    resultDiv.style.display = 'none';

    try {
        const data = await api(`/api/threat-intel/domain/${domain}`);
        const rep = data.reputation;

        const statusColors = {
            'Safe': 'var(--accent-green)',
            'Suspicious': 'var(--accent-amber)',
            'Malicious': 'var(--accent-red)'
        };
        const statusBadgeClass = {
            'Safe': 'badge-safe',
            'Suspicious': 'badge-suspicious',
            'Malicious': 'badge-malicious'
        };
        const color = statusColors[rep.status] || 'var(--accent-cyan)';

        resultDiv.innerHTML = `
            <div class="domain-result-card" style="border-left: 4px solid ${color};">
                <div class="domain-result-header">
                    <div>
                        <h4 class="domain-name">${rep.domain}</h4>
                        <span class="badge ${statusBadgeClass[rep.status] || 'badge-info'}" style="font-size: 0.85rem; padding: 6px 16px;">
                            ${rep.status}
                        </span>
                    </div>
                    <div class="domain-risk-circle" style="border-color: ${color}; color: ${color};">
                        ${rep.risk_score}
                    </div>
                </div>
                <div class="domain-details-grid">
                    <div class="domain-detail-item">
                        <span class="domain-detail-label">Blacklisted</span>
                        <span class="domain-detail-value ${rep.blacklisted ? 'text-red' : 'text-green'}">${rep.blacklisted ? 'Yes' : 'No'}</span>
                    </div>
                    <div class="domain-detail-item">
                        <span class="domain-detail-label">Malware</span>
                        <span class="domain-detail-value ${rep.details?.malware ? 'text-red' : 'text-green'}">${rep.details?.malware ? 'Detected' : 'Clean'}</span>
                    </div>
                    <div class="domain-detail-item">
                        <span class="domain-detail-label">Phishing</span>
                        <span class="domain-detail-value ${rep.details?.phishing ? 'text-red' : 'text-green'}">${rep.details?.phishing ? 'Detected' : 'Clean'}</span>
                    </div>
                    <div class="domain-detail-item">
                        <span class="domain-detail-label">Spam</span>
                        <span class="domain-detail-value ${rep.details?.spam ? 'text-red' : 'text-green'}">${rep.details?.spam ? 'Detected' : 'Clean'}</span>
                    </div>
                    <div class="domain-detail-item">
                        <span class="domain-detail-label">Reputation Score</span>
                        <span class="domain-detail-value">${rep.details?.reputation_score || 'N/A'}/100</span>
                    </div>
                    <div class="domain-detail-item">
                        <span class="domain-detail-label">Last Analysis</span>
                        <span class="domain-detail-value">${formatDate(rep.last_analysis)}</span>
                    </div>
                </div>
                ${rep.whois ? `
                    <div class="domain-whois">
                        <h5>WHOIS Information</h5>
                        <div class="domain-details-grid">
                            <div class="domain-detail-item">
                                <span class="domain-detail-label">Registrar</span>
                                <span class="domain-detail-value">${rep.whois.registrar}</span>
                            </div>
                            <div class="domain-detail-item">
                                <span class="domain-detail-label">Created</span>
                                <span class="domain-detail-value">${rep.whois.creation_date}</span>
                            </div>
                            <div class="domain-detail-item">
                                <span class="domain-detail-label">Country</span>
                                <span class="domain-detail-value">${rep.whois.country}</span>
                            </div>
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
        resultDiv.style.display = 'block';

    } catch (err) {
        Toast.show('Failed to check domain reputation: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Check Reputation
        `;
    }
}
