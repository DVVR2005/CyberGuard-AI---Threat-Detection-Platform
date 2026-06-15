// ============================================================
// CyberGuard AI - Scanner Module
// ============================================================

Router.register('scanner', renderScanner);

let currentScanId = null;

function renderScanner() {
    const content = document.getElementById('page-content');
    content.innerHTML = `
        <div class="page-header">
            <h1>Security Scanner</h1>
            <p class="page-subtitle">Analyze websites for vulnerabilities and security threats</p>
        </div>

        <!-- Scanner Input -->
        <div class="card" style="margin-bottom:24px;">
            <div class="scanner-input-section">
                <input type="url" id="scan-url-input" placeholder="Enter URL to scan (e.g., https://example.com)" required>
                <button class="btn btn-primary" id="scan-btn" onclick="initiateScan()">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="11" cy="11" r="8"/>
                        <path d="M21 21l-4.35-4.35"/>
                    </svg>
                    <span>Start Scan</span>
                </button>
            </div>
        </div>

        <!-- Progress Section (hidden initially) -->
        <div id="scan-progress-section" style="display:none;">
            <div class="card" style="margin-bottom:24px;">
                <div class="progress-section">
                    <div class="progress-container">
                        <div class="progress-bar" id="scan-progress-bar"></div>
                    </div>
                    <div class="progress-info">
                        <span id="scan-phase">Initializing...</span>
                        <span id="scan-percent">0%</span>
                    </div>
                </div>
            </div>
            <div class="scan-log" id="scan-log">
                <div class="scan-cursor" id="scan-cursor"></div>
            </div>
        </div>

        <!-- Results Section (hidden initially) -->
        <div id="scan-results-section" style="display:none;"></div>

        <!-- Scan History -->
        <div class="card" id="scan-history-card">
            <h3 class="card-title">Scan History</h3>
            <div id="scan-history"><div class="spinner"></div></div>
        </div>
    `;

    loadScanHistory();
}

// ============================================================
// Load Scan History
// ============================================================
async function loadScanHistory() {
    try {
        const data = await api('/api/scans');
        const container = document.getElementById('scan-history');
        if (!container) return;

        const scans = data.scans || data;
        if (!scans || scans.length === 0) {
            container.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:20px;">No scans yet. Start your first scan above!</p>';
            return;
        }

        container.innerHTML = `
            <div class="table-wrapper">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Target URL</th>
                            <th>Risk Score</th>
                            <th>Grade</th>
                            <th>Vulnerabilities</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${scans.map(scan => `
                            <tr>
                                <td style="color:var(--text-primary);font-weight:500;">${escapeHtml(scan.target_url || scan.url)}</td>
                                <td><span class="${getSeverityClass(getRiskSeverity(scan.risk_score))}">${scan.risk_score != null ? parseFloat(scan.risk_score).toFixed(1) : 'N/A'}</span></td>
                                <td><span class="grade-badge ${getGradeClass(scan.grade)}">${scan.grade || 'N/A'}</span></td>
                                <td>${scan.vulnerabilities_found ?? scan.vulnerability_count ?? (Array.isArray(scan.vulnerabilities) ? scan.vulnerabilities.length : scan.vulnerabilities) ?? 0}</td>
                                <td>${formatDate(scan.created_at || scan.date)}</td>
                                <td>
                                    <button class="btn btn-ghost btn-sm" onclick="viewScanResults(${scan.id})">
                                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                        View
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } catch (err) {
        const container = document.getElementById('scan-history');
        if (container) container.innerHTML = '<p style="color:var(--accent-red);text-align:center;padding:20px;">Failed to load scan history</p>';
    }
}

// ============================================================
// Initiate Scan with Animated Progress
// ============================================================
async function initiateScan() {
    const urlInput = document.getElementById('scan-url-input');
    const url = urlInput.value.trim();

    if (!url) {
        Toast.show('Please enter a URL to scan', 'warning');
        return;
    }

    // Basic URL validation
    try { new URL(url); } catch {
        Toast.show('Please enter a valid URL (e.g., https://example.com)', 'error');
        return;
    }

    // Disable input and button
    const btn = document.getElementById('scan-btn');
    urlInput.disabled = true;
    btn.disabled = true;

    // Show progress section
    document.getElementById('scan-progress-section').style.display = 'block';
    document.getElementById('scan-results-section').style.display = 'none';

    // Clear previous log
    const logContainer = document.getElementById('scan-log');
    logContainer.innerHTML = '<div class="scan-cursor" id="scan-cursor"></div>';

    // Start API call in parallel
    const apiPromise = api('/api/scans', {
        method: 'POST',
        body: { url: url }
    });

    // Run progress animation
    const phases = [
        { percent: 15, phase: 'Initializing scan engine...', logs: [
            `Target: ${url}`,
            'Loading vulnerability database...',
            'Scan engine initialized successfully'
        ], delay: 1000 },
        { percent: 30, phase: 'Performing port scan...', logs: [
            '\u25b8 Port scanning in progress...',
            '\u25b8 Scanning common ports (1-1024)...',
            '\u25b8 Scanning extended ports...'
        ], delay: 1500 },
        { percent: 50, phase: 'Analyzing SSL certificate...', logs: [
            '\u25b8 SSL/TLS handshake initiated...',
            '\u25b8 Certificate chain validation...',
            '\u25b8 Cipher suite analysis...'
        ], delay: 1000 },
        { percent: 65, phase: 'Checking security headers...', logs: [
            '\u25b8 HTTP security headers analysis...',
            '\u25b8 CORS policy check...',
            '\u25b8 Content Security Policy validation...'
        ], delay: 1000 },
        { percent: 80, phase: 'Discovering directories...', logs: [
            '\u25b8 Directory enumeration started...',
            '\u25b8 Checking common paths...',
            '\u25b8 Analyzing response codes...'
        ], delay: 1500 },
        { percent: 90, phase: 'Classifying OWASP vulnerabilities...', logs: [
            '\u25b8 OWASP Top 10 classification...',
            '\u25b8 CWE mapping in progress...',
            '\u25b8 CVSS scoring...'
        ], delay: 1000 },
        { percent: 95, phase: 'Calculating AI risk score...', logs: [
            '\u25b8 Machine learning model analysis...',
            '\u25b8 Threat pattern recognition...',
            '\u25b8 Risk aggregation...'
        ], delay: 500 },
        { percent: 98, phase: 'Generating threat intelligence...', logs: [
            '\u25b8 Compiling scan results...',
            '\u25b8 Generating recommendations...'
        ], delay: 500 }
    ];

    const progressBar = document.getElementById('scan-progress-bar');
    const phaseEl = document.getElementById('scan-phase');
    const percentEl = document.getElementById('scan-percent');

    // Add initial log
    addScanLog('CyberGuard AI scan engine v2.0 starting...');

    for (const phase of phases) {
        await sleep(300);
        progressBar.style.width = phase.percent + '%';
        phaseEl.textContent = phase.phase;
        percentEl.textContent = phase.percent + '%';

        addScanLog(phase.phase);

        for (const log of phase.logs) {
            await sleep(phase.delay / phase.logs.length);
            addScanLog(log);
        }
    }

    // Wait for API response
    try {
        const result = await apiPromise;

        // Complete progress
        progressBar.style.width = '100%';
        phaseEl.textContent = 'Scan complete!';
        percentEl.textContent = '100%';
        addScanLog('\u2713 Scan completed successfully!');
        addScanLog(`Risk Score: ${result.scan?.risk_score || 'N/A'} | Grade: ${result.scan?.grade || 'N/A'}`);

        await sleep(500);

        // Show results
        if (result.scan) {
            renderScanResults(result.scan);
        }

        // Reload scan history
        loadScanHistory();

        Toast.show('Scan completed successfully!', 'success');
    } catch (err) {
        progressBar.style.width = '100%';
        progressBar.style.background = 'var(--accent-red)';
        phaseEl.textContent = 'Scan failed';
        addScanLog(`\u2715 Error: ${err.message}`);
        Toast.show(`Scan failed: ${err.message}`, 'error');
    } finally {
        urlInput.disabled = false;
        btn.disabled = false;
    }
}

// ============================================================
// Scan Log Helper
// ============================================================
function addScanLog(message) {
    const logContainer = document.getElementById('scan-log');
    if (!logContainer) return;
    const cursor = document.getElementById('scan-cursor');
    const line = document.createElement('div');
    line.className = 'scan-log-line';
    const now = new Date();
    const time = now.toTimeString().slice(0, 8);
    line.innerHTML = `<span class="timestamp">[${time}]</span> ${escapeHtml(message)}`;
    logContainer.insertBefore(line, cursor);
    logContainer.scrollTop = logContainer.scrollHeight;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================
// View Scan Results (from history)
// ============================================================
async function viewScanResults(scanId) {
    try {
        Toast.show('Loading scan results...', 'info', 2000);
        const data = await api(`/api/scans/${scanId}`);
        if (data.scan) {
            document.getElementById('scan-progress-section').style.display = 'none';
            renderScanResults(data.scan);
            // Scroll to results
            document.getElementById('scan-results-section')?.scrollIntoView({ behavior: 'smooth' });
        }
    } catch (err) {
        Toast.show('Failed to load scan results', 'error');
    }
}

// ============================================================
// Render Scan Results (Tabbed Interface)
// ============================================================
function renderScanResults(scan) {
    const section = document.getElementById('scan-results-section');
    if (!section) return;
    section.style.display = 'block';

    const results = scan.results || scan;
    const ports = results.ports || results.port_scan || [];
    const ssl = results.ssl || results.ssl_analysis || {};
    const headers = results.headers || results.security_headers || [];
    const dirs = results.directories || results.directory_scan || [];
    const owaspFindings = results.owasp || results.owasp_findings || results.vulnerabilities || [];
    const riskData = {
        score: scan.risk_score,
        grade: scan.grade,
        severity: scan.severity_level || getRiskSeverityText(scan.risk_score),
        explanation: results.ai_explanation || scan.ai_explanation || '',
        factors: results.contributing_factors || results.risk_factors || []
    };

    section.innerHTML = `
        <div class="card" style="margin-bottom:24px;">
            <h3 class="card-title" style="margin-bottom:0;">Scan Results: ${escapeHtml(scan.target_url || scan.url || '')}</h3>
            <p style="color:var(--text-muted);font-size:13px;margin-bottom:20px;">Completed ${formatDateTime(scan.created_at || scan.date)}</p>

            <div class="scan-tabs">
                <button class="scan-tab active" onclick="switchScanTab(event, 'tab-ports')">Ports</button>
                <button class="scan-tab" onclick="switchScanTab(event, 'tab-ssl')">SSL/TLS</button>
                <button class="scan-tab" onclick="switchScanTab(event, 'tab-headers')">Headers</button>
                <button class="scan-tab" onclick="switchScanTab(event, 'tab-dirs')">Directories</button>
                <button class="scan-tab" onclick="switchScanTab(event, 'tab-owasp')">OWASP Findings</button>
                <button class="scan-tab" onclick="switchScanTab(event, 'tab-risk')">Risk Score</button>
            </div>

            <!-- Ports Tab -->
            <div class="scan-tab-content active" id="tab-ports">
                ${renderPortsTab(ports)}
            </div>

            <!-- SSL Tab -->
            <div class="scan-tab-content" id="tab-ssl">
                ${renderSSLTab(ssl)}
            </div>

            <!-- Headers Tab -->
            <div class="scan-tab-content" id="tab-headers">
                ${renderHeadersTab(headers)}
            </div>

            <!-- Directories Tab -->
            <div class="scan-tab-content" id="tab-dirs">
                ${renderDirectoriesTab(dirs)}
            </div>

            <!-- OWASP Tab -->
            <div class="scan-tab-content" id="tab-owasp">
                ${renderOWASPTab(owaspFindings)}
            </div>

            <!-- Risk Score Tab -->
            <div class="scan-tab-content" id="tab-risk">
                ${renderRiskScoreTab(riskData)}
            </div>
        </div>
    `;

    // Animate risk gauge if visible
    setTimeout(() => animateRiskGauge(riskData.score), 300);
}

// ============================================================
// Tab Switching
// ============================================================
function switchScanTab(event, tabId) {
    // Update tab buttons
    document.querySelectorAll('.scan-tab').forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');

    // Update tab content
    document.querySelectorAll('.scan-tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById(tabId)?.classList.add('active');

    // Animate risk gauge when switching to risk tab
    if (tabId === 'tab-risk') {
        const scoreEl = document.getElementById('risk-gauge-fill');
        if (scoreEl) {
            const score = parseInt(scoreEl.dataset.score || 0);
            animateRiskGauge(score);
        }
    }
}

// ============================================================
// Ports Tab
// ============================================================
function renderPortsTab(ports) {
    if (!ports || ports.length === 0) {
        return '<p style="color:var(--text-muted);text-align:center;padding:20px;">No port scan data available</p>';
    }
    return `
        <div class="table-wrapper">
            <table class="data-table">
                <thead>
                    <tr><th>Port</th><th>Service</th><th>Version</th><th>State</th></tr>
                </thead>
                <tbody>
                    ${ports.map(p => `
                        <tr>
                            <td style="font-family:'JetBrains Mono',monospace;color:var(--accent-cyan);">${p.port}</td>
                            <td>${escapeHtml(p.service || 'Unknown')}</td>
                            <td style="color:var(--text-muted);">${escapeHtml(p.version || 'N/A')}</td>
                            <td><span class="badge-${p.state === 'open' ? 'low' : 'medium'}">${p.state || 'unknown'}</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// ============================================================
// SSL Tab
// ============================================================
function renderSSLTab(ssl) {
    if (!ssl || Object.keys(ssl).length === 0) {
        return '<p style="color:var(--text-muted);text-align:center;padding:20px;">No SSL data available</p>';
    }
    const gradeClass = getGradeClass(ssl.grade);
    return `
        <div style="display:flex;flex-wrap:wrap;gap:24px;">
            <div style="flex:0 0 auto;text-align:center;padding:24px;">
                <div class="grade-badge ${gradeClass}" style="font-size:3rem;padding:20px 32px;">${ssl.grade || 'N/A'}</div>
                <p style="color:var(--text-muted);margin-top:12px;">SSL Grade</p>
            </div>
            <div style="flex:1;min-width:300px;">
                <div class="table-wrapper">
                    <table class="data-table">
                        <tbody>
                            <tr><td style="color:var(--text-muted);width:160px;">Valid</td><td><span class="badge-${ssl.valid ? 'low' : 'critical'}">${ssl.valid ? 'Yes' : 'No'}</span></td></tr>
                            <tr><td style="color:var(--text-muted);">Issuer</td><td>${escapeHtml(ssl.issuer || 'N/A')}</td></tr>
                            <tr><td style="color:var(--text-muted);">Expires</td><td>${ssl.expiry || ssl.expires || 'N/A'}</td></tr>
                            <tr><td style="color:var(--text-muted);">Protocol</td><td>${escapeHtml(ssl.protocol || 'N/A')}</td></tr>
                            <tr><td style="color:var(--text-muted);">Cipher</td><td style="font-family:'JetBrains Mono',monospace;font-size:13px;">${escapeHtml(ssl.cipher || 'N/A')}</td></tr>
                            <tr><td style="color:var(--text-muted);">Key Size</td><td>${ssl.key_size || 'N/A'} bits</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

// ============================================================
// Headers Tab
// ============================================================
function renderHeadersTab(headers) {
    if (!headers || headers.length === 0) {
        return '<p style="color:var(--text-muted);text-align:center;padding:20px;">No security headers data available</p>';
    }
    const statusIcons = {
        pass: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>',
        fail: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
        warning: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="3"><path d="M12 9v4"/><path d="M12 17h.01"/></svg>'
    };
    return `
        <div class="table-wrapper">
            <table class="data-table">
                <thead>
                    <tr><th>Header</th><th>Status</th><th>Value</th><th>Recommendation</th></tr>
                </thead>
                <tbody>
                    ${headers.map(h => {
                        let status = 'warning';
                        if (h.status) {
                            status = h.status.toLowerCase();
                        } else if (h.present === true) {
                            status = 'pass';
                        } else if (h.present === false) {
                            status = 'fail';
                        }
                        return `
                        <tr>
                            <td style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--text-primary);">${escapeHtml(h.header || h.name)}</td>
                            <td>${statusIcons[status] || statusIcons.warning}</td>
                            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;font-size:13px;">${escapeHtml(h.value || 'Not set')}</td>
                            <td style="font-size:13px;color:var(--text-muted);">${escapeHtml(h.recommendation || h.description || '')}</td>
                        </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// ============================================================
// Directories Tab
// ============================================================
function renderDirectoriesTab(dirs) {
    if (!dirs || dirs.length === 0) {
        return '<p style="color:var(--text-muted);text-align:center;padding:20px;">No directory scan data available</p>';
    }
    return `
        <div class="table-wrapper">
            <table class="data-table">
                <thead>
                    <tr><th>Path</th><th>Status Code</th><th>Risk Level</th></tr>
                </thead>
                <tbody>
                    ${dirs.map(d => {
                        const risk = (d.risk || d.risk_level || 'none').toLowerCase();
                        const riskClass = risk === 'high' ? 'badge-critical' : risk === 'medium' ? 'badge-medium' : risk === 'low' ? 'badge-low' : 'badge-info';
                        return `
                        <tr>
                            <td style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--accent-cyan);">${escapeHtml(d.path)}</td>
                            <td><span class="badge-info">${d.status_code || d.status || 'N/A'}</span></td>
                            <td><span class="${riskClass}">${risk}</span></td>
                        </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// ============================================================
// OWASP Findings Tab
// ============================================================
function renderOWASPTab(findings) {
    if (!findings || findings.length === 0) {
        return '<p style="color:var(--text-muted);text-align:center;padding:20px;">No OWASP findings detected</p>';
    }
    return findings.map((f, i) => `
        <div class="vuln-card">
            <div class="vuln-header">
                <span class="badge-info" style="font-family:'JetBrains Mono',monospace;">${escapeHtml(f.category || f.owasp_category || 'N/A')}</span>
                <span class="${getSeverityClass(f.severity)}">${escapeHtml(f.severity || 'Unknown')}</span>
            </div>
            <div class="vuln-title">${escapeHtml(f.title || f.name || 'Untitled Finding')}</div>
            <div class="vuln-meta">
                ${f.cwe_id ? `<span>CWE: ${escapeHtml(f.cwe_id)}</span>` : ''}
                ${f.cvss_score !== undefined ? `<span>CVSS: ${f.cvss_score}</span>` : ''}
                ${f.endpoint || f.affected_endpoint ? `<span>Endpoint: ${escapeHtml(f.endpoint || f.affected_endpoint)}</span>` : ''}
            </div>
            <div class="vuln-description">${escapeHtml(f.description || '')}</div>
            ${f.remediation ? `
                <button class="vuln-toggle" onclick="toggleVulnDetails(${i})">Show Remediation \u25be</button>
                <div class="vuln-details" id="vuln-detail-${i}">
                    <p style="font-size:13px;color:var(--text-secondary);line-height:1.7;">${escapeHtml(f.remediation)}</p>
                </div>
            ` : ''}
        </div>
    `).join('');
}

function toggleVulnDetails(index) {
    const details = document.getElementById(`vuln-detail-${index}`);
    if (details) {
        details.classList.toggle('open');
        const btn = details.previousElementSibling;
        if (btn) {
            btn.textContent = details.classList.contains('open') ? 'Hide Remediation \u25b4' : 'Show Remediation \u25be';
        }
    }
}

// ============================================================
// Risk Score Tab with SVG Gauge
// ============================================================
function renderRiskScoreTab(riskData) {
    const score = riskData.score ?? 0;
    const color = getScoreColor(score);
    const circumference = 2 * Math.PI * 90; // radius = 90

    return `
        <div class="risk-gauge-container">
            <div class="risk-gauge">
                <svg viewBox="0 0 200 200" width="200" height="200">
                    <circle class="risk-gauge-bg" cx="100" cy="100" r="90"/>
                    <circle class="risk-gauge-fill" id="risk-gauge-fill"
                        cx="100" cy="100" r="90"
                        stroke="${color}"
                        stroke-dasharray="${circumference}"
                        stroke-dashoffset="${circumference}"
                        data-score="${score}"/>
                </svg>
                <div class="risk-gauge-text">
                    <span class="risk-score-number" style="color:${color};" id="risk-score-display">0</span>
                    <span class="risk-score-label">${riskData.severity || 'Risk Score'}</span>
                </div>
            </div>
            <div class="grade-badge ${getGradeClass(riskData.grade)}" style="margin-top:20px;">
                Grade: ${riskData.grade || 'N/A'}
            </div>

            ${riskData.factors && riskData.factors.length > 0 ? `
                <div class="factor-bar-container" style="width:100%;max-width:500px;margin-top:32px;">
                    <h4 style="color:var(--text-secondary);margin-bottom:16px;">Contributing Factors</h4>
                    ${riskData.factors.map(f => {
                        const impact = f.impact || f.score || f.value || 0;
                        const barColor = impact >= 70 ? 'var(--accent-red)' : impact >= 40 ? 'var(--accent-amber)' : 'var(--accent-green)';
                        return `
                        <div class="factor-item">
                            <span class="factor-label">${escapeHtml(f.name || f.factor || f.label)}</span>
                            <div class="factor-bar">
                                <div class="factor-bar-fill" style="width:${impact}%;background:${barColor};"></div>
                            </div>
                            <span class="factor-impact">${impact}%</span>
                        </div>
                        `;
                    }).join('')}
                </div>
            ` : ''}

            ${riskData.explanation ? `
                <div class="ai-explanation" style="width:100%;max-width:600px;margin-top:24px;">
                    <div class="ai-icon">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 2a4 4 0 0 1 4 4v2a4 4 0 0 1-8 0V6a4 4 0 0 1 4-4z"/>
                            <path d="M16 14v2a4 4 0 0 1-8 0v-2"/>
                            <line x1="12" y1="18" x2="12" y2="22"/>
                            <line x1="8" y1="22" x2="16" y2="22"/>
                        </svg>
                        AI Analysis
                    </div>
                    <p>${escapeHtml(riskData.explanation)}</p>
                </div>
            ` : ''}
        </div>
    `;
}

// ============================================================
// Animate Risk Gauge
// ============================================================
function animateRiskGauge(score) {
    const fillEl = document.getElementById('risk-gauge-fill');
    const scoreDisplay = document.getElementById('risk-score-display');
    if (!fillEl || !scoreDisplay) return;

    const circumference = 2 * Math.PI * 90;
    const offset = circumference - (score / 100) * circumference;

    // Animate the circle
    setTimeout(() => {
        fillEl.style.strokeDashoffset = offset;
    }, 100);

    // Animate the number
    let current = 0;
    const step = score / 40;
    const interval = setInterval(() => {
        current += step;
        if (current >= score) {
            current = score;
            clearInterval(interval);
        }
        scoreDisplay.textContent = Math.round(current);
    }, 30);
}

function getRiskSeverityText(score) {
    if (score === undefined || score === null) return 'Unknown';
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 40) return 'Medium';
    if (score >= 20) return 'Low';
    return 'Minimal';
}
