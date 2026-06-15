/* ============================================================
   CyberGuard AI - Reports Module
   PDF Report Generation & Download
   ============================================================ */

Router.register('reports', renderReports);

async function renderReports() {
    const content = document.getElementById('page-content');
    content.innerHTML = `
        <div class="page-header">
            <h1>Security Reports</h1>
            <p class="page-subtitle">Generate and download professional security assessment reports</p>
        </div>

        <!-- Generate Report Section -->
        <div class="card" style="margin-bottom: 24px;">
            <h3 class="card-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2" style="margin-right: 8px; vertical-align: middle;">
                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                    <line x1="16" y1="13" x2="8" y2="13"/>
                    <line x1="16" y1="17" x2="8" y2="17"/>
                    <polyline points="10 9 9 9 8 9"/>
                </svg>
                Generate New Report
            </h3>
            <p class="text-secondary" style="margin-bottom: 16px;">Select a completed scan to generate a comprehensive PDF security assessment report.</p>
            <div class="report-generate-row">
                <select id="report-scan-select" class="form-select" style="flex: 1;">
                    <option value="">Loading scans...</option>
                </select>
                <button class="btn btn-primary" id="generate-report-btn" onclick="generateReport()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;">
                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                        <polyline points="14 2 14 8 20 8"/>
                        <line x1="12" y1="18" x2="12" y2="12"/>
                        <polyline points="9 15 12 12 15 15"/>
                    </svg>
                    Generate Report
                </button>
            </div>
        </div>

        <!-- Reports List -->
        <div class="card">
            <h3 class="card-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-green)" stroke-width="2" style="margin-right: 8px; vertical-align: middle;">
                    <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
                </svg>
                Generated Reports
            </h3>
            <div id="reports-list">
                <div class="loading-skeleton">
                    <div class="skeleton-row"></div>
                    <div class="skeleton-row"></div>
                    <div class="skeleton-row"></div>
                </div>
            </div>
        </div>
    `;

    loadReportsData();
}

async function loadReportsData() {
    try {
        const [scansData, reportsData] = await Promise.all([
            api('/api/scans'),
            api('/api/reports')
        ]);

        // Populate scan dropdown
        const scanSelect = document.getElementById('report-scan-select');
        const scans = scansData.scans || [];
        if (scans.length === 0) {
            scanSelect.innerHTML = '<option value="">No completed scans available</option>';
        } else {
            scanSelect.innerHTML = '<option value="">Select a scan...</option>' +
                scans.map(s => `<option value="${s.id}">${s.target_url} — Score: ${s.risk_score || 'N/A'} — ${formatDate(s.created_at)}</option>`).join('');
        }

        // Render reports list
        const reports = reportsData.reports || [];
        renderReportsList(reports);

    } catch (err) {
        Toast.show('Failed to load reports data', 'error');
        console.error(err);
    }
}

function renderReportsList(reports) {
    const container = document.getElementById('reports-list');
    if (!container) return;

    if (reports.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5">
                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                </svg>
                <p>No reports generated yet</p>
                <p class="text-muted">Select a scan above and click "Generate Report" to create your first report.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = `
        <div class="reports-grid">
            ${reports.map(report => `
                <div class="report-card">
                    <div class="report-card-icon">
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--accent-red)" stroke-width="1.5">
                            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                            <polyline points="14 2 14 8 20 8"/>
                            <line x1="16" y1="13" x2="8" y2="13"/>
                            <line x1="16" y1="17" x2="8" y2="17"/>
                        </svg>
                    </div>
                    <div class="report-card-info">
                        <div class="report-card-name">${report.filename}</div>
                        <div class="report-card-meta">
                            <span class="text-muted">Target:</span> ${report.target_url || 'N/A'}
                        </div>
                        <div class="report-card-meta">
                            <span class="text-muted">Generated:</span> ${formatDateTime(report.created_at)}
                        </div>
                    </div>
                    <div class="report-card-actions">
                        <button class="btn btn-primary btn-sm" onclick="downloadReport(${report.id}, '${report.filename}')">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px;">
                                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                                <polyline points="7 10 12 15 17 10"/>
                                <line x1="12" y1="15" x2="12" y2="3"/>
                            </svg>
                            Download
                        </button>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}

async function generateReport() {
    const scanSelect = document.getElementById('report-scan-select');
    const scanId = scanSelect.value;
    const btn = document.getElementById('generate-report-btn');

    if (!scanId) {
        Toast.show('Please select a scan first', 'warning');
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="btn-loader"></span> Generating...';

    try {
        const data = await api(`/api/reports/generate/${scanId}`, { method: 'POST' });
        Toast.show('Report generated successfully! Starting download...', 'success');
        loadReportsData(); // Refresh the list
        
        // Trigger automatic download
        if (data.report && data.report.id) {
            downloadReport(data.report.id, data.report.filename);
        }
    } catch (err) {
        Toast.show('Failed to generate report: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;">
                <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
                <line x1="12" y1="18" x2="12" y2="12"/>
                <polyline points="9 15 12 12 15 15"/>
            </svg>
            Generate Report
        `;
    }
}

async function downloadReport(reportId, filename) {
    try {
        const blob = await api(`/api/reports/${reportId}/download`, { cache: 'no-store' });
        if (!(blob instanceof Blob)) {
            throw new Error('Response is not a file');
        }
        
        // Enforce application/pdf content type on the Blob
        const pdfBlob = new Blob([blob], { type: 'application/pdf' });
        const url = URL.createObjectURL(pdfBlob);
        
        const a = document.createElement('a');
        a.href = url;
        
        // Enforce .pdf suffix
        let finalFilename = filename || 'CyberGuard_Report.pdf';
        if (!finalFilename.toLowerCase().endsWith('.pdf')) {
            finalFilename += '.pdf';
        }
        
        a.download = finalFilename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        Toast.show('Report downloaded as PDF!', 'success');
    } catch (err) {
        Toast.show('Failed to download report: ' + err.message, 'error');
    }
}
