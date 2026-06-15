// ============================================================
// CyberGuard AI - Research Metrics Dashboard Module
// ============================================================

Router.register('research', renderResearch);

let epssChartInstance = null;
let mttrChartInstance = null;
let threatChartInstance = null;

function renderResearch() {
    const content = document.getElementById('page-content');
    content.innerHTML = `
        <div class="page-header">
            <div>
                <h1>Research Metrics Dashboard</h1>
                <p class="text-muted">Analysis of Exploit Prediction Scoring System (EPSS) correlations and vulnerability remediation parameters.</p>
            </div>
        </div>

        <div class="row mb-4">
            <!-- EPSS Explainer Card -->
            <div class="col-md-12">
                <div class="card bg-dark border-cyan-80">
                    <div class="card-body">
                        <h5 class="text-cyan mb-2">🛡️ Exploit Prediction Scoring System (EPSS)</h5>
                        <p class="small text-muted mb-0">
                            EPSS is an open, data-driven framework for estimating the probability that a software vulnerability (CVE) will be exploited in the wild within 30 days. 
                            Combining CVSS severity with EPSS exploitation probability enables threat research teams to focus patching efforts on vulnerabilities that represent active threats, reducing remediation overhead by up to 80%.
                        </p>
                    </div>
                </div>
            </div>
        </div>

        <div class="row g-4 mb-4">
            <!-- Scatter Plot: EPSS vs CVSS -->
            <div class="col-lg-7">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">EPSS vs CVSS Correlation Analysis</h5>
                    </div>
                    <div class="card-body">
                        <div style="height: 300px; position: relative;">
                            <canvas id="epss-scatter-chart"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <!-- MTTR Chart -->
            <div class="col-lg-5">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Mean Time to Remediation (MTTR)</h5>
                    </div>
                    <div class="card-body">
                        <div style="height: 300px; position: relative;">
                            <canvas id="mttr-bar-chart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row g-4">
            <!-- Threat Distribution Pie -->
            <div class="col-lg-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Global Threat Vector Index</h5>
                    </div>
                    <div class="card-body d-flex justify-content-center">
                        <div style="height: 250px; width: 250px; position: relative;">
                            <canvas id="threat-pie-chart"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <!-- High Risk CVE Table -->
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">High Exploit Probability Threat List (Local CVE Database)</h5>
                    </div>
                    <div class="table-responsive" style="max-height: 250px;">
                        <table class="table table-hover align-middle mb-0">
                            <thead>
                                <tr>
                                    <th>CVE ID</th>
                                    <th>Title</th>
                                    <th>CVSS</th>
                                    <th>EPSS Probability</th>
                                    <th>EPSS Percentile</th>
                                </tr>
                            </thead>
                            <tbody id="research-cve-table-body">
                                <tr>
                                    <td colspan="5" class="text-center py-4 text-muted">Loading CVEs...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    `;

    loadResearchMetrics();
}

async function loadResearchMetrics() {
    try {
        const data = await api('/api/dashboard/research-metrics');
        const metrics = data.metrics;

        // Populate High EPSS CVE Table
        const cveTbody = document.getElementById('research-cve-table-body');
        if (cveTbody) {
            // Sort by epss_score descending
            const sortedCVEs = metrics.cves
                .sort((a, b) => (b.epss_score || 0) - (a.epss_score || 0))
                .slice(0, 5);

            cveTbody.innerHTML = sortedCVEs.map(c => `
                <tr>
                    <td class="fw-semibold text-cyan">${c.cve_id}</td>
                    <td class="text-muted text-truncate" style="max-width: 280px;" title="${c.title}">${c.title}</td>
                    <td><span class="badge ${getSeverityClass(c.severity)}">${c.cvss_score}</span></td>
                    <td class="fw-semibold text-light">${formatPercent(c.epss_score)}</td>
                    <td class="text-muted">${formatPercent(c.epss_percentile)}</td>
                </tr>
            `).join('');
        }

        // 1. Render Scatter Plot (EPSS vs CVSS)
        renderScatterPlot(metrics.cves);

        // 2. Render MTTR Bar Chart
        renderMTTRChart(metrics.remediation_timeline);

        // 3. Render Threat Distribution Pie
        renderThreatChart(metrics.threat_distribution);

    } catch (err) {
        console.error("Failed to load research metrics:", err);
        Toast.show("Failed to load research metrics chart data", "error");
    }
}

function renderScatterPlot(cves) {
    const ctx = document.getElementById('epss-scatter-chart');
    if (!ctx) return;

    if (epssChartInstance) epssChartInstance.destroy();

    // Group CVEs into coordinates {x: cvss_score, y: epss_score}
    const scatterData = cves.map(c => ({
        x: c.cvss_score,
        y: c.epss_score,
        cve_id: c.cve_id
    }));

    epssChartInstance = new Chart(ctx, {
        type: 'scatter',
        data: {
            datasets: [{
                label: 'CVE Threat Points',
                data: scatterData,
                backgroundColor: 'rgba(6, 182, 212, 0.65)',
                borderColor: '#06b6d4',
                borderWidth: 1,
                pointRadius: 6,
                pointHoverRadius: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    title: { display: true, text: 'CVSS Score (Severity)', color: '#94a3b8' },
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8' },
                    min: 0,
                    max: 10
                },
                y: {
                    title: { display: true, text: 'EPSS Score (Exploit Probability)', color: '#94a3b8' },
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: {
                        color: '#94a3b8',
                        callback: function(value) { return (value * 100).toFixed(0) + '%'; }
                    },
                    min: 0,
                    max: 1.0
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const item = context.raw;
                            return `${item.cve_id} (CVSS: ${item.x}, EPSS: ${(item.y * 100).toFixed(2)}%)`;
                        }
                    }
                }
            }
        }
    });
}

function renderMTTRChart(timeline) {
    const ctx = document.getElementById('mttr-bar-chart');
    if (!ctx) return;

    if (mttrChartInstance) mttrChartInstance.destroy();

    mttrChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: timeline.labels,
            datasets: [{
                label: 'Mean Time to Repair (Days)',
                data: timeline.data,
                backgroundColor: [
                    'rgba(239, 68, 68, 0.7)',   // Critical
                    'rgba(249, 115, 22, 0.7)',  // High
                    'rgba(234, 179, 8, 0.7)',   // Medium
                    'rgba(16, 185, 129, 0.7)'   // Low
                ],
                borderColor: [
                    '#ef4444', '#f97316', '#eab308', '#10b981'
                ],
                borderWidth: 1.5,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8' }
                },
                y: {
                    title: { display: true, text: 'Remediation Speed (Days)', color: '#94a3b8' },
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8' }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function renderThreatChart(dist) {
    const ctx = document.getElementById('threat-pie-chart');
    if (!ctx) return;

    if (threatChartInstance) threatChartInstance.destroy();

    threatChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: dist.labels,
            datasets: [{
                data: dist.data,
                backgroundColor: [
                    '#ef4444', '#f97316', '#06b6d4', '#eab308', '#a855f7'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        font: { size: 10 },
                        padding: 10,
                        boxWidth: 12
                    }
                }
            }
        }
    });
}
