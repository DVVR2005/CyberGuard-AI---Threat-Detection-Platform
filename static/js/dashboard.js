// ============================================================
// CyberGuard AI - Dashboard Module
// ============================================================

Router.register('dashboard', renderDashboard);

// Store chart instances for cleanup
let dashboardCharts = [];

async function renderDashboard() {
    // Destroy previous chart instances
    dashboardCharts.forEach(c => c.destroy());
    dashboardCharts = [];

    const content = document.getElementById('page-content');
    content.innerHTML = `
        <div class="page-header">
            <h1>Dashboard</h1>
            <p class="page-subtitle">Security Operations Overview</p>
        </div>

        <!-- KPI Cards Row -->
        <div class="kpi-grid">
            <div class="kpi-card kpi-cyan">
                <div class="kpi-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="11" cy="11" r="8"/>
                        <path d="M21 21l-4.35-4.35"/>
                        <path d="M11 8v6"/>
                        <path d="M8 11h6"/>
                    </svg>
                </div>
                <div class="kpi-info">
                    <span class="kpi-label">Total Scans</span>
                    <span class="kpi-value" id="kpi-scans">--</span>
                </div>
            </div>
            <div class="kpi-card kpi-amber">
                <div class="kpi-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                        <path d="M12 9v4"/>
                        <path d="M12 17h.01"/>
                    </svg>
                </div>
                <div class="kpi-info">
                    <span class="kpi-label">Vulnerabilities</span>
                    <span class="kpi-value" id="kpi-vulns">--</span>
                </div>
            </div>
            <div class="kpi-card kpi-red">
                <div class="kpi-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                </div>
                <div class="kpi-info">
                    <span class="kpi-label">Critical Findings</span>
                    <span class="kpi-value" id="kpi-critical">--</span>
                </div>
            </div>
            <div class="kpi-card kpi-green">
                <div class="kpi-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                    </svg>
                </div>
                <div class="kpi-info">
                    <span class="kpi-label">Avg Risk Score</span>
                    <span class="kpi-value" id="kpi-risk">--</span>
                </div>
            </div>
        </div>

        <!-- Charts Grid -->
        <div class="charts-grid">
            <div class="chart-card">
                <h3 class="chart-title">Vulnerability Distribution</h3>
                <div style="position:relative;height:280px;"><canvas id="chart-vuln-dist"></canvas></div>
            </div>
            <div class="chart-card">
                <h3 class="chart-title">Severity Breakdown</h3>
                <div style="position:relative;height:280px;"><canvas id="chart-severity"></canvas></div>
            </div>
            <div class="chart-card">
                <h3 class="chart-title">Risk Score Trend</h3>
                <div style="position:relative;height:280px;"><canvas id="chart-risk-trend"></canvas></div>
            </div>
            <div class="chart-card">
                <h3 class="chart-title">Monthly Scans</h3>
                <div style="position:relative;height:280px;"><canvas id="chart-monthly"></canvas></div>
            </div>
        </div>

        <!-- Recent Activity -->
        <div class="card">
            <h3 class="card-title">Recent Scan Activity</h3>
            <div id="recent-activity"><div class="spinner"></div></div>
        </div>
    `;

    // Fetch data and render
    try {
        const [statsData, chartsData, recentData] = await Promise.all([
            api('/api/dashboard/stats'),
            api('/api/dashboard/charts'),
            api('/api/dashboard/recent')
        ]);

        // Animate KPI numbers
        animateCounter('kpi-scans', statsData.stats.total_scans);
        animateCounter('kpi-vulns', statsData.stats.total_vulnerabilities);
        animateCounter('kpi-critical', statsData.stats.critical_count);
        animateCounter('kpi-risk', statsData.stats.avg_risk_score, true);

        // Render charts
        renderVulnDistChart(chartsData.charts.vuln_distribution);
        renderSeverityChart(chartsData.charts.severity_breakdown);
        renderRiskTrendChart(chartsData.charts.risk_trend);
        renderMonthlyChart(chartsData.charts.monthly_scans);

        // Render recent activity
        renderRecentActivity(recentData.recent);
    } catch (err) {
        Toast.show('Failed to load dashboard data', 'error');
        console.error('Dashboard error:', err);
    }
}

// ============================================================
// Animated Counter
// ============================================================
function animateCounter(elementId, target, isDecimal = false) {
    const el = document.getElementById(elementId);
    if (!el || target === undefined || target === null) return;
    let current = 0;
    const duration = 1200;
    const steps = 40;
    const step = target / steps;
    const interval = setInterval(() => {
        current += step;
        if (current >= target) {
            current = target;
            clearInterval(interval);
        }
        el.textContent = isDecimal ? current.toFixed(1) : Math.round(current);
    }, duration / steps);
}

// ============================================================
// Chart.js Global Defaults (dark theme)
// ============================================================
const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: {
            labels: {
                color: '#94a3b8',
                font: { family: 'Inter', size: 12 },
                padding: 16,
                usePointStyle: true,
                pointStyleWidth: 10
            }
        },
        tooltip: {
            backgroundColor: '#1e293b',
            titleColor: '#f1f5f9',
            bodyColor: '#94a3b8',
            borderColor: 'rgba(6, 182, 212, 0.2)',
            borderWidth: 1,
            padding: 12,
            cornerRadius: 8,
            titleFont: { family: 'Inter', weight: '600' },
            bodyFont: { family: 'Inter' },
            displayColors: true,
            boxPadding: 4
        }
    },
    scales: {
        x: {
            ticks: { color: '#64748b', font: { family: 'Inter', size: 11 } },
            grid: { color: 'rgba(30, 41, 59, 0.5)', drawBorder: false }
        },
        y: {
            ticks: { color: '#64748b', font: { family: 'Inter', size: 11 } },
            grid: { color: 'rgba(30, 41, 59, 0.5)', drawBorder: false }
        }
    }
};

// ============================================================
// Vulnerability Distribution - Doughnut Chart
// ============================================================
function renderVulnDistChart(data) {
    const ctx = document.getElementById('chart-vuln-dist');
    if (!ctx || !data) return;
    const chart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(d => d.category || d.name || d.label),
            datasets: [{
                data: data.map(d => d.count || d.value),
                backgroundColor: [
                    'rgba(6, 182, 212, 0.8)',
                    'rgba(245, 158, 11, 0.8)',
                    'rgba(239, 68, 68, 0.8)',
                    'rgba(139, 92, 246, 0.8)',
                    'rgba(16, 185, 129, 0.8)',
                    'rgba(236, 72, 153, 0.8)',
                    'rgba(59, 130, 246, 0.8)'
                ],
                borderColor: '#0f172a',
                borderWidth: 3,
                hoverBorderWidth: 0,
                hoverOffset: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        font: { family: 'Inter', size: 12 },
                        padding: 16,
                        usePointStyle: true,
                        pointStyleWidth: 10
                    }
                },
                tooltip: chartDefaults.plugins.tooltip
            }
        }
    });
    dashboardCharts.push(chart);
}

// ============================================================
// Severity Breakdown - Horizontal Bar Chart
// ============================================================
function renderSeverityChart(data) {
    const ctx = document.getElementById('chart-severity');
    if (!ctx || !data) return;
    const severityColors = {
        'Critical': 'rgba(239, 68, 68, 0.8)',
        'High': 'rgba(245, 158, 11, 0.8)',
        'Medium': 'rgba(234, 179, 8, 0.8)',
        'Low': 'rgba(16, 185, 129, 0.8)',
        'Info': 'rgba(6, 182, 212, 0.8)'
    };
    const labels = data.map(d => d.severity || d.label || d.name);
    const values = data.map(d => d.count || d.value);
    const colors = labels.map(l => severityColors[l] || 'rgba(100, 116, 139, 0.8)');

    const chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderRadius: 6,
                borderSkipped: false,
                barThickness: 24
            }]
        },
        options: {
            ...chartDefaults,
            indexAxis: 'y',
            plugins: {
                ...chartDefaults.plugins,
                legend: { display: false }
            },
            scales: {
                x: {
                    ...chartDefaults.scales.x,
                    beginAtZero: true
                },
                y: {
                    ...chartDefaults.scales.y
                }
            }
        }
    });
    dashboardCharts.push(chart);
}

// ============================================================
// Risk Score Trend - Line Chart
// ============================================================
function renderRiskTrendChart(data) {
    const ctx = document.getElementById('chart-risk-trend');
    if (!ctx || !data) return;

    const chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(d => d.date || d.label),
            datasets: [{
                label: 'Risk Score',
                data: data.map(d => d.score || d.value),
                borderColor: '#06b6d4',
                backgroundColor: (context) => {
                    const chart = context.chart;
                    const {ctx: c, chartArea} = chart;
                    if (!chartArea) return 'transparent';
                    const gradient = c.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
                    gradient.addColorStop(0, 'rgba(6, 182, 212, 0.3)');
                    gradient.addColorStop(1, 'rgba(6, 182, 212, 0)');
                    return gradient;
                },
                fill: true,
                tension: 0.4,
                borderWidth: 2,
                pointBackgroundColor: '#06b6d4',
                pointBorderColor: '#0f172a',
                pointBorderWidth: 2,
                pointRadius: 4,
                pointHoverRadius: 6
            }]
        },
        options: {
            ...chartDefaults,
            plugins: {
                ...chartDefaults.plugins,
                legend: { display: false }
            },
            scales: {
                x: { ...chartDefaults.scales.x },
                y: {
                    ...chartDefaults.scales.y,
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });
    dashboardCharts.push(chart);
}

// ============================================================
// Monthly Scans - Bar Chart
// ============================================================
function renderMonthlyChart(data) {
    const ctx = document.getElementById('chart-monthly');
    if (!ctx || !data) return;

    const chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(d => d.month || d.label),
            datasets: [{
                label: 'Scans',
                data: data.map(d => d.count || d.value),
                backgroundColor: 'rgba(6, 182, 212, 0.6)',
                hoverBackgroundColor: 'rgba(6, 182, 212, 0.8)',
                borderRadius: 8,
                borderSkipped: false,
                barThickness: 32
            }]
        },
        options: {
            ...chartDefaults,
            plugins: {
                ...chartDefaults.plugins,
                legend: { display: false }
            },
            scales: {
                x: { ...chartDefaults.scales.x },
                y: {
                    ...chartDefaults.scales.y,
                    beginAtZero: true
                }
            }
        }
    });
    dashboardCharts.push(chart);
}

// ============================================================
// Recent Activity Table
// ============================================================
function renderRecentActivity(data) {
    const container = document.getElementById('recent-activity');
    if (!container) return;

    if (!data || data.length === 0) {
        container.innerHTML = '<p style="color:var(--text-muted);padding:20px;text-align:center;">No recent scan activity</p>';
        return;
    }

    container.innerHTML = `
        <div class="table-wrapper">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Target URL</th>
                        <th>Risk Score</th>
                        <th>Vulnerabilities</th>
                        <th>Grade</th>
                        <th>Date</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.map(scan => `
                        <tr style="cursor:pointer" onclick="Router.navigate('scanner')">
                            <td>
                                <div style="display:flex;align-items:center;gap:8px;">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                        <circle cx="12" cy="12" r="10"/>
                                        <line x1="2" y1="12" x2="22" y2="12"/>
                                        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                                    </svg>
                                    <span style="color:var(--text-primary);font-weight:500;">${escapeHtml(scan.target_url || scan.url)}</span>
                                </div>
                            </td>
                            <td>
                                <span class="${getSeverityClass(getRiskSeverity(scan.risk_score))}">
                                    ${scan.risk_score !== undefined ? scan.risk_score : 'N/A'}
                                </span>
                            </td>
                            <td>${scan.vulnerability_count || scan.vulnerabilities || 0}</td>
                            <td><span class="grade-badge ${getGradeClass(scan.grade)}">${scan.grade || 'N/A'}</span></td>
                            <td>${formatDate(scan.created_at || scan.date)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function getRiskSeverity(score) {
    if (score === undefined || score === null) return 'info';
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
}
