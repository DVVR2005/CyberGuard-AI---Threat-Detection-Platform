/* ============================================================
   CyberGuard AI - Scoring & Grading Guide Module
   ============================================================ */

Router.register('guide', renderGuide);

function renderGuide() {
    const content = document.getElementById('page-content');
    content.innerHTML = `
        <div class="page-header">
            <div>
                <h1>Scoring & Grading Guide</h1>
                <p class="text-muted">Understand how CyberGuard AI evaluates system risk, computes scores, and determines letter grades.</p>
            </div>
        </div>

        <div class="row g-4 mb-4">
            <!-- Formula Card -->
            <div class="col-lg-7">
                <div class="card card-3d">
                    <div class="card-header border-bottom border-light-10">
                        <h3 class="card-title">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2" style="margin-right: 8px; vertical-align: middle;">
                                <path d="M4 9h16M4 15h16M10 3L6 21M18 3l-4 18"/>
                            </svg>
                            The Risk Score Formula
                        </h3>
                    </div>
                    <div class="card-body">
                        <p class="text-muted mb-4">
                            CyberGuard AI evaluates security risk using a weighted penalty and credit system. The final Risk Score is calculated from a base of <strong>100</strong>, clamped strictly between <strong>0.0</strong> (Perfect Security) and <strong>100.0</strong> (Maximum Exposure).
                        </p>
                        
                        <div class="formula-block text-center p-3 mb-4 rounded border border-cyan-30 bg-dark-20">
                            <code style="font-size: 1.1rem; color: var(--accent-cyan); font-family: var(--font-mono); font-weight: bold; word-break: break-all;">
                                Risk = 100 - (SSL_Credit + Header_Credit) + Port_Penalties + Vuln_Penalties + Dir_Penalties + Service_Penalties
                            </code>
                        </div>

                        <div class="formula-details">
                            <h5 class="text-light mb-3">Credits (Subtracts Risk)</h5>
                            <ul class="list-unstyled mb-4">
                                <li class="d-flex justify-content-between mb-2">
                                    <span>🛡️ <strong>SSL/TLS Grade:</strong> Max <strong>-20</strong> points (A+:-20, A:-18, B:-14, C:-10, D:-6, F:-2)</span>
                                    <span class="text-green">-20 Max</span>
                                </li>
                                <li class="d-flex justify-content-between">
                                    <span>🔌 <strong>Security Headers:</strong> Percentage of passing security headers (Max <strong>-15</strong> points)</span>
                                    <span class="text-green">-15 Max</span>
                                </li>
                            </ul>

                            <h5 class="text-light mb-3">Penalties (Adds Risk)</h5>
                            <ul class="list-unstyled">
                                <li class="d-flex justify-content-between mb-2">
                                    <span>🌐 <strong>Open Ports attack surface:</strong> +1.5 points per open port</span>
                                    <span class="text-red">+1.5 / port</span>
                                </li>
                                <li class="d-flex justify-content-between mb-2">
                                    <span>⚠️ <strong>Vulnerability Exposure:</strong> +3.0 points per vulnerability found</span>
                                    <span class="text-red">+3.0 / vuln</span>
                                </li>
                                <li class="d-flex justify-content-between mb-2">
                                    <span>🚨 <strong>Critical Severity Boost:</strong> Extra +8.0 points for each critical severity vulnerability</span>
                                    <span class="text-red">+8.0 / critical</span>
                                </li>
                                <li class="d-flex justify-content-between mb-2">
                                    <span>📂 <strong>Exposed Directories:</strong> +4.0 points per exposed directory path (high/medium risk)</span>
                                    <span class="text-red">+4.0 / directory</span>
                                </li>
                                <li class="d-flex justify-content-between">
                                    <span>🔥 <strong>High-Risk Service Penalty:</strong> Additional penalties for exposed dangerous endpoints:
                                        <ul class="mt-1 small text-muted" style="padding-left: 20px;">
                                            <li>Exposed Databases (3306, 5432, 27017): <strong>+5.0</strong> points</li>
                                            <li>Exposed FTP (21): <strong>+3.0</strong> points</li>
                                            <li>Exposed Redis (6379): <strong>+4.0</strong> points</li>
                                        </ul>
                                    </span>
                                    <span class="text-red">Variable</span>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Grade Scaling Card -->
            <div class="col-lg-5">
                <div class="card card-3d h-100">
                    <div class="card-header border-bottom border-light-10">
                        <h3 class="card-title">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-amber)" stroke-width="2" style="margin-right: 8px; vertical-align: middle;">
                                <circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/>
                            </svg>
                            Grade Threshold Matrix
                        </h3>
                    </div>
                    <div class="card-body">
                        <p class="text-muted mb-4">
                            Scores are mapped to industry-standard letter grades and severity levels. Use this table as a benchmark for compliance.
                        </p>
                        
                        <div class="table-responsive">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Risk Score</th>
                                        <th class="text-center">Grade</th>
                                        <th class="text-center">Severity</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td>0.0 - 10.0</td>
                                        <td class="text-center"><span class="badge badge-safe fw-bold" style="font-size:0.95rem; width:45px; display:inline-block;">A+</span></td>
                                        <td class="text-center text-green">Low</td>
                                    </tr>
                                    <tr>
                                        <td>10.1 - 20.0</td>
                                        <td class="text-center"><span class="badge badge-safe" style="font-size:0.9rem; width:45px; display:inline-block;">A</span></td>
                                        <td class="text-center text-green">Low</td>
                                    </tr>
                                    <tr>
                                        <td>20.1 - 40.0</td>
                                        <td class="text-center"><span class="badge badge-info" style="font-size:0.9rem; width:45px; display:inline-block;">B</span></td>
                                        <td class="text-center text-cyan">Medium</td>
                                    </tr>
                                    <tr>
                                        <td>40.1 - 60.0</td>
                                        <td class="text-center"><span class="badge badge-warning" style="font-size:0.9rem; width:45px; display:inline-block;">C</span></td>
                                        <td class="text-center text-cyan">Medium / High</td>
                                    </tr>
                                    <tr>
                                        <td>60.1 - 80.0</td>
                                        <td class="text-center"><span class="badge badge-danger" style="font-size:0.9rem; width:45px; display:inline-block;">D</span></td>
                                        <td class="text-center text-red">High / Critical</td>
                                    </tr>
                                    <tr>
                                        <td>80.1 - 100.0</td>
                                        <td class="text-center"><span class="badge badge-danger fw-bold" style="font-size:0.95rem; width:45px; display:inline-block;">F</span></td>
                                        <td class="text-center text-red">Critical</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Remediation Card -->
        <div class="card card-3d mb-4">
            <div class="card-header border-bottom border-light-10">
                <h3 class="card-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-green)" stroke-width="2" style="margin-right: 8px; vertical-align: middle;">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <path d="M9 11l2 2 4-4"/>
                    </svg>
                    Hardening Roadmap (How to Raise Your Grade)
                </h3>
            </div>
            <div class="card-body">
                <p class="text-muted mb-4">
                    Improve your grade and lower your security risk exposure score by applying these server hardening steps:
                </p>
                <div class="row g-4">
                    <div class="col-md-4">
                        <div class="hardening-step-card p-3 rounded bg-dark-20 border border-light-10">
                            <h5 class="text-cyan mb-2">1. Fortify HTTP Headers</h5>
                            <p class="small text-muted mb-0">Configure missing security headers like Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, and X-Content-Type-Options. This reduces risk by up to 15 points.</p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="hardening-step-card p-3 rounded bg-dark-20 border border-light-10">
                            <h5 class="text-amber mb-2">2. Secure SSL/TLS Config</h5>
                            <p class="small text-muted mb-0">Disable deprecated TLS 1.0/1.1 protocols and weak cipher suites. Enforce TLS 1.3 with a valid certificate to get an A+ rating and claim 20 score credits.</p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="hardening-step-card p-3 rounded bg-dark-20 border border-light-10">
                            <h5 class="text-red mb-2">3. Restrict Exposed Services</h5>
                            <p class="small text-muted mb-0">Close unnecessary open ports and configure firewall rules (e.g. iptables) to block public access to backend datastores (MySQL, PostgreSQL, MongoDB, Redis) and file transfer interfaces (FTP).</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}
