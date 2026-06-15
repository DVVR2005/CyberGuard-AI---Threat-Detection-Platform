// ============================================================
// CyberGuard AI - Mock API Layer for Firebase Hosting Demo
// Intercepts API calls when backend is unavailable
// ============================================================

const MOCK_MODE = true; // Enable mock responses

const MOCK_USERS = {
    'analyst@cyberguard.ai': { id: 1, name: 'Sarah Chen', email: 'analyst@cyberguard.ai', role: 'analyst', tenant_id: 1, tenant_name: 'CyberGuard Corp', status: 'active', password: 'Analyst@123' },
    'admin@cyberguard.ai': { id: 2, name: 'James Mitchell', email: 'admin@cyberguard.ai', role: 'admin', tenant_id: 1, tenant_name: 'CyberGuard Corp', status: 'active', password: 'Admin@123' },
    'user@cyberguard.ai': { id: 3, name: 'Alex Rivera', email: 'user@cyberguard.ai', role: 'user', tenant_id: 1, tenant_name: 'CyberGuard Corp', status: 'active', password: 'User@123' }
};

const MOCK_SCANS = [
    { id: 1, target_url: 'https://example-bank.com', scan_type: 'full', status: 'completed', risk_score: 72.5, grade: 'C', vulnerabilities_found: 18, critical_count: 3, high_count: 5, medium_count: 6, low_count: 4, created_at: '2026-06-10T09:30:00', completed_at: '2026-06-10T09:35:22', user_id: 1, tenant_id: 1 },
    { id: 2, target_url: 'https://shop-demo.io', scan_type: 'quick', status: 'completed', risk_score: 45.2, grade: 'B', vulnerabilities_found: 8, critical_count: 0, high_count: 2, medium_count: 4, low_count: 2, created_at: '2026-06-11T14:15:00', completed_at: '2026-06-11T14:17:45', user_id: 1, tenant_id: 1 },
    { id: 3, target_url: 'https://api.techstartup.dev', scan_type: 'api', status: 'completed', risk_score: 28.8, grade: 'A', vulnerabilities_found: 5, critical_count: 0, high_count: 0, medium_count: 3, low_count: 2, created_at: '2026-06-12T11:00:00', completed_at: '2026-06-12T11:04:10', user_id: 2, tenant_id: 1 },
    { id: 4, target_url: 'https://healthcare-portal.org', scan_type: 'full', status: 'completed', risk_score: 85.1, grade: 'D', vulnerabilities_found: 24, critical_count: 5, high_count: 8, medium_count: 7, low_count: 4, created_at: '2026-06-13T08:20:00', completed_at: '2026-06-13T08:28:15', user_id: 1, tenant_id: 1 },
    { id: 5, target_url: 'https://edu-platform.ac.uk', scan_type: 'quick', status: 'completed', risk_score: 15.3, grade: 'A+', vulnerabilities_found: 2, critical_count: 0, high_count: 0, medium_count: 1, low_count: 1, created_at: '2026-06-14T06:00:00', completed_at: '2026-06-14T06:02:30', user_id: 1, tenant_id: 1 }
];

const MOCK_VULNERABILITIES = [
    { id: 1, scan_id: 1, name: 'SQL Injection', severity: 'critical', category: 'injection', cwe_id: 'CWE-89', description: 'User input is directly concatenated into SQL queries without parameterization.', remediation: 'Use parameterized queries or prepared statements.', affected_url: 'https://example-bank.com/api/login', owasp_category: 'A03:2021 Injection', cvss_score: 9.8 },
    { id: 2, scan_id: 1, name: 'Cross-Site Scripting (XSS)', severity: 'high', category: 'xss', cwe_id: 'CWE-79', description: 'Reflected XSS vulnerability found in search parameter.', remediation: 'Implement proper output encoding and Content-Security-Policy headers.', affected_url: 'https://example-bank.com/search?q=', owasp_category: 'A03:2021 Injection', cvss_score: 7.5 },
    { id: 3, scan_id: 1, name: 'Missing Security Headers', severity: 'medium', category: 'misconfiguration', cwe_id: 'CWE-693', description: 'X-Frame-Options, X-Content-Type-Options, and CSP headers are missing.', remediation: 'Add security headers to all HTTP responses.', affected_url: 'https://example-bank.com/', owasp_category: 'A05:2021 Security Misconfiguration', cvss_score: 5.3 },
    { id: 4, scan_id: 1, name: 'Insecure Direct Object Reference', severity: 'critical', category: 'broken_access', cwe_id: 'CWE-639', description: 'Account IDs can be enumerated to access other users data.', remediation: 'Implement proper authorization checks on all data access.', affected_url: 'https://example-bank.com/api/account/123', owasp_category: 'A01:2021 Broken Access Control', cvss_score: 9.1 },
    { id: 5, scan_id: 1, name: 'Outdated TLS Configuration', severity: 'medium', category: 'cryptographic', cwe_id: 'CWE-326', description: 'Server supports TLS 1.0 and TLS 1.1 which are deprecated.', remediation: 'Disable TLS 1.0/1.1 and enforce TLS 1.2+ only.', affected_url: 'https://example-bank.com/', owasp_category: 'A02:2021 Cryptographic Failures', cvss_score: 5.9 },
    { id: 6, scan_id: 4, name: 'Remote Code Execution', severity: 'critical', category: 'injection', cwe_id: 'CWE-94', description: 'Unsafe deserialization allows arbitrary code execution.', remediation: 'Avoid deserializing untrusted data. Use safe serialization formats.', affected_url: 'https://healthcare-portal.org/api/import', owasp_category: 'A08:2021 Software and Data Integrity', cvss_score: 10.0 },
];

const MOCK_REPORTS = [
    { id: 1, scan_id: 1, format: 'pdf', filename: 'scan_report_1.pdf', created_at: '2026-06-10T09:40:00', status: 'ready' },
    { id: 2, scan_id: 4, format: 'pdf', filename: 'scan_report_4.pdf', created_at: '2026-06-13T08:35:00', status: 'ready' }
];

// ============================================================
// Mock API Router
// ============================================================
function mockApiResponse(endpoint, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const body = options.body ? (typeof options.body === 'string' ? JSON.parse(options.body) : options.body) : {};

    // Auth endpoints
    if (endpoint === '/api/auth/login' && method === 'POST') {
        const user = MOCK_USERS[body.email];
        if (user && body.password === user.password) {
            const { password, ...safeUser } = user;
            return { token: 'mock_jwt_' + btoa(user.email) + '_' + Date.now(), user: safeUser };
        }
        throw new Error('Invalid email or password');
    }

    if (endpoint === '/api/auth/register' && method === 'POST') {
        return { message: 'Registration successful! Please log in.', user: { id: 99, name: body.name, email: body.email, role: 'user' } };
    }

    if (endpoint === '/api/auth/profile' && method === 'PUT') {
        return { message: 'Profile updated successfully' };
    }

    // Dashboard endpoints
    if (endpoint === '/api/dashboard/stats') {
        return {
            total_scans: 47, completed_scans: 42, active_scans: 2, total_vulnerabilities: 186,
            critical_vulns: 23, high_vulns: 45, medium_vulns: 72, low_vulns: 46,
            avg_risk_score: 52.4, targets_scanned: 28, scans_this_week: 12, scans_today: 3,
            risk_trend: -5.2, vuln_trend: 8
        };
    }

    if (endpoint === '/api/dashboard/charts') {
        return {
            severity_distribution: { critical: 23, high: 45, medium: 72, low: 46 },
            scan_timeline: [
                { date: '2026-06-08', count: 5 }, { date: '2026-06-09', count: 8 },
                { date: '2026-06-10', count: 6 }, { date: '2026-06-11', count: 10 },
                { date: '2026-06-12', count: 7 }, { date: '2026-06-13', count: 9 },
                { date: '2026-06-14', count: 3 }
            ],
            category_breakdown: {
                'Injection': 34, 'XSS': 28, 'Misconfiguration': 42, 'Broken Access': 22,
                'Cryptographic': 18, 'SSRF': 8, 'Authentication': 15, 'Data Exposure': 19
            },
            risk_score_history: [
                { date: '2026-06-08', score: 58.2 }, { date: '2026-06-09', score: 55.1 },
                { date: '2026-06-10', score: 52.8 }, { date: '2026-06-11', score: 49.5 },
                { date: '2026-06-12', score: 53.2 }, { date: '2026-06-13', score: 50.7 },
                { date: '2026-06-14', score: 47.3 }
            ]
        };
    }

    if (endpoint === '/api/dashboard/recent') {
        return {
            recent_scans: MOCK_SCANS.slice(0, 5),
            recent_vulnerabilities: MOCK_VULNERABILITIES.slice(0, 5)
        };
    }

    if (endpoint === '/api/dashboard/research-metrics') {
        return {
            ml_model: { accuracy: 0.946, precision: 0.932, recall: 0.958, f1_score: 0.945, auc_roc: 0.978 },
            detection_rates: { sql_injection: 0.97, xss: 0.95, csrf: 0.91, ssrf: 0.88, rce: 0.94, lfi: 0.92, open_redirect: 0.89, xxe: 0.86 },
            confusion_matrix: { tp: 1842, fp: 132, fn: 78, tn: 4948 },
            performance: { avg_scan_time_seconds: 245, throughput_urls_per_minute: 120, false_positive_rate: 0.026 },
            training_data: { total_samples: 7000, malicious_samples: 1920, benign_samples: 5080, last_trained: '2026-06-01T00:00:00' },
            owasp_coverage: [
                { category: 'A01 Broken Access Control', coverage: 94 }, { category: 'A02 Cryptographic Failures', coverage: 91 },
                { category: 'A03 Injection', coverage: 97 }, { category: 'A04 Insecure Design', coverage: 85 },
                { category: 'A05 Security Misconfiguration', coverage: 92 }, { category: 'A06 Vulnerable Components', coverage: 88 },
                { category: 'A07 Auth Failures', coverage: 90 }, { category: 'A08 Data Integrity', coverage: 86 },
                { category: 'A09 Logging Failures', coverage: 82 }, { category: 'A10 SSRF', coverage: 89 }
            ]
        };
    }

    // Scanner endpoints
    if (endpoint === '/api/scans' && method === 'GET') {
        return { scans: MOCK_SCANS };
    }

    if (endpoint === '/api/scans' && method === 'POST') {
        const targetUrl = body.target_url || body.url || 'https://unknown.com';
        const critCount = Math.floor(Math.random() * 4);
        const highCount = Math.floor(Math.random() * 6);
        const medCount = Math.floor(Math.random() * 8);
        const lowCount = Math.floor(Math.random() * 5);
        const vulnCount = critCount + highCount + medCount + lowCount;
        const newScan = {
            id: MOCK_SCANS.length + 1, target_url: targetUrl, scan_type: body.scan_type || 'full',
            status: 'completed', risk_score: parseFloat((Math.random() * 80 + 10).toFixed(1)), grade: ['A', 'B', 'C', 'D'][Math.floor(Math.random() * 4)],
            vulnerabilities_found: vulnCount, vulnerability_count: vulnCount, critical_count: critCount,
            high_count: highCount, medium_count: medCount,
            low_count: lowCount, created_at: new Date().toISOString(),
            completed_at: new Date().toISOString(), user_id: 1, tenant_id: 1,
            owasp_results: { categories_tested: 10, issues_by_category: { 'A05 Security Misconfiguration': 2 } },
            mitre_mappings: [{ technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }]
        };
        MOCK_SCANS.unshift(newScan);
        return { message: 'Scan completed successfully', scan: newScan };
    }

    if (endpoint.match(/^\/api\/scans\/\d+$/) && method === 'GET') {
        const scanId = parseInt(endpoint.split('/').pop());
        const scan = MOCK_SCANS.find(s => s.id === scanId);
        if (scan) {
            return {
                ...scan,
                vulnerabilities: MOCK_VULNERABILITIES.filter(v => v.scan_id === scanId),
                owasp_results: { categories_tested: 10, issues_by_category: { 'A03 Injection': 2, 'A05 Misconfiguration': 1 } },
                mitre_mappings: [{ technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }],
                ssl_info: { protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', valid_from: '2026-01-01', valid_to: '2027-01-01', issuer: "Let's Encrypt" },
                headers_analysis: { 'X-Frame-Options': { present: false, severity: 'medium' }, 'Content-Security-Policy': { present: false, severity: 'high' }, 'Strict-Transport-Security': { present: true, severity: 'info' } }
            };
        }
        throw new Error('Scan not found');
    }

    // Reports endpoints
    if (endpoint === '/api/reports' && method === 'GET') {
        return { reports: MOCK_REPORTS };
    }

    if (endpoint.match(/^\/api\/reports\/generate\/\d+$/) && method === 'POST') {
        const genScanId = parseInt(endpoint.split('/')[4]);
        const genScan = MOCK_SCANS.find(s => s.id === genScanId);
        const newReport = { id: Date.now(), scan_id: genScanId, format: 'pdf', filename: `CyberGuard_Report_${genScanId}.pdf`, target_url: genScan ? genScan.target_url : 'N/A', status: 'ready', created_at: new Date().toISOString() };
        MOCK_REPORTS.push(newReport);
        return { message: 'Report generated successfully', report: newReport };
    }

    if (endpoint.match(/^\/api\/reports\/\d+\/download$/)) {
        // Generate a minimal valid PDF
        const pdfContent = [
            '%PDF-1.4',
            '1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj',
            '2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj',
            '3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>endobj',
            '4 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj',
            '5 0 obj<</Length 280>>',
            'stream',
            'BT',
            '/F1 24 Tf',
            '100 700 Td',
            '(CyberGuard AI) Tj',
            '/F1 16 Tf',
            '0 -40 Td',
            '(Security Assessment Report) Tj',
            '/F1 12 Tf',
            '0 -60 Td',
            '(This is a demo report generated by CyberGuard AI) Tj',
            '0 -25 Td',
            '(Threat Detection Platform hosted on Firebase.) Tj',
            '0 -25 Td',
            `(Generated: ${new Date().toLocaleDateString()}) Tj`,
            '0 -50 Td',
            '(--- Scan Summary ---) Tj',
            '0 -25 Td',
            '(Total Vulnerabilities Found: 18) Tj',
            '0 -20 Td',
            '(Critical: 3  |  High: 5  |  Medium: 6  |  Low: 4) Tj',
            '0 -20 Td',
            '(Overall Risk Score: 72.5 / 100  Grade: C) Tj',
            'ET',
            'endstream',
            'endobj',
            'xref',
            '0 6',
            '0000000000 65535 f ',
            '0000000009 00000 n ',
            '0000000058 00000 n ',
            '0000000115 00000 n ',
            '0000000266 00000 n ',
            '0000000340 00000 n ',
            'trailer<</Size 6/Root 1 0 R>>',
            'startxref',
            '672',
            '%%EOF'
        ].join('\n');
        return new Blob([pdfContent], { type: 'application/pdf' });
    }

    // Threat Intel endpoints
    if (endpoint === '/api/threat-intel/global-status') {
        return {
            global_threat_level: 'elevated', active_campaigns: 12, new_cves_today: 34,
            exploited_in_wild: 8, critical_advisories: 5,
            threat_actors: [
                { name: 'APT29', origin: 'Russia', active: true, targets: 'Government, Healthcare' },
                { name: 'Lazarus Group', origin: 'North Korea', active: true, targets: 'Financial, Crypto' },
                { name: 'APT41', origin: 'China', active: true, targets: 'Technology, Telecom' }
            ]
        };
    }

    if (endpoint.startsWith('/api/threat-intel/cves')) {
        return {
            cves: [
                { cve_id: 'CVE-2026-1234', description: 'Remote code execution in Apache HTTP Server', severity: 'critical', cvss_score: 9.8, published: '2026-06-12', affected_product: 'Apache HTTP Server 2.4.x', exploited: true },
                { cve_id: 'CVE-2026-5678', description: 'SQL injection in WordPress plugin WPForms', severity: 'high', cvss_score: 8.1, published: '2026-06-11', affected_product: 'WPForms < 1.8.9', exploited: false },
                { cve_id: 'CVE-2026-9012', description: 'Authentication bypass in Fortinet FortiOS', severity: 'critical', cvss_score: 9.6, published: '2026-06-10', affected_product: 'FortiOS 7.x', exploited: true },
                { cve_id: 'CVE-2026-3456', description: 'XSS vulnerability in React framework', severity: 'medium', cvss_score: 6.1, published: '2026-06-09', affected_product: 'React < 19.1', exploited: false },
                { cve_id: 'CVE-2026-7890', description: 'Privilege escalation in Linux kernel', severity: 'high', cvss_score: 7.8, published: '2026-06-08', affected_product: 'Linux Kernel 6.x', exploited: true }
            ],
            total: 5, page: 1, pages: 1
        };
    }

    if (endpoint.match(/^\/api\/threat-intel\/domain\/.+$/)) {
        const domain = endpoint.split('/').pop();
        return {
            domain: domain, reputation_score: 72, risk_level: 'medium',
            whois: { registrar: 'GoDaddy', created: '2020-03-15', expires: '2027-03-15', country: 'US' },
            dns_records: [{ type: 'A', value: '104.21.32.1' }, { type: 'MX', value: 'mail.'+domain }],
            threats_detected: [{ type: 'phishing', confidence: 0.3, last_seen: '2026-05-20' }],
            ssl_certificate: { issuer: "Let's Encrypt", valid: true, expires: '2027-01-15' }
        };
    }

    // SIEM endpoints
    if (endpoint.startsWith('/api/siem')) {
        return {
            events: [
                { id: 1, timestamp: '2026-06-14T10:30:00', event_type: 'authentication_failure', severity: 'warning', source_ip: '192.168.1.105', description: 'Multiple failed login attempts detected', details: { attempts: 5, username: 'admin' } },
                { id: 2, timestamp: '2026-06-14T10:25:00', event_type: 'port_scan', severity: 'high', source_ip: '10.0.0.55', description: 'Port scan detected from internal network', details: { ports_scanned: 1024, duration: '45s' } },
                { id: 3, timestamp: '2026-06-14T10:20:00', event_type: 'data_exfiltration', severity: 'critical', source_ip: '172.16.0.23', description: 'Unusual large data transfer to external IP', details: { bytes_transferred: 52428800, destination: '203.0.113.50' } },
                { id: 4, timestamp: '2026-06-14T10:15:00', event_type: 'malware_detected', severity: 'critical', source_ip: '192.168.1.42', description: 'Trojan detected in uploaded file', details: { filename: 'invoice.exe', hash: 'a1b2c3d4e5f6' } },
                { id: 5, timestamp: '2026-06-14T10:10:00', event_type: 'policy_violation', severity: 'medium', source_ip: '192.168.1.88', description: 'Access to restricted resource attempted', details: { resource: '/admin/config', user: 'guest' } }
            ],
            total: 5, page: 1
        };
    }

    // AI endpoints
    if (endpoint === '/api/ai/chat' && method === 'POST') {
        const userMsg = body.message || '';
        let response = "Based on my analysis, I recommend focusing on the critical vulnerabilities first, particularly SQL injection and IDOR issues. Here are my key recommendations:\n\n";
        response += "1. **Parameterize all SQL queries** - This addresses your most critical injection vulnerabilities\n";
        response += "2. **Implement RBAC** - Role-based access control will mitigate broken access control issues\n";
        response += "3. **Add security headers** - CSP, X-Frame-Options, and HSTS headers should be deployed\n";
        response += "4. **Update TLS configuration** - Disable TLS 1.0/1.1 and enforce TLS 1.2+\n";
        response += "5. **Enable WAF rules** - Web Application Firewall can provide immediate protection\n\n";
        response += `_Analysis based on your question: "${userMsg.substring(0, 80)}..."_`;
        return { response: response, confidence: 0.92 };
    }

    // Admin endpoints
    if (endpoint === '/api/admin/stats') {
        return { total_users: 15, active_users: 12, total_scans: 47, total_reports: 23, storage_used_mb: 156, api_calls_today: 342 };
    }

    if (endpoint === '/api/admin/users') {
        return { users: Object.values(MOCK_USERS).map(({ password, ...u }) => u) };
    }

    if (endpoint === '/api/admin/scans') {
        return { scans: MOCK_SCANS };
    }

    if (endpoint === '/api/admin/audit-logs') {
        return {
            logs: [
                { id: 1, user: 'admin@cyberguard.ai', action: 'login', timestamp: '2026-06-14T10:00:00', ip: '192.168.1.1', details: 'Successful login' },
                { id: 2, user: 'analyst@cyberguard.ai', action: 'scan_created', timestamp: '2026-06-14T09:30:00', ip: '192.168.1.5', details: 'Scan started for example-bank.com' },
                { id: 3, user: 'admin@cyberguard.ai', action: 'user_updated', timestamp: '2026-06-14T09:00:00', ip: '192.168.1.1', details: 'Updated user role' }
            ]
        };
    }

    if (endpoint.match(/^\/api\/admin\/users\/\d+$/) && (method === 'PUT' || method === 'DELETE')) {
        return { message: 'Operation completed successfully' };
    }

    // Default fallback
    return { message: 'OK', status: 'demo_mode' };
}

// ============================================================
// Override the global api() function to use mock when backend unavailable
// ============================================================
const _originalApiFn = typeof api === 'function' ? api : null;

async function api(endpoint, options = {}) {
    if (!MOCK_MODE && _originalApiFn) {
        return _originalApiFn(endpoint, options);
    }

    // For download/blob endpoints, skip fetch entirely — always use mock in demo mode
    if (endpoint.match(/\/download$/)) {
        console.log(`[MockAPI] Using mock for download endpoint: ${endpoint}`);
        return mockApiResponse(endpoint, options);
    }

    // Try real API first, fall back to mock
    try {
        const config = {
            headers: { 'Content-Type': 'application/json' },
            ...options
        };
        // Remove non-fetch options that may cause issues
        delete config.cache;
        if (Auth.getToken()) {
            config.headers['Authorization'] = `Bearer ${Auth.getToken()}`;
        }
        if (options.body && typeof options.body === 'object') {
            config.body = JSON.stringify(options.body);
        }

        const response = await fetch(`${API_BASE}${endpoint}`, config);
        const contentType = response.headers.get('content-type');

        // If we got HTML back instead of JSON, backend is unavailable — use mock
        if (contentType && contentType.includes('text/html')) {
            console.log(`[MockAPI] Backend unavailable for ${endpoint}, using mock data`);
            return mockApiResponse(endpoint, options);
        }

        if (response.status === 401) {
            Auth.logout();
            throw new Error('Session expired. Please log in again.');
        }

        if (contentType && contentType.includes('application/pdf')) {
            if (!response.ok) throw new Error('Failed to download file');
            return response.blob();
        }

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || data.message || 'Request failed');
        }
        return data;
    } catch (err) {
        // If it's a known mock error (like invalid login), re-throw
        if (err.message === 'Invalid email or password') throw err;

        // Network errors or HTML responses — fall back to mock
        console.log(`[MockAPI] Falling back to mock for ${endpoint}:`, err.message);
        try {
            return mockApiResponse(endpoint, options);
        } catch (mockErr) {
            throw mockErr;
        }
    }
}
