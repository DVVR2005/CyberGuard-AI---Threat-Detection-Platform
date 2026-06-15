# CyberGuard AI — Threat Detection Platform

<p align="center">
  <strong>AI-Powered Automated Vulnerability Assessment & Threat Detection</strong><br>
  <em>A full-stack cybersecurity SaaS dashboard for security professionals</em>
</p>

---

## Overview

CyberGuard AI is a professional cybersecurity platform that automates website vulnerability assessment, OWASP Top 10 detection, AI-based risk scoring, threat intelligence analysis, dashboard analytics, and PDF report generation.

**Key Features:**
- 🔐 Role-Based Access Control (Admin / Security Analyst)
- 🔍 Simulated Website Vulnerability Scanner (Ports, SSL, Headers, Directories)
- 🛡️ OWASP Top 10 Vulnerability Classification (A01–A10)
- 🤖 AI-Powered Risk Scoring Engine (0–100 scale with grade A+ to F)
- 📊 SOC-Style Dashboard with Interactive Charts
- 🌐 Threat Intelligence Feed (CVEs, Domain Reputation, Global Threat Level)
- 📄 Professional PDF Report Generation
- ⚙️ Admin Panel (User Management, Audit Logs, Platform Analytics)

## Tech Stack

| Layer       | Technology                                      |
|-------------|------------------------------------------------|
| Frontend    | HTML5, CSS3, JavaScript (Vanilla SPA)          |
| UI          | Bootstrap 5, Chart.js 4, Google Fonts (Inter)  |
| Backend     | Python Flask, REST API, JWT Authentication     |
| Database    | SQLite (easily swappable to MySQL/PostgreSQL)  |
| AI/ML       | Scikit-Learn (Random Forest), NumPy, Pandas    |
| PDF Reports | ReportLab                                       |
| Security    | bcrypt password hashing, JWT tokens, CORS      |

## Quick Start

### Prerequisites
- Python 3.9+
- pip

### Installation

```bash
# 1. Clone or navigate to the project directory
cd "Threat Detection Platform"

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. (Optional) Train the ML model
python ml_model/train_model.py

# 4. Start the application
python app.py
```

The application will be available at **http://localhost:5000**

### Demo Credentials

| Role     | Email                    | Password    |
|----------|--------------------------|-------------|
| Admin    | admin@cyberguard.ai      | Admin@123   |
| Analyst  | analyst@cyberguard.ai    | Analyst@123 |

## Project Structure

```
Threat Detection Platform/
├── app.py                          # Flask entry point
├── config.py                       # Application configuration
├── database.py                     # SQLite schema & seed data
├── models.py                       # Data access layer
├── requirements.txt                # Python dependencies
│
├── routes/                         # REST API endpoints
│   ├── auth.py                     # Authentication (login/register/JWT)
│   ├── scanner.py                  # Scan initiation & results
│   ├── dashboard.py                # Analytics aggregation
│   ├── reports.py                  # PDF generation & download
│   ├── admin.py                    # User/scan management
│   └── threat_intel.py             # Threat intelligence feeds
│
├── services/                       # Business logic layer
│   ├── scanner_service.py          # Simulated scanning engine
│   ├── owasp_engine.py             # OWASP Top 10 classification
│   ├── risk_scorer.py              # AI risk scoring algorithm
│   ├── threat_intel_service.py     # Mock threat intelligence
│   └── report_generator.py         # ReportLab PDF builder
│
├── templates/
│   └── index.html                  # SPA HTML shell
│
├── static/
│   ├── css/
│   │   └── style.css               # Complete dark cybersecurity theme
│   └── js/
│       ├── app.js                  # SPA router, auth state, API wrapper
│       ├── auth.js                 # Login & registration pages
│       ├── dashboard.js            # Chart.js analytics dashboard
│       ├── scanner.js              # Scan UI with progress & results
│       ├── threat_intel.js         # CVE feed & domain reputation
│       ├── reports.js              # Report generation & download
│       └── admin.js                # Admin panel UI
│
├── ml_model/
│   ├── train_model.py              # Random Forest training script
│   └── sample_dataset.csv          # Synthetic training data (auto-generated)
│
├── reports/                        # Generated PDF reports (auto-created)
├── docs/
│   └── api_docs.md                 # REST API documentation
└── README.md
```

## Application Modules

### Module 1: Authentication System
- JWT-based authentication with 24h token expiry
- Password hashing with bcrypt
- Account lockout after 5 failed login attempts (15-minute cooldown)
- Role-based access control (Admin / Analyst)
- Audit logging for all auth events

### Module 2: Website Scanner
- Input any URL to initiate a simulated vulnerability scan
- Real-time progress bar with phase labels and log console
- Scans cover: Port scanning, SSL analysis, security headers, directory discovery
- Results displayed in an interactive tabbed interface
- All scans are **simulated** — no actual network requests to targets

### Module 3: OWASP Top 10 Detection
- Automatically classifies findings into OWASP Top 10 categories
- Each vulnerability includes: description, severity, CWE ID, CVSS score, remediation
- Covers A01 through A10 with realistic mappings

### Module 4: AI Risk Scoring Engine
- Weighted algorithmic scoring (0–100 scale)
- Factors: open ports, vulnerability count, SSL grade, header compliance, exposed directories
- Severity levels: Low (0–20), Medium (21–40), High (41–60), Critical (61–100)
- Grades: A+ through F
- AI-style explanation with contributing factor analysis

### Module 5: Threat Intelligence
- Mock CVE feed with 20+ realistic entries
- Domain reputation lookup (Safe / Suspicious / Malicious)
- Global threat level indicator with active threat counts

### Module 6: Dashboard Analytics
- KPI cards: Total Scans, Vulnerabilities, Critical Findings, Avg Risk Score
- Chart.js charts: Vulnerability Distribution, Severity Breakdown, Risk Trend, Monthly Scans
- Recent scan activity feed

### Module 7: PDF Report Generator
- Professional PDF reports via ReportLab
- Sections: Executive Summary, Vulnerability Findings, Risk Assessment, Recommendations
- Downloadable from the Reports page

### Module 8: Admin Panel
- User management: view, activate, suspend, delete users
- Platform-wide scan overview
- Audit log viewer with filtering
- System statistics dashboard

## API Reference

See [API Documentation](docs/api_docs.md) for the complete REST API reference.

### Quick API Overview

| Method   | Endpoint                          | Auth     | Description              |
|----------|-----------------------------------|----------|--------------------------|
| POST     | `/api/auth/register`              | No       | Create account           |
| POST     | `/api/auth/login`                 | No       | Login + get JWT          |
| GET      | `/api/auth/me`                    | Required | Current user profile     |
| POST     | `/api/scans`                      | Required | Initiate scan            |
| GET      | `/api/scans`                      | Required | List scans               |
| GET      | `/api/scans/:id`                  | Required | Scan details             |
| GET      | `/api/dashboard/stats`            | Required | Dashboard KPIs           |
| GET      | `/api/dashboard/charts`           | Required | Chart data               |
| GET      | `/api/threat-intel/cves`          | Required | CVE feed                 |
| GET      | `/api/threat-intel/domain/:domain`| Required | Domain reputation        |
| POST     | `/api/reports/generate/:scan_id`  | Required | Generate PDF report      |
| GET      | `/api/reports/:id/download`       | Required | Download PDF             |
| GET      | `/api/admin/users`                | Admin    | List users               |
| GET      | `/api/admin/audit-logs`           | Admin    | View audit logs          |

## Database Schema

```
users ─┬── scans ─┬── vulnerabilities
       │          ├── risk_scores
       │          ├── threat_feeds
       │          └── reports
       └── audit_logs
```

## Security Notes

> ⚠️ **This is an educational/portfolio project.** All scanning functionality is simulated with mock data. No actual vulnerability scanning, port scanning, or network probing is performed against target URLs. The platform is designed to demonstrate cybersecurity concepts and full-stack development skills.

## License

This project is for educational purposes. Created as a B.Tech Cyber Security capstone project.
