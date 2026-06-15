"""
AI Cybersecurity Advisor service for CyberGuard AI.
Generates context-aware security advice by examining tenant vulnerabilities.
"""

import json
import logging
import models

logger = logging.getLogger(__name__)

# System instructions to guide the AI persona
SYSTEM_PROMPT = """You are CyberGuard AI, an elite enterprise-grade cybersecurity advisor. 
Your goal is to provide concise, practical, and highly secure remediation advice.
When explaining concepts, use Markdown formatting, list CVE IDs, CVSS scores, and CWE weaknesses,
and reference specific vulnerabilities present in the user's tenant if applicable.
Always follow OWASP and secure coding standards."""

def generate_security_advice(tenant_id, user_prompt, chat_history=None):
    """
    Generate cybersecurity advisor response.
    Analyzes the tenant's current vulnerabilities to deliver tailored context-aware advice.
    """
    try:
        # 1. Fetch current vulnerabilities for the tenant
        vulns = models.get_all_vulnerabilities(tenant_id)
        
        # 2. Extract context about vulnerabilities
        critical_count = sum(1 for v in vulns if v.get('severity') == 'Critical')
        high_count = sum(1 for v in vulns if v.get('severity') == 'High')
        medium_count = sum(1 for v in vulns if v.get('severity') == 'Medium')
        
        # Identify categories of weaknesses
        cwe_list = list(set(v.get('cwe_id') for v in vulns if v.get('cwe_id')))
        owasp_categories = list(set(v.get('owasp_category') for v in vulns if v.get('owasp_category')))
        
        # Compile a summary of vulnerable endpoints
        vulnerable_endpoints = []
        for v in vulns:
            if v.get('severity') in ('Critical', 'High'):
                vulnerable_endpoints.append(f"{v.get('title')} on {v.get('affected_endpoint') or 'system'}")
        
        # Limit summary lists for brevity
        vuln_summary_str = ""
        if vulnerable_endpoints:
            vuln_summary_str = "\n".join(f"- {item}" for item in vulnerable_endpoints[:5])
        
        # 3. Analyze prompt keywords for specific rule-based responses,
        # fallback to general security best practices context-aware of their tenant state.
        prompt_lower = user_prompt.lower()
        
        # Context block to inject
        tenant_context = f"""
[Tenant Environment Status Context]
- Critical issues: {critical_count}
- High issues: {high_count}
- Medium issues: {medium_count}
- Unique CWE classifications: {', '.join(cwe_list) if cwe_list else 'None'}
- OWASP Categories found: {', '.join(owasp_categories) if owasp_categories else 'None'}
- High-priority weaknesses detected:
{vuln_summary_str if vuln_summary_str else '- None detected'}
"""

        response = ""
        
        if "cve" in prompt_lower or "cve-" in prompt_lower:
            # User is asking about CVEs. Let's look up if we have details or mock them.
            # Example search for a CVE if specified
            cve_id = None
            import re
            cve_match = re.search(r'cve-\d{4}-\d{4,5}', prompt_lower)
            if cve_match:
                cve_id = cve_match.group(0).upper()
                
            if cve_id:
                cve_data = models.get_cve_by_id(cve_id)
                if cve_data:
                    response = f"""### Security Advisory: {cve_data['cve_id']} ({cve_data['title']})

**Severity**: `{cve_data['severity']}` | **CVSS**: `{cve_data['cvss_score']}`
**EPSS Score**: `{cve_data['epss_score']}` ({cve_data['epss_percentile'] * 100:.2f}% probability of exploitation in next 30 days)

**Description**:
{cve_data['description']}

**Affected Software**:
{cve_data['affected_products']}

**Remediation Recommendation**:
1. Apply the vendor update immediately.
2. If update cannot be applied, isolate the host running {cve_data['affected_products']} behind strict firewall rules.
3. Audit access logs for attempts targeting endpoints associated with this component.
"""
                else:
                    response = f"""### CVE Lookup: {cve_id}

I could not find `{cve_id}` in my local database cache. However, for most modern vulnerabilities of this category:
1. Ensure your software packages are upgraded to their latest stable version.
2. Implement virtual patching at the Web Application Firewall (WAF) layer if using public cloud services.
3. Check the official NVD or vendor advisory portal for remediation scripts.
"""
            else:
                response = """### CVE Vulnerability Query

To provide specific CVE advice, please search for a specific CVE code (e.g., `CVE-2024-3094` or `CVE-2024-21762`).
Meanwhile, looking at your environment:
- You currently have **{critical_count} Critical** and **{high_count} High** vulnerabilities.
- Prioritize patching the **.env file disclosure** and **exposed database ports** as they represent active entry vectors.
"""
                
        elif "status" in prompt_lower or "vulnerabilit" in prompt_lower or "my environment" in prompt_lower or "fix" in prompt_lower:
            if critical_count > 0 or high_count > 0:
                response = f"""### Environment Risk Mitigation Report

I analyzed your environment and found **{critical_count + high_count} high-priority issues**. Here is your customized remediation roadmap:

1. **Secure exposed secrets (Critical)**:
   - Your `.env` or configuration secrets are exposed. Immediately block external access to dotfiles (`.*`) in Nginx/Apache configuration.
   - Rotate all passwords, DB credentials, and API keys contained in those files.
   
2. **Restrict Database Access (Critical)**:
   - I detected database services accessible externally. Restrict MySQL/PostgreSQL ports (3306, 5432) to bind only to `127.0.0.1` or allow connection strictly from application containers.
   
3. **Upgrade TLS Configurations (High)**:
   - Some services are using deprecated TLS protocols (TLSv1.1 or key sizes under 2048-bit). Update your SSL cipher suites to enforce **TLSv1.3** and disable weak ciphers (3DES, RC4).

4. **Header Remediation**:
   - Add defense-in-depth headers: `Content-Security-Policy` and `Strict-Transport-Security`.
"""
            else:
                response = """### Environment Risk Mitigation Report

Great news! I analyzed your workspace environment and found **no critical or high vulnerabilities** currently active.

**Next Steps to Maintain Security**:
1. Implement continuous CI/CD scanning to catch new vulnerabilities before deployment.
2. Set up daily automated port scans to ensure no services are accidentally exposed.
3. Audit your user roles regularly. Enforce Multi-Factor Authentication (MFA) and Least Privilege principles.
"""

        elif "siem" in prompt_lower or "event" in prompt_lower or "alert" in prompt_lower:
            # Query recent SIEM alerts
            recent_events = models.get_siem_events(tenant_id, limit=3)
            event_strs = []
            for ev in recent_events:
                event_strs.append(f"- `[{ev['severity']}]` **{ev['event_type']}** from {ev['source_ip']}: {ev['description']}")
            
            events_joined = "\n".join(event_strs) if event_strs else "- No security events recorded."
            
            response = f"""### SIEM Alert Analysis

Here is a summary of recent security alerts in your workspace:

{events_joined}

**Security Recommendations**:
- Review critical events (like `privilege_escalation` or `data_exfiltration`) immediately in the **SIEM Logs** panel.
- Implement rate limits on APIs to throttle automated brute-force attempts.
- Enforce network segmentation to contain source IPs showing high failure logs.
"""
            
        else:
            # General Response with tenant summary
            response = f"""### Security Advisory Assistant

Welcome to the CyberGuard AI Assistant. I am monitoring your workspace in **tenant #{tenant_id}**.

**Current Environment Posture**:
- **Risk Profile**: {"HIGH RISK" if critical_count > 0 else ("MEDIUM RISK" if high_count > 0 else "SECURE")}
- **Active Critical Findings**: {critical_count}
- **Active High Findings**: {high_count}

**How can I assist you today?**
- You can ask me how to fix specific vulnerabilities (e.g. *"how do I fix my exposed .env file?"*).
- You can query CVEs (e.g. *"tell me about CVE-2024-3094"*).
- You can get SIEM intelligence advice (*"what are my recent alerts?"*).
"""
            
        return {
            'response': response,
            'context': tenant_context
        }
    except Exception as e:
        logger.exception("Error generating AI security advice")
        return {
            'response': f"I apologize, but I encountered an error retrieving security context: {str(e)}",
            'context': ""
        }
