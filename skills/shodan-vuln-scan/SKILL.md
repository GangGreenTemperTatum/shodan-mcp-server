---
name: shodan-vuln-scan
description: Identify vulnerabilities in internet-facing systems using Shodan. Use for vulnerability assessment, CVE discovery, and security auditing. Triggers on requests for "vulnerability scan", "find vulns", "CVE check", or "security assessment".
---

# Shodan Vulnerability Scanner Skill

Identify and assess vulnerabilities in internet-facing systems using Shodan's vulnerability database.

## When to Use

- Vulnerability assessments on authorized targets
- CVE impact analysis
- Security posture evaluation
- Patch management verification
- Threat intelligence gathering

## Workflow

1. **Scope Definition**
   - Define target scope (IPs, domains, organizations)
   - Verify authorization
   - Check API credits

2. **Vulnerability Discovery**
   - Search for specific CVEs: `vuln:CVE-YYYY-NNNN`
   - Search for vulnerable products
   - Use facets to aggregate vulnerability data

3. **Host Analysis**
   - Use `shodan_host_info` to get vulnerability details
   - Analyze service versions against known CVEs
   - Check for outdated software

4. **Exploit Availability**
   - Use `shodan_exploits_search` to find public exploits
   - Identify high-risk vulnerabilities with available exploits
   - Assess exploit complexity and requirements

5. **Risk Assessment**
   - Prioritize based on severity and exploitability
   - Consider exposure level (internet-facing vs internal)
   - Evaluate business impact

6. **Reporting**
   - Provide vulnerability matrix
   - Include remediation recommendations
   - Track historical vulnerability data

## Common Vulnerability Queries

### Critical CVEs
```
vuln:CVE-2021-44228  # Log4Shell
vuln:CVE-2020-1472   # Zerologon
vuln:CVE-2017-0144   # EternalBlue
```

### Vulnerable Web Servers
```
"apache/2.4.49" vuln:CVE-2021-41773
"nginx" vuln:CVE-2021-23017
```

### Exposed Management Interfaces
```
title:"Dashboard" http.component:"admin"
title:"Login" port:8443
```

### Weak SSL/TLS
```
ssl.version:sslv2
ssl.version:sslv3
ssl.cipher:export
```

### Default Credentials
```
"default password"
http.html:"default password"
```

### Unpatched Systems
```
org:"Example Corp" os:"Windows Server 2003"
org:"Example Corp" os:"CentOS 6"
```

## Exploit Database Queries

### Find Exploits by CVE
```
CVE-2021-44228
```

### Find Exploits by Software
```
type:webapps platform:linux "apache"
```

### Recent Exploits
```
date:[2024-01-01 TO 2024-12-31]
```

## Severity Assessment

Rate findings by:
1. **Critical**: RCE, authentication bypass, known exploits
2. **High**: SQL injection, XSS, sensitive data exposure
3. **Medium**: Information disclosure, weak configurations
4. **Low**: Version disclosure, deprecated protocols

## Output Format

```markdown
# Vulnerability Assessment Report

## Executive Summary
- Total hosts analyzed: X
- Critical vulnerabilities: X
- High vulnerabilities: X
- Exploits available: X

## Critical Findings

### CVE-YYYY-NNNN - [Vulnerability Name]
- **Affected Hosts**: [IP addresses]
- **CVSS Score**: X.X
- **Exploit Available**: Yes/No
- **Impact**: [Description]
- **Remediation**: [Steps]

## Vulnerability Matrix
[Table of all findings]

## Recommendations
1. Immediate patching required for: [List]
2. Configuration changes needed: [List]
3. Further investigation required: [List]
```

## Best Practices

1. Focus on exploitable vulnerabilities
2. Verify findings (Shodan data may be outdated)
3. Consider defense in depth
4. Prioritize internet-facing critical services
5. Track remediation progress over time
6. Use historical data to identify patterns
7. Coordinate with vulnerability management teams

## Integration with Other Tools

- Export findings to vulnerability scanners
- Correlate with threat intelligence feeds
- Feed into SIEM for monitoring
- Update asset management databases
