---
name: shodan-asset-monitor
description: Monitor and track organizational assets over time using Shodan. Use for continuous security monitoring, attack surface management, and change detection. Triggers on requests for "monitor assets", "track changes", "continuous monitoring", or "attack surface management".
---

# Shodan Asset Monitoring Skill

Continuously monitor organizational assets, detect changes, and manage attack surface using Shodan's historical data capabilities.

## When to Use

- Continuous security monitoring
- Attack surface management
- Change detection and alerting
- Shadow IT discovery
- Compliance verification
- Security posture tracking

## Workflow

### 1. Initial Baseline

**Establish Asset Inventory**
```
1. Use shodan_host_search with org/domain filters
2. Document all discovered assets
3. Categorize by criticality and function
4. Create baseline snapshot
```

**Baseline Query Examples**:
```
org:"Example Corp"
hostname:*.example.com
net:192.168.0.0/16
ssl:"example.com"
```

### 2. Regular Monitoring

**Daily/Weekly Checks**
- Re-run baseline queries
- Compare results with baseline
- Identify new assets
- Detect removed assets
- Track service changes

**Change Detection Queries**:
```
# New web servers
org:"Example Corp" port:80,443 after:YYYY-MM-DD

# New SSH endpoints
org:"Example Corp" port:22 after:YYYY-MM-DD

# New databases
org:"Example Corp" product:mongodb,mysql,postgresql after:YYYY-MM-DD
```

### 3. Historical Analysis

Use `shodan_host_info` with `history: true` to:
- Track host lifecycle
- Identify service migrations
- Detect configuration changes
- Analyze vulnerability windows

### 4. Alerting Triggers

Monitor for:
- **New Assets**: Unauthorized or shadow IT
- **Service Changes**: New ports or protocols
- **Version Changes**: Upgrades or downgrades
- **Certificate Changes**: SSL/TLS modifications
- **Vulnerability Exposure**: New CVEs detected
- **Geolocation Changes**: Asset migration
- **Expired Certificates**: Security risks

### 5. Reporting and Trending

Generate periodic reports on:
- Asset count trends
- Service distribution
- Vulnerability trends
- Attack surface growth/reduction
- Compliance status

## Monitoring Queries

### New Asset Discovery

```
# Assets added in last 30 days
org:"Example Corp" after:YYYY-MM-DD

# New subdomains
hostname:*.example.com after:YYYY-MM-DD

# New IP ranges
net:192.168.0.0/24 after:YYYY-MM-DD
```

### Service Changes

```
# HTTP services exposing admin panels
org:"Example Corp" http.title:"admin,dashboard,login"

# New database exposures
org:"Example Corp" product:mongo,mysql,postgres,redis

# New remote access services
org:"Example Corp" port:22,3389,5900
```

### Security Degradation

```
# Systems with expired certificates
org:"Example Corp" ssl.cert.expired:true

# Outdated software versions
org:"Example Corp" product:"Apache" version:"2.2,2.3"

# Weak SSL configurations
org:"Example Corp" ssl.version:sslv2,sslv3
```

### Shadow IT Detection

```
# Cloud services not in known IP ranges
org:"Example Corp" -net:known.range.0.0/16

# Unauthorized cloud providers
org:"Example Corp" cloud.provider:!AWS,!Azure,!GCP

# Development/staging in production
org:"Example Corp" http.title:"dev,staging,test"
```

### Compliance Monitoring

```
# PCI-DSS: Open ports that shouldn't be
org:"Example Corp" port:23,69,111,135

# HIPAA: Unencrypted health data endpoints
org:"Example Corp" http.html:"PHI,medical,patient" -port:443

# GDPR: Data processing systems
org:"Example Corp" http.html:"personal data,GDPR"
```

## Monitoring Workflow Script

### Weekly Asset Review

```markdown
1. **New Asset Discovery**
   - Query: org:"Example Corp" after:[last_week]
   - Action: Verify authorization and document

2. **Service Change Detection**
   - Compare port distribution with baseline
   - Action: Investigate unexpected changes

3. **Vulnerability Scan**
   - Query: org:"Example Corp" vuln:CVE-*
   - Action: Priority remediation for new vulns

4. **Certificate Monitoring**
   - Query: org:"Example Corp" ssl.cert.expired:true
   - Query: org:"Example Corp" ssl.cert.expires:[next_30_days]
   - Action: Schedule renewals

5. **Compliance Check**
   - Run compliance-specific queries
   - Action: Document violations and remediate

6. **Generate Report**
   - Summarize changes
   - Highlight critical findings
   - Track metrics over time
```

## Key Performance Indicators

### Attack Surface Metrics

```markdown
- **Total Internet-Facing Assets**: Count of unique IPs
- **Critical Services Exposed**: RDP, SSH, databases, admin panels
- **Vulnerable Assets**: Count with known CVEs
- **Certificate Issues**: Expired or expiring soon
- **Configuration Issues**: Weak SSL, default credentials
- **Shadow IT**: Unauthorized assets
```

### Trend Analysis

Track over time:
- Asset count (increasing/decreasing?)
- Vulnerability exposure (improving/worsening?)
- Mean time to patch
- Certificate hygiene
- Service distribution changes

## Automated Monitoring Setup

### Daily Monitoring Tasks

```
1. Run baseline search
2. Compare with yesterday's results
3. Alert on:
   - New assets (> 5)
   - Critical vulns detected
   - Expired certificates
   - Unauthorized services
4. Log all changes
```

### Weekly Reporting

```
1. Aggregate daily findings
2. Generate trend graphs
3. Highlight top risks
4. Document remediation status
5. Share with stakeholders
```

### Monthly Review

```
1. Deep dive analysis
2. Attack surface assessment
3. Compliance audit
4. Security posture review
5. Budget planning for improvements
```

## Output Format

### Daily Monitoring Report

```markdown
# Daily Shodan Monitor Report - [Date]

## Changes Detected: [Count]

### New Assets [Count]
| IP | Hostname | Services | First Seen |
|----|----------|----------|------------|
| x.x.x.x | host.example.com | 80,443,22 | 2024-01-17 |

### Service Changes [Count]
| IP | Change Type | Details |
|----|-------------|---------|
| x.x.x.x | New Port | Port 3306 (MySQL) |

### Vulnerabilities [Count]
| IP | CVE | Severity | Service |
|----|-----|----------|---------|
| x.x.x.x | CVE-2024-XXXX | Critical | Apache 2.4.49 |

### Alerts
- 🔴 CRITICAL: 3 new critical vulnerabilities
- 🟡 WARNING: 2 certificates expiring in 7 days
- 🟢 INFO: 1 service upgrade detected
```

### Weekly Trend Report

```markdown
# Weekly Asset Monitor - Week of [Date]

## Summary
- Assets monitored: 1,234
- Changes detected: 45
- New assets: 3
- Vulnerabilities found: 12
- Certificates renewed: 5

## Trends
📈 Attack Surface: +0.2% (3 new assets)
📉 Vulnerabilities: -1.5% (18 patched, 12 new)
📊 Certificate Health: 98% valid

## Top Findings
1. Shadow IT: 2 unauthorized cloud instances
2. Critical Vuln: Log4j detected on staging server
3. Compliance: 1 PCI violation (telnet enabled)

## Actions Required
1. Investigate unauthorized AWS instances
2. Patch staging Log4j vulnerability
3. Disable telnet on payment server
```

## Integration Points

### SIEM Integration
- Export daily changes to SIEM
- Create correlation rules
- Alert on anomalies

### Ticketing System
- Auto-create tickets for critical findings
- Track remediation progress
- SLA monitoring

### Asset Management
- Update CMDB with discoveries
- Reconcile discrepancies
- Maintain accurate inventory

### Vulnerability Management
- Feed vulns to scanner
- Prioritize based on exposure
- Track remediation metrics

## Best Practices

1. **Consistent Scheduling**: Run queries same time daily/weekly
2. **Document Baseline**: Maintain clear baseline documentation
3. **Version Queries**: Track query changes over time
4. **False Positive Management**: Build exclusion lists
5. **Stakeholder Communication**: Regular reporting cadence
6. **Action Tracking**: Don't just report, track fixes
7. **Historical Retention**: Keep monitoring data for trends
8. **Query Optimization**: Refine queries based on findings

## Advanced Techniques

### Differential Analysis

```javascript
// Compare two time periods
const baseline = await shodan_host_search({
  query: 'org:"Example Corp"',
  page: 1
});

// Wait 7 days, then:
const current = await shodan_host_search({
  query: 'org:"Example Corp"',
  page: 1
});

// Identify:
// - new_assets = current - baseline
// - removed_assets = baseline - current
// - changed_assets = assets in both but with differences
```

### Anomaly Detection

Look for:
- Assets outside normal IP ranges
- Services on unexpected ports
- Unusual certificate patterns
- Geographic anomalies
- Hosting provider changes

### Predictive Monitoring

Track patterns to predict:
- Certificate renewal needs
- Patch cycles
- Infrastructure growth
- Budget requirements

## Compliance Use Cases

### PCI-DSS
Monitor for:
- Insecure protocols (telnet, FTP)
- Unnecessary services
- Weak encryption
- Segmentation violations

### HIPAA
Monitor for:
- Unencrypted health data
- Unauthorized access points
- Mobile devices
- Third-party connections

### SOC 2
Monitor for:
- System availability
- Access controls
- Change management
- Incident detection

### ISO 27001
Monitor for:
- Asset inventory completeness
- Vulnerability management
- Access control implementation
- Continuous monitoring evidence

## Troubleshooting

**Issue**: Too many false positives
```
Solution:
1. Refine queries to be more specific
2. Build exclusion lists
3. Tune alert thresholds
4. Focus on critical assets first
```

**Issue**: Missing changes
```
Solution:
1. Increase query frequency
2. Add more query variations
3. Monitor Shodan data freshness
4. Supplement with active scanning
```

**Issue**: Query credit exhaustion
```
Solution:
1. Use shodan_count before full searches
2. Implement query result caching
3. Prioritize critical queries
4. Consider API tier upgrade
```
