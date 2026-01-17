---
name: shodan-threat-intel
description: Gather threat intelligence using Shodan. Use for tracking threat actors, identifying attack infrastructure, and monitoring emerging threats. Triggers on requests for "threat intelligence", "track attackers", "C2 servers", or "threat hunting".
---

# Shodan Threat Intelligence Skill

Leverage Shodan for threat intelligence gathering, tracking malicious infrastructure, and identifying emerging threats.

## When to Use

- Tracking command and control (C2) infrastructure
- Identifying malicious server patterns
- Monitoring for specific threat actor TTPs
- Investigating security incidents
- Proactive threat hunting
- IOC enrichment

## Workflow

1. **Intelligence Requirements**
   - Define intelligence objectives
   - Identify indicators of compromise (IOCs)
   - Determine threat actor TTPs to track

2. **Infrastructure Discovery**
   - Search for C2 server characteristics
   - Identify phishing infrastructure
   - Find malware distribution points
   - Locate cryptocurrency mining operations

3. **Pattern Analysis**
   - Analyze service configurations
   - Identify unique banners or certificates
   - Track infrastructure changes over time
   - Correlate multiple indicators

4. **Attribution Clues**
   - SSL certificate patterns
   - Unique server configurations
   - Hosting provider patterns
   - Geographic clustering

5. **Monitoring and Alerting**
   - Set up regular queries for new threats
   - Track changes to known infrastructure
   - Monitor for copycat infrastructure

6. **Intelligence Reporting**
   - Document findings with context
   - Provide actionable intelligence
   - Share IOCs in standard formats

## Threat Intelligence Queries

### C2 Infrastructure

#### Cobalt Strike
```
product:"Cobalt Strike"
ssl:"Cobalt Strike"
http.html:"Cobalt Strike"
```

#### Metasploit
```
"metasploit" port:4444
ssl.cert.subject.cn:"MetasploitSelfSignedCA"
```

#### Generic C2 Beacons
```
http.html:"beacon"
port:8443,8080,443 ssl.cert.subject.cn:"localhost"
```

### Phishing Infrastructure

```
http.title:"Microsoft" -org:"Microsoft"
http.title:"Login" ssl.cert.expired:true
http.title:"Amazon" -asn:AS16509
```

### Ransomware Infrastructure

```
http.html:"your files have been encrypted"
http.title:"ransom"
"onion" http.html:"bitcoin"
```

### Cryptominers

```
"stratum" port:3333
"xmrig"
http.html:"coinhive"
```

### Malware Distribution

```
http.html:".exe" title:"Index of"
port:80 "Content-Type: application/x-msdos-program"
```

### Suspicious Certificates

```
ssl.cert.subject.cn:"localhost" ssl.cert.expired:false
ssl.cert.serial:1
ssl.cert.subject.cn:"example.com"
```

### Botnets and DDoS

```
product:"Mirai"
"botnet" port:23
port:80 http.html:"DDoS"
```

### Tor Exit Nodes

```
"Tor" port:9001
```

### Open Proxies (Often Abused)

```
port:8080,3128 "Squid"
port:1080 "socks"
```

## IOC Enrichment

Use Shodan to enrich indicators:

1. **IP Address Enrichment**
   ```
   shodan_host_info for detailed host data
   - Services and versions
   - Hosting provider
   - Geographic location
   - Historical data
   ```

2. **Domain Enrichment**
   ```
   shodan_dns_lookup for resolution
   Then shodan_host_info on IPs
   ```

3. **SSL Certificate Tracking**
   ```
   ssl.cert.serial:XXXX
   ssl.cert.fingerprint:XXXX
   ```

## Advanced Threat Hunting

### Hunt for Specific Malware Families

```
# Find potential Zeus C&C
http.html:"gate.php" port:80

# Find potential Emotet infrastructure
ssl.cert.subject.cn:"localhost" port:443 country:RU

# Find potential APT infrastructure
ssl.cert.issuer.cn:"Acme Co" -org:"Acme Co"
```

### Track Threat Actor Infrastructure

```
# Track by ASN
asn:AS12345 ssl.cert.subject.cn:"*.badactor.com"

# Track by certificate patterns
ssl.cert.serial:XXXXX

# Track by unique server configs
http.html:"unique-string-from-ttp"
```

## Temporal Analysis

Track infrastructure over time:

1. Use historical data in `shodan_host_info`
2. Monitor for infrastructure changes
3. Identify infrastructure setup patterns
4. Track service migrations

## Output Format

```markdown
# Threat Intelligence Report

## Executive Summary
- Threat Type: [C2/Phishing/Malware/etc]
- Infrastructure Identified: X servers
- Active/Inactive: X/X
- Confidence Level: High/Medium/Low

## Infrastructure Details

### Server: [IP Address]
- **First Seen**: [Date]
- **Last Seen**: [Date]
- **Hosting**: [Provider, ASN, Country]
- **Services**: [Ports and services]
- **SSL Certificate**: [Details]
- **Associated Domains**: [List]
- **Indicators**: [Specific TTPs observed]

## Attribution Clues
- [Certificate patterns]
- [Hosting patterns]
- [Configuration similarities]

## IOCs
```csv
indicator_type,indicator_value,confidence,first_seen,last_seen
ip,192.0.2.1,high,2024-01-01,2024-01-15
domain,evil.example.com,high,2024-01-01,2024-01-15
ssl_cert_serial,XXXXX,medium,2024-01-01,2024-01-15
```

## Recommendations
1. Block IOCs at perimeter
2. Hunt for IOCs in environment
3. Monitor for similar patterns
4. Share intelligence with community
```

## Integration Points

- **SIEM**: Feed IOCs for alerting
- **Threat Intel Platforms**: Export in STIX/TAXII format
- **Firewall/IDS**: Blocklist generation
- **EDR**: Hunt for related artifacts

## Best Practices

1. Verify findings before attribution
2. Consider false positives (legitimate services)
3. Track infrastructure lifecycle
4. Correlate with other intelligence sources
5. Document methodology for reproducibility
6. Share responsibly with security community
7. Respect privacy and legal boundaries
8. Use VPN/proxy when investigating active threats

## Operational Security

When investigating active threats:
- Use isolated analysis environment
- Avoid direct connection to suspicious IPs
- Don't trigger defensive mechanisms
- Document all interactions
- Follow incident response procedures
