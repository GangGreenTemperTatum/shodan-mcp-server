---
name: shodan-recon
description: Perform comprehensive reconnaissance using Shodan. Use for asset discovery, network mapping, and identifying internet-facing systems. Triggers on requests for "recon", "reconnaissance", "asset discovery", "find hosts", or "map network".
---

# Shodan Reconnaissance Skill

Perform comprehensive reconnaissance and asset discovery using Shodan's extensive internet scanning database.

## When to Use

- User requests reconnaissance on a domain or organization
- Need to discover internet-facing assets
- Mapping an organization's attack surface
- Finding exposed services or systems
- Authorized security assessments

## Workflow

1. **Initial Scope**
   - Identify target (domain, organization, IP range)
   - Verify authorization for reconnaissance
   - Check Shodan API credits with `shodan_api_info`

2. **DNS Enumeration**
   - Use `shodan_dns_lookup` for domain resolution
   - Use `shodan_dns_reverse` for IP to hostname mapping

3. **Asset Discovery**
   - Use `shodan_host_search` with organization name
   - Common queries:
     - `org:"Company Name"`
     - `hostname:example.com`
     - `net:192.168.0.0/24`
     - `ssl:"example.com"`

4. **Port and Service Enumeration**
   - Analyze discovered hosts for open ports
   - Identify running services and versions
   - Check for common vulnerable services

5. **Detailed Host Analysis**
   - Use `shodan_host_info` for deep dive on interesting hosts
   - Include historical data for change tracking
   - Note vulnerabilities and weak configurations

6. **Reporting**
   - Summarize discovered assets
   - Highlight critical findings
   - Recommend next steps

## Example Queries

### Find Organization Assets
```
org:"Example Corp"
```

### Find Web Servers by Domain
```
hostname:example.com port:80,443
```

### Find Exposed Databases
```
"mongodb server information" port:27017 org:"Example Corp"
```

### Find VPN Gateways
```
ssl:"example.com" port:443 product:vpn
```

### Find Exposed Remote Access
```
port:3389 org:"Example Corp"  # RDP
port:22 org:"Example Corp"    # SSH
port:5900 org:"Example Corp"  # VNC
```

## Best Practices

1. Always verify authorization before reconnaissance
2. Start broad, then narrow down
3. Use facets to aggregate results efficiently
4. Cross-reference findings with other sources
5. Document all discovered assets
6. Respect rate limits and API quotas
7. Focus on actionable intelligence

## Output Format

Provide results in structured format:
- **Summary**: Total assets discovered
- **Critical Findings**: High-priority items
- **Asset Inventory**: Categorized list of discovered systems
- **Vulnerabilities**: Known CVEs or weak configurations
- **Recommendations**: Next steps for analysis or remediation
