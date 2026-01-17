# Shodan MCP Server (stdio)

Model Context Protocol (MCP) server integration for Shodan API, enabling Claude AI to perform comprehensive security reconnaissance, vulnerability assessment, and threat intelligence gathering.

## Features

- **Comprehensive Host Search**: Search Shodan's database of internet-connected devices
- **Detailed Host Information**: Get in-depth data about specific IP addresses
- **DNS Operations**: Forward and reverse DNS lookups
- **Vulnerability Discovery**: Find hosts with specific CVEs and security issues
- **Exploit Database**: Search for available exploits
- **API Management**: Monitor query credits and usage
- **Protocol/Port Information**: Access Shodan's supported protocols and ports

## Prerequisites

- Node.js 18.0.0 or higher
- Shodan API key ([Get one here](https://account.shodan.io/))
- Claude Desktop or compatible MCP client

## Installation

### 1. Clone and Install Dependencies

```bash
cd /path/to/shodan-mcp-server
npm install
```

### 2. Get Shodan API Key

1. Sign up at [shodan.io](https://account.shodan.io/register)
2. Navigate to [Account](https://account.shodan.io/)
3. Copy your API key

### 3. Configure Environment

Create a `.env` file:

```bash
echo "SHODAN_API_KEY=your_api_key_here" > .env
```

### 4. Configure Claude Desktop

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "shodan": {
      "command": "node",
      "args": ["/path/to/shodan-mcp-server/src/index.js"],
      "env": {
        "SHODAN_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

## Available Tools

### shodan_host_search
Search Shodan for hosts matching a query.

**Parameters:**
- `query` (required): Shodan search query
- `facets` (optional): Comma-separated facets for aggregation
- `page` (optional): Page number for pagination

**Example:**
```
Query: "apache country:US"
Facets: "country,org,port"
```

### shodan_host_info
Get detailed information about a specific IP address.

**Parameters:**
- `ip` (required): IP address to lookup
- `history` (optional): Include historical data

**Example:**
```
IP: "8.8.8.8"
History: true
```

### shodan_dns_lookup
Resolve domain names to IP addresses.

**Parameters:**
- `hostnames` (required): Array of hostnames

**Example:**
```
Hostnames: ["example.com", "google.com"]
```

### shodan_dns_reverse
Perform reverse DNS lookup on IP addresses.

**Parameters:**
- `ips` (required): Array of IP addresses

**Example:**
```
IPs: ["8.8.8.8", "1.1.1.1"]
```

### shodan_api_info
Get information about your API plan and remaining credits.

**Parameters:** None

### shodan_exploits_search
Search the Shodan Exploits database.

**Parameters:**
- `query` (required): Search query
- `facets` (optional): Facets for aggregation
- `page` (optional): Page number

**Example:**
```
Query: "CVE-2021-44228"
Facets: "type,platform"
```

### shodan_ports
Get list of ports that Shodan crawls.

**Parameters:** None

### shodan_protocols
Get supported protocols for querying.

**Parameters:** None

### shodan_count
Get total count of results for a query without returning data.

**Parameters:**
- `query` (required): Shodan search query
- `facets` (optional): Facets for aggregated counts

### shodan_query_search
Search for saved community queries.

**Parameters:**
- `query` (required): Search term
- `page` (optional): Page number

### shodan_query_tags
Get popular tags for saved queries.

**Parameters:**
- `size` (optional): Number of tags to return (default: 10)

## Shodan Query Syntax

### Basic Filters

```
city:"San Francisco"          - Filter by city
country:US                    - Filter by country code
org:"Google"                  - Filter by organization
net:192.168.0.0/24           - Filter by IP range
port:22                       - Filter by port
product:Apache               - Filter by product name
version:2.4.1                - Filter by version
os:"Windows 10"              - Filter by operating system
```

### Vulnerability Filters

```
vuln:CVE-2021-44228          - Search for specific CVE
vuln:CVE-2020-*              - Search for CVEs from 2020
```

### HTTP Filters

```
http.title:"Admin Panel"      - Filter by page title
http.html:"password"          - Search in HTML content
http.status:200               - Filter by HTTP status
http.component:"wordpress"    - Filter by web component
```

### SSL Filters

```
ssl:"example.com"             - Search by SSL certificate
ssl.cert.expired:true         - Find expired certificates
ssl.version:sslv2            - Filter by SSL version
ssl.cipher:export            - Find weak ciphers
```

### Combining Filters

```
port:22 country:US org:"Amazon"
apache city:"Los Angeles" vuln:CVE-2021-44228
```

## Usage Examples

### 1. Asset Discovery

```javascript
// Find all assets for an organization
{
  "query": "org:\"Example Corp\"",
  "facets": "country,port,product"
}
```

### 2. Vulnerability Assessment

```javascript
// Find systems vulnerable to Log4Shell
{
  "query": "vuln:CVE-2021-44228 country:US",
  "page": 1
}
```

### 3. Threat Intelligence

```javascript
// Find potential C2 infrastructure
{
  "query": "product:\"Cobalt Strike\"",
  "facets": "country,org"
}
```

### 4. DNS Investigation

```javascript
// Resolve multiple domains
{
  "hostnames": [
    "example.com",
    "suspicious-domain.com"
  ]
}
```

### 5. Exploit Research

```javascript
// Find exploits for a CVE
{
  "query": "CVE-2021-44228",
  "facets": "type,platform,author"
}
```

## Skills

Three comprehensive skills are included:

### 1. shodan-recon
Perform reconnaissance and asset discovery. Automates the process of:
- DNS enumeration
- Asset discovery
- Port and service enumeration
- Detailed host analysis
- Comprehensive reporting

### 2. shodan-vuln-scan
Identify and assess vulnerabilities. Includes:
- CVE discovery
- Exploit availability checking
- Risk assessment
- Remediation recommendations
- Vulnerability matrix generation

### 3. shodan-threat-intel
Gather threat intelligence. Capabilities:
- C2 infrastructure tracking
- Phishing infrastructure identification
- Malware distribution point discovery
- IOC enrichment
- Threat actor tracking
- Temporal analysis

## Development

### Running in Development

```bash
npm run dev
```

### Testing Tools

```bash
# Test the server manually
node src/index.js

# In another terminal, send test requests
# (requires MCP client for full testing)
```

### Adding New Tools

1. Add tool definition to `TOOLS` array in `src/index.js`
2. Add case handler in `CallToolRequestSchema` handler
3. Update README with new tool documentation

## Resources

- [Shodan Official Documentation](https://developer.shodan.io/)
- [Shodan Search Query Guide](https://www.shodan.io/search/filters)
- [Shodan Filters Reference](https://www.shodan.io/search/filters)
- [MCP Protocol Documentation](https://modelcontextprotocol.io/)
