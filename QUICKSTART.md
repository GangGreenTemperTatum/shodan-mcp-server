# Shodan MCP Server - Quick Start Guide

Get up and running with Shodan MCP Server in 5 minutes.

## Prerequisites Checklist

- [ ] Node.js 18+ installed (`node --version`)
- [ ] Claude Desktop installed
- [ ] Shodan account created at [shodan.io](https://account.shodan.io/register)
- [ ] Shodan API key obtained

## Step 1: Installation (2 minutes)

```bash
# Navigate to the repository
cd /path/to/shodan-mcp-server

# Install dependencies
npm install
```

## Step 2: Configuration (2 minutes)

### Get Your API Key

1. Login to [Shodan](https://account.shodan.io/)
2. Copy your API key from the account page

### Configure Claude Desktop

**macOS**:
```bash
# Edit Claude config
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**Add this configuration**:
```json
{
  "mcpServers": {
    "shodan": {
      "command": "node",
      "args": ["/path/to/shodan-mcp-server/src/index.js"],
      "env": {
        "SHODAN_API_KEY": "YOUR_ACTUAL_API_KEY_HERE"
      }
    }
  }
}
```

Replace `YOUR_ACTUAL_API_KEY_HERE` with your real API key.

## Step 3: Install Skills (1 minute)

```bash
# Create skills directory if it doesn't exist
mkdir -p ~/.claude/skills

# Copy all skill directories
cp -r skills/*/ ~/.claude/skills/

# Or create symlinks for easier updates
ln -s /path/to/shodan-mcp-server/skills/shodan-recon ~/.claude/skills/
ln -s /path/to/shodan-mcp-server/skills/shodan-vuln-scan ~/.claude/skills/
ln -s /path/to/shodan-mcp-server/skills/shodan-threat-intel ~/.claude/skills/
ln -s /path/to/shodan-mcp-server/skills/shodan-asset-monitor ~/.claude/skills/
```

## Step 4: Restart Claude Desktop

Close and reopen Claude Desktop completely.

## Step 5: Test It! (30 seconds)

In Claude Desktop, try:

```
Check my Shodan API credits
```

Expected response: Claude will use the `shodan_api_info` tool to show your credits.

## Quick Usage Examples

### Example 1: Simple Host Search

```
Search Shodan for Apache servers in San Francisco
```

Claude will use `shodan_host_search` with query: `apache city:"San Francisco"`

### Example 2: Vulnerability Check

```
Find hosts vulnerable to Log4Shell (CVE-2021-44228)
```

Claude will search: `vuln:CVE-2021-44228`

### Example 3: DNS Lookup

```
Resolve the IP addresses for google.com and github.com
```

Claude will use `shodan_dns_lookup` tool.

### Example 4: Host Investigation

```
Get detailed information about IP address 8.8.8.8
```

Claude will use `shodan_host_info` tool.

## Common First-Time Issues

### Issue: Server not showing in Claude

**Solution:**
1. Check config file syntax (valid JSON?)
2. Verify file path is correct
3. Restart Claude Desktop completely (not just close window)
4. Check Claude Desktop logs

### Issue: API key error

**Solution:**
1. Verify API key is correct (copy/paste from Shodan)
2. Check for extra spaces or quotes
3. Ensure key is in correct config location
4. Test key manually:

```bash
export SHODAN_API_KEY="your_key"
node src/index.js
# Should start without errors
```

### Issue: No results returned

**Solution:**
1. Check your API credits: `/shodan api-info`
2. Try a simpler query first
3. Verify query syntax
4. Check if query requires paid API tier

## Next Steps

### Learn Query Syntax

Read the Shodan search guide:
- [Shodan Filters](https://www.shodan.io/search/filters)
- [Search Examples](https://www.shodan.io/search/examples)

### Try the Skills

Activate the skills by asking Claude:

```
Use shodan-recon skill to find assets for example.com
```

```
Use shodan-vuln-scan skill to assess vulnerabilities
```

```
Use shodan-threat-intel skill to find C2 infrastructure
```

### Advanced Usage

1. Combine multiple tools in workflows
2. Save common queries
3. Set up monitoring schedules
4. Integrate with other security tools

## Available Tools Quick Reference

| Tool | Purpose | Example |
|------|---------|---------|
| `shodan_host_search` | Search for hosts | Find web servers |
| `shodan_host_info` | Get IP details | Investigate specific IP |
| `shodan_dns_lookup` | Resolve domains | Convert domain to IPs |
| `shodan_dns_reverse` | Reverse lookup | Find domains for IP |
| `shodan_api_info` | Check credits | Monitor API usage |
| `shodan_exploits_search` | Find exploits | Search CVE exploits |
| `shodan_ports` | List ports | See crawled ports |
| `shodan_protocols` | List protocols | See supported protocols |
| `shodan_count` | Count results | Estimate query size |
| `shodan_query_search` | Find queries | Discover community queries |
| `shodan_query_tags` | Get tags | Browse popular tags |

## Pro Tips

1. **Start Simple**: Test with basic queries before complex ones
2. **Check Credits First**: Run `shodan_api_info` before large operations
3. **Use Facets**: Get aggregated data efficiently
4. **Combine Filters**: `org:"Company" port:80 country:US`
5. **Use Skills**: Let Claude automate complex workflows
6. **Monitor Usage**: Keep track of API credits
7. **Document Findings**: Save important results

## Getting Help

1. **Documentation**: Read the full [README.md](README.md)
2. **Shodan Docs**: [developer.shodan.io](https://developer.shodan.io/)
3. **Skills**: Check skill files for detailed workflows
4. **Examples**: See README for more query examples

## Security Reminder

⚠️ **Important**: Only use this tool for:
- ✅ Authorized security assessments
- ✅ Your own infrastructure
- ✅ Defensive security
- ✅ Threat intelligence
- ❌ Never for unauthorized reconnaissance
- ❌ Never for malicious purposes

## Success Checklist

- [ ] MCP server installed and configured
- [ ] API key working
- [ ] Skills installed
- [ ] Tested basic search
- [ ] Checked API credits
- [ ] Read documentation
- [ ] Understand query syntax
- [ ] Know security boundaries

## What's Next?

Now that you're set up, try these scenarios:

1. **Asset Discovery**: Map your organization's internet footprint
2. **Vulnerability Scan**: Find systems with known CVEs
3. **Threat Hunting**: Search for malicious infrastructure
4. **Monitoring**: Set up continuous asset monitoring
5. **Compliance**: Check for security policy violations

Happy hunting! 🔍
