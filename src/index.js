#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import shodan from 'shodan-client';

const SHODAN_API_KEY = process.env.SHODAN_API_KEY;

if (!SHODAN_API_KEY) {
  console.error('Error: SHODAN_API_KEY environment variable is required');
  process.exit(1);
}

const server = new Server(
  {
    name: 'shodan-mcp-server',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Tool definitions
const TOOLS = [
  {
    name: 'shodan_host_search',
    description: 'Search Shodan for hosts matching a query. Returns detailed information about discovered hosts including IP addresses, ports, services, and vulnerabilities. Use for asset discovery and reconnaissance.\n\nICS/SCADA Examples:\n- "port:502 tag:ics" - Modbus industrial control systems\n- "port:502 Siemens" - Siemens SCADA/PLCs\n- "port:502 \\"Schneider Electric\\"" - Schneider Modbus devices\n- "port:44818 \\"Allen-Bradley\\"" - Rockwell EtherNet/IP\n- "port:20000 tag:ics" - DNP3 utility SCADA\n- "port:102 S7" - Siemens S7 PLCs\n- "port:47808 BACnet" - Building automation\n- "port:4840 \\"OPC UA\\"" - Modern ICS protocol\n- "port:502 org:\\"Electric\\"" - Power infrastructure\n- "port:502 country:US has_vuln:true" - Vulnerable Modbus in US\n\nEffective Patterns:\n- Combine filters: "port:502 tag:ics country:US org:\\"Water\\""\n- Use facets for overview: facets="country,org,product"\n- Start broad, narrow down: "port:502" → "port:502 tag:ics" → "port:502 tag:ics Siemens"',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Shodan search query. General examples: "apache city:San Francisco", "port:22 country:US", "vuln:CVE-2021-44228". ICS/SCADA: "port:502 tag:ics" (Modbus), "port:20000" (DNP3), "port:44818" (EtherNet/IP), "port:102" (Siemens S7), "port:47808" (BACnet). Combine with org:"", country:, product:"", has_vuln:true',
        },
        facets: {
          type: 'string',
          description: 'Optional comma-separated facets for aggregated results. Common: "country,org,port,product". For ICS: "country,org,product" to see distribution. Use to get overview without burning credits.',
        },
        page: {
          type: 'number',
          description: 'Page number for pagination (default: 1)',
          default: 1,
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'shodan_host_info',
    description: 'Get detailed information about a specific host by IP address. Returns all services, open ports, vulnerabilities, and historical data.',
    inputSchema: {
      type: 'object',
      properties: {
        ip: {
          type: 'string',
          description: 'IP address to lookup (e.g., "8.8.8.8")',
        },
        history: {
          type: 'boolean',
          description: 'Include historical data (default: false)',
          default: false,
        },
      },
      required: ['ip'],
    },
  },
  {
    name: 'shodan_dns_lookup',
    description: 'Perform DNS lookups to resolve domain names to IP addresses.',
    inputSchema: {
      type: 'object',
      properties: {
        hostnames: {
          type: 'array',
          items: { type: 'string' },
          description: 'Array of hostnames to resolve (e.g., ["example.com", "google.com"])',
        },
      },
      required: ['hostnames'],
    },
  },
  {
    name: 'shodan_dns_reverse',
    description: 'Reverse DNS lookup to find hostnames associated with IP addresses.',
    inputSchema: {
      type: 'object',
      properties: {
        ips: {
          type: 'array',
          items: { type: 'string' },
          description: 'Array of IP addresses (e.g., ["8.8.8.8", "1.1.1.1"])',
        },
      },
      required: ['ips'],
    },
  },
  {
    name: 'shodan_api_info',
    description: 'Get information about the current API plan including query credits remaining and scan credits.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'shodan_exploits_search',
    description: 'Search for exploits in the Shodan Exploits database. Useful for finding known exploits for specific CVEs or software. Critical for ICS/SCADA security assessments.\n\nICS/SCADA Exploit Examples:\n- "Modbus" - Modbus protocol exploits\n- "SCADA" - General SCADA vulnerabilities\n- "Siemens" - Siemens PLC/SCADA exploits\n- "Schneider Electric" - Schneider vulnerabilities\n- "Allen-Bradley" - Rockwell exploits\n- "CVE-2019-6575" - Modbus simulator vulnerability\n- "CVE-2020-15782" - BACnet buffer overflow\n- "type:remote platform:hardware" - Hardware-specific\n- "ICS" - Industrial Control System exploits\n\nCommon ICS CVE Searches:\n- Modbus vulnerabilities: Often memory corruption, authentication bypass\n- SCADA exploits: Remote code execution, denial of service\n- PLC exploits: Ladder logic manipulation, configuration changes',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search query. General: "microsoft", "CVE-2021-44228". ICS/SCADA: "Modbus", "SCADA", "Siemens", "Schneider", "ICS". Filters: "type:remote", "platform:hardware", "platform:linux"',
        },
        facets: {
          type: 'string',
          description: 'Optional facets for aggregation. Common: "type,platform,author". For ICS: "type,platform" to see exploit categories.',
        },
        page: {
          type: 'number',
          description: 'Page number (default: 1)',
          default: 1,
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'shodan_ports',
    description: 'Get a list of port numbers that Shodan crawls on the Internet. Useful for discovering what protocols are monitored.\n\nKey ICS/SCADA Ports in Shodan:\n- 102: Siemens S7 PLCs\n- 502: Modbus TCP (most common ICS protocol)\n- 1911: Niagara Fox (building automation)\n- 2404: IEC 60870-5-104 (power systems)\n- 4840: OPC UA (modern ICS standard)\n- 20000: DNP3 (utilities/SCADA)\n- 44818: EtherNet/IP (Rockwell/Allen-Bradley)\n- 47808: BACnet (HVAC/building systems)\n\nUse this to verify Shodan monitors your target protocol.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'shodan_protocols',
    description: 'Get information about the protocols that Shodan supports for querying.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'shodan_count',
    description: 'Get the total number of results for a search query without returning the actual results. Useful for scoping searches before running full queries to avoid wasting API credits.\n\nBest Practice: Always use count first for large ICS/SCADA queries.\n\nExample Workflow:\n1. Count: "port:502 tag:ics" → 50,000 results\n2. Narrow: "port:502 tag:ics country:US" → 15,000 results  \n3. Refine: "port:502 tag:ics country:US org:\\"Electric\\"" → 500 results\n4. Then run full search on refined query\n\nUse with facets to see distribution without burning credits on full results.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Shodan search query. Same syntax as shodan_host_search. Examples: "port:502 tag:ics", "port:502 country:US", "tag:ics has_vuln:true"',
        },
        facets: {
          type: 'string',
          description: 'Optional facets for aggregated counts. Use to see distribution: "country,org,product". Shows breakdown without full results.',
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'shodan_query_search',
    description: 'Search for saved Shodan queries shared by the community. Useful for discovering popular query patterns and learning effective search techniques.\n\nPopular ICS/SCADA Query Topics:\n- "SCADA" - Find SCADA-related searches\n- "ICS" - Industrial control system queries\n- "Modbus" - Modbus protocol queries\n- "PLC" - Programmable logic controller searches\n- "industrial" - General industrial searches\n- "critical infrastructure" - Infrastructure queries\n\nUse community queries to:\n- Learn effective search patterns\n- Discover new reconnaissance techniques\n- Find popular vulnerability searches\n- Get ideas for your own queries',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search term for queries. Try: "SCADA", "ICS", "Modbus", "PLC", "industrial", "critical infrastructure"',
        },
        page: {
          type: 'number',
          description: 'Page number (default: 1)',
          default: 1,
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'shodan_query_tags',
    description: 'Get a list of popular tags for saved Shodan queries. Tags help discover trending search topics and common query categories.\n\nCommon ICS/SCADA Related Tags:\n- ics - Industrial Control Systems\n- scada - SCADA systems  \n- industrial - Industrial equipment\n- malware - Malware-infected systems\n- webcam - IP cameras (often in facilities)\n- default - Default credentials/configs\n\nUse to browse popular query categories and discover new search angles.',
    inputSchema: {
      type: 'object',
      properties: {
        size: {
          type: 'number',
          description: 'Number of tags to return (default: 10). Increase to 20-30 for comprehensive tag list.',
          default: 10,
        },
      },
    },
  },
];

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: TOOLS,
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'shodan_host_search': {
        const { query, facets, page = 1 } = args;
        const options = { page };
        if (facets) {
          options.facets = facets;
        }
        const results = await shodan.search(query, SHODAN_API_KEY, options);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                total: results.total,
                matches: results.matches.map(match => ({
                  ip: match.ip_str,
                  port: match.port,
                  org: match.org,
                  hostnames: match.hostnames,
                  domains: match.domains,
                  location: {
                    country: match.location?.country_name,
                    city: match.location?.city,
                  },
                  data: match.data,
                  vulns: match.vulns,
                  transport: match.transport,
                  product: match.product,
                  version: match.version,
                })),
                facets: results.facets,
              }, null, 2),
            },
          ],
        };
      }

      case 'shodan_host_info': {
        const { ip, history = false } = args;
        const hostInfo = await shodan.host(ip, SHODAN_API_KEY, { history });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                ip: hostInfo.ip_str,
                org: hostInfo.org,
                os: hostInfo.os,
                ports: hostInfo.ports,
                hostnames: hostInfo.hostnames,
                domains: hostInfo.domains,
                location: hostInfo.location,
                vulns: hostInfo.vulns,
                data: hostInfo.data,
                tags: hostInfo.tags,
                last_update: hostInfo.last_update,
              }, null, 2),
            },
          ],
        };
      }

      case 'shodan_dns_lookup': {
        const { hostnames } = args;
        const results = await shodan.dnsResolve(hostnames, SHODAN_API_KEY);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(results, null, 2),
            },
          ],
        };
      }

      case 'shodan_dns_reverse': {
        const { ips } = args;
        const results = await shodan.dnsReverse(ips, SHODAN_API_KEY);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(results, null, 2),
            },
          ],
        };
      }

      case 'shodan_api_info': {
        const info = await shodan.apiInfo(SHODAN_API_KEY);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                query_credits: info.query_credits,
                scan_credits: info.scan_credits,
                telnet: info.telnet,
                plan: info.plan,
                https: info.https,
                unlocked: info.unlocked,
              }, null, 2),
            },
          ],
        };
      }

      case 'shodan_exploits_search': {
        const { query, facets, page = 1 } = args;
        const options = { page };
        if (facets) {
          options.facets = facets;
        }
        const results = await shodan.exploits.search(query, SHODAN_API_KEY, options);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                total: results.total,
                matches: results.matches.map(match => ({
                  id: match._id,
                  description: match.description,
                  author: match.author,
                  type: match.type,
                  platform: match.platform,
                  date: match.date,
                  source: match.source,
                  cve: match.cve,
                })),
                facets: results.facets,
              }, null, 2),
            },
          ],
        };
      }

      case 'shodan_ports': {
        const ports = await shodan.ports(SHODAN_API_KEY);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(ports, null, 2),
            },
          ],
        };
      }

      case 'shodan_protocols': {
        const protocols = await shodan.protocols(SHODAN_API_KEY);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(protocols, null, 2),
            },
          ],
        };
      }

      case 'shodan_count': {
        const { query, facets } = args;
        const options = {};
        if (facets) {
          options.facets = facets;
        }
        const results = await shodan.count(query, SHODAN_API_KEY, options);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                total: results.total,
                facets: results.facets,
              }, null, 2),
            },
          ],
        };
      }

      case 'shodan_query_search': {
        const { query, page = 1 } = args;
        const results = await shodan.querySearch(query, SHODAN_API_KEY, { page });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                total: results.total,
                matches: results.matches.map(match => ({
                  title: match.title,
                  description: match.description,
                  query: match.query,
                  votes: match.votes,
                  tags: match.tags,
                })),
              }, null, 2),
            },
          ],
        };
      }

      case 'shodan_query_tags': {
        const { size = 10 } = args;
        const tags = await shodan.queryTags(SHODAN_API_KEY, { size });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(tags, null, 2),
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${error.message}`,
        },
      ],
      isError: true,
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Shodan MCP server running on stdio');
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
