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
    description: 'Search Shodan for hosts matching a query. Returns detailed information about discovered hosts including IP addresses, ports, services, and vulnerabilities. Use for asset discovery and reconnaissance.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Shodan search query (e.g., "apache city:San Francisco", "port:22 country:US", "vuln:CVE-2021-44228")',
        },
        facets: {
          type: 'string',
          description: 'Optional comma-separated facets for aggregated results (e.g., "country,org,port")',
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
    description: 'Search for exploits in the Shodan Exploits database. Useful for finding known exploits for specific CVEs or software.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search query (e.g., "microsoft", "CVE-2021-44228", "type:webapps platform:linux")',
        },
        facets: {
          type: 'string',
          description: 'Optional facets for aggregation (e.g., "type,platform,author")',
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
    description: 'Get a list of port numbers that Shodan crawls on the Internet.',
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
    description: 'Get the total number of results for a search query without returning the actual results. Useful for scoping searches.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Shodan search query',
        },
        facets: {
          type: 'string',
          description: 'Optional facets for aggregated counts',
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'shodan_query_search',
    description: 'Search for saved Shodan queries shared by the community.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search term for queries',
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
    description: 'Get a list of popular tags for saved Shodan queries.',
    inputSchema: {
      type: 'object',
      properties: {
        size: {
          type: 'number',
          description: 'Number of tags to return (default: 10)',
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
