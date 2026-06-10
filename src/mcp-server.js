import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";

/**
 * MCP Server for Privacy Guard Interceptor
 * 
 * Exposes interceptor capabilities as MCP tools for AI assistants.
 */
export class McpServer {
  /**
   * Create a new MCP server.
   * 
   * @param {Object} options - Server options
   * @param {number} options.port - Port to listen on (default: 3001)
   * @param {Function} options.detectPII - Reference to detectPII() function
   * @param {Object} options.dashboardStore - Dashboard store instance
   * @param {Function} options.splGenerator - SPL generator function
   * @param {Function} options.splunkSearch - Splunk search client
   */
  constructor({ port = 3001, detectPII, dashboardStore, splGenerator, splunkSearch }) {
    this.port = port;
    this.detectPII = detectPII;
    this.dashboardStore = dashboardStore;
    this.splGenerator = splGenerator;
    this.splunkSearch = splunkSearch;
    this.server = null;
    this.transport = null;
  }

  /**
   * Start the MCP server.
   */
  async start() {
    console.log(`[MCP Server] Starting on port ${this.port}...`);
    
    // Create server instance
    this.server = new Server(
      {
        name: "privacy-guard-interceptor",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Register tool handlers
    this._registerTools();

    // Set up error handling
    this.server.onerror = (error) => {
      console.error("[MCP Server] Error:", error);
    };

    // Create SSE transport (HTTP/SSE for server compatibility)
    this.transport = new SSEServerTransport({
      pathPattern: "/mcp",
      port: this.port,
    });

    // Connect server to transport
    await this.server.connect(this.transport);

    console.log(`[MCP Server] Ready on http://localhost:${this.port}/mcp`);
  }

  /**
   * Stop the MCP server.
   */
  async stop() {
    if (this.transport) {
      await this.transport.close();
      this.transport = null;
    }
    
    if (this.server) {
      // Note: Server doesn't have a close method in SDK
      this.server = null;
    }
    
    console.log("[MCP Server] Stopped");
  }

  /**
   * Register all MCP tools.
   */
  _registerTools() {
    // Tool 1: intercept_log
    this.server.setRequestHandler("tools/call", async (request) => {
      const { name, arguments: args } = request.params;
      
      try {
        switch (name) {
          case "intercept_log":
            return await this._handleInterceptLog(args);
          case "query_violations":
            return await this._handleQueryViolations(args);
          case "get_dashboard_snapshot":
            return await this._handleGetDashboardSnapshot(args);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error: ${error.message}`,
            },
          ],
          isError: true,
        };
      }
    });

    // Tool list
    this.server.setRequestHandler("tools/list", async () => {
      return {
        tools: [
          {
            name: "intercept_log",
            description: "Scan a log message for PII and redact it",
            inputSchema: {
              type: "object",
              properties: {
                message: {
                  type: "string",
                  description: "Log message to scan for PII",
                },
                level: {
                  type: "string",
                  description: "Log level (INFO, WARN, ERROR, etc.)",
                  default: "INFO",
                },
              },
              required: ["message"],
            },
          },
          {
            name: "query_violations",
            description: "Ask a natural-language question about violation history",
            inputSchema: {
              type: "object",
              properties: {
                question: {
                  type: "string",
                  description: "Natural language question about violation history",
                },
              },
              required: ["question"],
            },
          },
          {
            name: "get_dashboard_snapshot",
            description: "Get current dashboard statistics and recent records",
            inputSchema: {
              type: "object",
              properties: {
                limit: {
                  type: "number",
                  description: "Maximum number of recent records to return",
                  default: 10,
                },
              },
            },
          },
        ],
      };
    });
  }

  /**
   * Handle intercept_log tool call.
   */
  async _handleInterceptLog(args) {
    const { message, level = "INFO" } = args;
    
    if (!message || typeof message !== "string") {
      throw new Error("message parameter is required and must be a string");
    }
    
    console.log(`[MCP Server:intercept_log] Scanning message: ${message.substring(0, 100)}...`);
    
    const result = await this.detectPII(message);
    
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            containsPII: result.containsPII,
            severity: result.severity,
            redactedMessage: result.redactedMessage,
            categories: result.findings.map(f => f.category),
            sources: result.findings.map(f => f.source),
            aiAudited: result.aiAudited,
            aiError: result.aiError,
            detectionMs: result.detectionMs,
          }, null, 2),
        },
      ],
    };
  }

  /**
   * Handle query_violations tool call.
   */
  async _handleQueryViolations(args) {
    const { question } = args;
    
    if (!question || typeof question !== "string") {
      throw new Error("question parameter is required and must be a string");
    }
    
    console.log(`[MCP Server:query_violations] Processing question: ${question.substring(0, 100)}...`);
    
    // Check if SPL generator and Splunk search are available
    if (!this.splGenerator || !this.splunkSearch) {
      throw new Error("SPL query feature not available (SPLUNK_REST_URL and SPLUNK_API_TOKEN required)");
    }
    
    try {
      // Generate SPL from question
      const splResult = await this.splGenerator.generateSplFromQuestion(question);
      
      // Execute SPL query
      const results = await this.splunkSearch.executeSplQuery(splResult.spl);
      
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              question,
              spl: splResult.spl,
              resultsCount: results.length,
              results: results.slice(0, 20), // Limit to first 20 results
              confidence: splResult.confidence,
            }, null, 2),
          },
        ],
      };
      
    } catch (error) {
      throw new Error(`Query failed: ${error.message}`);
    }
  }

  /**
   * Handle get_dashboard_snapshot tool call.
   */
  async _handleGetDashboardSnapshot(args) {
    const { limit = 10 } = args;
    
    if (!this.dashboardStore || typeof this.dashboardStore.getSnapshot !== "function") {
      throw new Error("Dashboard store not available");
    }
    
    console.log(`[MCP Server:get_dashboard_snapshot] Getting snapshot with limit ${limit}`);
    
    const snapshot = this.dashboardStore.getSnapshot();
    
    // Apply limit to recent records
    const limitedRecent = snapshot.recent.slice(0, limit);
    
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            counters: snapshot.counters,
            severityCounts: snapshot.severityCounts,
            categoryCounts: snapshot.categoryCounts,
            recent: limitedRecent,
            totalRecords: snapshot.recent.length,
            limitedTo: limit,
          }, null, 2),
        },
      ],
    };
  }
}

/**
 * Start the MCP server with the given dependencies.
 * 
 * @param {Object} config - MCP server configuration
 * @param {Object} dependencies - Required dependencies
 * @returns {Promise<McpServer>} Started MCP server instance
 */
export async function startMcpServer(config, dependencies) {
  const server = new McpServer({
    port: config.port,
    ...dependencies,
  });
  
  await server.start();
  return server;
}