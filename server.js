import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { config } from "./src/config.js";
import { detectPII } from "./src/detection/index.js";
import { sendToSplunk } from "./src/splunk.js";
import { triggerSecurityAlert } from "./src/alerts.js";
import { store as dashboardStore } from "./src/dashboard/store.js";
import { createDashboardRouter } from "./src/dashboard/routes.js";
import { generateSplFromQuestion } from "./src/spl-generator.js";
import { executeSplQuery } from "./src/splunk-search.js";
import { RemediationAgent } from "./src/remediation-agent.js";
import { startMcpServer } from "./src/mcp-server.js";
import { TrendAnalyzer } from "./src/trend-analyzer.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dashboardHtmlPath = path.join(__dirname, "public", "dashboard.html");

console.log("[Init] Starting Privacy Guard Interceptor...");

// Feature availability validation
const features = {
  spl_query: config.splunkSearch.restUrl && config.splunkSearch.apiToken,
  remediation_agent:
    config.splunkSearch.restUrl && config.splunkSearch.apiToken,
  mcp_server: config.mcp.enabled,
  trend_analyzer: config.trendAnalysis.enabled,
};

console.log("[Config] Feature availability:");
for (const [feature, enabled] of Object.entries(features)) {
  console.log(`  ${feature}: ${enabled ? "ENABLED" : "DISABLED"}`);
  if (!enabled) {
    switch (feature) {
      case "spl_query":
      case "remediation_agent":
        if (!config.splunkSearch.restUrl || !config.splunkSearch.apiToken) {
          console.log(
            `    [Warning] Splunk REST API not configured: SPLUNK_REST_URL and SPLUNK_API_TOKEN required`,
          );
        }
        break;
      case "mcp_server":
        if (!config.mcp.enabled) {
          console.log(
            `    [Info] MCP server disabled: Set MCP_ENABLED="true" to enable`,
          );
        }
        break;
      case "trend_analyzer":
        if (!config.trendAnalysis.enabled) {
          console.log(
            `    [Info] Trend analysis disabled: Set TREND_ANALYSIS_ENABLED="true" to enable`,
          );
        }
        break;
    }
  }
}

// Feature initialization:
// - SPL query endpoint (/api/ai/query) is added only if features.spl_query
// - Remediation agent triggers automatically on critical violations if features.remediation_agent
// - MCP server is started only if features.mcp_server
// - Trend analyzer is started only if features.trend_analyzer

const app = express();
app.use(express.json());
app.use(createDashboardRouter(dashboardStore, dashboardHtmlPath));

function validateLog(body) {
  if (!body || typeof body !== "object") return "body must be an object";
  if (typeof body.time !== "number") return "time must be a number";
  if (!body.event || typeof body.event !== "object") return "event missing";
  if (typeof body.event.message !== "string")
    return "event.message must be a string";
  if (typeof body.event.level !== "string")
    return "event.level must be a string";
  return null;
}

app.post("/api/intercept", async (req, res) => {
  const validationError = validateLog(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  const { time, event } = req.body;
  console.log(`\n[Interceptor] Received: ${event.message}`);

  try {
    const result = await detectPII(event.message);

    try {
      dashboardStore.record({
        ts: time,
        level: event.level,
        originalMessage: event.message,
        redactedMessage: result.redactedMessage,
        severity: result.severity,
        categories: result.findings.map((f) => f.category),
        sources: result.findings.map((f) => f.source),
        aiAudited: result.aiAudited,
        aiError: result.aiError,
        detectionMs: result.detectionMs,
      });
    } catch (err) {
      console.warn("[Dashboard] record failed:", err.message);
    }

    if (result.containsPII) {
      const categories = result.findings.map((f) => f.category).join(", ");
      console.warn(
        `[Interceptor] Violation severity=${result.severity} categories=${categories}`,
      );
      console.warn(`[Interceptor] Redacted: ${result.redactedMessage}`);
      triggerSecurityAlert(
        { reason: `${result.severity}: ${categories}` },
        event.level,
      );

      // Trigger remediation agent for critical violations
      if (result.severity === "critical" && features.remediation_agent) {
        console.log(
          `[Interceptor] Triggering remediation agent for critical violation`,
        );
        try {
          await RemediationAgent.trigger(req.body, result);
        } catch (agentError) {
          console.warn(
            "[Interceptor] Remediation agent trigger failed:",
            agentError.message,
          );
          // Don't fail the intercept pipeline if agent fails
        }
      }
    } else {
      console.log("[Interceptor] Safe log passed.");
    }

    const cleanPayload = {
      time,
      event: {
        level: event.level,
        message: result.redactedMessage,
        ai_audited: result.aiAudited,
        ai_error: result.aiError,
        violation_flag: result.containsPII,
        violation_severity: result.severity,
        violation_categories: result.findings.map((f) => f.category),
        violation_sources: result.findings.map((f) => f.source),
        detection_ms_regex: result.detectionMs.regex,
        detection_ms_llm: result.detectionMs.llm,
      },
    };

    const splunkData = await sendToSplunk(cleanPayload);
    res.status(200).json({ status: "Processed", splunk_response: splunkData });
  } catch (error) {
    console.error("[Interceptor] Pipeline error:", error.stack ?? error.message);
    if (error.cause) console.error("[Interceptor] Caused by:", error.cause);
    res.status(502).json({ error: "Pipeline failure" });
  }
});

// Add /api/ai/query endpoint only if SPL query feature is enabled
if (features.spl_query) {
  app.post("/api/ai/query", async (req, res) => {
    console.log(
      `\n[AI Query] Received question: ${req.body.question?.substring(0, 100)}${req.body.question?.length > 100 ? "..." : ""}`,
    );

    // Validate request
    if (!req.body || typeof req.body !== "object") {
      return res
        .status(400)
        .json({ error: "Request body must be a JSON object" });
    }

    const { question } = req.body;

    if (
      !question ||
      typeof question !== "string" ||
      question.trim().length === 0
    ) {
      return res.status(400).json({
        error: "Question field is required and must be a non-empty string",
      });
    }

    try {
      // Generate SPL from question using Gemini
      console.log("[AI Query] Generating SPL from question...");
      const splResult = await generateSplFromQuestion(question, {
        index: config.splunkSearch.index,
      });

      console.log(`[AI Query] Generated SPL: ${splResult.spl}`);
      console.log(`[AI Query] Confidence: ${splResult.confidence.toFixed(2)}`);

      // Execute SPL query against Splunk
      console.log("[AI Query] Executing SPL query against Splunk...");
      const results = await executeSplQuery(splResult.spl, {
        index: config.splunkSearch.index,
        timeoutMs: config.splunkSearch.timeoutMs,
      });

      console.log(
        `[AI Query] Query completed successfully, returned ${results.length} results`,
      );

      // Return structured response
      return res.status(200).json({
        question: question,
        spl: splResult.spl,
        results: results,
        confidence: splResult.confidence,
        metadata: {
          results_count: results.length,
          splunk_index: config.splunkSearch.index,
        },
      });
    } catch (error) {
      console.error("[AI Query] Error:", error.message);

      // Determine error type for appropriate HTTP status code
      if (
        error.message.includes("Gemini") ||
        error.message.includes("API key not configured")
      ) {
        return res.status(502).json({
          error: "spl_generation_failed",
          reason: error.message,
        });
      } else if (
        error.message.includes("Splunk") ||
        error.message.includes("SPLUNK_REST_URL") ||
        error.message.includes("SPLUNK_API_TOKEN")
      ) {
        return res.status(502).json({
          error: "splunk_search_failed",
          reason: error.message,
        });
      } else {
        // Generic error
        return res.status(500).json({
          error: "internal_server_error",
          reason: error.message,
        });
      }
    }
  });

  console.log(`[Route] /api/ai/query endpoint enabled (SPL query feature)`);
} else {
  console.log(
    `[Route] /api/ai/query endpoint disabled (SPL query feature requires SPLUNK_REST_URL and SPLUNK_API_TOKEN)`,
  );
}

// Initialize features after server starts
const server = app.listen(config.port, () => {
  console.log(
    `[Success] Privacy Guard Interceptor listening on http://localhost:${config.port}`,
  );

  // Initialize MCP server if enabled (async)
  if (features.mcp_server) {
    startMcpServer(config.mcp, {
      detectPII,
      dashboardStore,
      splGenerator: { generateSplFromQuestion },
      splunkSearch: { executeSplQuery },
    })
      .then((mcpServerInstance) => {
        console.log(`[MCP Server] Started on port ${config.mcp.port}`);
        server.mcpServerInstance = mcpServerInstance;
      })
      .catch((error) => {
        console.error(`[MCP Server] Failed to start:`, error.message);
      });
  }

  // Initialize Trend Analyzer if enabled
  if (features.trend_analyzer) {
    try {
      // Create broadcast callback that uses dashboard store's broadcast method
      const broadcastCallback = async (anomalyAlerts) => {
        if (dashboardStore.broadcastAnomalyAlerts) {
          dashboardStore.broadcastAnomalyAlerts(anomalyAlerts);
        }
      };

      const trendAnalyzerInstance = new TrendAnalyzer(
        dashboardStore,
        broadcastCallback,
      );
      trendAnalyzerInstance.start();
      server.trendAnalyzerInstance = trendAnalyzerInstance;
      console.log(
        `[Trend Analyzer] Started with ${config.trendAnalysis.intervalMs}ms interval`,
      );
    } catch (error) {
      console.error(`[Trend Analyzer] Failed to start:`, error.message);
    }
  }
});

// Graceful shutdown handlers
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    console.log(`\n[Shutdown] ${signal} received, closing server...`);

    // Stop MCP server
    if (server.mcpServerInstance) {
      server.mcpServerInstance.stop().catch((err) => {
        console.error("[Shutdown] Error stopping MCP server:", err.message);
      });
    }

    // Stop Trend Analyzer
    if (server.trendAnalyzerInstance) {
      server.trendAnalyzerInstance.stop();
    }

    server.close(() => process.exit(0));
  });
}
