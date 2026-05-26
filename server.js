import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { config } from "./src/config.js";
import { detectPII } from "./src/detection/index.js";
import { sendToSplunk } from "./src/splunk.js";
import { triggerSecurityAlert } from "./src/alerts.js";
import { store as dashboardStore } from "./src/dashboard/store.js";
import { createDashboardRouter } from "./src/dashboard/routes.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dashboardHtmlPath = path.join(__dirname, "public", "dashboard.html");

console.log("[Init] Starting Privacy Guard Interceptor...");

const app = express();
app.use(express.json());
app.use(createDashboardRouter(dashboardStore, dashboardHtmlPath));

function validateLog(body) {
  if (!body || typeof body !== "object") return "body must be an object";
  if (typeof body.time !== "number") return "time must be a number";
  if (!body.event || typeof body.event !== "object") return "event missing";
  if (typeof body.event.message !== "string") return "event.message must be a string";
  if (typeof body.event.level !== "string") return "event.level must be a string";
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
      console.warn(`[Interceptor] Violation severity=${result.severity} categories=${categories}`);
      console.warn(`[Interceptor] Redacted: ${result.redactedMessage}`);
      triggerSecurityAlert(
        { reason: `${result.severity}: ${categories}` },
        event.level,
      );
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
    console.error("[Interceptor] Pipeline error:", error.message);
    res.status(502).json({ error: "Pipeline failure" });
  }
});

const server = app.listen(config.port, () => {
  console.log(
    `[Success] Privacy Guard Interceptor listening on http://localhost:${config.port}`,
  );
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    console.log(`\n[Shutdown] ${signal} received, closing server...`);
    server.close(() => process.exit(0));
  });
}
