function required(name) {
  const value = process.env[name];
  if (!value || value.startsWith("PASTE_")) {
    throw new Error(`Missing required env var: ${name}`);
  }
  return value;
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  ollama: {
    url: process.env.OLLAMA_URL || "http://localhost:11434",
    model: process.env.OLLAMA_MODEL || "llama3",
    timeoutMs: Number(process.env.OLLAMA_TIMEOUT_MS || 15000),
  },
  splunk: {
    hecUrl: required("SPLUNK_HEC_URL"),
    token: required("SPLUNK_TOKEN"),
    insecureTls: process.env.SPLUNK_INSECURE_TLS === "true",
    timeoutMs: 5000,
  },
  alerts: {
    webhookUrl: process.env.SLACK_WEBHOOK_URL || null,
    timeoutMs: 3000,
  },
  // New configuration sections for agentic enhancements
  splunkSearch: {
    restUrl: process.env.SPLUNK_REST_URL || null,
    apiToken: process.env.SPLUNK_API_TOKEN || null,
    index: process.env.SPLUNK_SEARCH_INDEX || 'main',
    timeoutMs: Number(process.env.SPLUNK_SEARCH_TIMEOUT_MS || 15000),
  },
  mcp: {
    enabled: process.env.MCP_ENABLED === 'true',
    port: Number(process.env.MCP_PORT || 3001),
  },
  trendAnalysis: {
    enabled: process.env.TREND_ANALYSIS_ENABLED === 'true',
    intervalMs: Number(process.env.TREND_ANALYSIS_INTERVAL_MS || 60000),
    windowSize: Number(process.env.TREND_ANALYSIS_WINDOW_SIZE || 50),
  },
};