function required(name) {
  const value = process.env[name];
  if (!value || value.startsWith("PASTE_")) {
    throw new Error(`Missing required env var: ${name}`);
  }
  return value;
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  gemini: {
    apiKey: required("GEMINI_API_KEY"),
    model: "gemini-2.5-flash",
    timeoutMs: 8000,
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
};
