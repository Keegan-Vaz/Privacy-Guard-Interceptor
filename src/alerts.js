import { config } from "./config.js";

export async function triggerSecurityAlert(aiResponse, originalLevel) {
  if (!config.alerts.webhookUrl) return;

  const payload = {
    text:
      `*Privacy Guard Alert*\n` +
      `*Severity:* ${originalLevel}\n` +
      `*Violation:* ${aiResponse.reason}\n` +
      `*Action Taken:* Log intercepted and redacted before indexing.`,
  };

  try {
    await fetch(config.alerts.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(config.alerts.timeoutMs),
    });
    console.log("[Webhook] Alert sent to engineering team.");
  } catch (error) {
    console.error("[Webhook] Failed to send alert:", error.message);
  }
}
