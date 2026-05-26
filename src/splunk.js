import { Agent } from "undici";
import { config } from "./config.js";

// Scoped TLS bypass: only applied to Splunk requests when SPLUNK_INSECURE_TLS=true.
// Avoids the global NODE_TLS_REJECT_UNAUTHORIZED=0 footgun in the original code.
const dispatcher = config.splunk.insecureTls
  ? new Agent({ connect: { rejectUnauthorized: false } })
  : undefined;

export async function sendToSplunk(payload) {
  const response = await fetch(config.splunk.hecUrl, {
    method: "POST",
    headers: {
      Authorization: `Splunk ${config.splunk.token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(config.splunk.timeoutMs),
    dispatcher,
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      `Splunk HEC rejected log (HTTP ${response.status}): ${JSON.stringify(data)}`,
    );
  }

  return data;
}
