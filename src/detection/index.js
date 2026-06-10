import { config } from "../config.js";
import { regexDetector } from "./regex.js";
import { llmDetector } from "./llm.js";
import { merge } from "./merge.js";
import { redact } from "./redact.js";
import { maxSeverity } from "./severity.js";

export async function detectPII(message) {
  const llmStart = performance.now();
  const llmPromise = llmDetector(message, config.ollama).then((result) => ({
    result,
    ms: performance.now() - llmStart,
  }));

  const regexStart = performance.now();
  const regexFindings = regexDetector(message);
  const regexMs = performance.now() - regexStart;

  const { result: llmResult, ms: llmMs } = await llmPromise;

  const findings = merge(regexFindings, llmResult.findings);
  const redactedMessage = redact(message, findings);
  const severity = maxSeverity(findings);

  return {
    containsPII: findings.length > 0,
    redactedMessage,
    severity,
    findings,
    detectionMs: {
      regex: Math.round(regexMs * 100) / 100,
      llm: Math.round(llmMs * 100) / 100,
    },
    aiAudited: llmResult.error === null,
    aiError: llmResult.error,
  };
}
