import { severityFor } from "./severity.js";

const SYSTEM_PROMPT = `You are a Data Privacy Officer scanning a single log line for sensitive data. Identify entities in these categories: address, name, dob, password, phone, passport_or_national_id, medical_record, credit_card, ssn, api_key, private_key, jwt, oauth_token, iban, email, other.

Focus on contextual PII that a regex would miss (addresses, names, free-text passwords, DOBs, medical record contexts). The other categories are usually caught by regex — only include them when you see context regex would miss.

Return strict JSON of the form:
{ "findings": [ { "category": "<one of above>", "value": "<exact substring as it appears in the input>" } ] }

Use an empty array if nothing sensitive. Do not invent or modify substrings.

Examples:
Input: "Database connection established to PostgreSQL."
Output: {"findings": []}

Input: "Shipment address: 221B Baker Street, London NW1 6XE."
Output: {"findings": [{"category": "address", "value": "221B Baker Street, London NW1 6XE"}]}

Input: "User reset password to 'P@ssw0rd2024!'."
Output: {"findings": [{"category": "password", "value": "P@ssw0rd2024!"}]}

Input: "Healthcheck OK; uptime 14d 3h 22m."
Output: {"findings": []}`;

export async function llmDetector(message, options) {
  const { apiKey, model, timeoutMs } = options;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(timeoutMs),
      body: JSON.stringify({
        system_instruction: { parts: { text: SYSTEM_PROMPT } },
        contents: [{ parts: [{ text: message }] }],
        generationConfig: {
          response_mime_type: "application/json",
          temperature: 0.0,
        },
      }),
    });
  } catch (error) {
    const reason = error.name === "TimeoutError" ? "timeout" : "network";
    return { findings: [], error: reason };
  }

  if (!response.ok) {
    return { findings: [], error: `http_${response.status}` };
  }

  let data;
  try {
    data = await response.json();
  } catch {
    return { findings: [], error: "malformed_response" };
  }

  const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!rawText) {
    return { findings: [], error: "empty_response" };
  }

  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return { findings: [], error: "malformed_json" };
  }

  if (!parsed || !Array.isArray(parsed.findings)) {
    return { findings: [], error: "malformed_json" };
  }

  const findings = [];
  for (const item of parsed.findings) {
    if (!item || typeof item.category !== "string" || typeof item.value !== "string") continue;
    const start = message.indexOf(item.value);
    if (start === -1) continue;
    findings.push({
      category: item.category,
      source: "llm",
      start,
      end: start + item.value.length,
      severity: severityFor(item.category),
    });
  }
  return { findings, error: null };
}
