import { config } from "./config.js";

const SYSTEM_PROMPT = `You are a Splunk Query Assistant. Your task is to translate natural language questions about log violation data into valid Splunk Processing Language (SPL) queries.

## Context
- Splunk index name: "main" (unless otherwise specified)
- Available fields in the data:
  - \`violation_severity\` (critical, high, medium, low, none)
  - \`violation_categories\` (array of strings: credit_card, ssn, api_key, private_key, password, jwt, oauth_token, iban, dob, passport_or_national_id, medical_record, address, phone, email, name, other)
  - \`violation_sources\` (array of strings: regex, llm)
  - \`violation_flag\` (boolean: true if any PII detected)
  - \`ai_audited\` (boolean: true if Gemini successfully analyzed the log)
  - \`ai_error\` (string or null: reason if Gemini failed)
  - \`time\` (epoch timestamp)
  - \`event.level\` (string: INFO, WARN, ERROR, etc.)
  - \`event.message\` (string: redacted log message)

## Rules
1. Generate ONLY the SPL query string, nothing else.
2. Use proper SPL syntax: start with \`search index="main"\` or \`search index=main\`.
3. Include time ranges when relevant: \`earliest=-1h\`, \`earliest=-24h\`, \`earliest=-7d\`, etc.
4. Use field names exactly as shown above.
5. For array fields, use \`mvfind()\` or \`like()\` operators.
6. Always include a \`stats\` or \`timechart\` command when asking for counts or trends.
7. Return the query ready to execute — no explanations, no markdown formatting.

## Examples

Input: "show me critical violations in the last hour by category"
Output: \`search index="main" violation_severity="critical" earliest=-1h | stats count by violation_categories\`

Input: "how many high severity violations detected by regex in the last 24 hours"
Output: \`search index="main" violation_severity="high" mvfind(violation_sources, "regex") earliest=-24h | stats count\`

Input: "trend of password violations over the last week"
Output: \`search index="main" mvfind(violation_categories, "password") earliest=-7d | timechart span=1d count\`

Input: "what are the top 5 violation categories from the last 30 days"
Output: \`search index="main" earliest=-30d | stats count by violation_categories | sort -count | head 5\`

Input: "show me logs where AI audit failed in the last 2 hours"
Output: \`search index="main" ai_audited=false earliest=-2h\`

Now translate the following question:`;

/**
 * Generate a SPL query from a natural language question using Gemini.
 * 
 * @param {string} question - Natural language question about violation data
 * @param {Object} context - Additional context for the query
 * @param {string} context.index - Splunk index to use (defaults to config.splunkSearch.index)
 * @returns {Promise<{spl: string, confidence: number, rawResponse: object}>}
 */
export async function generateSplFromQuestion(question, context = {}) {
  const { index = config.splunkSearch.index } = context;
  
  if (!config.gemini.apiKey) {
    throw new Error("Gemini API key not configured");
  }

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${config.gemini.model}:generateContent?key=${config.gemini.apiKey}`;
  
  // Update system prompt with actual index from context
  const actualPrompt = SYSTEM_PROMPT.replace(/index="main"/g, `index="${index}"`) + `\n\n"${question}"`;

  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(config.gemini.timeoutMs),
      body: JSON.stringify({
        system_instruction: { parts: { text: actualPrompt } },
        contents: [{ parts: [{ text: question }] }],
        generationConfig: {
          response_mime_type: "text/plain",
          temperature: 0.0,
        },
      }),
    });
  } catch (error) {
    const reason = error.name === "TimeoutError" ? "timeout" : "network";
    throw new Error(`Gemini API ${reason} error: ${error.message}`);
  }

  if (!response.ok) {
    const errorText = await response.text().catch(() => `HTTP ${response.status}`);
    throw new Error(`Gemini API HTTP error ${response.status}: ${errorText}`);
  }

  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("Failed to parse Gemini response as JSON");
  }

  const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!rawText) {
    throw new Error("Gemini returned empty response");
  }

  // Clean up the response: remove markdown code blocks, trim whitespace
  let spl = rawText.trim();
  
  // Remove markdown code blocks if present
  spl = spl.replace(/^```(?:spl)?\s*/i, "").replace(/\s*```$/, "");
  
  // Remove any explanatory text after the query (look for newlines after query)
  const queryEnd = spl.indexOf("\n\n");
  if (queryEnd !== -1) {
    spl = spl.substring(0, queryEnd).trim();
  }

  // Basic validation: should contain "search" keyword
  if (!spl.toLowerCase().includes("search")) {
    throw new Error(`Generated query doesn't appear to be valid SPL: ${spl}`);
  }

  // Ensure it starts with search command
  if (!spl.toLowerCase().startsWith("search")) {
    // Try to find where search command begins
    const searchIdx = spl.toLowerCase().indexOf("search");
    if (searchIdx !== -1) {
      spl = spl.substring(searchIdx);
    }
  }

  const confidence = calculateConfidence(spl, question);
  
  return {
    spl,
    confidence,
    rawResponse: data,
  };
}

/**
 * Calculate a simple confidence score based on query characteristics.
 * 
 * @param {string} spl - Generated SPL query
 * @param {string} question - Original question
 * @returns {number} Confidence score 0-1
 */
function calculateConfidence(spl, question) {
  let score = 0.5; // Base score
  
  // Check for essential SPL components
  if (spl.toLowerCase().includes("search")) score += 0.2;
  if (spl.includes("|")) score += 0.1; // Has pipeline
  
  // Check if question keywords appear in query
  const questionWords = question.toLowerCase().split(/\s+/).filter(w => w.length > 3);
  const splLower = spl.toLowerCase();
  const matchingKeywords = questionWords.filter(w => splLower.includes(w)).length;
  score += (matchingKeywords / Math.max(questionWords.length, 1)) * 0.2;
  
  // Cap at 1.0
  return Math.min(score, 1.0);
}

/**
 * Validate that a SPL query is safe to execute (basic sanity check).
 * 
 * @param {string} spl - SPL query to validate
 * @returns {boolean} True if query appears safe
 */
export function validateSplQuery(spl) {
  const lower = spl.toLowerCase();
  
  // Block obviously dangerous commands
  const dangerousCommands = ["inputlookup", "outputlookup", "sendemail", "rest", "dbxquery"];
  for (const cmd of dangerousCommands) {
    if (lower.includes(cmd)) return false;
  }
  
  // Should contain a search command
  if (!lower.includes("search")) return false;
  
  // Reasonable length check
  if (spl.length > 10000) return false;
  
  return true;
}