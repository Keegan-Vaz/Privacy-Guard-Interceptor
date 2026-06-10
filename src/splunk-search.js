import { Agent } from "undici";
import { config } from "./config.js";

// Reuse scoped TLS bypass from existing splunk.js pattern
const dispatcher = config.splunk.insecureTls
  ? new Agent({ connect: { rejectUnauthorized: false } })
  : undefined;

/**
 * Execute a SPL query against Splunk REST API.
 * 
 * @param {string} splQuery - The SPL query string to execute
 * @param {Object} options - Optional settings
 * @param {string} options.index - Splunk index to search (defaults to config.splunkSearch.index)
 * @param {number} options.timeoutMs - Maximum wait time in milliseconds (defaults to config.splunkSearch.timeoutMs)
 * @returns {Promise<Array<Object>>} Array of result rows from Splunk
 * @throws {Error} If authentication fails, query times out, or Splunk returns an error
 */
export async function executeSplQuery(splQuery, options = {}) {
  const { index = config.splunkSearch.index, timeoutMs = config.splunkSearch.timeoutMs } = options;
  
  if (!config.splunkSearch.restUrl || !config.splunkSearch.apiToken) {
    throw new Error(
      "Splunk REST API not configured: SPLUNK_REST_URL and SPLUNK_API_TOKEN required",
    );
  }

  const baseUrl = config.splunkSearch.restUrl.replace(/\/$/, "");
  // Support both Basic Auth (Base64 encoded username:password) and Bearer tokens
  const apiToken = config.splunkSearch.apiToken;
  const authHeader = apiToken.startsWith('Basic ') ? apiToken : `Bearer ${apiToken}`;

  // 1. Create search job
  const jobResponse = await fetch(`${baseUrl}/services/search/jobs`, {
    method: "POST",
    headers: {
      Authorization: authHeader,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      search: `search index="${index}" ${splQuery}`,
      output_mode: "json",
      earliest_time: "-30d",
      latest_time: "now",
    }),
    signal: AbortSignal.timeout(timeoutMs),
    dispatcher,
  });

  if (!jobResponse.ok) {
    const errorData = await jobResponse.json().catch(() => ({}));
    throw new Error(
      `Splunk search job creation failed (HTTP ${jobResponse.status}): ${JSON.stringify(errorData)}`,
    );
  }

  const jobData = await jobResponse.json();
  const sid = jobData?.sid;
  if (!sid) {
    throw new Error("Splunk did not return a valid job SID");
  }

  // 2. Poll for job completion
  const pollStart = Date.now();
  const pollInterval = 500; // ms
  const maxPollTime = timeoutMs - 2000; // Reserve 2s for result retrieval

  while (Date.now() - pollStart < maxPollTime) {
    await new Promise((resolve) => setTimeout(resolve, pollInterval));

    const statusResponse = await fetch(`${baseUrl}/services/search/jobs/${sid}`, {
      headers: { Authorization: authHeader },
      signal: AbortSignal.timeout(5000),
      dispatcher,
    });

    if (!statusResponse.ok) {
      throw new Error(`Failed to poll search job status (HTTP ${statusResponse.status})`);
    }

    const statusData = await statusResponse.json();
    const dispatchState = statusData?.entry?.[0]?.content?.dispatchState;

    if (dispatchState === "DONE") {
      break;
    }
    if (dispatchState === "FAILED") {
      throw new Error(`Splunk search job failed: ${JSON.stringify(statusData)}`);
    }
    // Continue polling for PENDING, QUEUED, RUNNING, etc.
  }

  if (Date.now() - pollStart >= maxPollTime) {
    throw new Error(`Splunk search timed out after ${timeoutMs}ms`);
  }

  // 3. Fetch results
  const resultsResponse = await fetch(
    `${baseUrl}/services/search/jobs/${sid}/results?output_mode=json`,
    {
      headers: { Authorization: authHeader },
      signal: AbortSignal.timeout(10000),
      dispatcher,
    },
  );

  if (!resultsResponse.ok) {
    throw new Error(`Failed to fetch search results (HTTP ${resultsResponse.status})`);
  }

  const resultsData = await resultsResponse.json();
  return resultsData?.results || [];
}

/**
 * Check if Splunk REST API is available and credentials are valid.
 * 
 * @returns {Promise<boolean>} True if API is reachable and credentials work
 */
export async function testSplunkConnection() {
  if (!config.splunkSearch.restUrl || !config.splunkSearch.apiToken) {
    return false;
  }

  try {
    const baseUrl = config.splunkSearch.restUrl.replace(/\/$/, "");
    const apiToken = config.splunkSearch.apiToken;
    const authHeader = apiToken.startsWith('Basic ') ? apiToken : `Bearer ${apiToken}`;
    const response = await fetch(`${baseUrl}/services/server/info`, {
      headers: { Authorization: authHeader },
      signal: AbortSignal.timeout(5000),
      dispatcher,
    });
    return response.ok;
  } catch {
    return false;
  }
}