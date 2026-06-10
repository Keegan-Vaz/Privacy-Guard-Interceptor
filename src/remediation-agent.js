import { config } from "./config.js";
import { executeSplQuery } from "./splunk-search.js";

const FIX_SUGGESTION_PROMPT = `You are a Security Engineer reviewing a critical PII violation in application logs.

## Context
- **Violation Category**: {category}
- **Source Service**: {service}
- **Historical Occurrences**: This pattern has appeared {count} times in the past 30 days
- **Redacted Log Message**: "{redactedMessage}"

## Task
Generate a concrete code fix suggestion for the developer to prevent this type of PII from appearing in logs.

Focus on:
1. **Root Cause Analysis**: What likely caused this PII to be logged? (e.g., debug statement, exception message, request body logging)
2. **Specific Fix**: Provide actual code changes (pseudocode or language-agnostic patterns)
3. **Prevention Strategy**: How to avoid similar issues in the future

## Format
Return a JSON object with:
{
  "rootCause": "Brief analysis of why this happened",
  "codeFix": "Concrete code change suggestion",
  "prevention": "Long-term prevention strategy"
}

## Examples

Example 1:
Input: category="credit_card", service="payment-service", count=3, redactedMessage="Payment failed for card ending in [REDACTED_CREDIT_CARD]"
Output: {
  "rootCause": "Payment service is logging full credit card numbers in error messages when transactions fail",
  "codeFix": "Replace: console.error(\`Payment failed for card \${cardNumber}\`) with: console.error(\`Payment failed for card ending in \${cardNumber.slice(-4)}\`)",
  "prevention": "Add a log sanitization middleware that masks sensitive fields before any logging occurs"
}

Example 2:
Input: category="api_key", service="auth-service", count=1, redactedMessage="Invalid API key [REDACTED_API_KEY] rejected"
Output: {
  "rootCause": "Authentication service is logging raw API keys in rejection messages",
  "codeFix": "Replace: logger.warn(\`Invalid API key \${apiKey} rejected\`) with: logger.warn(\`Invalid API key \${apiKey.substring(0, 8)}... rejected\`)",
  "prevention": "Implement a centralized logging utility that automatically redacts known sensitive patterns"
}

Now generate a fix suggestion for this violation:`;

/**
 * Remediation Agent for investigating critical PII violations.
 */
export class RemediationAgent {
  /**
   * Trigger the remediation agent for a critical violation.
   * 
   * @param {Object} log - The original log object from /api/intercept
   * @param {Object} detectionResult - Result from detectPII() function
   * @returns {Promise<void>} Resolves when investigation completes (doesn't block)
   */
  static async trigger(log, detectionResult) {
    // Fire and forget - don't block the intercept response
    setTimeout(async () => {
      try {
        await this._investigate(log, detectionResult);
      } catch (error) {
        console.error("[RemediationAgent] Investigation failed:", error.message);
      }
    }, 0);
  }

  /**
   * Main investigation workflow.
   */
  static async _investigate(log, detectionResult) {
    const investigationId = `inv_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    console.log(`[RemediationAgent:${investigationId}] Starting investigation for critical violation`);
    
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error("Remediation investigation timed out after 30 seconds")), 30000);
    });

    try {
      const investigation = await Promise.race([
        this._runInvestigation(investigationId, log, detectionResult),
        timeoutPromise
      ]);
      
      console.log(`[RemediationAgent:${investigationId}] Investigation completed successfully`);
      await this._postToSlack(investigation);
      
    } catch (error) {
      console.error(`[RemediationAgent:${investigationId}] Investigation failed:`, error.message);
    }
  }

  /**
   * Run the full investigation workflow.
   */
  static async _runInvestigation(investigationId, log, detectionResult) {
    // 1. Extract source service
    const sourceService = this._extractSourceService(log);
    console.log(`[RemediationAgent:${investigationId}] Source service: ${sourceService}`);
    
    // 2. Get primary violation category
    const primaryCategory = detectionResult.findings[0]?.category || "unknown";
    
    // 3. Query historical occurrences (if Splunk REST is available)
    let historicalData = { count: 0, recentTimestamps: [] };
    if (config.splunkSearch.restUrl && config.splunkSearch.apiToken) {
      try {
        historicalData = await this._queryHistoricalOccurrences(sourceService, primaryCategory);
        console.log(`[RemediationAgent:${investigationId}] Historical occurrences: ${historicalData.count}`);
      } catch (error) {
        console.warn(`[RemediationAgent:${investigationId}] Historical query failed:`, error.message);
        // Continue with historicalData.count = 0
      }
    }
    
    // 4. Generate code fix suggestion
    let fixSuggestion = null;
    let aiError = null;
    
    try {
      fixSuggestion = await this._generateFixSuggestion(
        primaryCategory,
        sourceService,
        historicalData.count,
        detectionResult.redactedMessage
      );
    } catch (error) {
      console.warn(`[RemediationAgent:${investigationId}] Fix suggestion generation failed:`, error.message);
      aiError = error.message;
    }
    
    // 5. Assemble remediation report
    const report = {
      investigationId,
      incidentTimestamp: log.time || Date.now(),
      sourceService,
      violationCategory: primaryCategory,
      severity: detectionResult.severity,
      historicalOccurrenceCount: historicalData.count,
      mostRecentOccurrences: historicalData.recentTimestamps.slice(0, 5),
      fixSuggestion,
      aiError,
      reportGeneratedAt: Date.now(),
    };
    
    return report;
  }

  /**
   * Extract source service from log metadata.
   */
  static _extractSourceService(log) {
    // Check various common metadata fields
    if (log.event?.source && typeof log.event.source === "string") {
      return log.event.source;
    }
    if (log.event?.service && typeof log.event.service === "string") {
      return log.event.service;
    }
    if (log.event?.host && typeof log.event.host === "string") {
      return log.event.host;
    }
    if (log.event?.app && typeof log.event.app === "string") {
      return log.event.app;
    }
    
    return "unknown";
  }

  /**
   * Query Splunk for historical occurrences of this violation pattern.
   */
  static async _queryHistoricalOccurrences(sourceService, category) {
    const splQuery = `violation_categories="${category}" AND (source="${sourceService}" OR service="${sourceService}" OR host="${sourceService}" OR app="${sourceService}")`;
    
    const results = await executeSplQuery(splQuery, {
      earliest_time: "-30d",
      latest_time: "now",
      limit: 100,
    });
    
    const timestamps = results
      .filter(r => r.time)
      .map(r => ({
        timestamp: parseInt(r.time),
        logId: r._cd || `log_${r.time}`
      }))
      .sort((a, b) => b.timestamp - a.timestamp);
    
    return {
      count: results.length,
      recentTimestamps: timestamps,
    };
  }

  /**
   * Generate code fix suggestion using Gemini.
   */
  static async _generateFixSuggestion(category, service, historicalCount, redactedMessage) {
    if (!config.gemini.apiKey) {
      throw new Error("Gemini API key not configured");
    }
    
    const prompt = FIX_SUGGESTION_PROMPT
      .replace("{category}", category)
      .replace("{service}", service)
      .replace("{count}", historicalCount.toString())
      .replace("{redactedMessage}", redactedMessage);
    
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${config.gemini.model}:generateContent?key=${config.gemini.apiKey}`;
    
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(config.gemini.timeoutMs),
      body: JSON.stringify({
        system_instruction: { parts: { text: prompt } },
        contents: [{ parts: [{ text: "Generate fix suggestion" }] }],
        generationConfig: {
          response_mime_type: "application/json",
          temperature: 0.0,
        },
      }),
    });
    
    if (!response.ok) {
      throw new Error(`Gemini API HTTP error ${response.status}`);
    }
    
    const data = await response.json();
    const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    
    if (!rawText) {
      throw new Error("Gemini returned empty response");
    }
    
    try {
      const parsed = JSON.parse(rawText);
      
      // Validate response structure
      if (!parsed.rootCause || !parsed.codeFix || !parsed.prevention) {
        throw new Error("Gemini response missing required fields");
      }
      
      return {
        rootCause: parsed.rootCause,
        codeFix: parsed.codeFix,
        prevention: parsed.prevention,
        generatedAt: Date.now(),
      };
      
    } catch (error) {
      throw new Error(`Failed to parse Gemini response: ${error.message}`);
    }
  }

  /**
   * Post remediation report to Slack.
   */
  static async _postToSlack(report) {
    if (!config.alerts.webhookUrl) {
      console.log("[RemediationAgent] Slack webhook not configured, skipping notification");
      return;
    }
    
    const slackMessage = {
      text: `*🔍 Critical PII Violation Investigation Complete*`,
      blocks: [
        {
          type: "header",
          text: {
            type: "plain_text",
            text: "🔍 Critical PII Violation Investigation Complete",
            emoji: true,
          },
        },
        {
          type: "section",
          fields: [
            {
              type: "mrkdwn",
              text: `*Investigation ID:*\n${report.investigationId}`,
            },
            {
              type: "mrkdwn",
              text: `*Severity:*\n${report.severity}`,
            },
            {
              type: "mrkdwn",
              text: `*Source Service:*\n${report.sourceService}`,
            },
            {
              type: "mrkdwn",
              text: `*Violation Category:*\n${report.violationCategory}`,
            },
            {
              type: "mrkdwn",
              text: `*Historical Occurrences (30d):*\n${report.historicalOccurrenceCount}`,
            },
            {
              type: "mrkdwn",
              text: `*Incident Time:*\n${new Date(report.incidentTimestamp).toISOString()}`,
            },
          ],
        },
      ],
    };
    
    // Add fix suggestion section if available
    if (report.fixSuggestion) {
      slackMessage.blocks.push({
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*💡 Code Fix Suggestion*\n${report.fixSuggestion.codeFix}\n\n*Root Cause:* ${report.fixSuggestion.rootCause}\n*Prevention:* ${report.fixSuggestion.prevention}`,
        },
      });
    } else if (report.aiError) {
      slackMessage.blocks.push({
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*⚠️ AI Suggestion Unavailable*\n${report.aiError}`,
        },
      });
    }
    
    // Add divider and footer
    slackMessage.blocks.push({ type: "divider" });
    slackMessage.blocks.push({
      type: "context",
      elements: [
        {
          type: "mrkdwn",
          text: `Investigation completed at ${new Date(report.reportGeneratedAt).toISOString()} | Privacy Guard Interceptor`,
        },
      ],
    });
    
    try {
      const response = await fetch(config.alerts.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(slackMessage),
        signal: AbortSignal.timeout(config.alerts.timeoutMs),
      });
      
      if (!response.ok) {
        throw new Error(`Slack API responded with ${response.status}`);
      }
      
      console.log(`[RemediationAgent:${report.investigationId}] Slack notification sent successfully`);
      
    } catch (error) {
      console.error(`[RemediationAgent:${report.investigationId}] Failed to send Slack notification:`, error.message);
      // Don't re-throw - this shouldn't fail the entire investigation
    }
  }
}