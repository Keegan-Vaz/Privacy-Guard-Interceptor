import { config } from "./config.js";

const ANOMALY_ASSESSMENT_PROMPT = `You are a Security Operations Analyst reviewing recent PII violation activity for anomalies.

## Recent Activity Summary
- Analysis Window: Last {windowSize} log intercepts
- Time Range: {firstTimestamp} to {lastTimestamp}
- Total Records: {totalRecords}
- AI Audit Status: {aiAuditedCount} successfully audited, {aiFailedCount} failed

## Category Distribution
{categorySummary}

## Severity Distribution
{severitySummary}

## Task
Analyze this activity summary and identify any statistical anomalies or concerning patterns.

Look for:
1. **Category Spikes**: Any PII category showing unusually high frequency compared to normal baseline
2. **New Categories**: PII categories appearing for the first time in recent history
3. **Critical Severity Surges**: Spike in "critical" severity violations
4. **AI-Down Clustering**: Multiple consecutive AI audit failures suggesting service degradation

Return a JSON array of anomaly objects. Each anomaly should have:
{
  "type": "category_spike" | "new_category" | "critical_spike" | "ai_down_cluster",
  "detail": "Human-readable description of the anomaly",
  "affectedCategory": "Only for category_spike or new_category",
  "affectedSeverity": "Only for critical_spike",
  "magnitude": "How unusual this is (low, medium, high)"
}

Return empty array [] if no anomalies detected.

Examples:
Input: category "credit_card" appears 15 times in window of 50 records (normally 2-3)
Output: [{ "type": "category_spike", "detail": "Credit card violations 5x above normal baseline", "affectedCategory": "credit_card", "magnitude": "high" }]

Input: category "medical_record" appears for first time in window
Output: [{ "type": "new_category", "detail": "Medical record category detected for first time", "affectedCategory": "medical_record", "magnitude": "medium" }]

Now analyze this summary:`;

/**
 * Trend Analyzer for detecting anomalies in recent PII violation patterns.
 */
export class TrendAnalyzer {
  /**
   * Initialize the trend analyzer with a dashboard store.
   * 
   * @param {Object} store - Dashboard store instance (must have getSnapshot() method)
   * @param {Function} broadcastCallback - Function to call when anomaly is detected
   */
  constructor(store, broadcastCallback) {
    this.store = store;
    this.broadcastCallback = broadcastCallback;
    this.intervalId = null;
    this.isRunning = false;
  }

  /**
   * Start the trend analysis background job.
   */
  start() {
    if (this.isRunning) {
      console.warn("[TrendAnalyzer] Already running");
      return;
    }

    if (!config.trendAnalysis.enabled) {
      console.log("[TrendAnalyzer] Feature disabled via TREND_ANALYSIS_ENABLED=false");
      return;
    }

    const intervalMs = config.trendAnalysis.intervalMs;
    console.log(`[TrendAnalyzer] Starting with ${intervalMs}ms interval, window size ${config.trendAnalysis.windowSize}`);

    this.isRunning = true;
    
    // Run immediately, then on interval
    this._runAnalysisCycle();
    this.intervalId = setInterval(() => {
      this._runAnalysisCycle();
    }, intervalMs);
  }

  /**
   * Stop the trend analysis background job.
   */
  stop() {
    if (!this.isRunning) return;
    
    console.log("[TrendAnalyzer] Stopping");
    this.isRunning = false;
    
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  /**
   * Run a single analysis cycle.
   */
  async _runAnalysisCycle() {
    const cycleId = `cycle_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    console.log(`[TrendAnalyzer:${cycleId}] Starting analysis cycle`);
    
    try {
      // 1. Get analysis window from store
      const window = this._getAnalysisWindow();
      
      if (window.records.length < 5) {
        console.log(`[TrendAnalyzer:${cycleId}] Insufficient data (${window.records.length} records), skipping`);
        return;
      }
      
      console.log(`[TrendAnalyzer:${cycleId}] Analyzing ${window.records.length} records`);
      
      // 2. Compute summary statistics
      const summary = this._computeSummary(window);
      
      // 3. Call Gemini for anomaly assessment
      const anomalies = await this._assessAnomalies(summary, window);
      
      // 4. Broadcast anomalies if any detected
      if (anomalies.length > 0) {
        console.log(`[TrendAnalyzer:${cycleId}] Detected ${anomalies.length} anomalies`);
        await this._broadcastAnomalies(anomalies, summary, cycleId);
      } else {
        console.log(`[TrendAnalyzer:${cycleId}] No anomalies detected`);
      }
      
    } catch (error) {
      console.error(`[TrendAnalyzer:${cycleId}] Analysis failed:`, error.message);
      // Don't stop the interval - continue with next cycle
    }
  }

  /**
   * Get the analysis window from the dashboard store.
   */
  _getAnalysisWindow() {
    const snapshot = this.store.getSnapshot();
    const windowSize = config.trendAnalysis.windowSize;
    
    // Get most recent N records (or all if less than N)
    const records = snapshot.recent.slice(0, windowSize);
    
    return {
      records,
      firstTimestamp: records.length > 0 ? Math.min(...records.map(r => r.ts || r.id)) : null,
      lastTimestamp: records.length > 0 ? Math.max(...records.map(r => r.ts || r.id)) : null,
    };
  }

  /**
   * Compute summary statistics from analysis window.
   */
  _computeSummary(window) {
    const { records } = window;
    
    // Category counts
    const categoryCounts = {};
    // Severity counts
    const severityCounts = { low: 0, medium: 0, high: 0, critical: 0, none: 0 };
    // AI audit status
    let aiAuditedCount = 0;
    let aiFailedCount = 0;
    // Seen categories (for new category detection)
    const seenCategories = new Set();
    
    records.forEach(record => {
      // Count categories
      if (record.categories && Array.isArray(record.categories)) {
        record.categories.forEach(cat => {
          categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
          seenCategories.add(cat);
        });
      }
      
      // Count severity
      if (record.severity && severityCounts.hasOwnProperty(record.severity)) {
        severityCounts[record.severity]++;
      }
      
      // Count AI audit status
      if (record.aiAudited === true) {
        aiAuditedCount++;
      } else if (record.aiAudited === false) {
        aiFailedCount++;
      }
    });
    
    // Format category summary for prompt
    const categoryLines = Object.entries(categoryCounts)
      .map(([cat, count]) => `- ${cat}: ${count} occurrences`)
      .join("\n");
    
    const categorySummary = categoryLines || "No PII categories detected";
    
    // Format severity summary
    const severityLines = Object.entries(severityCounts)
      .filter(([_, count]) => count > 0)
      .map(([sev, count]) => `- ${sev}: ${count} occurrences`)
      .join("\n");
    
    const severitySummary = severityLines || "No severity data";
    
    return {
      totalRecords: records.length,
      categoryCounts,
      severityCounts,
      aiAuditedCount,
      aiFailedCount,
      seenCategories: Array.from(seenCategories),
      categorySummary,
      severitySummary,
      firstTimestamp: window.firstTimestamp ? new Date(window.firstTimestamp).toISOString() : "unknown",
      lastTimestamp: window.lastTimestamp ? new Date(window.lastTimestamp).toISOString() : "unknown",
    };
  }

  /**
   * Assess anomalies using Gemini.
   */
  async _assessAnomalies(summary, window) {
    if (!config.gemini.apiKey) {
      throw new Error("Gemini API key not configured");
    }
    
    const prompt = ANOMALY_ASSESSMENT_PROMPT
      .replace("{windowSize}", config.trendAnalysis.windowSize.toString())
      .replace("{totalRecords}", summary.totalRecords.toString())
      .replace("{firstTimestamp}", summary.firstTimestamp)
      .replace("{lastTimestamp}", summary.lastTimestamp)
      .replace("{aiAuditedCount}", summary.aiAuditedCount.toString())
      .replace("{aiFailedCount}", summary.aiFailedCount.toString())
      .replace("{categorySummary}", summary.categorySummary)
      .replace("{severitySummary}", summary.severitySummary);
    
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${config.gemini.model}:generateContent?key=${config.gemini.apiKey}`;
    
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(config.gemini.timeoutMs),
      body: JSON.stringify({
        system_instruction: { parts: { text: prompt } },
        contents: [{ parts: [{ text: "Analyze for anomalies" }] }],
        generationConfig: {
          response_mime_type: "application/json",
          temperature: 0.0,
        },
      }),
    });
    
    if (!response.ok) {
      const errorText = await response.text().catch(() => `HTTP ${response.status}`);
      throw new Error(`Gemini API HTTP error ${response.status}: ${errorText}`);
    }
    
    const data = await response.json();
    const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    
    if (!rawText) {
      throw new Error("Gemini returned empty response");
    }
    
    try {
      const parsed = JSON.parse(rawText);
      
      if (!Array.isArray(parsed)) {
        throw new Error("Gemini response is not an array");
      }
      
      // Validate each anomaly object
      const validAnomalies = parsed.filter(anomaly => {
        if (!anomaly || typeof anomaly !== "object") return false;
        if (!anomaly.type || !anomaly.detail) return false;
        
        const validTypes = ["category_spike", "new_category", "critical_spike", "ai_down_cluster"];
        if (!validTypes.includes(anomaly.type)) return false;
        
        // Validate type-specific fields
        switch (anomaly.type) {
          case "category_spike":
          case "new_category":
            return !!anomaly.affectedCategory;
          case "critical_spike":
            return anomaly.affectedSeverity === "critical";
          case "ai_down_cluster":
            return true; // No additional required fields
          default:
            return false;
        }
      });
      
      return validAnomalies;
      
    } catch (error) {
      throw new Error(`Failed to parse Gemini response: ${error.message}`);
    }
  }

  /**
   * Broadcast detected anomalies.
   */
  async _broadcastAnomalies(anomalies, summary, cycleId) {
    const anomalyAlerts = anomalies.map(anomaly => ({
      type: anomaly.type,
      detail: anomaly.detail,
      affectedCategory: anomaly.affectedCategory,
      affectedSeverity: anomaly.affectedSeverity,
      magnitude: anomaly.magnitude || "medium",
      windowSize: summary.totalRecords,
      detectedAt: new Date().toISOString(),
      summary: {
        categoryCounts: summary.categoryCounts,
        severityCounts: summary.severityCounts,
        aiAuditStats: {
          audited: summary.aiAuditedCount,
          failed: summary.aiFailedCount,
        },
      },
    }));
    
    // Broadcast via callback (to be connected to SSE)
    if (this.broadcastCallback) {
      try {
        await this.broadcastCallback(anomalyAlerts);
        console.log(`[TrendAnalyzer:${cycleId}] Broadcasted ${anomalyAlerts.length} anomalies`);
      } catch (error) {
        console.error(`[TrendAnalyzer:${cycleId}] Broadcast failed:`, error.message);
      }
    }
    
    // Post to Slack if configured
    await this._postToSlack(anomalyAlerts, cycleId);
  }

  /**
   * Post anomaly alerts to Slack.
   */
  async _postToSlack(anomalyAlerts, cycleId) {
    if (!config.alerts.webhookUrl) {
      return; // Slack not configured
    }
    
    try {
      const slackMessage = {
        text: `🚨 PII Violation Anomaly Detected (${anomalyAlerts.length} anomalies)`,
        blocks: [
          {
            type: "header",
            text: {
              type: "plain_text",
              text: "🚨 PII Violation Anomaly Detected",
              emoji: true,
            },
          },
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: `*${anomalyAlerts.length} anomaly${anomalyAlerts.length === 1 ? '' : 's'} detected* in the last ${config.trendAnalysis.windowSize} records`,
            },
          },
        ],
      };
      
      // Add a section for each anomaly
      anomalyAlerts.forEach((anomaly, index) => {
        let emoji = "⚠️";
        if (anomaly.magnitude === "high") emoji = "🔴";
        if (anomaly.magnitude === "medium") emoji = "🟠";
        if (anomaly.magnitude === "low") emoji = "🟡";
        
        slackMessage.blocks.push({
          type: "section",
          text: {
            type: "mrkdwn",
            text: `${emoji} *${anomaly.type.replace(/_/g, ' ').toUpperCase()}*\n${anomaly.detail}`,
          },
        });
      });
      
      // Add divider and footer
      slackMessage.blocks.push({ type: "divider" });
      slackMessage.blocks.push({
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `Analysis cycle ${cycleId} | Privacy Guard Interceptor Trend Analyzer`,
          },
        ],
      });
      
      const response = await fetch(config.alerts.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(slackMessage),
        signal: AbortSignal.timeout(config.alerts.timeoutMs),
      });
      
      if (!response.ok) {
        throw new Error(`Slack API responded with ${response.status}`);
      }
      
      console.log(`[TrendAnalyzer:${cycleId}] Slack notification sent`);
      
    } catch (error) {
      console.error(`[TrendAnalyzer:${cycleId}] Failed to send Slack notification:`, error.message);
      // Don't re-throw - this shouldn't fail the analysis cycle
    }
  }
}