const DEFAULT_CAPACITY = 200;
const SEVERITY_KEYS = ["low", "medium", "high", "critical"];

export function createStore({ capacity = DEFAULT_CAPACITY } = {}) {
  const buffer = []; // newest-first
  const subscribers = new Set();
  const counters = {
    totalProcessed: 0,
    totalRedacted: 0,
    llmOnlyCatches: 0,
  };
  let nextId = 1;

  function record(entryWithoutId) {
    const entry = { id: nextId++, ...entryWithoutId };
    buffer.unshift(entry);
    if (buffer.length > capacity) buffer.length = capacity;

    counters.totalProcessed++;
    if (entry.severity !== "none") counters.totalRedacted++;
    const hasLlm = entry.sources.includes("llm");
    const hasRegex = entry.sources.includes("regex");
    if (hasLlm && !hasRegex) counters.llmOnlyCatches++;

    // Snapshot the subscriber set so handlers that add new subscribers
    // don't trigger them for the in-flight event.
    for (const cb of [...subscribers]) {
      try {
        cb(entry);
      } catch (err) {
        console.warn("[Dashboard store] subscriber threw:", err.message);
      }
    }
    return entry;
  }

  function getSnapshot() {
    const severityCounts = { low: 0, medium: 0, high: 0, critical: 0 };
    const categoryCounts = {};
    for (const entry of buffer) {
      if (SEVERITY_KEYS.includes(entry.severity)) {
        severityCounts[entry.severity]++;
      }
      for (const cat of entry.categories) {
        categoryCounts[cat] = (categoryCounts[cat] ?? 0) + 1;
      }
    }
    return {
      counters: { ...counters },
      recent: [...buffer],
      severityCounts,
      categoryCounts,
    };
  }

  function subscribe(callback) {
    subscribers.add(callback);
    return () => subscribers.delete(callback);
  }

  /**
   * Broadcast anomaly alerts to all subscribers.
   * @param {Array} anomalyAlerts - Array of anomaly alert objects
   */
  function broadcastAnomalyAlerts(anomalyAlerts) {
    if (!Array.isArray(anomalyAlerts) || anomalyAlerts.length === 0) {
      return;
    }
    
    // Snapshot the subscriber set
    for (const cb of [...subscribers]) {
      try {
        // Call with a special event type that clients can differentiate
        cb({
          _type: 'anomaly_alert',
          timestamp: Date.now(),
          alerts: anomalyAlerts,
        });
      } catch (err) {
        console.warn("[Dashboard store] subscriber threw during anomaly broadcast:", err.message);
      }
    }
  }

  return { record, getSnapshot, subscribe, broadcastAnomalyAlerts };
}

export const store = createStore();
