import { Router } from "express";

const HEARTBEAT_INTERVAL_MS = 30000;

export function createDashboardRouter(store, htmlPath) {
  const router = Router();

  router.get("/dashboard", (req, res) => {
    res.sendFile(htmlPath);
  });

  router.get("/api/dashboard/snapshot", (req, res) => {
    res.json(store.getSnapshot());
  });

  router.get("/api/dashboard/stream", (req, res) => {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();
    res.write(`: connected\n\n`);

    const unsubscribe = store.subscribe((entry) => {
      // Check if this is an anomaly alert (has _type field)
      if (entry._type === 'anomaly_alert') {
        // Send as anomaly_alert event type
        res.write(`event: anomaly_alert\ndata: ${JSON.stringify(entry)}\n\n`);
      } else {
        // Regular log entry
        res.write(`data: ${JSON.stringify(entry)}\n\n`);
      }
    });
    const heartbeat = setInterval(() => {
      res.write(`: keepalive\n\n`);
    }, HEARTBEAT_INTERVAL_MS);

    req.on("close", () => {
      clearInterval(heartbeat);
      unsubscribe();
      res.end();
    });
  });

  return router;
}
