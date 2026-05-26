// generator.js - Run with: npm run generate
const targetEndpoint = "http://localhost:3000/api/intercept";
const INTERVAL_MS = 5000;

const sampleLogs = [
  // --- Clean operational logs ---
  { level: "INFO",  message: "Database connection established to PostgreSQL." },
  { level: "DEBUG", message: "Cache miss for key user:profile:42; falling back to DB." },
  { level: "DEBUG", message: "Cache hit for key product:list:home." },
  { level: "INFO",  message: "Healthcheck OK; uptime 14d 3h 22m." },
  { level: "INFO",  message: "User admin authenticated successfully via SAML." },
  { level: "INFO",  message: "Service mesh sidecar started on port 15001." },
  { level: "INFO",  message: "Worker pool resized from 8 to 12 threads." },
  { level: "INFO",  message: "Kafka consumer group rebalanced; partitions reassigned." },
  { level: "INFO",  message: "Scheduled cleanup job completed in 412ms." },
  { level: "INFO",  message: "Background indexer processed 1240 documents." },
  { level: "INFO",  message: "Migration 0042_add_idx_orders applied successfully." },
  { level: "DEBUG", message: "Feature flag 'new-checkout' evaluated to true for cohort B." },
  { level: "DEBUG", message: "Rate limiter window reset for tenant t-prod-eu." },
  { level: "INFO",  message: "Build pipeline #4821 finished green." },
  { level: "INFO",  message: "Deployment to staging completed in 2m17s." },
  { level: "WARN",  message: "Container restarted by Kubernetes liveness probe." },
  { level: "INFO",  message: "CPU usage steady at 32% across cluster." },
  { level: "DEBUG", message: "Memory pressure low; GC pause 8ms." },
  { level: "INFO",  message: "Disk usage on /var/log at 47%." },
  { level: "INFO",  message: "TLS certificate renewed via cert-manager." },
  { level: "INFO",  message: "CDN purge issued for path /assets/v3." },
  { level: "INFO",  message: "Search index reindex pass finished." },
  { level: "INFO",  message: "Webhook delivered to subscriber sub_8821 with HTTP 200." },
  { level: "INFO",  message: "Outbound email queued; queue depth 14." },
  { level: "INFO",  message: "Order processed; total in cents recorded." },
  { level: "INFO",  message: "Inventory reconciliation matched expected totals." },
  { level: "DEBUG", message: "Cron job 'daily-rollup' started." },
  { level: "DEBUG", message: "Metric exporter scrape completed." },
  { level: "DEBUG", message: "Trace span emitted to OTLP collector." },
  { level: "DEBUG", message: "Session refresh requested for active user." },
  { level: "INFO",  message: "New device fingerprint registered for known account." },
  { level: "INFO",  message: "CSP report received; no policy violations." },
  { level: "INFO",  message: "Service discovered new healthy upstream." },
  { level: "WARN",  message: "Circuit breaker reset to CLOSED state." },
  { level: "DEBUG", message: "GraphQL query executed in 38ms." },
  { level: "DEBUG", message: "WebSocket connection upgraded successfully." },
  { level: "DEBUG", message: "Static asset bundle hash unchanged; skipping reupload." },
  { level: "INFO",  message: "Configuration reloaded after SIGHUP." },
  { level: "INFO",  message: "Replica lag within threshold: 120ms." },
  { level: "WARN",  message: "Read replica promoted during failover drill." },
  { level: "INFO",  message: "Backup snapshot uploaded to cold storage." },
  { level: "INFO",  message: "Object lifecycle policy archived 230 old blobs." },
  { level: "INFO",  message: "SSO group sync from IdP completed." },
  { level: "INFO",  message: "License check against entitlement service passed." },
  { level: "INFO",  message: "Plugin marketplace synced 18 new versions." },
  { level: "INFO",  message: "Locale catalog regenerated for de-DE." },
  { level: "DEBUG", message: "Translation memory cache warmed." },
  { level: "INFO",  message: "ETL pipeline ingested 92340 rows from source." },
  { level: "DEBUG", message: "Dashboard widget rendered in 14ms." },
  { level: "DEBUG", message: "A/B experiment 'pricing-v2' bucketed user into control." },

  // --- Compliance violations (PII / secrets) ---
  { level: "DEBUG", message: "Processing payment for CC: 4532-1111-2222-3333." },
  { level: "ERROR", message: "Sync failed. AWS Token used: AKIAIOSFODNN7EXAMPLE." },
  { level: "INFO",  message: "New customer onboarded with SSN 123-45-6789." },
  { level: "DEBUG", message: "Form submission received; password field value: hunter2." },
  { level: "INFO",  message: "User reset password to 'P@ssw0rd2024!'." },
  { level: "ERROR", message: "Stripe secret key sk_live_51HabcXYZ123abcDEF used in test request." },
  { level: "DEBUG", message: "Authorization header logged: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123." },
  { level: "ERROR", message: "GitHub PAT exposed in build log: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789." },
  { level: "ERROR", message: "Database URL: postgres://admin:s3cretPassword@db.internal:5432/prod." },
  { level: "ERROR", message: "Slack webhook leaked: https://hooks.slack.com/services/T00/B11/abc123secret." },
  { level: "INFO",  message: "Customer DOB 1987-03-14 stored in plaintext." },
  { level: "DEBUG", message: "Shipment address: 221B Baker Street, London NW1 6XE." },
  { level: "INFO",  message: "IBAN logged: DE89 3704 0044 0532 0130 00." },
  { level: "INFO",  message: "Personalausweis number captured: T220001293." },
  { level: "ERROR", message: "Credit card CVV 471 included in error trace." },
  { level: "DEBUG", message: "Customer phone number +49 151 23456789 written to console." },
  { level: "ERROR", message: "Private RSA key block detected in payload: -----BEGIN RSA PRIVATE KEY-----." },
  { level: "WARN",  message: "JWT signing secret rotated; old value: my-super-secret-jwt-key-2023." },
  { level: "INFO",  message: "User email jane.doe@example.com bound to invoice PDF." },
  { level: "INFO",  message: "Passport scan filename: passport_MUELLER_C12345678.jpg." },
  { level: "INFO",  message: "Tax ID DE123456789 entered during signup." },
  { level: "WARN",  message: "Login attempt with username admin, password 'admin123'." },
  { level: "ERROR", message: "Discord bot token MTAxMjM0NTY3.AbCdEf.GhIjKlMnOpQrStUvWxYz exposed in env dump." },
  { level: "ERROR", message: "Twilio account SID ACabcdef0123456789abcdef0123456789 with auth token logged." },
  { level: "DEBUG", message: "SSH private key path /home/build/.ssh/id_rsa printed to stdout." },
  { level: "DEBUG", message: "Customer credit card 5500-0000-0000-0004 expired and retried." },
  { level: "ERROR", message: "Google API key AIzaSyD-fakekey-1234567890abcdefGHI exposed in client bundle." },
  { level: "INFO",  message: "PayPal recipient email billing@example.org included in error log." },
  { level: "INFO",  message: "Patient record id 88421 with diagnosis code F32.1 written." },
  { level: "INFO",  message: "Driver's license D1234567 attached to ride history." },
  { level: "INFO",  message: "National Insurance Number QQ123456C captured in form submission." },
  { level: "ERROR", message: "Card track 2 data ;4111111111111111=25121011000000000000? captured." },
  { level: "ERROR", message: "Bank routing number 021000021 and account 123456789 logged." },
  { level: "DEBUG", message: "Customer address: Marienplatz 8, 80331 Munich." },
  { level: "WARN",  message: "Recovery codes generated: 1f2a-3b4c, 9d8e-7f6a — full list written to log." },
  { level: "ERROR", message: "PIN entered for card ending 1234: 4071." },
  { level: "ERROR", message: "Azure storage key DefaultEndpointsProtocol=https;AccountKey=abcXYZ== printed." },
  { level: "ERROR", message: "Mailchimp API key us12-abcdef0123456789abcdef0123456789 in config dump." },
  { level: "INFO",  message: "Customer SSN last4 6789 reused in support ticket subject." },
  { level: "INFO",  message: "OAuth refresh token 1//0abcdefXYZ saved in audit row." },
  { level: "ERROR", message: "Internal admin password 'CorrectHorseBatteryStaple' logged on rotate." },
  { level: "DEBUG", message: "Apple device UDID 00008101-001234567890ABCDE captured." },
  { level: "INFO",  message: "Vehicle VIN 1HGCM82633A123456 with owner name appended." },
  { level: "INFO",  message: "Customer Steuernummer 12/345/67890 in invoice template." },
  { level: "INFO",  message: "Hospital MRN 887654321 referenced in pager message." },
  { level: "ERROR", message: "Bitcoin private WIF L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ found." },
  { level: "ERROR", message: "Encrypted .pfx file password 'OpenSesame2024' echoed to terminal." },
  { level: "WARN",  message: "Customer mother's maiden name 'Schmidt' captured for verification." },
  { level: "ERROR", message: "Credit application income 95000 attached to SSN 987-65-4321." },
  { level: "ERROR", message: "HR record: employee 12993, salary 78400 EUR, IBAN DE12 5001 0517 0648 4898 90." },
];

async function startStream() {
  console.log(`Starting data stream to ${targetEndpoint} (${sampleLogs.length} log templates, every ${INTERVAL_MS}ms)...`);

  setInterval(async () => {
    const log = sampleLogs[Math.floor(Math.random() * sampleLogs.length)];
    const payload = { time: Date.now(), event: log };

    try {
      await fetch(targetEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      console.log(`[Stream] Sent ${log.level} log`);
    } catch (err) {
      console.error("[Stream] Agent offline. Is your interceptor running?");
    }
  }, INTERVAL_MS);
}

startStream();
