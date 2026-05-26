# Privacy Guard Interceptor

A drop-in compliance middleware that sits between your application logs and
Splunk, redacting PII and secrets **before** they ever reach the indexer.
Detection is hybrid: deterministic regex for high-confidence patterns (with
Luhn / IBAN validation), and Google Gemini for the contextual PII regex
cannot see — names, addresses, free-text passwords, DOBs, medical-record
context. Every intercept is streamed to a live dashboard and (optionally)
fanned out as a Slack alert.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the system diagram and data flow.
A short pitch-style description lives in [PROJECT.md](PROJECT.md).

## Features

- **POST /api/intercept** — single endpoint that accepts a structured log,
  runs detection, redacts in place, and forwards the safe payload to Splunk
  HEC.
- **Hybrid detection** — regex + LLM run in parallel; regex hits are
  authoritative, LLM fills the contextual gap. Overlapping spans are
  deduplicated.
- **Validated patterns** — credit cards are Luhn-checked, IBANs are mod-97
  checked, so logs full of order IDs do not get spuriously redacted.
- **Severity scoring** — every record is tagged
  `critical | high | medium | low | none`, surfaced both to Splunk and the
  dashboard.
- **Live compliance dashboard** at `/dashboard` — counters, severity mix,
  category breakdown, and a streaming feed of recent intercepts powered by
  Server-Sent Events.
- **AI-down badge** — if Gemini times out or rate-limits, the dashboard
  shows the failure mode and regex detection continues uninterrupted.
- **Slack alerting** (optional) — webhook notification on every violation.
- **Scoped TLS bypass** — `SPLUNK_INSECURE_TLS=true` only loosens cert
  validation for the Splunk request itself, never globally.

## Requirements

- Node.js 20.6+ (uses `node --env-file=...` and built-in `--test`).
- A Splunk instance with HTTP Event Collector enabled and a token.
- A Google AI Studio key for Gemini (`gemini-2.5-flash`).
- Optional: a Slack incoming webhook URL.

## Setup

```bash
git clone <repo-url> splunk-hackathon
cd splunk-hackathon
npm install
cp .env.example .env
# then edit .env and fill in the values below
```

### Environment variables

| Variable              | Required | Notes                                                    |
| --------------------- | -------- | -------------------------------------------------------- |
| `GEMINI_API_KEY`      | yes      | From https://aistudio.google.com/app/apikey              |
| `SPLUNK_HEC_URL`      | yes      | e.g. `https://localhost:8088/services/collector/event`   |
| `SPLUNK_TOKEN`        | yes      | HEC token, used as `Authorization: Splunk <token>`       |
| `SPLUNK_INSECURE_TLS` | no       | Set `true` only for local Splunk with a self-signed cert |
| `SLACK_WEBHOOK_URL`   | no       | Leave blank to disable Slack alerts                      |
| `PORT`                | no       | Defaults to `3000`                                       |

`src/config.js` fails fast on startup if any required variable is missing
or still set to the placeholder.

### Splunk HEC quick setup

A reference Splunk install is provided in `splunk.zip`. If you are using
your own Splunk:

1. In Splunk Web, go to **Settings → Data inputs → HTTP Event Collector**.
2. Enable the HEC, create a new token, and copy it into `SPLUNK_TOKEN`.
3. Confirm the collector URL matches `SPLUNK_HEC_URL`. The default
   `/services/collector/event` endpoint is correct for this app.

## Run

Start the interceptor:

```bash
npm start
```

You should see `Privacy Guard Interceptor listening on http://localhost:3000`.
Open the dashboard at <http://localhost:3000/dashboard>.

In a second terminal, start the demo log stream:

```bash
npm run generate
```

`data-generator.js` posts a randomized mix of clean operational logs and
~50 PII-bearing logs to `/api/intercept` every 5 seconds, so the dashboard
fills with real-looking traffic. Open Splunk's search head and you should
see redacted events arriving with their violation metadata.

### Send a log manually

```bash
curl -X POST http://localhost:3000/api/intercept \
  -H "Content-Type: application/json" \
  -d '{
    "time": 1716742800000,
    "event": {
      "level": "ERROR",
      "message": "Stripe key sk_live_51HabcXYZ123abcDEF used in request"
    }
  }'
```

The response includes Splunk's ack, and the Splunk event itself contains
`message: "Stripe key [REDACTED_API_KEY] used in request"` plus
`violation_severity: "critical"` and `violation_sources: ["regex"]`.

## Tests

```bash
npm test
```

Runs the built-in Node test runner against every `*.test.js` under `src/`.
Tests cover the regex detector (including Luhn / IBAN validation), LLM
response parsing and error paths, merge / redact ordering, the severity
ranker, the dashboard store (ring buffer, counters, subscriber isolation),
and the dashboard routes.

## Project layout

```
.
├── server.js                          # Express bootstrap + /api/intercept
├── data-generator.js                  # Demo log producer
├── public/dashboard.html              # Single-page compliance dashboard
├── src/
│   ├── config.js                      # Env loading & validation
│   ├── splunk.js                      # HEC client (scoped TLS bypass)
│   ├── alerts.js                      # Optional Slack webhook
│   ├── detection/
│   │   ├── index.js                   # detectPII() — orchestrates regex + LLM
│   │   ├── regex.js                   # Luhn / IBAN-validated patterns
│   │   ├── llm.js                     # Gemini contextual detector
│   │   ├── merge.js                   # Deduplicated finding merge
│   │   ├── redact.js                  # In-place [REDACTED_*] substitution
│   │   └── severity.js                # Category → severity ranking
│   └── dashboard/
│       ├── store.js                   # Ring buffer + SSE pub/sub
│       └── routes.js                  # /dashboard, /api/dashboard/{snapshot,stream}
├── ARCHITECTURE.md
├── PROJECT.md
└── LICENSE                            # MIT
```

## Security notes

- `.env` is gitignored. Never commit your Gemini key or HEC token.
- Splunk only ever receives the redacted message; original PII never
  leaves the interceptor process.
- The Slack alert payload contains category names and severity only — not
  the offending values.
- LLM responses are validated by checking that every claimed substring
  actually exists in the original message before being trusted.

## License

MIT — see [LICENSE](LICENSE).
