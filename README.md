# Privacy Guard Interceptor

**AI-Powered PII Detection & Splunk Integration Platform**

A drop-in compliance middleware that sits between your application logs and Splunk, redacting PII and secrets **before** they ever reach the indexer. Features hybrid detection (regex + AI), real-time dashboard, and four powerful agentic enhancements for the Splunk AI Hackathon.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Environment Configuration](#environment-configuration)
- [Splunk Setup Guide](#splunk-setup-guide)
- [Running the Application](#running-the-application)
- [API Endpoints](#api-endpoints)
- [Agentic Enhancements](#agentic-enhancements)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)

---

## Overview

Privacy Guard Interceptor provides real-time PII detection and redaction for application logs before they reach Splunk. The system uses a hybrid approach:

1. **Deterministic Regex Detection**: High-confidence patterns (credit cards, SSNs, API keys) with validation algorithms (Luhn, IBAN mod-97)
2. **AI-Powered Contextual Detection**: Google Gemini identifies contextual PII that regex can't see (names, addresses, free-text passwords, medical records)
3. **Agentic Enhancements**: Four AI-powered features for automated investigation, query generation, and anomaly detection

Every intercept is:
- ✅ Redacted in real-time
- ✅ Tagged with severity (critical/high/medium/low)
- ✅ Streamed to live dashboard
- ✅ Forwarded to Splunk HEC
- ✅ Optionally alerted to Slack

---

## Features

### Core Capabilities

- **POST /api/intercept** — Single endpoint that accepts structured logs, runs detection, redacts PII, and forwards to Splunk HEC
- **Hybrid Detection** — Regex + LLM run in parallel; regex hits are authoritative, LLM fills contextual gaps
- **Validated Patterns** — Credit cards are Luhn-checked, IBANs are mod-97 checked to prevent false positives
- **Severity Scoring** — Every record tagged with `critical | high | medium | low | none`
- **Live Dashboard** — Real-time compliance dashboard at `/dashboard` with SSE streaming
- **AI-Down Badge** — Graceful degradation when Gemini times out; regex continues uninterrupted
- **Slack Alerting** — Optional webhook notifications on violations

### Agentic Enhancements (New!)

1. **SPL Query Generation** — Natural language to Splunk queries via `/api/ai/query`
2. **Agentic Remediation Loop** — Autonomous investigation of critical violations
3. **Splunk MCP Server** — Model Context Protocol tools for AI assistants
4. **Trend Anomaly Detection** — Background analysis of violation patterns

---

## Requirements

- **Node.js** 20.6+ (uses `node --env-file` and built-in `--test`)
- **Splunk Instance** with:
  - HTTP Event Collector (HEC) enabled
  - Optional: REST API access for agentic features
- **Google AI Studio** API key for Gemini (`gemini-2.5-flash`)
- **Optional**: Slack incoming webhook URL for alerts

---

## Quick Start

```bash
# Clone the repository
git clone <repo-url> privacy-guard-interceptor
cd privacy-guard-interceptor

# Install dependencies
npm install

# Copy environment template
cp .env .env.local

# Edit .env with your credentials (see Environment Configuration section)
nano .env

# Start the server
npm start
```

Visit **http://localhost:3000/dashboard** to see the live compliance dashboard.

---

## Environment Configuration

Create a `.env` file in the project root with the following variables:

### Required Variables (Core Functionality)

```bash
# Google Gemini API Key (Required)
# Get it from: https://aistudio.google.com/app/apikey
GEMINI_API_KEY=your-gemini-api-key-here

# Splunk HTTP Event Collector (Required)
SPLUNK_HEC_URL=https://localhost:8088/services/collector/event
SPLUNK_TOKEN=your-hec-token-here
SPLUNK_INSECURE_TLS=false  # Set to "true" for local Splunk with self-signed cert
```

### Optional Variables (Core Features)

```bash
# Slack Webhook (Optional - for alerts)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Server Port
PORT=3000
```

### Optional Variables (Agentic Enhancements)

```bash
# Splunk REST API (Required for SPL Query & Remediation Agent)
SPLUNK_REST_URL=https://localhost:8089
SPLUNK_API_TOKEN=your-api-token-here  # See Splunk Setup Guide for obtaining this
SPLUNK_SEARCH_INDEX=main
SPLUNK_SEARCH_TIMEOUT_MS=15000

# MCP Server (Optional - for AI assistant integration)
MCP_ENABLED=false
MCP_PORT=3001

# Trend Anomaly Detection (Optional - for background analysis)
TREND_ANALYSIS_ENABLED=false
TREND_ANALYSIS_INTERVAL_MS=60000
TREND_ANALYSIS_WINDOW_SIZE=50
```

### Environment Variable Reference Table

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GEMINI_API_KEY` | ✅ Yes | - | Google Gemini API key for AI detection |
| `SPLUNK_HEC_URL` | ✅ Yes | - | Splunk HEC endpoint URL |
| `SPLUNK_TOKEN` | ✅ Yes | - | HEC token for log forwarding |
| `SPLUNK_INSECURE_TLS` | No | `false` | Allow self-signed certs (local dev only) |
| `SLACK_WEBHOOK_URL` | No | - | Slack webhook for alerts |
| `PORT` | No | `3000` | Server port |
| `SPLUNK_REST_URL` | No | - | Splunk REST API URL (enables SPL Query & Remediation) |
| `SPLUNK_API_TOKEN` | No | - | Splunk REST API token |
| `SPLUNK_SEARCH_INDEX` | No | `main` | Default Splunk index to search |
| `SPLUNK_SEARCH_TIMEOUT_MS` | No | `15000` | Query timeout in milliseconds |
| `MCP_ENABLED` | No | `false` | Enable MCP server for AI assistants |
| `MCP_PORT` | No | `3001` | MCP server port |
| `TREND_ANALYSIS_ENABLED` | No | `false` | Enable trend anomaly detection |
| `TREND_ANALYSIS_INTERVAL_MS` | No | `60000` | Analysis interval (60 seconds) |
| `TREND_ANALYSIS_WINDOW_SIZE` | No | `50` | Number of records to analyze |

---

## Splunk Setup Guide

### Step 1: Install Splunk

If you don't have Splunk installed:

1. **Download Splunk Enterprise**: https://www.splunk.com/en_us/download/splunk-enterprise.html
2. **Install following platform-specific instructions**
3. **Start Splunk**:
   ```bash
   # Linux/macOS
   cd /opt/splunk/bin  # or your install directory
   ./splunk start --accept-license
   
   # Windows
   cd "C:\Program Files\Splunk\bin"
   splunk.exe start --accept-license
   ```
4. **Access Splunk Web**: https://localhost:8000 (default credentials: admin/changeme)

### Step 2: Enable HTTP Event Collector (HEC)

**Required for core functionality**

1. Log into Splunk Web (https://localhost:8000)
2. Navigate to **Settings → Data inputs → HTTP Event Collector**
3. Click **Global Settings**:
   - Enable HEC: **Yes**
   - HTTP Port: `8088` (default)
   - Click **Save**
4. Click **New Token**:
   - Name: `privacy-guard-interceptor`
   - Source type: Select or create `_json`
   - Index: `main` (or your preferred index)
   - Click **Create**
5. **Copy the token value** and set it as `SPLUNK_TOKEN` in your `.env` file

### Step 3: Obtain Splunk REST API Token

**Required for SPL Query Generation and Remediation Agent**

#### Option A: Create Token via Splunk Web

1. Navigate to **Settings → Token Management** (requires Splunk 8.2+)
2. Click **Create Token**
3. Configure:
   - Name: `privacy-guard-api`
   - Expiration: Choose duration (e.g., 365 days)
   - Roles: Select `admin` or appropriate role
4. Click **Create**
5. **Copy the token** and set it as `SPLUNK_API_TOKEN` in your `.env` file

#### Option B: Create Token via Command Line

```bash
# Navigate to Splunk bin directory
cd /opt/splunk/bin  # Linux/macOS
# or: cd "C:\Program Files\Splunk\bin"  # Windows

# Create token
./splunk createtoken --name "privacy-guard-api" --roles "admin" --expire-days 365

# Output will show the token value
```

#### Option C: Use Basic Authentication

If token creation fails (KVStore issues), use Basic Auth:

```bash
# Generate Base64 encoded credentials
echo -n "admin:yourpassword" | base64

# Output example: YWRtaW46Y2hhbmdlbWU=
```

Then in `.env`:
```bash
SPLUNK_API_TOKEN=Basic YWRtaW46Y2hhbmdlbWU=
```

### Step 4: Verify Splunk Configuration

Test your HEC setup:
```bash
curl -k https://localhost:8088/services/collector/event \
  -H "Authorization: Splunk YOUR_HEC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"event": {"message": "test"}, "sourcetype": "_json"}'
```

Test your REST API token:
```bash
curl -k https://localhost:8089/services/server/info \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

---

## Running the Application

### Start the Server

```bash
# Using npm script
npm start

# Or directly with Node
node --env-file=.env server.js
```

You should see:
```
[Init] Starting Privacy Guard Interceptor...
[Config] Feature availability:
  spl_query: ENABLED
  remediation_agent: ENABLED
  mcp_server: DISABLED
  trend_analyzer: DISABLED
[Success] Privacy Guard Interceptor listening on http://localhost:3000
```

### Start Demo Log Generator

In a separate terminal:
```bash
npm run generate
```

This posts randomized logs (clean + PII-bearing) to `/api/intercept` every 5 seconds, demonstrating real-time detection and redaction.

### Access the Dashboard

Open **http://localhost:3000/dashboard** to see:
- Total processed logs counter
- Severity breakdown
- PII category distribution
- Live streaming feed of intercepts
- AI audit status

---

## API Endpoints

### POST /api/intercept

Core endpoint for log interception, PII detection, and Splunk forwarding.

**Request:**
```json
{
  "time": 1717862400000,
  "event": {
    "level": "ERROR",
    "message": "Payment failed for card 4111111111111111"
  }
}
```

**Response:**
```json
{
  "status": "Processed",
  "splunk_response": {
    "text": "Success",
    "code": 0
  }
}
```

**Redacted Event in Splunk:**
```json
{
  "level": "ERROR",
  "message": "Payment failed for card [REDACTED_CREDIT_CARD]",
  "violation_flag": true,
  "violation_severity": "critical",
  "violation_categories": ["credit_card"],
  "violation_sources": ["regex"],
  "ai_audited": true
}
```

### POST /api/ai/query

**Agentic Enhancement**: Natural language to Splunk queries.

**Request:**
```json
{
  "question": "Show me all critical credit card violations in the last 24 hours"
}
```

**Response:**
```json
{
  "question": "Show me all critical credit card violations in the last 24 hours",
  "spl": "index=\"main\" violation_severity=\"critical\" violation_categories=\"credit_card\" earliest=-24h",
  "results": [
    { "time": 1717862400, "message": "[REDACTED_CREDIT_CARD]", ... }
  ],
  "confidence": 0.85,
  "metadata": {
    "results_count": 15,
    "splunk_index": "main"
  }
}
```

**Requirements**: `SPLUNK_REST_URL` and `SPLUNK_API_TOKEN` must be configured.

### GET /api/dashboard/snapshot

Returns current dashboard state snapshot.

**Response:**
```json
{
  "totalProcessed": 1250,
  "totalRedacted": 423,
  "severityCounts": {
    "critical": 12,
    "high": 45,
    "medium": 156,
    "low": 210
  },
  "categoryCounts": {
    "credit_card": 89,
    "api_key": 34,
    "ssn": 23,
    "email": 67
  },
  "recent": [...]
}
```

### GET /api/dashboard/stream

Server-Sent Events endpoint for real-time dashboard updates.

---

## Agentic Enhancements

### 1. SPL Query Generation

**Endpoint**: `POST /api/ai/query`

Transform natural language questions into valid Splunk queries:

```bash
curl -X POST http://localhost:3000/api/ai/query \
  -H "Content-Type: application/json" \
  -d '{"question": "How many API key violations occurred this week?"}'
```

**Features:**
- AI-powered query generation using Gemini
- Automatic query execution against Splunk
- Confidence scoring for generated queries
- Natural language interpretation of results

**Requirements**: `SPLUNK_REST_URL` + `SPLUNK_API_TOKEN`

### 2. Agentic Remediation Loop

**Trigger**: Automatically activated on critical severity violations

When a critical PII violation is detected:
1. Extracts source service from log metadata
2. Queries Splunk for historical occurrences (30-day window)
3. Generates AI-powered code fix suggestions using Gemini
4. Posts comprehensive investigation report to Slack
5. All actions logged with investigation ID for tracking

**Example Slack Alert:**
```
🔍 Critical PII Violation Investigation Complete

Investigation ID: inv_1717862400_abc123
Severity: critical
Source Service: payment-service
Violation Category: credit_card
Historical Occurrences (30d): 7

💡 Code Fix Suggestion:
Replace: console.error(`Payment failed for card ${cardNumber}`)
With: console.error(`Payment failed for card ending in ${cardNumber.slice(-4)}`)

Root Cause: Payment service logging full card numbers in error messages
Prevention: Add log sanitization middleware
```

**Requirements**: `SPLUNK_REST_URL` + `SPLUNK_API_TOKEN` + `SLACK_WEBHOOK_URL` (optional)

### 3. Splunk MCP Server

**Port**: 3001 (configurable via `MCP_PORT`)

Provides Model Context Protocol tools for AI assistants:

**Available Tools:**
- `detect_pii` — Analyze text for PII violations
- `get_dashboard_snapshot` — Get current compliance metrics
- `generate_spl_query` — Convert natural language to SPL
- `execute_spl_query` — Execute SPL against Splunk

**Usage with AI Assistants:**
Configure your AI assistant (Claude, GPT-4, etc.) to connect to the MCP server at `http://localhost:3001`

**Requirements**: `MCP_ENABLED=true`

### 4. Trend Anomaly Detection

**Trigger**: Background job running every 60 seconds (configurable)

Monitors recent PII violation patterns and detects anomalies:
- **Category Spikes**: Unusual frequency in specific PII categories
- **New Categories**: First-time appearance of PII types
- **Critical Severity Surges**: Spike in critical violations
- **AI-Down Clustering**: Consecutive AI audit failures

**Alert Channels:**
- Dashboard broadcast (real-time)
- Slack notifications

**Requirements**: `TREND_ANALYSIS_ENABLED=true`

---

## Testing

### Run All Tests

```bash
npm test
```

Runs 80 tests covering:
- Regex detector (Luhn/IBAN validation)
- LLM response parsing and error handling
- Merge/redact ordering
- Severity ranking
- Dashboard store (ring buffer, counters, SSE)
- Dashboard routes

### Test Coverage

```
✓ Detection (30 tests)
  ✓ Regex patterns (credit card, SSN, API keys, etc.)
  ✓ Luhn validation
  ✓ IBAN validation
  ✓ LLM detector
  ✓ Merge logic
  ✓ Redaction

✓ Dashboard (25 tests)
  ✓ Store operations
  ✓ SSE streaming
  ✓ Snapshot generation
  ✓ Ring buffer eviction

✓ Integration (25 tests)
  ✓ API endpoints
  ✓ Error handling
  ✓ Graceful degradation
```

### Manual Testing

Test a single intercept:
```bash
curl -X POST http://localhost:3000/api/intercept \
  -H "Content-Type: application/json" \
  -d '{
    "time": 1717862400000,
    "event": {
      "level": "ERROR",
      "message": "User john.doe@example.com failed login with SSN 123-45-6789"
    }
  }'
```

---

## Project Structure

```
.
├── server.js                          # Express server + route definitions
├── data-generator.js                  # Demo log producer
├── public/dashboard.html              # Single-page compliance dashboard
├── src/
│   ├── config.js                      # Environment config & validation
│   ├── splunk.js                      # HEC client (scoped TLS bypass)
│   ├── alerts.js                      # Slack webhook integration
│   ├── spl-generator.js               # SPL query generator (AI)
│   ├── splunk-search.js               # Splunk REST API client
│   ├── remediation-agent.js           # Autonomous investigation agent
│   ├── remediation-report.js          # Investigation report formatting
│   ├── mcp-server.js                  # MCP server for AI assistants
│   ├── trend-analyzer.js              # Anomaly detection background job
│   ├── anomaly-alert.js               # Anomaly alert formatting
│   ├── detection/
│   │   ├── index.js                   # detectPII() — orchestrates regex + LLM
│   │   ├── regex.js                   # Luhn / IBAN-validated patterns
│   │   ├── llm.js                     # Gemini contextual detector
│   │   ├── merge.js                   # Deduplicated finding merge
│   │   ├── redact.js                  # In-place [REDACTED_*] substitution
│   │   └── severity.js                # Category → severity ranking
│   └── dashboard/
│       ├── store.js                   # Ring buffer + SSE pub/sub
│       └── routes.js                  # /dashboard, /api/dashboard/*
├── ARCHITECTURE.md                    # System diagram & data flow
├── PROJECT.md                         # Project pitch
├── README.md                          # This file
├── LICENSE                            # MIT
└── .env                               # Environment variables (gitignored)
```

---

## Security Notes

- **Environment Variables**: `.env` is gitignored. Never commit API keys or tokens.
- **PII Isolation**: Splunk only receives redacted messages; original PII never leaves the interceptor process.
- **Slack Alerts**: Contain category names and severity only—not the offending values.
- **LLM Validation**: Responses are validated by checking that every claimed substring actually exists in the original message.
- **Scoped TLS Bypass**: `SPLUNK_INSECURE_TLS=true` only loosens cert validation for Splunk requests, never globally.
- **Token Security**: Splunk tokens should have minimal required permissions.

---

## Troubleshooting

### "Missing required env var: GEMINI_API_KEY"

**Solution**: Set your Gemini API key in `.env`:
```bash
GEMINI_API_KEY=your-api-key-here
```
Get a key from: https://aistudio.google.com/app/apikey

### "Splunk REST API not configured"

**Solution**: Add Splunk REST API credentials:
```bash
SPLUNK_REST_URL=https://localhost:8089
SPLUNK_API_TOKEN=your-token-here
```

### "Token creation failed because: KVStore is not ready"

**Solution A**: Restart Splunk and wait 30-60 seconds for KVStore to initialize:
```bash
./splunk restart
sleep 60
```

**Solution B**: Use Basic Auth instead of token:
```bash
echo -n "admin:yourpassword" | base64
# Add to .env as: SPLUNK_API_TOKEN=Basic <base64-output>
```

### "SPLUNK_INSECURE_TLS warnings"

**Solution**: This is expected for local Splunk with self-signed certificates. For production, use proper TLS certificates and set `SPLUNK_INSECURE_TLS=false`.

### Dashboard shows "AI-down badge"

**Cause**: Gemini API timeout or rate limit.

**Solution**: 
- Check your API key is valid
- Verify internet connectivity
- Check Gemini service status: https://status.cloud.google.com/

### Tests failing

**Solution**: Ensure all dependencies are installed:
```bash
npm install
npm test
```

### Application won't start

**Check logs for**:
- Missing environment variables
- Port already in use (change `PORT` in `.env`)
- Invalid API keys

---

## API Examples

### Example 1: Credit Card Detection

```bash
curl -X POST http://localhost:3000/api/intercept \
  -H "Content-Type: application/json" \
  -d '{
    "time": 1717862400000,
    "event": {
      "level": "ERROR",
      "message": "Payment failed for card 4111111111111111"
    }
  }'
```

**Result**: `4111111111111111` → `[REDACTED_CREDIT_CARD]`

### Example 2: API Key Detection

```bash
curl -X POST http://localhost:3000/api/intercept \
  -H "Content-Type: application/json" \
  -d '{
    "time": 1717862400000,
    "event": {
      "level": "WARN",
      "message": "Invalid API key sk_live_51HabcXYZ123abcDEF rejected"
    }
  }'
```

**Result**: `sk_live_51HabcXYZ123abcDEF` → `[REDACTED_API_KEY]`

### Example 3: SPL Query Generation

```bash
curl -X POST http://localhost:3000/api/ai/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Count violations by severity in the last 7 days"}'
```

**Result**: Returns Splunk query and results:
```json
{
  "spl": "index=\"main\" violation_flag=true earliest=-7d | stats count by violation_severity",
  "results": [...],
  "confidence": 0.92
}
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## Support

- **Issues**: Open an issue on GitHub
- **Documentation**: See [ARCHITECTURE.md](ARCHITECTURE.md) for system details
- **Splunk Setup**: See [Splunk Setup Guide](#splunk-setup-guide) section above

---

**Built for the Splunk AI Hackathon** 🚀
