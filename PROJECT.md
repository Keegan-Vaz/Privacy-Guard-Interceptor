# Privacy Guard Interceptor

**One-line pitch:** A compliance middleware that scrubs PII and secrets out
of application logs *before* they reach Splunk, using a hybrid of
deterministic regex and Google Gemini for contextual detection — with a
live dashboard that proves it is working.

## The problem

Modern apps generate enormous volumes of logs, and developers routinely
write sensitive data into them by accident: a debug print of a request
body, an exception that includes a Stripe key in its stack trace, a SQL
log that captures a customer's password reset. Once that data hits
Splunk, it is indexed, replicated, queryable, and — under GDPR, HIPAA,
PCI-DSS — a reportable incident. Cleanup is expensive (re-indexing,
forensic search history audits) and often impossible to do completely.

The standard mitigation, regex-based filtering at the forwarder, catches
high-confidence patterns like credit cards and API keys but is blind to
contextual PII: names, postal addresses, free-text passwords, dates of
birth, medical-record context. Those are exactly the categories most
regulators care about.

## The value

Privacy Guard Interceptor moves the redaction boundary *before* Splunk
ingest and adds a contextual AI pass on top of regex. It:

- **Prevents incidents instead of cleaning them up.** Splunk only ever
  sees `[REDACTED_CREDIT_CARD]`, never the card number. Your audit log
  history stays clean.
- **Catches what regex misses.** Gemini 2.5 Flash flags
  "Shipment address: 221B Baker Street, London NW1 6XE" or "User reset
  password to 'P@ssw0rd2024!'" — both invisible to pattern matchers.
- **Validates before it redacts.** Credit-card candidates are Luhn-checked
  and IBANs are mod-97-checked, so logs full of order IDs do not get
  spuriously masked.
- **Proves compliance in real time.** A live dashboard streams every
  intercept over Server-Sent Events with severity, category breakdown,
  redacted output, and counters for regulators or on-call engineers.
- **Fails safely.** If Gemini times out or rate-limits, regex detection
  continues and the dashboard surfaces an "AI down" badge — the pipeline
  never silently degrades to no-op.

## How it works

1. Applications POST logs to `/api/intercept` instead of writing directly
   to a Splunk forwarder.
2. The interceptor runs **regex and LLM detection in parallel**. Regex
   hits are authoritative for the patterns it knows; the LLM is asked
   only about contextual categories regex cannot see, and its claimed
   substrings are verified against the original message before being
   trusted (the model cannot invent or rewrite text).
3. Findings are merged, the message is rewritten in place with
   `[REDACTED_<CATEGORY>]` markers, and the worst category sets the
   record's overall severity (`critical | high | medium | low`).
4. The **redacted** payload is forwarded to Splunk HEC together with
   structured violation metadata (`violation_severity`,
   `violation_categories`, `violation_sources`, detection timings,
   `ai_audited` flag).
5. The same intercept is recorded in an in-memory ring buffer and pushed
   to any connected dashboards via SSE. Violations also optionally fire a
   Slack webhook with category + severity (never the offending value).

## Where AI fits

Google Gemini 2.5 Flash is the **contextual detection** layer. It runs
with `temperature: 0.0`, JSON response mode, a small enumerated category
set, and a strict system prompt that instructs the model to return exact
substrings — which the interceptor then verifies against the original
log before any redaction. This sharply constrains the failure modes:
Gemini cannot rewrite the log, cannot invent PII, and cannot mask
something that was not actually there.

## Splunk integration

Forwarding is plain HTTP Event Collector (`Authorization: Splunk <token>`).
The redacted message and every violation field land as structured fields
in the indexed event, so a single search like
`violation_severity=critical | stats count by violation_categories`
shows what kinds of sensitive data your codebase tries to log most often
— without ever exposing the values themselves.

## Status

End-to-end working: hybrid detection, Splunk HEC forwarding, live
dashboard with SSE updates, optional Slack alerts, and a packaged demo
data generator. Tests cover detection, merging, redaction, severity,
dashboard store, and routes.
