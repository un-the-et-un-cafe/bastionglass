# Network visibility and responsible reporting

## What traffic analysis actually does

v0 analyzes **synthetic, preclassified metadata only**. It can count supplied byte amounts, plaintext labels, unknown transports and unapproved-destination labels. It cannot see packets, inspect actual TLS payloads, classify real endpoints, detect exfiltration, or observe provider-hosted connector traffic. No packet-capture capability probe is attempted.

A VPN is a transport, not proof of endpoint detection. HTTPS encrypts application data; ordinary packet capture does not reveal all plaintext. TLS interception would introduce a high-value trust/key boundary and could expose session cookies, API tokens and private messages. It is absent from v0.1.0. Any proposed deep inspection needs a separate threat/privacy review, supported provider permissions and an explicit decision about whether its benefit justifies that exposure; roadmap inclusion does not enable interception.

Before any future live telemetry: define exact interfaces/process scope, ownership and approval, minimum fields, local retention, redaction tests, access controls, traffic overhead and failure behavior. Prefer provider-supported aggregate metadata over payload capture. Never collect credentials or unrelated user content. No raw socket, packet capture, proxy, certificate injection, VPN, host network setting or persistent collector may be introduced as a routine rule update.

## Evidence ladder

1. **Observation or heuristic candidate:** a pattern match, old version, failed build, access denial or unexpected network label. Keep local and investigate safely. These do not prove malicious execution.
2. **Corroborated vulnerability:** reproducible evidence within authorized scope, an affected component/configuration and a minimized explanation. Do not execute exploits to obtain evidence outside authorization.
3. **Confirmed dangerous execution/incident:** stop affected owned work where allowed, preserve minimal redacted evidence without rerunning it, notify the owner privately and use the approved secure disclosure process.

The current suite does not decide or submit an external report at any level. Approved, minimized reporting is a planned capability in the [roadmap](ROADMAP.md). “Report every anomaly” is not an acceptable implementation shortcut: it can leak private data, create false alarms and obscure meaningful incidents. An eventual reporting component needs an exact authorized recipient, minimal allowed fields, redaction validation, evidence threshold, deduplication, rate limits, delivery receipts and an owner-controlled stop. No such component is active in v0.

## Official OpenAI route, checked 2026-10-30

- https://openai.com/security.txt
- https://openai.com/policies/coordinated-vulnerability-disclosure-policy/
- The official security.txt lists Bugcrowd and `disclosure@openai.com`; its encryption-key location is https://cdn.openai.com/security/disclosure.asc.pub .

Recheck the official route and applicable reporting permissions at the time of a real report. A downloaded key or signed security.txt requires appropriate authenticity verification; reading its URL is not signature verification. The disclosure policy requests encrypted incident reports. Do not claim OpenAI received or accepted a report without a receipt, or is monitoring this workspace without evidence.

## Minimal private incident template (not sent)

- Evidence category and affected component/version, including uncertainty/backports.
- UTC observation time and bounded reproduction summary using benign/minimized material.
- Security impact supported by observations, not speculation.
- Already-permitted containment taken and work paused.
- Redacted evidence references; no credentials, session data, private prompts, customer records or unrelated source.
- Exact approved recipient/channel and secure delivery method.
- Owner approval/standing permission checked at action time; delivery outcome if actually sent.

Never automatically attach a full scan report or upload source code. Keep even redacted local observations private until reviewed for their specific destination.
