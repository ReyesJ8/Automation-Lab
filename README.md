# Automated SecOps CVE Alert & Enrichment Pipeline

An automated Security Operations (SecOps) pipeline built with n8n, OpenAI (GPT-4), the NIST National Vulnerability Database (NVD) API v2.0, and Discord Webhooks.

This workflow fetches recently published High- and Critical-severity CVEs, deduplicates entries using n8n Data Tables, enriches each finding with LLM-generated context, and posts actionable, Markdown-formatted alerts to a SecOps Discord channel.

---

## Table of Contents

- [Overview](#overview)
- [Architecture & Workflow](#architecture--workflow)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Implementation Steps](#implementation-steps)
  - [Step 1: Pipeline Trigger Setup](#step-1-pipeline-trigger-setup)
  - [Step 2: Dynamic Lookback Window Calculation](#step-2-dynamic-lookback-window-calculation)
  - [Step 3: NVD API v2.0 Querying](#step-3-nvd-api-v20-querying)
  - [Step 4: CVE Schema Normalization](#step-4-cve-schema-normalization)
  - [Step 5: Vulnerability Severity Filtering](#step-5-vulnerability-severity-filtering)
  - [Step 6: Stateful Tracking & Deduplication](#step-6-stateful-tracking--deduplication)
  - [Step 7: AI Threat Enrichment (LLM Chain)](#step-7-ai-threat-enrichment-llm-chain)
  - [Step 8: Incident Delivery via Discord Webhook](#step-8-incident-delivery-via-discord-webhook)
- [Sample Discord Alert Output](#sample-discord-alert-output)
- [Key SOC Analyst Takeaways](#key-soc-analyst-takeaways)
- [Future Enhancements](#future-enhancements)

---

## Overview

Manual triage of vulnerability feeds consumes significant SOC analyst time. NVD notifications are machine-readable but often lack operational context, detection guidance, and direct integration with team communication channels.

This project implements an automated SecOps pipeline that:

1. Polls the NVD API v2.0 on a configurable schedule.
2. Isolates CVEs published within a dynamic rolling lookback window.
3. Filters for high-impact threats (CVSS Base Score >= 8.0 by default).
4. Prevents duplicate alerts using stateful table management.
5. Uses an LLM to generate SIEM detection queries, EDR hunting rules, and remediation steps.
6. Publishes Markdown alerts to Discord for ChatOps-driven triage.

---

## Architecture & Workflow

Flow (high-level):

Schedule Trigger -> Dynamic Lookback (JS) -> NVD API v2.0 Fetch -> Extract Vulnerabilities -> Data Mapping & Fallbacks -> CVSS Filter -> Upsert to Data Table -> LLM Enrichment -> Discord Webhook

ASCII diagram:

```
┌─────────────────┐    ┌────────────────────┐    ┌─────────────────────┐
│ Schedule        │───>│ Dynamic Date       │───>│ NVD API v2.0        │
│ Trigger         │    │ Lookback (JS)      │    │ Fetch (GET)         │
└─────────────────┘    └────────────────────┘    └─────────────────────┘
                                                            │
┌─────────────────┐    ┌────────────────────┐    ┌──────────┴──────────┐
│ CVSS Filter     │<───│ Data Mapping &     │<───│ Extract Raw         │
│ (Score >= 8.0)  │    │ Fallback Handling  │    │ Vulnerabilities     │
└────────┬────────┘    └────────────────────┘    └─────────────────────┘
         │
         ▼
┌─────────────────┐    ┌────────────────────┐    ┌─────────────────────┐
│ Upsert to Data  │───>│ New CVE Filter     │───>│ LLM Enrichment      │
│ Table Storage   │    │ (Exclude Handled)  │    │ (OpenAI GPT-4)      │
└─────────────────┘    └────────────────────┘    └──────────┬──────────┘
                                                            │
                                                            ▼
                                                 ┌─────────────────────┐
                                                 │ Discord Webhook     │
                                                 │ Alert Notification  │
                                                 └─────────────────────┘
```

---

## Features

- Automated data retrieval from NVD API v2.0 with ISO 8601 date filters and configurable lookback window (note: NVD enforces a 120-day max lookback for some endpoints — respect the API rules).
- Custom severity thresholds to reduce alert fatigue (default: CVSS >= 8.0).
- Stateful deduplication using n8n Data Tables (store processed CVE IDs and metadata).
- LLM-driven enrichment that converts raw CVE descriptions into prioritized remediation steps, SIEM queries, and EDR hunting logic.
- ChatOps integration: formatted Markdown alerts posted to Discord via Webhooks.

---

## Prerequisites

- n8n instance (self-hosted via Docker or desktop, or n8n Cloud).
- NVD API key (register at the NIST NVD Developer Portal).
- OpenAI API key (for GPT-4 or similar model usage).
- Discord Webhook URL (create under Server Settings -> Integrations -> Webhooks).

---

## Implementation Steps

### Step 1: Pipeline Trigger Setup

1. Open your n8n canvas and create a new workflow named "SecOps CVE Alert Pipeline".
2. Add a Schedule Trigger node with these parameters:
   - Trigger Interval: Hours
   - Hours Between Triggers: 4 (adjust as desired)
   - Trigger at Minute: 0

### Step 2: Dynamic Lookback Window Calculation

NVD expects date-time in ISO 8601. Below is an n8n JavaScript Code node that computes a 5-day lookback window and formats dates to the pattern used by NVD (YYYY-MM-DDTHH:mm:ss.SSS). Adjust the window as required. Ensure you stay within any API-enforced window limits (for example: 120 days maximum in some NVD endpoints).

Code node (JavaScript, Mode: Run Once for All Items):

```javascript
// Establish dynamic 5-day lookback window
const endDate = new Date();
const startDate = new Date();
startDate.setDate(endDate.getDate() - 5);

// Format date to NVD ISO 8601 requirement (YYYY-MM-DDTHH:mm:ss.000)
function formatNvdDate(date) {
  // Use toISOString(), then replace the fractional seconds part with .000 (NVD examples use .000)
  return date.toISOString().replace(/\.\d+Z$/, '.000');
}

return [{
  json: {
    pubStartDate: formatNvdDate(startDate),
    pubEndDate: formatNvdDate(endDate)
  }
}];
```

Notes:
- If you need millisecond precision, you can use date.toISOString() directly. The replace above normalizes fractional seconds to `.000` which aligns with many NVD examples.

### Step 3: NVD API v2.0 Querying

Add an HTTP Request node in n8n to query the NVD API endpoint.

Parameters:
- Method: GET
- URL: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Send Query Parameters: on
  - `pubStartDate`: `{{ $json.pubStartDate }}`
  - `pubEndDate`: `{{ $json.pubEndDate }}`
  - `resultsPerPage`: `20` (tune as needed)
  - `startIndex`: `0`
- Send Headers: on
  - Header Name: `apiKey`
  - Header Value: `<YOUR_NVD_API_KEY>` (use n8n credentials or environment secrets; never hardcode in plain text)

Tip: Respect API rate limits and implement pagination if you expect more than `resultsPerPage` results.

### Step 4: CVE Schema Normalization

NVD responses are nested. Normalize the payload into a flat schema with fallbacks for missing fields.

Add a Code node (JavaScript, Mode: Run Once for All Items) and paste:

```javascript
return $input.all().flatMap(item => {
  return item.json.vulnerabilities.map(v => {
    const cve = v.cve;
    // Extract CVSS v3.1 metrics with optional chaining fallbacks
    const metrics = cve.metrics?.cvssMetricV31?.[0]?.cvssData || {};
    return {
      json: {
        cveId: cve.id,
        description: cve.descriptions?.[0]?.value || "No description provided.",
        score: metrics.baseScore || 0,
        severity: metrics.baseSeverity || "UNKNOWN",
        published: cve.published
      }
    };
  });
});
```

Consider adding additional fields (references, CWE, affected products) as needed by your SOC.

### Step 5: Vulnerability Severity Filtering

Add an If node to allow only high-impact vulnerabilities to continue down the pipeline.

Condition example:
- Value 1: `{{ $json.score }}`
- Operation: `is greater than or equal to`
- Value 2: `8`

Adjust the threshold to your operational tolerance (e.g., 7.0 for medium-high environments).

### Step 6: Stateful Tracking & Deduplication

Use n8n Data Tables to record processed CVEs and prevent duplicate notifications.

1. Create Data Table
   - Name: `Processed CVEs`
   - Columns: `cveID` (String), `description` (String), `severity` (String), `score` (Number), `published` (String)

2. Upsert Rows Node (connected to the True branch of the If node)
   - Operation: Upsert
   - Data Table: `Processed CVEs`
   - Match Condition: `cveID Equals {{ $json.cveId }}`
   - Mapping Mode: Map Each Column Manually (map `cveID`, `description`, `severity`, `score`, `published`)

3. Deduplication filter
   - Add a second If node to exclude items that were already present before the upsert (check the returned metadata from the upsert to determine whether the row was newly created or already existed).

Notes:
- Store a timestamp of first-seen and last-seen if you want to track recurring exposures.

### Step 7: AI Threat Enrichment (LLM Chain)

Add an LLM node (e.g., OpenAI Chat Model) to synthesize the raw CVE into actionable guidance.

System message (example):

```
You are an expert SecOps assistant. Convert raw CVE data into a concise, high-priority Discord Markdown alert containing:
- CVE overview and severity assessment
- Prioritized recommended actions
- Detection guidance (SIEM query template & EDR hunt logic)
- Example remediation commands or playbook steps (Ansible, iptables, vendor patch guidance)
Keep responses short, actionable, and formatted using Markdown headings, fenced code blocks for queries/commands, and bullet lists for steps.
```

User message (example):

```
{{ $json.description }}
Additional metadata:
- CVE ID: {{ $json.cveId }}
- Score: {{ $json.score }}
- Severity: {{ $json.severity }}
- Published: {{ $json.published }}
```

Connect the LLM model sub-node set to `gpt-4` or a suitable model in your account.

Security note: Do not send any sensitive internal telemetry or PII to external LLM services unless allowed by policy.

### Step 8: Incident Delivery via Discord Webhook

Add a Discord node (Webhook) to send the LLM-generated text as a message in your channel.

Parameters:
- Resource / Operation: Message -> Send a Message
- Connection Type: Webhook
- Webhook Credential: Use your configured Discord Webhook
- Message content: `{{ $json.text }}` or `{{ $json.body }}` depending on your LLM node output field

Formatting:
- Use Markdown for headings and fenced code blocks so messages render cleanly in Discord.

---

## Sample Discord Alert Output

Below is an example of the kind of Markdown alert this pipeline should produce. The LLM should output a similar structure but tailored to the CVE.

```
**CVE-2026-XXXX** — Critical (CVSS: 9.1)
Published: 2026-10-21

Summary:
A remote code execution vulnerability exists in ExampleProduct <= 1.2.3 that allows unauthenticated attackers to execute arbitrary code via crafted requests to the `api/upload` endpoint.

Risk Assessment:
- Impact: Remote Code Execution
- Likelihood: High (public exploit available)

Recommended Actions (Prioritized):
1. Immediately apply vendor patch 1.2.4 or later.
2. If patching is not possible, block access to `api/upload` from untrusted networks via firewall rules.
3. Mitigate by disabling the vulnerable feature or using WAF rules to block exploit payloads.

Detection (SIEM query):
```sql
/* Example Splunk query */
index=web_logs source="/var/log/nginx/access.log" "POST" "/api/upload" | stats count by src_ip, http_user_agent
```

EDR Hunt (example):
```bash
# Search for process executions of the vulnerable binary
process_name=exampled
ps aux | grep "${process_name}"
```

Remediation Example (iptables):
```bash
# Block inbound access to the vulnerable endpoint from the internet
iptables -A INPUT -p tcp --dport 80 -m string --string "/api/upload" --algo bm -j DROP

```
References:
- https://nvd.nist.gov/vuln/detail/CVE-2026-XXXX

## Key SOC Analyst Takeaways

- The pipeline reduces manual triage by delivering prioritized, context-rich alerts.
- Use the Data Table metadata to measure the rate of new vs. recurring CVEs and tune filters.
- Maintain an allow/blocklist for affected vendors and products to reduce false positives.

---

## Future Enhancements

- Add multi-model consensus (run two different LLM prompts/models and compare outputs before posting).
- Integrate vendor advisories and exploit databases (ExploitDB, Metasploit) for exploit maturity scoring.
- Add CI/CD automation to open and close tickets (Jira, ServiceNow) for tracked remediation tasks.
- Support multiple ChatOps targets (Slack, Microsoft Teams) and templated incident pages (Confluence).

---

## Appendix: Useful n8n Tips

- Store API keys and Webhook URLs in n8n Credentials or environment variables — never inline them in the workflow code.
- Test LLM prompts offline on a few sample CVEs before enabling automatic posting to production channels.
- Add exponential backoff and retry handling to the HTTP Request node to handle transient NVD API errors gracefully.
# Automation-Lab
Automated SecOps CVE Alert &amp; Enrichment Pipeline
