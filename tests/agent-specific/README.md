# Glance — Agent-Specific Test Cases

Demo-ready security test cases showing vulnerabilities unique to AI agent systems.
Each snippet is real agent/MCP/skill code with the vulnerability clearly marked.

Use these to demonstrate Glance on launch day and in marketing materials.

---

## Quick Demo Script

```bash
cd agent-security-scanner

# Run Glance on each vulnerable case
node dist/cli.js analyze --file tests/agent-specific/01_hardcoded_credentials.js
node dist/cli.js analyze --file tests/agent-specific/02_mcp_sql_injection.js
node dist/cli.js analyze --file tests/agent-specific/04_command_injection_skill.js

# Show the safe case passes cleanly (zero findings)
node dist/cli.js analyze --file tests/agent-specific/09_safe_mcp_server.js

# Scan the entire agent-specific directory at once
node dist/cli.js analyze --path tests/agent-specific/
```

---

## Test Cases

### 01 — Hardcoded Credentials in Agent Skill
**File:** `01_hardcoded_credentials.js`
**Severity:** CRITICAL
**Category:** Hardcoded Secrets

A payment-processing agent skill with Stripe secret key, OpenAI API key, and
database password hardcoded in source. Any agent that loads this skill, any
skill registry that indexes it, or any developer who clones the repo gets
all three credentials immediately.

**Glance flags:**
- Stripe `sk_live_` key — CRITICAL
- OpenAI `sk-proj-` token — CRITICAL
- Hardcoded DB password — HIGH

**Demo talking point:** "This is the number one mistake we see in real agent deployments. The skill ships with working credentials baked in."

---

### 02 — SQL Injection in MCP Server Tool
**File:** `02_mcp_sql_injection.js`
**Severity:** CRITICAL
**Category:** SQL Injection

An MCP server exposes a `query_users` tool. The tool concatenates the tool
argument directly into a SQL string. Any orchestrator — or a prompt injection
attack that hijacks an orchestrator — can call this tool with a crafted argument
to dump, modify, or destroy the database.

**Glance flags:**
- SQL injection via string concatenation in MCP tool handler — CRITICAL
- No input validation before database query — HIGH

**Demo talking point:** "Traditional scanners miss this because they don't understand that MCP tool arguments are untrusted user input. Glance's semantic layer does."

---

### 03 — Path Traversal in File-Reader Skill
**File:** `03_path_traversal_skill.js`
**Severity:** HIGH
**Category:** Path Traversal

An agent skill that reads workspace files on request uses `path.join()` —
which does NOT prevent directory traversal — instead of `path.resolve()` with
a boundary check. An LLM prompted with "read ../../.env" will pass that string
directly to the skill.

**Glance flags:**
- User input used in file path without boundary validation — HIGH

**Demo talking point:** "The developer used path.join thinking it was safe. It's not. Only path.resolve + startsWith check creates a real sandbox."

---

### 04 — Command Injection in DevOps Agent Skill
**File:** `04_command_injection_skill.js`
**Severity:** CRITICAL
**Category:** Command Injection

A DevOps agent skill accepts a command and hostname from the LLM and runs
`ssh ${target} "${command}"` via exec(). A single prompt injection in any
message the agent processes gives the attacker RCE on both the agent host
and any SSH-accessible server.

**Glance flags:**
- User input passed to exec() — CRITICAL
- Shell interpolation of untrusted variable — CRITICAL

**Demo talking point:** "This is the agent equivalent of OS command injection. The blast radius is enormous because the agent has SSH access to production."

---

### 05 — Privilege Escalation via Tool Orchestration
**File:** `05_privilege_escalation.js`
**Severity:** CRITICAL
**Category:** Privilege Escalation

An agent orchestrator chains a low-privilege lookup tool into a high-privilege
delete tool without re-checking authorization between steps. The agent's support
role token is used for both. A prompt injection in a support ticket can pivot
the lookup into an account deletion.

**Glance flags:**
- No authorization check before admin action — CRITICAL
- Tool chain executes privileged operations without re-validation — HIGH

**Demo talking point:** "This is unique to agents. No single tool is broken — the vulnerability is in how they're chained. Only agent-aware scanning catches this."

---

### 06 — Sensitive Data Leakage via Logs
**File:** `06_sensitive_data_leakage.js`
**Severity:** HIGH
**Category:** Information Disclosure

A CRM agent skill logs the full API response (including SSN, DOB, credit card
data) and the session token to stdout. In production these logs ship to Datadog
or CloudWatch, making sensitive customer data available to anyone with log access.

**Glance flags:**
- Sensitive data (PII/credentials) written to logs — HIGH
- Session token logged in plain text — HIGH

**Demo talking point:** "Agents process sensitive data constantly. Every console.log is a potential GDPR incident. Glance catches these before they reach prod."

---

### 07 — Unsafe Deserialization in Task Queue Consumer
**File:** `07_unsafe_deserialization.js`
**Severity:** CRITICAL
**Category:** Insecure Deserialization

An agent that consumes tasks from a message queue uses `node-serialize.unserialize()`,
which executes any function embedded in the serialized string. An attacker with
write access to the queue sends a crafted payload and achieves RCE inside the
agent process.

**Glance flags:**
- Unsafe deserialization via node-serialize — CRITICAL
- Code execution via crafted serialized payload — CRITICAL

**Demo talking point:** "Agent task queues are an often-overlooked attack surface. If another agent or service is compromised, it can use the queue to pivot into your agent."

---

### 08 — Prompt Injection via Unvalidated External Content
**File:** `08_prompt_injection_relay.js`
**Severity:** HIGH
**Category:** Prompt Injection / Information Disclosure

An agent summarization skill fetches a URL and passes the raw page content
directly into the LLM prompt. An attacker who controls the page content can
inject instructions that hijack the agent's next actions.

**Glance flags:**
- Unvalidated external content injected into LLM prompt — HIGH
- No content sanitization before passing to model context — HIGH

**Demo talking point:** "Prompt injection is the XSS of AI agents. Every piece of external content is potentially adversarial. Glance's semantic analysis understands what goes into the model context."

---

### 09 — Safe MCP Server (Zero Findings)
**File:** `09_safe_mcp_server.js`
**Severity:** NONE
**Category:** Reference Implementation

A correctly-written MCP server demonstrating all mitigations:
- Credentials from environment variables
- Table name validated against allowlist
- Input validated (type, length, character class)
- Parameterized SQL query
- Sanitized logging (no PII, no tokens)
- TLS enforced on database connection

**Glance flags:** None. Risk score: 0.

**Demo talking point:** "Glance knows the difference between real vulnerabilities and safe patterns. Zero false positives on correctly-written agent code."

---

## Coverage Summary

| # | File | Vulnerability | Severity | OWASP / Agent Risk |
|---|------|--------------|----------|-------------------|
| 01 | `01_hardcoded_credentials.js` | Hardcoded API keys + DB password | CRITICAL | A07: Identification failures |
| 02 | `02_mcp_sql_injection.js` | SQL injection in MCP tool | CRITICAL | A03: Injection |
| 03 | `03_path_traversal_skill.js` | Path traversal via skill input | HIGH | A01: Broken access control |
| 04 | `04_command_injection_skill.js` | RCE via exec() + user input | CRITICAL | A03: Injection |
| 05 | `05_privilege_escalation.js` | Privilege escalation via tool chain | CRITICAL | A01: Broken access control |
| 06 | `06_sensitive_data_leakage.js` | PII + token logged in plain text | HIGH | A02: Cryptographic failures |
| 07 | `07_unsafe_deserialization.js` | RCE via node-serialize | CRITICAL | A08: Software integrity failures |
| 08 | `08_prompt_injection_relay.js` | Prompt injection via external content | HIGH | Agent-specific: LLM input validation |
| 09 | `09_safe_mcp_server.js` | **No findings** (safe reference) | NONE | — |

---

## Notes for Shiri

- All snippets are realistic but **synthetic** — no real credentials, no live endpoints.
- The safe case (09) is the key demo closer: "We're not crying wolf. When code is clean, we say so."
- For live demos, run the directory scan to show all 8 vulnerabilities found in one pass.
- Command injection (04) and SQL injection (02) are the most visually impactful for a technical audience.
- Hardcoded credentials (01) and data leakage (06) land best with a compliance/security buyer.
