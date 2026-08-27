// AGENT SKILL: customer-lookup-tool.js
// VULNERABILITY: Sensitive Data Leakage via Logs (HIGH)
//
// Glance detects: Agent skill logs full API responses and user PII to stdout/
// file logs without redaction. In a production agent, these logs are often
// shipped to centralized logging (Datadog, CloudWatch, Splunk) where they
// are retained and accessible to a much wider audience than intended.
//
// Real-world risk: Credit card numbers, SSNs, health data, and session tokens
// appear in plain text in log aggregators. A single misconfigured log export
// or insider threat exposes every customer the agent ever looked up.
//
// Expected Glance output:
//   🟠 HIGH  Sensitive data (PII/credentials) written to logs — line 40
//   🟠 HIGH  Full API response logged without field filtering — line 46
//   🟡 MED   No log-level guard around debug output containing user data — line 40

const axios = require('axios');

/**
 * Agent skill: fetch full customer profile for CRM agent.
 *
 * @param {string} customerId
 * @param {string} sessionToken - Agent's API session token
 */
async function getCustomerProfile(customerId, sessionToken) {
  console.log(`[DEBUG] Fetching customer ${customerId} with token ${sessionToken}`);
  // BAD: session token in logs — anyone with log access can impersonate the agent

  const res = await axios.get(`https://api.crm.internal/customers/${customerId}`, {
    headers: { Authorization: `Bearer ${sessionToken}` },
  });

  const customer = res.data;
  // BAD: full object logged — contains SSN, credit_card_last4, date_of_birth, etc.
  console.log('[DEBUG] Customer response:', JSON.stringify(customer));

  // BAD: individual sensitive fields also logged for "convenience"
  console.log(`[INFO] Looked up customer: ${customer.name} | SSN: ${customer.ssn} | DOB: ${customer.dob}`);

  return customer;
}

/**
 * SAFE version (for comparison in demos):
 *
 * async function getCustomerProfileSafe(customerId, sessionToken) {
 *   console.log(`[DEBUG] Fetching customer ${customerId}`);  // no token in log
 *   const res = await axios.get(...);
 *   const { id, name, email } = res.data;  // destructure only non-sensitive fields
 *   console.log(`[INFO] Looked up customer: ${name} <${email}>`);
 *   return res.data;  // full data returned to agent, but not logged
 * }
 */

module.exports = { getCustomerProfile };
