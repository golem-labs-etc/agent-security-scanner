// AGENT ORCHESTRATOR: privileged-tool-chain.js
// VULNERABILITY: Privilege Escalation via Tool Orchestration (CRITICAL)
//
// Glance detects: Agent performs a privileged action (delete user, grant admin)
// without verifying that the calling context has the required permission level.
// The vulnerability is in the orchestration layer — individual tools trust each
// other implicitly, so a low-privilege tool can chain into a high-privilege one.
//
// Real-world risk: An agent asked to "clean up old test accounts" could be
// manipulated to delete production accounts or grant admin to an attacker-
// controlled user — because the orchestrator never re-checks authorization
// between tool steps.
//
// Expected Glance output:
//   🔴 CRITICAL  Privilege escalation — no authz check before admin action — line 52
//   🟠 HIGH      Tool chain executes privileged ops without re-validation — line 60

const axios = require('axios');

// Simulated agent context — set once at startup, never re-validated per action
const agentContext = {
  sessionToken: process.env.AGENT_SESSION_TOKEN,
  role: 'support',          // Low-privilege role
  userId: 'agent-bot-001',
};

/**
 * Low-privilege tool: look up a user (fine for support role)
 */
async function lookupUser(email) {
  const res = await axios.get(`/api/users?email=${email}`, {
    headers: { Authorization: `Bearer ${agentContext.sessionToken}` },
  });
  return res.data;
}

/**
 * HIGH-PRIVILEGE tool: delete a user account
 * BAD: uses the same session token as the low-privilege lookup — no re-auth.
 * The agent's support-role token should NOT be able to delete accounts,
 * but the API doesn't enforce this and the orchestrator doesn't check.
 */
async function deleteUser(userId) {
  // BAD: no check that agentContext.role === 'admin' before destructive action
  // BAD: no additional auth challenge or human-in-the-loop confirmation
  const res = await axios.delete(`/api/users/${userId}`, {
    headers: { Authorization: `Bearer ${agentContext.sessionToken}` },
  });
  return res.data;
}

/**
 * Agent orchestration: "clean up accounts mentioned in this support ticket"
 * A prompt injection in the ticket body can pivot lookup -> delete.
 */
async function handleSupportTicket(ticketBody) {
  const emailMatch = ticketBody.match(/[\w.]+@[\w.]+/);
  if (!emailMatch) return { done: true };

  const user = await lookupUser(emailMatch[0]);

  // BAD: orchestrator blindly follows LLM instruction to chain into delete
  // No confirmation, no privilege re-check, no audit log before action
  if (ticketBody.includes('remove account') || ticketBody.includes('delete user')) {
    await deleteUser(user.id);
    return { deleted: user.id };
  }

  return { found: user };
}

module.exports = { handleSupportTicket, lookupUser, deleteUser };
