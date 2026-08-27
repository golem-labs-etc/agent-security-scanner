// AGENT SKILL: stripe-payment-tool.js
// VULNERABILITY: Hardcoded credentials (CRITICAL)
//
// Glance detects: Hardcoded Stripe secret key, OpenAI token, and DB password
// embedded directly in agent skill source code.
//
// Real-world risk: If this skill is shared, published to a skill registry,
// or loaded by another agent, all credentials are exposed. An attacker who
// reads this file owns your Stripe account, your AI budget, and your database.
//
// Expected Glance output:
//   🔴 CRITICAL  Hardcoded API key (STRIPE_SECRET_KEY) — line 10
//   🔴 CRITICAL  Hardcoded API key (OPENAI_API_KEY) — line 11
//   🟠 HIGH      Hardcoded database password — line 14

const Stripe = require('stripe');
const OpenAI = require('openai');
const { Pool } = require('pg');

// BAD: credentials hardcoded — never do this in a skill
const stripe = new Stripe('sk_live_EXAMPLE_REPLACE_WITH_ENV_VAR_NOT_REAL');
const openai = new OpenAI({ apiKey: 'sk-proj-EXAMPLE_REPLACE_WITH_ENV_VAR_NOT_REAL' });
const db = new Pool({
  host: 'prod-db.internal',
  user: 'admin',
  password: 'ExampleHardcodedPassword_NotReal_2024',
  database: 'payments',
});

/**
 * Agent skill: charge a customer
 * @param {string} customerId
 * @param {number} amountCents
 */
async function chargeCustomer(customerId, amountCents) {
  const charge = await stripe.paymentIntents.create({
    amount: amountCents,
    currency: 'usd',
    customer: customerId,
  });

  await db.query(
    'INSERT INTO charges (customer_id, amount, intent_id) VALUES ($1, $2, $3)',
    [customerId, amountCents, charge.id]
  );

  return { success: true, chargeId: charge.id };
}

module.exports = { chargeCustomer };
