// AGENT MCP SERVER: database-query-tool.js
// VULNERABILITY: SQL Injection (CRITICAL)
//
// Glance detects: User-controlled input concatenated directly into SQL query
// inside an MCP tool handler. The agent exposes this as a callable tool,
// meaning any orchestrator (or prompt injection) can trigger arbitrary SQL.
//
// Real-world risk: An attacker who gains influence over the agent's input
// (via prompt injection, tool poisoning, or malicious user message) can
// dump the entire database, modify records, or drop tables.
//
// Expected Glance output:
//   🔴 CRITICAL  SQL injection via string concatenation in MCP tool — line 38
//   🟠 HIGH      No input validation before database query — line 36

const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const sqlite3 = require('sqlite3');

const db = new sqlite3.Database('./agent_data.db');

const server = new Server(
  { name: 'database-query-tool', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler('tools/list', async () => ({
  tools: [
    {
      name: 'query_users',
      description: 'Query users from the database by name',
      inputSchema: {
        type: 'object',
        properties: {
          username: { type: 'string', description: 'Username to look up' },
        },
        required: ['username'],
      },
    },
  ],
}));

server.setRequestHandler('tools/call', async (request) => {
  if (request.params.name === 'query_users') {
    const username = request.params.arguments.username;

    // BAD: user input concatenated directly into SQL — injectable
    const query = "SELECT * FROM users WHERE username = '" + username + "'";

    return new Promise((resolve, reject) => {
      db.all(query, (err, rows) => {
        if (err) reject(err);
        else resolve({ content: [{ type: 'text', text: JSON.stringify(rows) }] });
      });
    });
  }
});

const transport = new StdioServerTransport();
server.connect(transport);
