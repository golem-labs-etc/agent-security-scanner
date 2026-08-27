// AGENT MCP SERVER: safe-database-tool.js
// VULNERABILITY: NONE — this is the safe reference implementation
//
// Glance detects: No findings. This is the expected result for a
// correctly-written agent skill.
//
// Use in demos to show Glance's low false-positive rate:
//   - Parameterized queries (no SQL injection)
//   - Credentials from environment (no hardcoded secrets)
//   - Input validation and allowlist (no injection)
//   - Scoped permissions (least privilege)
//   - Sanitized logging (no PII leakage)
//
// Expected Glance output:
//   ✅ No findings. Risk score: 0.

const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { Pool } = require('pg');

// GOOD: credentials from environment, never hardcoded
const db = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: true },  // GOOD: enforce TLS
});

// GOOD: strict allowlist of permitted query types
const ALLOWED_TABLES = ['public_posts', 'product_catalog', 'faq_entries'];

const server = new Server(
  { name: 'safe-database-tool', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler('tools/list', async () => ({
  tools: [
    {
      name: 'search_catalog',
      description: 'Search product catalog by keyword',
      inputSchema: {
        type: 'object',
        properties: {
          keyword: { type: 'string', maxLength: 100 },
          table:   { type: 'string', enum: ALLOWED_TABLES },
        },
        required: ['keyword', 'table'],
      },
    },
  ],
}));

server.setRequestHandler('tools/call', async (request) => {
  if (request.params.name === 'search_catalog') {
    const { keyword, table } = request.params.arguments;

    // GOOD: table validated against allowlist — no injection possible
    if (!ALLOWED_TABLES.includes(table)) {
      return { content: [{ type: 'text', text: 'Invalid table' }], isError: true };
    }

    // GOOD: keyword length and character validation
    if (typeof keyword !== 'string' || keyword.length > 100 || !/^[\w\s\-]+$/.test(keyword)) {
      return { content: [{ type: 'text', text: 'Invalid keyword' }], isError: true };
    }

    // GOOD: parameterized query — no SQL injection possible
    const result = await db.query(
      `SELECT id, title, description FROM ${table} WHERE title ILIKE $1 LIMIT 20`,
      [`%${keyword}%`]
    );

    // GOOD: only non-sensitive fields returned and logged
    console.log(`[INFO] Catalog search: table=${table} keyword=<redacted> results=${result.rows.length}`);

    return {
      content: [{ type: 'text', text: JSON.stringify(result.rows) }],
    };
  }
});

const transport = new StdioServerTransport();
server.connect(transport);
