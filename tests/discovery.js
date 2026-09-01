/**
 * Discovery tests: which config filenames `discoverInventory` actually reads.
 *
 * These exist because `src/surfaces/discover.ts` had no test at all. The names
 * list was the only thing standing between a Claude Code user and a scan that
 * reported clean while never opening their user-scope MCP config. A list with
 * no test is a list that silently loses an entry.
 *
 * Every fixture is written by this file into a throwaway tree. Nothing is read
 * from the real machine, and no real config is ever opened.
 */
const path = require('path');
const fs = require('fs');
const os = require('os');

const { discoverInventory } = require('../dist/surfaces/discover');

let pass = 0, fail = 0;
const failures = [];

function check(name, ok, detail) {
  if (ok) { pass++; console.log('  ok    ' + name + (detail ? '  ' + detail : '')); }
  else { fail++; failures.push(name); console.log('  FAIL  ' + name + (detail ? '  ' + detail : '')); }
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'glance-discovery-'));

// A home-shaped tree: the user-scope file sits AT the root, beside .claude/,
// not inside it. That placement is the defect, so the fixture reproduces it.
fs.mkdirSync(path.join(root, '.claude'), { recursive: true });
fs.mkdirSync(path.join(root, 'work', 'proj'), { recursive: true });

fs.writeFileSync(path.join(root, '.claude.json'), JSON.stringify({
  userID: 'irrelevant',
  projects: {},
  mcpServers: {
    'user-scope-server': { command: 'node', args: ['server.js'] },
  },
}));

fs.writeFileSync(path.join(root, 'work', 'proj', '.mcp.json'), JSON.stringify({
  mcpServers: {
    'project-scope-server': { command: 'node', args: ['p.js'] },
  },
}));

// A decoy inside .claude/ with a name we do NOT claim to read. If discovery
// ever starts matching on directory rather than filename this fires.
fs.writeFileSync(path.join(root, '.claude', 'not-a-config.json'), JSON.stringify({
  mcpServers: { 'must-not-appear': { command: 'node' } },
}));

console.log('discovery: which config names are read');

const inv = discoverInventory(root);
const names = inv.mcp_servers.map((s) => s.name).sort();

// POSITIVE: user scope is found, at $HOME rather than inside ~/.claude/.
check('user-scope .claude.json is read',
      names.indexOf('user-scope-server') !== -1,
      'found: ' + JSON.stringify(names));

// POSITIVE: the fix did not cost the case that already worked.
check('project-scope .mcp.json still read',
      names.indexOf('project-scope-server') !== -1,
      'both scopes in one inventory');

// NEGATIVE: an unlisted filename stays unread, even holding a valid mcpServers
// block in a directory we care about. Matching is by filename, not location.
check('an unlisted filename is not read',
      names.indexOf('must-not-appear') === -1,
      '.claude/not-a-config.json ignored despite a valid mcpServers block');

// NEGATIVE: the source path is recorded, so a finding can name the file the
// human has to open. A finding that cannot be located is not actionable.
const userEntry = inv.mcp_servers.find((s) => s.name === 'user-scope-server');
check('the entry carries the file it came from',
      !!userEntry && userEntry.source === path.join(root, '.claude.json'),
      userEntry ? userEntry.source : '(entry missing)');

console.log('');
console.log('discovery: ' + pass + '/' + (pass + fail) + ' passed on ' + process.platform);
if (fail) {
  console.log('failed: ' + failures.join(', '));
  process.exit(1);
}
