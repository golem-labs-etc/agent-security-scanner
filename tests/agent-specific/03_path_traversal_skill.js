// AGENT SKILL: file-reader-tool.js
// VULNERABILITY: Path Traversal (HIGH)
//
// Glance detects: Agent skill accepts a filename from the LLM/user and
// constructs a file path without validating that it stays within the
// allowed workspace directory. A crafted input like "../../etc/passwd"
// escapes the sandbox entirely.
//
// Real-world risk: The agent can be manipulated (via prompt injection or
// direct user input) to read any file the process has access to — SSH keys,
// .env files, cloud credentials in ~/.aws/credentials, etc.
//
// Expected Glance output:
//   🟠 HIGH  Path traversal — user input used in file path without validation — line 28
//   🟡 MED   No path.resolve() / boundary check before fs.readFile — line 28

const fs = require('fs').promises;
const path = require('path');

const WORKSPACE = '/home/agent/workspace';

/**
 * Agent skill: read a file from the workspace and return contents to the LLM.
 * Called by the agent orchestrator when the user asks to "read a file".
 *
 * @param {string} filename - Filename requested by the user or LLM
 */
async function readWorkspaceFile(filename) {
  // BAD: filename comes from untrusted input; no boundary check
  const filePath = path.join(WORKSPACE, filename);

  // An LLM prompted to read "../../etc/passwd" will pass exactly that.
  // path.join('/home/agent/workspace', '../../etc/passwd')
  //   => '/home/agent/etc/passwd'  (still escapes workspace!)
  const contents = await fs.readFile(filePath, 'utf-8');

  return { filename, contents };
}

/**
 * SAFE version (for comparison in demos):
 *
 * async function readWorkspaceFileSafe(filename) {
 *   const filePath = path.resolve(WORKSPACE, filename);
 *   if (!filePath.startsWith(WORKSPACE + path.sep)) {
 *     throw new Error('Access denied: path escapes workspace boundary');
 *   }
 *   return { filename, contents: await fs.readFile(filePath, 'utf-8') };
 * }
 */

module.exports = { readWorkspaceFile };
