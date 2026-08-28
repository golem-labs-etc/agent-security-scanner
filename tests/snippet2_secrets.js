// Test snippet 2: hardcoded credentials.
//
// The previous version of this file held `sk_live_REDACTED_FOR_DEMO`, which is
// not a credential shape. No honest secret scanner could flag it, so the case
// measured nothing. These two ARE credential shapes and are detected.
//
// Both values are public and inert on purpose: the JWT is the example token
// from jwt.io, signed with the well-known key "your-256-bit-secret", and the
// API key is a fixed hex string. Nothing here is a real key for anything, and
// nothing here is shaped like a live provider key that a push-protection scan
// would have to treat as a leak.
const mysql = require('mysql');

// VULNERABLE: a signed token committed to source. Anyone with the repository
// has it, and rotating it means a deploy.
const SESSION_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk';

// VULNERABLE: API key in source rather than in the environment.
const api_key = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: process.env.DB_PASSWORD,
  database: 'myapp'
});

module.exports = { connection, SESSION_TOKEN, api_key };
