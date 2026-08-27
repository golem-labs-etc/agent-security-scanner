// Test snippet 2: Hardcoded credentials vulnerability
const mysql = require('mysql');

// VULNERABLE: API key and password hardcoded in source
const STRIPE_API_KEY = 'sk_live_REDACTED_FOR_DEMO';
const DB_PASSWORD = 'hardcoded_password_example';

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: DB_PASSWORD,
  database: 'myapp'
});

module.exports = { connection };
