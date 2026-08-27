// Test snippet 1: SQL Injection vulnerability
const sql = require('sqlite3');
const db = new sql.Database();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  // VULNERABLE: Direct string concatenation in SQL query
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  db.all(query, (err, rows) => {
    res.json(rows);
  });
});
