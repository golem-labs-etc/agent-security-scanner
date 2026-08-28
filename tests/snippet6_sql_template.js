// Test snippet 6: SQL injection built with a template literal.
//
// This is the same vulnerability as snippet1, written the other way. It exists
// to hold the boundary of rules/js-sql-concat.yaml honest: that rule requires
// `+` concatenation, deliberately, because without it semgrep flags correctly
// parameterised queries whose table name is interpolated and validated against
// an allowlist. Requiring `+` bought zero false positives at the cost of this
// case.
//
// So this file is expected NOT to be detected by the static scan. If a future
// rule catches it, the suite says so and the expectation gets updated. What the
// suite must never do is stop asking.

app.get('/orders/:id', (req, res) => {
  // VULNERABLE: request data interpolated into the statement text.
  db.all(`SELECT * FROM orders WHERE id = ${req.params.id}`, (err, rows) => {
    res.json(rows);
  });
});
