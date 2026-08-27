// Test snippet 4: XSS vulnerability
const express = require('express');
const ejs = require('ejs');

app.get('/search', (req, res) => {
  const query = req.query.q;
  // VULNERABLE: User input rendered without escaping
  res.render('search.ejs', { searchTerm: query, results: [] });
});

// In search.ejs template:
// <h1>You searched for: <%= searchTerm %></h1>
