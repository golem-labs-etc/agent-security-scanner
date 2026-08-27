// Test snippet 5: Safe code (no vulnerabilities)
const express = require('express');
const db = require('./database');

app.get('/api/posts/:id', (req, res) => {
  const postId = parseInt(req.params.id, 10);
  
  // SAFE: Using parameterized queries
  db.prepare('SELECT * FROM posts WHERE id = ?').get(postId, (err, row) => {
    if (err) {
      res.status(500).json({ error: 'Database error' });
      return;
    }
    res.json(row);
  });
});

// SAFE: Using environment variables for secrets
const apiKey = process.env.STRIPE_API_KEY;
const dbUrl = process.env.DATABASE_URL;
