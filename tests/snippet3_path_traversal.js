// Test snippet 3: Path traversal
const express = require('express');
const fs = require('fs');
const path = require('path');

app.get('/download', (req, res) => {
  // VULNERABLE: User input directly used in file path
  const filename = req.query.file;
  const filepath = path.join('/uploads', filename);
  const content = fs.readFileSync(filepath, 'utf-8');
  res.send(content);
});
