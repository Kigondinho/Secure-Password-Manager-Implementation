const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));

const DB_FILE = './db.json';

// 1. Load the encrypted keychain
app.get('/keychain', (req, res) => {
  if (!fs.existsSync(DB_FILE)) return res.json({ exists: false });
  const data = JSON.parse(fs.readFileSync(DB_FILE));
  res.json({ exists: true, ...data });
});

// 2. Save the encrypted keychain
app.post('/keychain', (req, res) => {
  const { repr, checksum } = req.body;
  // Simply overwrite the file. In a real DB, you'd update a row by User ID.
  fs.writeFileSync(DB_FILE, JSON.stringify({ repr, checksum }));
  res.json({ success: true });
});

app.listen(3001, () => console.log('Database server running on port 3001'));