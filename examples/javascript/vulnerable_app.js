/**
 * Vulnerable Express.js API - For Testing Only
 * DO NOT USE IN PRODUCTION
 */

const express = require('express');
const app = express();
app.use(express.json());

// VULNERABILITY 1: Hardcoded credentials
const DB_PASSWORD = 'password123';
const JWT_SECRET = 'my_secret_key';

// VULNERABILITY 2: Cross-Site Scripting (XSS)
app.get('/search', (req, res) => {
    const query = req.query.q;
    // Vulnerable: Unescaped HTML
    res.send(`<h1>Search results for: ${query}</h1>`);
});

// VULNERABILITY 3: Prototype Pollution
app.post('/update-settings', (req, res) => {
    const settings = {};
    
    // Vulnerable: User-controlled object keys
    for (let key in req.body) {
        settings[key] = req.body[key];
    }
    
    res.json({ success: true, settings });
});

// VULNERABILITY 4: Server-Side Request Forgery (SSRF)
app.get('/fetch-url', async (req, res) => {
    const axios = require('axios');
    const url = req.query.url;
    
    // Vulnerable: Unvalidated URL fetch
    try {
        const response = await axios.get(url);
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// VULNERABILITY 5: NoSQL Injection
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    // Vulnerable: Direct object in query
    const user = await User.findOne({ username, password });
    
    if (user) {
        res.json({ success: true, token: 'fake_token' });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// VULNERABILITY 6: Missing rate limiting
app.post('/api/expensive-operation', (req, res) => {
    // No rate limiting - vulnerable to DDoS
    res.json({ result: 'operation complete' });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});