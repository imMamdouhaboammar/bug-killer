// Vulnerable: untrusted query param reaches eval sink
const express = require('express');
const app = express();

app.get('/run', (req, res) => {
    const code = req.query.code;
    eval(code);
    res.send("executed");
});
