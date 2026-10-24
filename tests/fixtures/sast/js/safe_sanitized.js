// Safe: input is strictly parsed as integer before use
const express = require('express');
const app = express();

app.get('/page', (req, res) => {
    const rawId = req.query.id;
    const cleanId = parseInt(rawId, 10);
    if (isNaN(cleanId)) {
        return res.status(400).send("Invalid ID");
    }
    res.json({ id: cleanId });
});
