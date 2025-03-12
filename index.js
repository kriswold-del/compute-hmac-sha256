require('dotenv').config();
const express = require('express');
const OAuth = require('oauth-1.0a');
const crypto = require('crypto');

const app = express();

app.get('/', (req, res) => {
    const {
        consumerKey,
        consumerSecret,
        tokenKey,
        tokenSecret,
        realm,
        url,
        method
    } = req.query;

    if (!consumerKey || !consumerSecret || !tokenKey || !tokenSecret || !url || !method) {
        return res.status(400).send('Missing required query parameters');
    }

    const oauth = OAuth({
        consumer: {
            key: consumerKey,
            secret: consumerSecret
        },
        signature_method: 'HMAC-SHA256',
        realm: realm,
        hash_function(base_string, key) {
            return crypto.createHmac('sha256', key)
                .update(base_string)
                .digest('base64');
        }
    });

    const token = {
        key: tokenKey,
        secret: tokenSecret
    };

    const request_data = { url, method };

    const oauthData = oauth.authorize(request_data, token);
    const authorizationHeader = oauth.toHeader(oauthData);

    res.json(authorizationHeader);
});

const port = process.env.PORT || 5006;
app.listen(port, () => console.log(`Server running on port ${port}`));