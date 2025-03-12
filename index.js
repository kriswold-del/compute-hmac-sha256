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
    var oauth = new OAuth({
        "hash_function" : function(base_string, key) {
            return crypto.createHmac('sha1', key).update(base_string).digest('base64');
        },
        "consumer" : { "key" : consumerKey, "secret" : consumerSecret },
        "signature_method" : "HMAC-SHA256"
    });

    const oauthToken = { "key" : tokenKey, "secret" : tokenSecret },
        request = { "url" : url, "method" : method };

            let headers = oauth.toHeader(oauth.authorize(request, oauthToken));
            headers.Authorization += `,realm="${realm}"`;


    // const oauth = OAuth({
    //     consumer: {
    //         key: consumerKey,
    //         secret: consumerSecret
    //     },
    //     signature_method: 'HMAC-SHA256',
    //     realm: realm,
    //     hash_function(base_string, key) {
    //         return crypto.createHmac('sha256', key)
    //             .update(base_string)
    //             .digest('base64');
    //     }
    // });
    //
    // const token = {
    //     key: tokenKey,
    //     secret: tokenSecret
    // };
    //
    // const request_data = { url, method };
    //
    // const oauthData = oauth.authorize(request_data, token);
    // const authorizationHeader = oauth.toHeader(oauthData);


    res.send(headers.Authorization);
});

const port = process.env.PORT || 5006;
app.listen(port, () => console.log(`Server running on port ${port}`));