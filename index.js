require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const OAuth = require('oauth-1.0a');
const app = express();


app.get('/', (req, res) => {

    const {
        netsuiteAccountId,
        consumerKey,
        consumerSecret,
        tokenId,
        tokenSecret,
        scriptId,
        scriptDeploymentId,
        method
    } = req.query;

    if (
        !netsuiteAccountId ||
        !consumerKey ||
        !consumerSecret ||
        !tokenId ||
        !tokenSecret ||
        !scriptId ||
        !scriptDeploymentId ||
        !method
    ) {
        return res.status(400).send('Missing required query parameters');
    }
        const oauth = OAuth({
            consumer: {
                key: consumerKey,
                secret: consumerSecret
            },
            signature_method: 'HMAC-SHA256',
            realm: netsuiteAccountId.replace('-sb1', '_SB1'),
            hash_function(base_string, key) {
                return crypto.createHmac('sha256', key)
                    .update(base_string)
                    .digest('base64');
            }
        });

        const token = {
            key: tokenId,
            secret: tokenSecret
        };
    const baseUrl = `https://${netsuiteAccountId}.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=${scriptId}&deploy=${scriptDeploymentId}`;
        const request_data = {
            url: baseUrl,
            method: method,
        };
        const oauthData = oauth.authorize(request_data, token);
        const authorizationHeader = oauth.toHeader(oauthData);

        return res.send(authorizationHeader.Authorization);

})
const port = process.env.PORT || 5006;
app.listen(port, () => console.log(`Server running on port ${port}`));
