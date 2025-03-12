require('dotenv').config();
const express = require('express');
const https = require('https');
const crypto = require('crypto');
const OAuth = require('oauth-1.0a');
const app = express();

function generateNonce(length = 16) {
    return crypto.randomBytes(length).toString('hex');
}

function createSignature(
    CONSUMER_SECRET,
    TOKEN_SECRET,
    SCRIPT_DEPLOYMENT_ID,
    CONSUMER_KEY,
    OAUTH_NONCE,
    TIMESTAMP,
    TOKEN_ID,
    OAUTH_VERSION,
    SCRIPT_ID,
    HTTP_METHOD,
    BASE_URL
) {
    const key = `${CONSUMER_SECRET}&${TOKEN_SECRET}`;
    const data = `deploy=${SCRIPT_DEPLOYMENT_ID}&oauth_consumer_key=${CONSUMER_KEY}&oauth_nonce=${OAUTH_NONCE}&oauth_signature_method=HMAC-SHA256&oauth_timestamp=${TIMESTAMP}&oauth_token=${TOKEN_ID}&oauth_version=${OAUTH_VERSION}&script=${SCRIPT_ID}`;
    const payload = `${HTTP_METHOD}&${encodeURIComponent(BASE_URL)}&${encodeURIComponent(data)}`;
    const hmac = crypto.createHmac('sha256', key);
    const digest = hmac.update(payload).digest('base64');
    const signature = Buffer.from(digest).toString('base64');
    return signature;
}

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
        !scriptDeploymentId
    ) {
        return res.status(400).send('Missing required query parameters');
    }

    const HTTP_METHOD = method ? method.toUpperCase() : 'GET';
    const OAUTH_VERSION = '1.0';
    const OAUTH_NONCE = generateNonce();
    const TIMESTAMP = Math.floor(Date.now() / 1000);
    const BASE_URL = `https://${netsuiteAccountId}.restlets.api.netsuite.com/app/site/hosting/restlet.nl`;

    const signature = createSignature(
        consumerSecret,
        tokenSecret,
        scriptDeploymentId,
        consumerKey,
        OAUTH_NONCE,
        TIMESTAMP,
        tokenId,
        OAUTH_VERSION,
        scriptId,
        HTTP_METHOD,
        BASE_URL
    );

    var realm = netsuiteAccountId;
    if(netsuiteAccountId.includes('sb1')) {
        realm = netsuiteAccountId.replace('-sb1', '_SB1');
    }
    const authorizationHeader = `OAuth oauth_signature="${encodeURIComponent(signature)}", oauth_version="${OAUTH_VERSION}", oauth_nonce="${OAUTH_NONCE}", oauth_signature_method="HMAC-SHA256", oauth_consumer_key="${consumerKey}", oauth_token="${tokenId}", oauth_timestamp="${TIMESTAMP}", realm="${realm}"`;
    const requestUrl = `${BASE_URL}?script=${scriptId}&deploy=${scriptDeploymentId}`;

    res.send(authorizationHeader);
});

app.get('/test/', (req, res) => {
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
    const httpMethod = method; // Or 'POST', depending on your RESTlet
    const baseUrl = `https://${netsuiteAccountId}.restlets.api.netsuite.com/app/site/hosting/restlet.nl`;

// OAuth & request params combined
    const params = {
        oauth_consumer_key: consumerKey,
        oauth_token: tokenId,
        oauth_nonce: generateNonce(),
        oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
        oauth_signature_method: 'HMAC-SHA256', // IMPORTANT for updated NetSuite
        oauth_version: '1.0',
        script: scriptId,
        deploy: scriptDeploymentId,
        realm: netsuiteAccountId.replace('-sb1', '_SB1')
    };

// Generate signature
    const signature = createOAuthSignature(params, consumerSecret, tokenSecret, httpMethod, baseUrl);

// Add signature to params
    params['oauth_signature'] = signature;

// Build Authorization Header (only OAuth params, script & deploy NOT included here)
    const oauthHeader = 'OAuth ' + Object.keys(params)
        .filter(key => key.startsWith('oauth_'))
        .map(key => `${percentEncode(key)}="${percentEncode(params[key])}"`)
        .join(',');

// Request URL with query params (script & deploy)
    const requestUrl = `${baseUrl}?script=${scriptId}&deploy=${scriptDeploymentId}`;


    const orderedHeader = `OAuth realm="${params.realm}",oauth_consumer_key="${params.oauth_consumer_key}",oauth_token="${params.oauth_token}",oauth_signature_method="HMAC-SHA256",oauth_timestamp="${params.oauth_timestamp}",oauth_nonce="${params.oauth_nonce}",oauth_version="1.0",oauth_signature="${percentEncode(params.oauth_signature)}"`;
// Output
    console.log('Authorization Header:',orderedHeader);
    console.log('Request URL:', requestUrl);
    res.send(orderedHeader);
})




function percentEncode(str) {
    return encodeURIComponent(str)
        .replace(/\!/g, '%21')
        .replace(/\'/g, '%27')
        .replace(/\*/g, '%2A')
        .replace(/\(/g, '%28')
        .replace(/\)/g, '%29');
}

function createOAuthSignature(params, consumerSecret, tokenSecret, httpMethod, baseUrl) {
    // Sort parameters alphabetically and percent-encode them
    const sortedParams = Object.keys(params).sort().map(key => {
        return `${percentEncode(key)}=${percentEncode(params[key])}`;
    }).join('&');

    // Construct the signature base string
    const baseString = [
        httpMethod,
        percentEncode(baseUrl),
        percentEncode(sortedParams)
    ].join('&');

    // Construct signing key
    const signingKey = `${percentEncode(consumerSecret)}&${percentEncode(tokenSecret)}`;

    // Generate HMAC-SHA256 signature
    const hmac = crypto.createHmac('sha256', signingKey);
    const signature = hmac.update(baseString).digest('base64');

    return signature;
}

app.get('/test2/', (req, res) => {

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
    const baseUrl = `https://${netsuiteAccountId}.restlets.api.netsuite.com/app/site/hosting/restlet.nl??script=${scriptId}&deploy=${scriptDeploymentId}`;
        const request_data = {
            url: baseUrl,
            method: method,
        };
        const oauthData = oauth.authorize(request_data, token);
        const authorizationHeader = oauth.toHeader(oauthData);

        return res.send(authorizationHeader);

})
const port = process.env.PORT || 5006;
app.listen(port, () => console.log(`Server running on port ${port}`));
