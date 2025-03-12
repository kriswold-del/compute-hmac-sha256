require('dotenv').config();
const express = require('express');
const https = require('https');
const crypto = require('crypto');

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
    const signature = Buffer.from(digest)//.toString('base64');
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
    const authorizationHeader = `OAuth oauth_signature="${signature}", oauth_version="${OAUTH_VERSION}", oauth_nonce="${OAUTH_NONCE}", oauth_signature_method="HMAC-SHA256", oauth_consumer_key="${consumerKey}", oauth_token="${tokenId}", oauth_timestamp="${TIMESTAMP}", realm="${realm}"`;
    const requestUrl = `${BASE_URL}?script=${scriptId}&deploy=${scriptDeploymentId}`;

    res.send(authorizationHeader);
});

app.get('/test/', (req, res) => {

})

const port = process.env.PORT || 5006;
app.listen(port, () => console.log(`Server running on port ${port}`));
