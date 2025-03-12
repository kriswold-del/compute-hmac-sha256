const fs = require('fs');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios'); // For future API posting
require('dotenv').config();
const app = express();
app.use(express.json({limit: '500mb'}));
app.use(express.urlencoded({limit: '500mb', extended: true}));

const crypto = require('crypto');

app.get('/', (req, res) => {

    res.send('Hello World');
});


const port = process.env.PORT || 5006;
app.listen(port, () => console.log(`Server running on port ${port}`));