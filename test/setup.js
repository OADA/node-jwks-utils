/* Copyright 2014 Open Ag Data Alliance
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

var fs = require('fs');
var express = require('express');
var https = require('https');
var cors = require('cors');

var jwkSet = require('./jwk_set.json');

var app = express();

app.use(cors());

app.get('/jwks_uri', function(req, res) {
    res.json(jwkSet);
});

app.get('/jwks_uri_broken', function(req, res) {
    res.send('');
});

app.get('/jwks_uri_invalid', function(req, res) {
    res.json({});
});

app.get('/jwks_uri_slow', function(req, res) {
    // Never responds, only test using timeouts on the request side
});

var options = {
    key: fs.readFileSync('./test/server.key', 'utf8'),
    cert: fs.readFileSync('./test/server.crt', 'utf8'),
    ca: fs.readFileSync('./test/ca.crt', 'utf8'),
    requestCrt: true,
    rejectUnauthorized: false
};

https.createServer(options, app).listen(3000);
