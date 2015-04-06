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

var url = require('url');
var jws = require('jws');
var equal = require('deep-equal');
var request;
try {
    request = require('superagent');
} catch (err) {}

var utils = {};

// Decide if an object is a JWK
utils.isJWK = function isJWK(key) {
    return !!(key && key.kty);
};
// Decide if an object is a set of JWKs
utils.isJWKset = function isJWKset(set) {
    var keys = set && set.keys;

    return !!keys && typeof keys.some === 'function' && keys.some(utils.isJWK);
};

// Pick a JWK from a JWK set by its Key ID
utils.findJWK = function findJWK(kid, jwks) {
    var res;

    if (!kid) {
        return undefined;
    }

    jwks.keys.every(function(jwk) {
        if (utils.isJWK(jwk) && (jwk.kid === kid)) {
            res = jwk;
            return false;
        }
        return true;
    });

    return res;
};

// Maybe move to a JWS library?
// Supported headers: [kid, jwk, jku]
utils.jwkForSignature = function jwkForSignature(sig, hint, options, callback) {
    var jose = jws.decode(sig).header;
    if (typeof options === 'function') {
        callback = options;
        options = undefined;
    }
    options = options || {};

    switch (typeof hint) {
    case 'boolean':
        if (hint === false) {
            // Lookup soley based on JOSE headers
            if (jose.jku) {
                return getJWK(jose.jku);
            } else {
                return callback(null, jose.jwk);
            }
        }
        break;
    case 'string':
        return getJWK(hint);
    case 'object':
        if (utils.isJWKset(hint)) {
            return check(null, utils.findJWK(jose.kid, hint));
        } else if (utils.isJWK(hint) && jose.kid === hint.kid) {
            return check(null, hint);
        }
        break;
    }

    return callback(new Error('Invalid hint'));

    function check(err, jwk) {
        if (jose.jwk && !equal(jwk, jose.jwk, {strict: true})) {
            err = err || new Error('JWK did not match jwk JOSE header');
        }
        callback(err, jwk);
    }

    // Retieve from a URI
    function getJWK(uri) {
        // MUST use HTTPS (not HTTP)
        var u = url.parse(uri);
        u.protocol = 'https';
        uri = url.format(u);

        var req = request.get(uri);
        if (typeof req.buffer === 'function') {
            req.buffer();
        }
        req.timeout(options.timeout || 1000);

        return req.end(function recieveJWKSet(err, resp) {
            var e = err || resp.error;
            var jwks;
            if (e) { return callback(e); }

            try {
                jwks = JSON.parse(resp.text);
                if (!utils.isJWKset(jwks)) {
                    throw new Error();
                }
            } catch (err) {
                return callback(new Error('Could not parse retrieved JWK Set'));
            }

            return check(null, utils.findJWK(jose.kid, jwks));
        });
    }
};

module.exports = utils;
