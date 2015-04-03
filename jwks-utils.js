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

var jws = require('jws');
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

utils.jwkForSignature = function jwkForSignature(signature, hint, callback) {
    var jose = jws.decode(signature).header;
    var jwk;
    if (typeof hint === 'function') {
        callback = hint;
        hint = undefined;
    }

    if (jose.jwk) {
        jwk = jose.jwk;
    } else if (((jose.jku && jose.kid) || typeof hint === 'string') &&
            request && callback) {
        var req = request.get(jose.jku || hint);
        if (typeof req.buffer === 'function') {
            req.buffer();
        }
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

            return callback(null, utils.findJWK(jose.kid, jwks));
        });
    } else if (utils.isJWKset(hint)) {
        jwk = utils.findJWK(jose.kid, hint);
    } else if (utils.isJWK(hint)) {
        jwk = hint;
    }

    return (callback && callback(null, jwk)) || jwk;
};

module.exports = utils;
