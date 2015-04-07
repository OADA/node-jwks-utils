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

var expect = require('chai').expect;
var jwku = require('../');

var jwkSet = require('./jwk_set.json');
var jwk = jwkSet.keys[0];
var jwk2 = jwkSet.keys[1];

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

describe('jwks-utils', function() {
    describe('#isJWK', function() {
        it('should return true for a JWK', function() {
            expect(jwku.isJWK(jwk)).to.equal(true);
        });

        it('should return false for object without "kty"', function() {
            expect(jwku.isJWK({foo: 'bar'})).to.equal(false);
        });
    });

    describe('#isJWKset', function() {
        it('should return true for a JWK Set', function() {
            expect(jwku.isJWKset(jwkSet)).to.equal(true);
        });

        it('should return false for object without "kty"', function() {
            expect(jwku.isJWKset({foo: 'bar'})).to.equal(false);
        });
    });

    describe('#findJWK', function() {
        it('should find JWK with matching "kid"', function() {
            var kid = jwk.kid;
            expect(jwku.findJWK(kid, jwkSet)).to.deep.equal(jwk);
        });

        it('should not find a JWK for undefined "kid"', function() {
            expect(jwku.findJWK(undefined, jwkSet)).to.be.not.ok;
        });
    });

    describe('#jwkForSignature', function() {
        var jws;

        before(function() {
            jws = require('jws');
        });

        it('should work with "jwk" JOSE header', function(done) {
            var sig = jws.sign({
                header: {
                    alg: 'HS256',
                    jwk: jwk
                },
                payload: 'FOO BAR',
                secret: 'DEAD BEEF'
            });

            jwku.jwkForSignature(sig, false, function(err, key) {
                expect(err).to.be.not.ok;
                expect(key).to.deep.equal(jwk);
                done();
            });
        });

        it('should work with "jku" JOSE header', function(done) {
            var sig = jws.sign({
                header: {
                    alg: 'HS256',
                    jku: 'https://localhost:3000/jwks_uri',
                    kid: jwk.kid
                },
                payload: 'FOO BAR',
                secret: 'DEAD BEEF'
            });

            jwku.jwkForSignature(sig, false, function(err, key) {
                expect(err).to.be.not.ok;
                expect(key).to.deep.equal(jwk);
                done();
            });
        });

        describe('whith both "jku" and "jwk" JOSE headers', function() {
            it('should work when they agree', function(done) {
                var sig = jws.sign({
                    header: {
                        alg: 'HS256',
                        jku: 'https://localhost:3000/jwks_uri',
                        kid: jwk.kid,
                        jwk: jwk
                    },
                    payload: 'FOO BAR',
                    secret: 'DEAD BEEF'
                });

                jwku.jwkForSignature(sig, false, function(err, key) {
                    expect(err).to.be.not.ok;
                    expect(key).to.deep.equal(jwk);
                    done();
                });
            });

            it('should error when they disagree', function(done) {
                var sig = jws.sign({
                    header: {
                        alg: 'HS256',
                        jku: 'https://localhost:3000/jwks_uri',
                        kid: jwk.kid,
                        jwk: jwk2
                    },
                    payload: 'FOO BAR',
                    secret: 'DEAD BEEF'
                });

                jwku.jwkForSignature(sig, false, function(err) {
                    expect(err).to.be.ok;
                    expect(err.message)
                        .to.equal('JWK did not match jwk JOSE header');
                    done();
                });
            });
        });
    });
});
