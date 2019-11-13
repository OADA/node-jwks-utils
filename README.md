[![Build Status](https://travis-ci.org/OADA/node-jwks-utils.svg?branch=master)](https://travis-ci.org/OADA/node-jwks-utils)
[![Coverage Status](https://coveralls.io/repos/OADA/node-jwks-utils/badge.svg?branch=master)](https://coveralls.io/r/OADA/node-jwks-utils?branch=master)
[![Dependency Status](https://david-dm.org/oada/node-jwks-utils.svg)](https://david-dm.org/oada/node-jwks-utils)
[![License](http://img.shields.io/:license-Apache%202.0-green.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

node-jwks-utils
===============

*THIS LIBRARY IS DEPRECATED. WE USE OADA-CERTS NOW INSTEAD.*

A set of useful tools when working with [JSON Web Key (JWK)][JWK] and [JSON Web
Key Set (JWKs)][JWKs].

Install
-------
```shell
$ npm install jwks-utils
```

Example
-------
```javascript
var jwksUtils = require('jwks-utils');

var jwk = { kid: '1234', kty: 'RSA', n: '12345...XYZ=', e: 'AQAB' };
var jwks = { keys: [ jwk ] }

// Detect a JWK object
if(jwksUtils.isJWK(jwk)) {
    // Do stuff with the JWk
}

// Detect a JWKs object
if(jwksUtils.isJWKset(jwks)) {
    // Do stuff with the JWKs
}

// Find a particilar JWK within a JWKs
var jwk1 = jwkUtils.findJWK('1234', jwks);

// Find the JWK corsponding to a particular JWS (or JWT)
var signature = getJWSFromSomwhere();
jwkUtils.jwkForSignature(signature, false, {timeout: 100}, function(err, jwk2) {
    if (!err) {
        // jwk2 is the corresponding JWK
    }
};

```

## Caching of JSON Web Key Sets (`jwks`) from a JSON Web Key URI (`jku`) ##
This library makes requests to outside web URI's if it determines that a `jku` is needed
to get the public key (`jwk`) to verify a signature.  It expects that URL to have a JSON
Web Key Set (`jwks` according to the standard).  Because this process can sometimes be 
slow, and because in production sometimes networks go down, we have added a small in-memory
cache to this library.  

When the library decides it needs a `jwks` from a `jku`, it will immediately return the 
cached value if the given signature's key is in the cached keyset.  It will also fire off
a request in the background that will update the cache to the latest copy of the jwk set.
It will consider the cache entry stale after 1 hour and then wait for the request to update
the cache.

If the key in the signature was not in a cached `jwks` (or it was not yet cached at all),
the function will wait for the request to finish.  Once it finishes, if there was an error
in the request, it will check the cache to see if we have a stale cached copy.  If so, then
it will use that stale cached copy for up to 24 hours before removing it from the cache.

If it does not have an error in the request, even if we've already returned the cached copy
for the signature, it will go ahead and put the new response's `jwks` into the cache and then
return it.

In this way, whenever you publish a new `kid` in your `jwks`, any clients will immediately be
able to use it.  However, if you revoke a `kid`, the client will still allow for 1 valid
signature in the first hour, and then any request after the first one, or after an hour, will
be invalid.

References
----------
1. [JSON Web Key (JWK) Draft 40](https://tools.ietf.org/html/draft-ietf-jose-json-web-key-40)

[JWK]: https://tools.ietf.org/html/draft-ietf-jose-json-web-key-40#section-4 "JSON Web Key"
[JWKs]: https://tools.ietf.org/html/draft-ietf-jose-json-web-key-40#section-5 "JSON Web Key Set"
