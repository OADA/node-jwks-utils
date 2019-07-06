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

const debug = require('debug');
const trace = debug('node-jwks-utils:trace');
const  info = debug('node-jwks-utils:info');
const  warn = debug('node-jwks-utils:warn');

const request = require('superagent');

var utils = {};

//----------------------------------------------------------------------
// Caching jwks requests/responses:
const jwksCache = {};
const cacheStaleTimeoutSec = 3600; // 1 hour
const cacheFailureTimeout = 3600*24; // 24 hours: how long to use cached value if network request fails
const cacheMaxSizeMB = 20; // Maximum MB allowed in the jwks cache before pruning old ones
const cacheSize = () => Object.keys(jwksCache).reduce((acc,uri) => (acc+jwksCache[uri].strbytes), 0);
const cachePruneOldest = () => {
  const oldest = Object.keys(jwksCache).reduce((acc,uri) => {
    if (!acc) return uri; // first one
    const curold = jwksCache[acc.uri];
    if (jwksCache[uri].timePutIntoCache < curold.timePutIntoCache) {
      return uri; // this uri is now min
    }
    return acc; // previous min is still min
  }, false);
  if (!oldest) {
    // nothing in the cache)
    return false;
  }
  delete jwksCache[oldest];
  return true;
}
const putInCache = (uri,jwks,strbytes) => {
  if (strbytes/1000000 > cacheMaxSizeMB) {
    warn('WARNING: refusing to cache jwks from uri '+uri+' because it\'s size alone ('+strbytes+') is larger than cacheMaxSizeMB ('+cacheMaxSizeMB+')');
    return false;
  }

  while (cacheSize() + strbytes > cacheMaxSizeMB) {
    if (!cachePruneOldest()) break; // if pruneOldest fails, stop looping
  }

  if (jwksCache[uri]) trace('Putting uri ',uri,' into cache with new timestamp, replacing previous entry')
  jwksCache[uri] = {
    timePutIntoCache: Date.now()/1000,
    jwks,
  };
  return true;
}
const cachePruneIfFailureTimeout = uri => {
  const now = Date.now() / 1000;
  if (jwksCache[uri] && (now - jwksCache[uri].timePutIntoCache) > cacheFailureTimeout) {
    info('jku request failed for uri ', uri, ', and it has been longer than cacheFailureTimeout, so removing that uri from cache due to failure');
    // remove from cache
    delete jwksCache[uri];
  }
}
const cacheHasURIThatIsNotStale = uri => {
  const now = Date.now() / 1000;
  return (jwksCache[uri] && (now - jwksCache[uri].timePutIntoCache) < cacheStaleTimeoutSec);
}


//-------------------------------------------------
// Primary exported module:

// Exporting some cache functions for testing:
utils.clearJWKsCache = function() { jwksCache = {}; }
utils.getJWKsCache = function() { return jwksCache; }
utils.cachePruneOldest = cachePruneOldest;


// Decide if an object is a JWK
utils.isJWK = function isJWK(key) {
  return !!(key && key.kty);
};

// Decide if an object is a set of JWKs
utils.isJWKset = function isJWKset(set) {
  const keys = set && set.keys;
  return !!keys && typeof keys.some === 'function' && keys.some(utils.isJWK);
};

// Pick a JWK from a JWK set by its Key ID
utils.findJWK = function findJWK(kid, jwks) {
  if (!kid) return undefined;
  let res = undefined;
  jwks.keys.every(jwk => {
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
  if (typeof options === 'function') {
    callback = options;
    options = undefined;
  }
  options = options || {};

  const jose = jws.decode(sig).header;

  // The only place the callback is allowed to be called is inside this 
  // checkJWKEqualsJoseJWK.  That way it's easier to manage the two threads
  // to make sure we don't call the callback twice.
  let alreadyCalledCallback = false;
  const checkJWKEqualsJoseJWK = (err, jwk) => {
    if (jose.jwk && !equal(jwk, jose.jwk, {strict: true})) {
      err = err || new Error('JWK did not match jwk JOSE header');
    }
    if (!alreadyCalledCallback) {
      alreadyCalledCallback = true;
      callback(err, jwk);
    }
  }

  // Retieve JWKS from a JKU URI
  // Update for 1.0.6: Adding an in-memory cache that will both 
  //   1: speedup requests with jku's, and
  //   2: keep working with cached copy for 24 hours in the event of network outage.
  // The cache will respond immediately with a cached value if the cached value is less than
  // 1 hour old and the kid is in it.  It will always go get the latest jwks at the URL to 
  // update the cache, but if the kid is already in the cached copy it will return that immediately
  // and not wait on the request to finish.  If the kid is not found in the cached value, it will 
  // wait for the request to finish and then look for the kid in the new copy.  In this way, if a 
  // new kid is published in your jwks, it will be immediately available to all clients.  If a key
  // is deemed no longer trusted and removed from the jwks, then it will only validate at most one
  // time in at most a 1 hour window after un-publishing.
  const getJWK = uri => {
    // MUST use HTTPS (not HTTP)
    const u = url.parse(uri);
    u.protocol = 'https';
    uri = url.format(u);

    const req = request.get(uri);
    if (typeof req.buffer === 'function') req.buffer();
    req.timeout(options.timeout || 1000);

    // Fire off the request here first, then immediately check cache before javascript event queue moves on.  
    // If it's there, then that "thread" of execution will call the callback instead of the one after 
    // the request finishes.  If it wasn't there, then the request's callback here will call it.
    trace('Sending out GET request for uri '+uri+', will check cache while it is waiting');
    const promiseToWaitOnRequest = req.end(function recieveJWKSet(err, resp) {
      let e = err || resp.error;
      let jwks;

      // If there was no error, then we can go ahead and try to parse the body (which could result in an error)
      if (!e) {
        trace('Finished retrieving uri ',uri,', had no error in the request, will now try to parse response.');
        try {
          jwks = JSON.parse(resp.text);
          if (!utils.isJWKset(jwks)) {
            throw new Error('jwks parsed successfully with JSON.parse, but it was not a valid jwks');
          }
          // Put this successful jwks set into the cache
          if (putInCache(uri, jwks, resp.text.length)) {
            trace('Added jwks to cache for uri '+uri);
          } else {
            info('Failed to add jwks to cache for uri '+uri);
          }
        } catch (err) {
          e = err;
          warn('WARNING: failed to read jwks response from jku uri '+uri+', error was: ' + e.toString());
        }
      }

      // If we get to this point, either jwks is valid and in the jwks variable, or we had an error
      if (e) { 
        warn('jku request failed for uri ', uri);
        // If the request had an error (i.e. network or host is down now), let's check if we have 
        // the jwks in the cache.  If we do, we'll go ahead and use it for up to 24 hours before
        // removing it due to the failure.
        cachePruneIfFailureTimeout(uri);
        // Now if it's not in the cache, since the request had an error, then return the error
        if (!jwksCache[uri]) return checkJWKEqualsJoseJWK(e);
        
        // If we get here, there was an error, but it was in the cache still before the cacheFailureTimeout, 
        // so put that in the main jwks variable to check later
        info('jku request failed for uri ',uri,', but we have cached copy that we will use for 24 hours');
        jwks = jwksCache[uri].jwks;
      }
        
      // And finally, if we got to this point, we either did not have an error, or we had an error but 
      // we decided to use our cached value.  Either way, the jwks variable now has a valid jwks in it.
      // This ends the thread that runs after the web request finishes.
      return checkJWKEqualsJoseJWK(null, utils.findJWK(jose.kid, jwks));
    });

    // Now, check if we already have the uri in the cache and 
    // if the kid is already in it's list of keys:
    trace('Checking cache for non-stale uri ', uri);
    if (cacheHasURIThatIsNotStale(uri)) {
      trace('Found uri ',uri,' in cache and it is not stale, returning it immediately');
      const jwk = utils.findJWK(jose.kid, jwksCache[uri].jwks);
      if (jwk) return checkJWKEqualsJoseJWK(null, jwk);
    }
    trace('Did not find non-stale uri ',uri,' in cache, waiting on request to complete instead');

    // If we get here, then we did not have a valid, un-stale kid in the cache, so we need
    // to wait on the request to call the callback instead (above).  If it fails above, then it
    // will continue to use the stale URI until the 24-hour failure period.  The callback for the
    // overall function will end up being called in the callback for the request.
    return;
  }


  // Now we can do the main part of the function which checks the hint and then calls one of
  // the functions above....

  // This hint thing is complicated....
  // It was designed to make it simple to say something like:
  // "hint: I looked up the JKU ot JWK on the signature, and it was from a trusted source." 
  // (i.e. hint = truthy), 
  // and it's truthy value is then either the JWKS (object) from the trusted source, 
  //     or the jku (string) of the trusted source's jwks
  // or 
  // "hint: I looked at my trusted sources and this one doesn't have a jwk or jku that matches." 
  // (i.e. hint === false)
  // which means "just use the header on the signature because I have no outside reference that verifies it"
  //
  // - If boolean false, use the jku from the jose header and if no jku then use jose's jwk
  // - If boolean true, throw error (it should have been either an object or a string)
  // - If string, assume string is a jku uri, go get that URI and then check jose's jwk against it
  // - If object and looks like a jwks, look for jose's jwk in the set
  // - If object and looks like a jwk, compare that jwk with jose's jwk
  switch (typeof hint) {
    case 'boolean':
      if (hint === false) {
        // Lookup soley based on JOSE headers
        if (jose.jku) return getJWK(jose.jku);
        // If no jku uri, then just use the jwk on the jose header as last resort
        return checkJWKEqualsJoseJWK(null, jose.jwk);
      }
    break;
    case 'string':
      return getJWK(hint);
    break;
    case 'object':
      if (utils.isJWKset(hint)) {
        return checkJWKEqualsJoseJWK(null, utils.findJWK(jose.kid, hint));
      } 
      if (utils.isJWK(hint) && jose.kid === hint.kid) {
        return checkJWKEqualsJoseJWK(null, hint);
      }
    break;
  }

  // If we get here, the hint didn't make sense so we error out:
  return checkJWKEqualsJoseJWK(new Error('Invalid hint'));
};

module.exports = utils;
