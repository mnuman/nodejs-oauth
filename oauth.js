/* This implementation is loosely inspired on the mockService.js by Robert Wunderlich as supplied
 * as part of the APICS BETA VM distribution.
 */
var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var unirest = require("unirest");
var storage = require('node-persist');
var port = process.env.PORT || 80;

// Service level variables
var clientID = '849309030102-r5fv5k1s1oo1n036snh0dmn828otdksn.apps.googleusercontent.com';
var clientSecret = 'SMBm9R6ml060HcBqzIpJ1FrR';
var redirectUri = 'urn:ietf:wg:oauth:2.0:oob';

// Used in constructing complete URLs for service resources
var googleBaseUrl = 'https://www.googleapis.com';
var googleTokenPath = '/oauth2/v4/token';
var validityOfToken = 59 * 60000; // validity of token in ms, 59 mins is safe, Google tokens expire in 1h

// initialize to store in storage subdir
storage.initSync({ dir: 'storage'});
app.use(defaultContentTypeMiddleware);
app.use(bodyParser.json({ type: '*/*' }));
/* Accepting any type and assuming it is application/json, otherwise the caller
 *    is forced to pass the content-type specifically.
 *    */
function defaultContentTypeMiddleware (req, res, next) {
  req.headers['content-type'] = req.headers['content-type'] || 'application/json';
  next();
}

function knownToken(id){
  token = storage.getItem(id);
  return (token != null && token.access_token != null);
}

function getAccessToken(req, res){
  var id = req.params.id;
  if (knownToken( req.params.id )){
    var now = new Date().getTime();
    token = getToken( id );

    if (now < token.expiry){
    // token is still fresh, can just be returned
      res.statusCode = 200
      res.json(token);
    } else {
      console.log('Token expired, refresh is required ...');
      unirest.post(googleBaseUrl.concat(googleTokenPath))
      .strictSSL(false)
      .query({ refresh_token: token.refresh_token
             , client_id: clientID
             , client_secret: clientSecret
             , grant_type: 'refresh_token'
             }
            )
      .end( function (response){
              storeToken( id, response.body.access_token, token.refresh_token);
              res.statusCode = 200;
              res.json( getToken(id));
            }
          );
    }
  } else {
    res.statusCode = 404;
    res.json({ "error" : "User cannot be found in store"});
  }
}

/* Store the generated/refreshed token in the tokenstore
 */
function storeToken(id, access_token, refresh_token){
  var t = {};
  var now = new Date().getTime();
  t.access_token  = access_token;
  t.refresh_token = refresh_token;
  // expiry date of token in 59 min (actually 3600 s = 60 min for Google, but this is easier
  t.expiry = new Date(now + validityOfToken);
  storage.setItem(id, t);
}

function getToken(id){
  var token = {}
  token = storage.getItem(id);
  return token;
}

/* Redeem the authorization code by performing a
 * POST request using application/x-www-form-urlencoded submission for the
 * parameters.
 * Need to make sure SSL is not applied strictly because of Rabo man-in-the-middle
 * on our network segment.
 */
function redeemAuthorizationCode(req,res){
  var id = req.body.id;
  console.log('Start-Redeeming authorization code for id: ' + id);
  unirest.post(googleBaseUrl.concat(googleTokenPath))
  .strictSSL(false)
  .query({ code: req.body.authorizationCode
         , client_id: clientID
         , client_secret: clientSecret
         , redirect_uri: redirectUri
         , grant_type: 'authorization_code'
         }
        )
  .end( function (response){ 
          storeToken( id, response.body.access_token, response.body.refresh_token);
          res.statusCode = 201;
          res.json(getToken( id));
          console.log('End-Redeeming authorization code for id: ' + id);
        }
      );
}
// Test function to story my token, returning the token
function putTestTokenInStore(req,res){
  storeToken( req.body.id, req.body.access_token, req.body.refresh_token);
  res.statusCode = 201;
  res.json(getToken( req.body.id));
}

// Forced refresh of token
function refreshToken(req, res){
  var id = req.params.id;
  if (knownToken(id)){
    var token = getToken(id);
    unirest.post(googleBaseUrl.concat(googleTokenPath))
    .strictSSL(false)
    .query({ refresh_token: token.refresh_token
           , client_id: clientID
           , client_secret: clientSecret
           , grant_type: 'refresh_token'
           }
          )
    .end( function (response){ 
            storeToken( id, response.body.access_token, token.refresh_token);
            res.statusCode = 200;
            res.json( getToken(id));
          }
        );
  } else {
      res.statusCode = 404;
      res.json({ "error" : "Could not refresh token -- token not found"});
  }
}
// Associate methods with their handlers
app.post('/authorization', redeemAuthorizationCode);
app.get('/access/:id', getAccessToken);

//Creating the server process
app.listen(port);
console.log('Listening on port ' + port);

