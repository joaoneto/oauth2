var express = require('express'),
  mongoose = require('mongoose');

// Init oauth2
var oauth2 = require('../lib/oauth2');
oauth2.driver('mongoose', { db: 'mongodb://localhost/teste' });

var routes = require('./routes')(oauth2);

// Init app
var app = module.exports = express();
app.configure(function () {
  app.use(express.bodyParser());
  app.use(express.cookieParser());
});

// List and create client form
app.get('/clients', routes.listClients);

// Add new client
app.post('/clients', routes.createClient);

// User Authorization
// app.get('/authorization', routes.authorization());

// Oauth2 handle user Authorization
app.get('/authorization', oauth2.handleAuthorization(), function (req, res) {
  console.log(req.method);
});
app.post('/authorization', oauth2.handleAuthorization(), function (req, res) {
  console.log(req.method);
});
app.all('/authorization', oauth2.handleAuthorization(), function (req, res) {
  console.log(req.method);
});
/*
app.all('/authorization', function (req, res) {
  oauth2.handleAuthorization()(req, res);
  console.log('Authorization');
  console.log(req.method);
});
*/

// Oauth2 endpoint
app.post('/token', oauth2.grantAccessToken(), function (req, res) {
  console.log('Endpoint');
})
/*
app.post('/token', function (req, res) {
  oauth2.grantAccessToken()(req, res);
  console.log('Endpoint');
});
*/

// Restricted resource
app.get('/resource', oauth2.verifyAccessToken(), function (req, res) {
  res.json({test: 'restrict_resource'});
});
// console.log(oauth2.parseHeaderParams());

app.listen(3000, function () {
  console.log('> NODE_ENV:', app.settings.env);
  console.log('> Express server listening on port:', 3000);
});