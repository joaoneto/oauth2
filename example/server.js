var express = require('express'),
  mongoose = require('mongoose');

var oauth2 = require('../lib/oauth2');

oauth2.driver('mongoose', { db: 'mongodb://localhost/teste' });

// OAuth2 mongoose models
var Client = oauth2.Client;

var app = module.exports = express();

app.configure(function () {
  app.use(express.bodyParser());
  app.use(express.cookieParser());
});

// New client form
app.get('/clients', function (req, res) {
  var secret = oauth2.genClientSecret();
  res.send('<html><body><form action="", method="post">Client secret: <input name="secret" readonly="readyonly" value="' + secret + '"> Redirect uri: <input name="redirect_uri"><input type="submit"></form></body></html>');
});

// Add new client and list clients
app.post('/clients', function (req, res) {
  if (!req.body || !req.body.redirect_uri || !req.body.secret)
    res.send('Client secret or redirect uri invalid, or not present, please try again!').end();

  var new_client = new Client(req.body);
  new_client.save(function (err, client) {
    if (err)
      return req.send('Error saving new client, please try again!').end();

    Client.find({}).sort({'_id': -1}).execFind(function (err, docs) {
      var result = ['<table>\n<tr><td>client_id</td><td>client_secret</td><td>request_uri</td></tr>\n'];

      for (var x = 0, len = docs.length; x < len; x++)
        result.push(['<tr><td>', docs[x]._id, '</td><td>', docs[x].secret, '</td><td>', docs[x].redirect_uri, '</td></tr>\n'].join(''));

      result.push(['</table>\n']);

      res.send(result.join('')).end();
    });

  });
});

// Oauth2 authorization
app.post('/authorization', oauth2.handleAuthorization());

// Oauth2 endpoint
app.post('/token', oauth2.grantAccessToken());

// Restricted resource
app.get('/resource', oauth2.verifyAccessToken(), function (req, res) {
  res.json({test: 'restrict_resource'});
});
// console.log(oauth2.parseHeaderParams());

app.listen(3000, function () {
  console.log('> NODE_ENV:', app.settings.env);
  console.log('> Express server listening on port:', 3000);
});