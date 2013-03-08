var express = require('express'),
  mongoose = require('mongoose');

var oauth2 = require('../lib/oauth2');

oauth2.driver('mongoose', { db: 'mongodb://localhost/teste' });

var app = module.exports = express();

app.configure(function () {
  app.use(express.bodyParser());
  app.use(express.cookieParser());
});

// Oauth2 endpoint
app.post('/', oauth2.grantAccessToken());

// Restricted resource
app.get('/resource', oauth2.verifyAccessToken(), function (req, res) {
  res.json({test: 'restrict_resource'});
});
// console.log(oauth2.parseHeaderParams());

app.listen(3000, function () {
  console.log('> NODE_ENV:', app.settings.env);
  console.log('> Express server listening on port:', 3000);
});