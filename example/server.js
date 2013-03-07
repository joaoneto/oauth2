var express = require('express'),
  mongoose = require('mongoose');

var oauth2 = require('../lib/oauth2');

oauth2.driver('mongoose', { db: 'mongodb://localhost/teste' });

var app = module.exports = express();

app.configure(function () {
  app.use(express.bodyParser());
  app.use(express.cookieParser());
});

app.post('/', oauth2.grantAccessToken());
// console.log(oauth2.parseHeaderParams());

app.listen(3000, function () {
  console.log('> NODE_ENV:', app.settings.env);
  console.log('> Express server listening on port:', 3000);
});