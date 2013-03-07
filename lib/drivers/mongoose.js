var mongoose = require('mongoose');

// Client
var ClientSchema = new mongoose.Schema({
  secret: { type: String }
});
var Client = mongoose.model('Client', ClientSchema);

// AuthorizationCode
var AuthorizationCodeSchema = new mongoose.Schema({
  code: { type: String },
  client_id: { type: Number },
  redirect_uri: { type: String },
  user_id: { type: String },
  scope: { type: String }
});
var AuthorizationCode = mongoose.model('AuthorizationCode', AuthorizationCodeSchema);

// AccessToken
var AccessTokenSchema = new mongoose.Schema({
  token: { type: String },
  client_id: { type: Number },
  user_id: { type: String }
});
var AccessToken = mongoose.model('AccessToken', AccessTokenSchema);

/*
 * OAuth2 driver
 */
var OAuth2 = module.exports = {};

OAuth2.checkClientCredentials = function (credentials, next) {
  var criteria = {};

  criteria._id = credentials.user;
  if (credentials.pass)
    criteria.secret = credentials.pass;

  Client.findOne(criteria, function (err, client) {
    next(err, client);
  })
};