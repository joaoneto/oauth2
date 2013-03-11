var mongoose = require('mongoose');

/*
 * OAuth2 driver
 */
var OAuth2 = module.exports = {};

// Client
var ClientSchema = new mongoose.Schema({
  secret: { type: String },
  redirect_uri: { type: String }
});
OAuth2.Client = mongoose.model('Client', ClientSchema);

// AuthorizationCode
var AuthorizationCodeSchema = new mongoose.Schema({
  code: { type: String },
  client_id: { type: mongoose.Schema.ObjectId, ref: 'Client' },
  redirect_uri: { type: String },
  user_id: { type: String },
  scope: { type: String }
});
OAuth2.AuthorizationCode = mongoose.model('AuthorizationCode', AuthorizationCodeSchema);

// AccessToken
var AccessTokenSchema = new mongoose.Schema({
  oauth_token: { type: String },
  client_id: { type: mongoose.Schema.ObjectId, ref: 'Client' },
  expires: { type: Number },
  scope: { type: String }
});
OAuth2.AccessToken = mongoose.model('AccessToken', AccessTokenSchema);


OAuth2.init = function (config) {
  var db = config.db = 'mongodb://localhost/authorization';
  mongoose.connect(db);
};

OAuth2.checkClientCredentials = function (credentials, next) {
  var criteria = {},
    client_id = credentials.user,
    secret = credentials.pass;


  criteria._id = client_id;
  if (secret)
    criteria.secret = secret;


  this.Client.findOne(criteria, function (err, client) {
    if (err)
      return next(500, 'internal_service_error');

    if (!client || secret && client.secret !== secret)
      return next(400, 'invalid_client');

    return next(null, client);
  });
};

OAuth2.getAuthCode = function (code, next) {
  this.AuthorizationCode.findOne({code: code}, function (err, auth_code) {
    if (err)
      return next(500, 'internal_service_error');

    return next(null, auth_code);
  });
};

OAuth2.setAccessToken = function (access_token_config, next) {
  if (!access_token_config.scope)
    delete access_token_config.scope;

  var access_token = new this.AccessToken(access_token_config);
  access_token.save(function (err, token) {
    if (err || !token)
      return next(500, 'internal_service_error');

    return next(null, token);
  });
};

OAuth2.getAccessToken = function (oauth_token, next) {
  this.AccessToken.findOne({oauth_token: oauth_token}, function (err, token) {
    return next(null, token);
  });
};