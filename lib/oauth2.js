var crypto = require('crypto'),
  fs = require('fs'),
  path = require('path'),
  basename = path.basename;

/*
 * @todo
 * WWW-Authenticate Response Header Field
 *
 * /^(authorization_code|password|assertion|refresh_token|none)$/
 *
 */

/*
 * OAuth2 Server
 */
var OAuth2 = module.exports = {};

OAuth2.codeLifeTime = 3600;
OAuth2.tokenParamName = 'oauth_token';

OAuth2.supportedScopes = [];
OAuth2.supportedGrantTypes = ['authorization_code', 'password', 'assertion', 'refresh_token'];

OAuth2.drivers = {};
fs.readdirSync(__dirname + '/drivers').forEach(function (filename) {
  if (!/\.js$/.test(filename)) return;
  var name = basename(filename, '.js');
  OAuth2.drivers[name] = require('./drivers/' + name);
});

OAuth2.config = function (key, fn) {
  if (fn) {
    this[key] = fn;
  } else {
    for (var k in key)
      this[k] = key[k];
  }
  return this;
};

OAuth2.driver = function (name) {
  if ('string' === typeof name) {
    this.config(this.drivers[name]);
  } else {
    var self = this;
    drivers.forEach(function (driver) {
      self.config(self.drivers[name]);
    });
  }
  return this;
}

var parseHeaderParams = function (req) {
  var params = {};

  if (req.headers) {
    var authorization = req.headers.authorization || '';
    // header_parts with trim ?
    // var header_parts = authorization.replace(/^\s*|\s*$/g, '').replace(/\s+/g, ' ').split(' ');
    var header_parts = authorization.split(' ');
    var scheme = header_parts[0];

    params.scheme = /^(Basic|OAuth2)$/.test(scheme) ? scheme : 'Invalid';

    if (scheme === 'Basic') {
      var credentials = new Buffer(header_parts[1], 'base64').toString();
      var split_index = credentials.indexOf(':');

      if (split_index < 0) {
        params.user = credentials.slice(0, split_index);
        params.pass = credentials.slice(split_index + 1);
      }
    }

    if (scheme === 'OAuth2') {
      params[OAuth2.tokenParamName] = header_parts[1] || null;
    }

  }

  return params;
};

var getClientCredentials = function (req) {
  var header_params = parseHeaderParams(req);

  // Basic or POST auth, not both
  if (header_params.user && req && req.body && req.body.client_id)
    return null;

  // Basic or POST auth
  if (req.body && req.body.client_id) {
    header_params.user = req.body.client_id;
    header_params.pass = req.body.client_secret || null;
    return header_params;
  }

  // No credentials were specified
  return null;
};

OAuth2.checkClientCredentials = function (credentials) {
  throw new Error('Oauth2#checkClientCredentials must be overridden by driver');
};

OAuth2.grantAccessToken = function () {
  var self = this;

  return function (req, res) {
    var grant_type = req.body.grant_type,
      scope = req.body.scope,
      code = req.body.code,
      redirect_uri = req.body.redirect_uri,
      username = req.body.username,
      password = req.body.password,
      assertion_type = req.body.assertion_type,
      refresh_token = req.body.refresh_token;

    var header_params = parseHeaderParams(req);
    
    if (!grant_type)
      res.status(400).json({error: 'Invalid grant_type parameter or parameter missing'});

    if (!OAuth2.supportedGrantTypes.indexOf(grant_type) < 0)
      res.status(400).json({error: 'Bad request'});

    var credentials = getClientCredentials(req);
    self.checkClientCredentials(credentials, function (err, client) {
      if (err)
        res.json({error: err});

      res.json(client);
    });
    
    res.json(header_params);
  };


};