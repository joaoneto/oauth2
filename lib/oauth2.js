var crypto = require('crypto');
/*
 * @todo
 * WWW-Authenticate Response Header Field
 */

/*
 * OAuth2 Server
 */
var OAuth2 = module.exports = {};

OAuth2.codeLifeTime = 3600;
OAuth2.tokenParamName = 'oauth_token';

OAuth2.supportedScopes = [];
// OAuth2.supportedGrantTypes = ['authorization_code', 'password', 'assertion', 'refresh_token'];
OAuth2.supportedGrantTypes = ['authorization_code'];

OAuth2.drivers = {};

OAuth2.config = function (key, fn) {
  if (fn) {
    this[key] = fn;
  } else {
    for (var k in key)
      this[k] = key[k];
  }
  return this;
};

OAuth2.driver = function (name, config) {
  if ('string' === typeof name) {
    var driver = require('./drivers/' + name);
    if (driver.init)
      driver.init(config);
    this.config(driver);
  }
  return this;
};

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

OAuth2.getAuthCode = function (code, next) {
  throw new Error('Oauth2#getAuthCode must be overridden by driver');
};

// Check if client have grant_type
OAuth.checkRestrictedGrantType = function (client_id, grant_type) {
  return true;
};

OAuth.createAccessToken = function (client_id, scope, next) {

}

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

    var credentials = getClientCredentials(req),
      client_id = credentials.client_id;

    self.checkClientCredentials(credentials, function (err, client) {
      if ('number' === typeof err)
        res.status(err).json({error: client});

      if (!self.checkRestrictedGrantType(client_id, grant_type))
        res.status(400).json({error: 'unauthorized_client'});

      switch (grant_type) {
        case 'authorization_code':
          if (!code || !redirect_uri)
            res.status(400).json({error: 'invalid_request'});

          var stored = self.getAuthCode(code);

          if (!stored || redirect_uri.indexOf(stored.redirect_uri) < 0 || client_id != stored.client_id)
            res.status(400).json({error: 'invalid_grant'});

          if (stored.expires < new Date().getTime())
            res.status(400).json({error: 'expired_token'});

          break;
        case 'password':
        case 'assertion':
        case 'refresh_token':
          res.status(500).json({error: 'not_implemented'});

          break;
      }

      if (scope && !stored.scope || stored.scope && stored.scope.indexOf(scope) < 0)
        res.status(400).json({error: 'invalid_scope'});

      var token = self.createAccessToken(client_id, scope);

      res.json(token);
    });
    
  };


};