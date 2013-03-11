var crypto = require('crypto');

/*
 * OAuth2 Server
 */
var OAuth2 = module.exports = {};

OAuth2.codeLifeTime = 3600 * 1000;
OAuth2.tokenParamName = 'oauth_token';
OAuth2.salt = 'oauth2_node_salt';


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
  var params = {scheme: 'Invalid'};

  if (req.headers && req.headers.authorization) {
    var authorization = req.headers.authorization;
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

var errorWWWAuthenticateResponseHeader = function (res, status_code, error, realm, scope) {
  function quote(str) {
    return "'" + str + "'";
  };

  var result = [];
  result.push('realm=' + quote(realm || 'Service'));
  
  if (error)
    result.push('error=' + quote(error));

  if (scope)
    result.push('scope=' + quote(scope));

  res.status(status_code).set('WWW-Authenticate', 'OAuth ' + result.join(', '));
  res.json({error: error});
};

OAuth2.checkClientCredentials = function (credentials) {
  throw new Error('Oauth2#checkClientCredentials must be overridden by driver');
};

OAuth2.getAuthCode = function (code, next) {
  throw new Error('Oauth2#getAuthCode must be overridden by driver');
};

// Check if client have grant_type
OAuth2.checkRestrictedGrantType = function (client_id, grant_type) {
  return true;
};

OAuth2.genAccessToken = function (client_id, expires) {
  var now = new Date().getTime(),
    oauth2_salt = this.salt;

  return crypto.createHmac('sha1', 'access_token')
    .update([client_id, now, expires, oauth2_salt].join())
    .digest('hex');
};

OAuth2.genClientSecret = function () {
  var now = new Date().getTime(),
    oauth2_salt = this.salt;

  return crypto.createHmac('sha1', 'client_secret')
    .update([now, oauth2_salt].join())
    .digest('hex');
};

OAuth2.createAccessToken = function (client_id, scope, next) {
  var expires_in = this.codeLifeTime,
    expires = new Date().getTime() + expires_in,
    oauth_token = this.genAccessToken(client_id, expires);

  var access_token_config = {
    client_id: client_id,
    oauth_token: oauth_token,
    expires: expires,
    scope: scope
  };

  this.setAccessToken(access_token_config, function (err, access_token) {
    if (err)
      return next(err, access_token);

    var ret = {};
    ret.access_token = access_token.oauth_token;
    ret.expires_in = expires_in / 1000;

    if (scope)
      ret.scope = scope;

    return next(null, ret);
  });
};

OAuth2.verifyAccessToken = function (scope, realm) {
  var self = this;

  return function (req, res, next) {
    var header_params = parseHeaderParams(req),
      oauth_token = header_params.oauth_token;

    if (header_params.scheme === 'Invalid')
      return errorWWWAuthenticateResponseHeader(res, 400, 'invalid_request', realm, scope);

    self.getAccessToken(oauth_token, function (err, token) {
      if (!token)
        return errorWWWAuthenticateResponseHeader(res, 401, 'invalid_request', realm, scope);

      if (!token.expires || new Date().getTime() > token.expires)
        return errorWWWAuthenticateResponseHeader(res, 401, 'expired_token', realm, scope);

      if (scope && !token.scope || token.scope.indexOf(token.scope) < 0)
        return errorWWWAuthenticateResponseHeader(res, 401, 'expired_token', realm, scope);

      next(null, token);
    });
  }
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

    // var header_params = parseHeaderParams(req);
    
    if (!grant_type)
      res.status(400).json({error: 'invalid_grant'});

    if (!OAuth2.supportedGrantTypes.indexOf(grant_type) < 0)
      res.status(400).json({error: 'bad_request'});

    var credentials = getClientCredentials(req),
      client_id = credentials.user;

    self.checkClientCredentials(credentials, function (err, client) {
      if ('number' === typeof err)
        res.status(err).json({error: client});

      if (!self.checkRestrictedGrantType(client_id, grant_type))
        res.status(400).json({error: 'unauthorized_client'});
      
      var stored;
      switch (grant_type) {
        case 'authorization_code':
          if (!code || !redirect_uri)
            res.status(400).json({error: 'invalid_request'});

          self.getAuthCode(code, function (err, auth_code) {
            stored = auth_code;
            if (!stored || redirect_uri.indexOf(stored.redirect_uri) < 0 || client_id != stored.client_id)
              res.status(400).json({error: 'invalid_grant'});

            if (!stored || stored.expires < new Date().getTime())
              res.status(400).json({error: 'expired_token'});
            
          });

          break;
        case 'password':
        case 'assertion':
        case 'refresh_token':
          res.status(500).json({error: 'not_implemented'});

          break;
      }

      if (scope && !stored || stored && stored.scope && stored.scope.indexOf(scope) < 0)
        res.status(400).json({error: 'invalid_scope'});

      self.createAccessToken(client_id, scope, function (err, access_token) {
        if ('number' === typeof err)
          res.status(err).json({error: access_token});

        if (err)
          res.status(500).json({error: 'internal_service_error'});

        res.json(access_token);
      });
    });
  };
};

OAuth2.handleAuthorization = function (is_authorized, scope, state) {
  return function (req, res, next) {

  }
};
