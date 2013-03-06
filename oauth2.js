var crypto = require('crypto');
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

OAuth2.config = OAuth2.driver = function (key, fn) {
  if (fn) {
    this[key] = fn;
  } else {
    for (var k in key)
      this[k] = key[k];
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
      if (!err)
        res.json(client);

      res.json({error: err});
    });
    
    res.json(header_params);
  };


};

/*

OAuth2.setup = function (config, driver) {
  config = config || {};
  driver = driver || config.driver;

  // Dependencies
  this.inject = config.inject || ['Client', 'AccessToken', 'AuthorizationCode'];
  
  this.supported_scopes = config.supported_scopes || ['generic'];

  this.supported_grant_types = config.supported_grant_types || [ this.GRANT_TYPE_AUTH_CODE, this.GRANT_TYPE_USER_CREDENTIALS, this.GRANT_TYPE_ASSERTION, this.GRANT_TYPE_REFRESH_TOKEN ];

  // Load driver methods
  if (driver) {
    for (var key in driver) {
      OAuth2[key] = driver[key];
    }
  }
  
  return this;
}

OAuth2.setup();

module.exports = OAuth2;

OAuth2.parseHeaderParams = function (req) {
  var params = {};

  if (req && req.headers) {
    var authorization = req.headers.authorization;
    // header_parts with trim ?
    // var header_parts = authorization.replace(/^\s*|\s*$/g, '').replace(/\s+/g, ' ').split(' ');
    var header_parts = authorization.split(' ');
    var scheme = header_parts[0];

    params.scheme = /^(Basic|OAuth)$/.test(scheme) ? scheme : 'Invalid';

    if (scheme === 'Basic') {
      var credentials = new Buffer(header_parts[1], 'base64').toString();
      var split_index = credentials.indexOf(':');

      if (split_index > 0) {
        params.user = credentials.slice(0, split_index);
        params.pass = credentials.slice(split_index + 1);
      }
    }

    if (scheme === 'OAuth') {
      params[OAUTH2_TOKEN_PARAM_NAME] = header_parts[1] || null;

      if (req.body) {
        params.client_id = req.body.client_id || null;
        params.client_secret = req.body.client_secret || null;
      }
    }

  }

  return params;
}

OAuth2.getAccessTokenParams = function (req, next) {
  if (req && req.headers) {
    var header_params = this.parseHeaderParams(req);

    if (header_params.scheme) {
      if (req.params && req.params[OAUTH2_TOKEN_PARAM_NAME] || req.body && req.body[OAUTH2_TOKEN_PARAM_NAME])
        return next('Auth token found in GET or POST when token present in header');

      if (header_params.scheme !== 'OAuth')
        return next('Auth header found that doesn\'t start with "OAuth"');

      if (!header_params[OAUTH2_TOKEN_PARAM_NAME])
        return next('Malformed auth header');

      return next(null, header_params[OAUTH2_TOKEN_PARAM_NAME]);
    }

  }

  if (req.params && req.params[OAUTH2_TOKEN_PARAM_NAME]) {
    if (req.body && req.body[OAUTH2_TOKEN_PARAM_NAME])
      return next('Only send the token in GET or POST, not both');

    return next(null, req.params[OAUTH2_TOKEN_PARAM_NAME]);
  }

  if (req.body && req.body[OAUTH2_TOKEN_PARAM_NAME])
    return next(null, req.body[OAUTH2_TOKEN_PARAM_NAME]);

  return next();
};

OAuth2.getClientCredentials = function (req, next) {
  var header_params = this.parseHeaderParams(req);

  // Basic or POST auth, not both
  if (header_params.user && req && req.body && req.body.client_id)
    return next('invalid_client');

  // Basic or POST auth
  if (header_params.user || header_params.client_id)
    return next(null, header_params);

  // No credentials were specified
  return next('invalid_client');
};

// Make sure that the client credentials is valid.
OAuth2.checkClientCredentials = function (credentials, next) {
  throw new Error('Oauth2#authenticate must be overridden by driver');
}

OAuth2.getRedirectUri = function (client_id) {
  throw new Error('Oauth2#getRedirectUri must be overridden by driver');
}

OAuth2.getAccessToken = function (oauth_token) {
  throw new Error('Oauth2#getAccessToken must be overridden by driver');
}

OAuth2.setAccessToken = function (oauth_token, client_id, expires, scope) {
  throw new Error('Oauth2#setAccessToken must be overridden by driver');
}

OAuth2.getSupportedScopes = function () {
  return this.supported_scopes;
}

OAuth2.getSupportedGrantTypes = function () {
  return this.supported_grant_types;
}

OAuth2.getAuthCode = function (code) {
  throw new Error('Oauth2#getAuthCode must be overridden by driver');
}

OAuth2.setAuthCode = function (code, client_id, redirect_uri, expires, scope) {
  throw new Error('Oauth2#setAuthCode must be overridden by driver');
}

OAuth2.createAuthCode = function (client_id, redirect_uri, scope) {
}

OAuth2.genAccessToken = function () {
  return crypto.createHash('md5').update('AT-WOGLIB$' + new Date().getTime()).digest("hex");
}

OAuth2.genAuthCode = function () {
  return crypto.createHash('md5').update('AC-WOGLIB#' + new Date().getTime()).digest("hex");
}

OAuth2.grantAccessToken = function (req, res, next) {
  var authorization = req.headers.Authorization;

  var grant_type = req.body.grant_type,
    scope = req.body.scope,
    code = req.body.code,
    redirect_uri = req.body.redirect_uri,
    username = req.body.username,
    password = req.body.password,
    assertion_type = req.body.assertion_type,
    refresh_token = req.body.refresh_token;

  if (!grant_type)
    next('Invalid grant_type parameter or parameter missing');
  
  if (!grant_type.indexOf(this.getSupportedGrantTypes()))
    next('Bad request');

  var client_credentials;
  credentials = this.getClientCredentials(req);

  this.checkClientCredentials(client_credentials);

  // var auth_header = provider.getAuthorizationHeader(req);
}
*/