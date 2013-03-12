var should = require('should'),
  utils = require('../lib/utils'),
  oauth2 = require('../lib/oauth2');

describe('OAuth2 server <API>: ', function () {
  it('should OAuth2 setup', function (done) {
    done();
  });
});

describe('Utils <LIB>: ', function () {
  it('should Utils.parseUri parse simple uri', function (done) {
    var parse_uri = utils.parseUri('http://localhost/callback');
    console.log(parse_uri);
    done();
  });

  it('should Utils.parseUri parse uri with port', function (done) {
    var parse_uri = utils.parseUri('http://localhost:3000/callback');
    console.log(parse_uri);
    done();
  });

  it('should Utils.parseUri parse uri with user, password and port', function (done) {
    var parse_uri = utils.parseUri('http://foo:bar@localhost:3000/callback');
    console.log(parse_uri);
    done();
  });

  it('should Utils.parseUri parse uri with queryString and hash fragment', function (done) {
    var parse_uri = utils.parseUri('http://localhost/callback/?teste=teste#top:foo=bar');
    console.log(parse_uri);
    done();
  });
});
