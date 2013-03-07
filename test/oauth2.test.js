var
  should = require('should'),
  oauth2 = require('../lib/oauth2');

describe('OAuth2 server <API>: ', function () {
  it('should OAuth2 setup', function (done) {
    oauth2.config({
      parseHeaderParams: function bb () {
        console.log('HAHAHA!');
      }
    });
    oauth2.config('teste', function aa () { })
    console.log(oauth2);
    done();
  });

  /*
  it('should OAuth2 inject', function (done) {
    oauth2.inject = ['Client', 'AccessToken', 'AuthorizationCode'];
    
    di.register('Client', function Client() {});
    di.register('AccessToken', function AccessToken() {});
    di.register('AuthorizationCode', function AuthorizationCode() {});

    di.inject(oauth2);
    console.log(oauth2);
    done();
  });
  */
  
});
