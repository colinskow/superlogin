'use strict';
var BPromise = require('bluebird');
var expect = require('chai').expect;
var Session = require('../lib/session');
var Configure = require('../lib/configure');
var fs = BPromise.promisifyAll(require('fs-extra'));
var debug = require('debug-logger')('superlogin:test:session');

var testToken = {
  _id: 'colinskow',
  roles: ['admin', 'user'],
  key: 'test123',
  password: 'pass123',
  issued: Date.now(),
  expires: Date.now() + 50000
};

var config = new Configure({
  session: {
    adapter: 'memory'
  }
});

var fileConfig = new Configure({
  session: {
    adapter: 'file',
    file: {
      sessionsRoot: '.session'
    }
  }
});

describe('Session', function() {
  return runTest(config, 'Memory adapter')
    .finally(function() {
      return runTest(fileConfig, 'File adapter');
    })
    .finally(function() {
      config.setItem('session.adapter', 'redis');
      return runTest(config, 'Redis adapter');
    })
    .finally(function() {
      return fs.removeAsync('./.session');
    });
});

function runTest(config, adapter) {

  var session = new Session(config);
  var previous;

  return new BPromise(function(resolve, reject) {

    describe(adapter, function() {

      it('should store a token', function(done) {
        previous = session.storeToken(testToken)
          .then(function() {
            return session.confirmToken(testToken.key, testToken.password);
          })
          .then(function(result) {
            debug.log('stored token');
            expect(result.key).to.equal(testToken.key);
            done();
          })
          .catch(function(err) {
            done(err);
          });
      });

      it('should confirm a key and return the full token if valid', function(done) {
        previous.then(function() {
          return session.confirmToken(testToken.key, testToken.password)
            .then(function(result) {
              debug.log('confirmed token');
              expect(result._id).to.equal('colinskow');
              done();
            })
            .catch(function(err) {
              done(err);
            });
        });
      });

      it('should reject an invalid token', function(done) {
        previous.then(function() {
          return session.confirmToken('faketoken', testToken.password)
            .catch(function (err) {
              debug.log('rejected invalid token');
              expect(err).to.equal('invalid token');
              done();
            });
        });
      });

      it('should reject a wrong password', function(done) {
        previous.then(function() {
          return session.confirmToken(testToken.key, 'wrongpass')
            .catch(function (err) {
              debug.log('rejected invalid token');
              expect(err).to.equal('invalid token');
              done();
            });
        });
      });

      it('should delete a token', function(done) {
        previous.then(function() {
          return session.deleteTokens(testToken.key)
            .then(function (result) {
              expect(result).to.equal(1);
              return session.confirmToken(testToken.key);
            })
            .then(function() {
              throw new Error('failed to delete token');
            })
            .catch(function(err) {
              debug.log('deleted token');
              expect(err).to.equal('invalid token');
              session.quit();
              done();
              resolve();
            });
        });
      });

    });
  });

}
