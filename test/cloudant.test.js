'use strict';
var PouchDB = require('pouchdb');
var BPromise = require('bluebird');
var expect = require('chai').expect;
var cloudant = require('../lib/dbauth/cloudant');

var cloudantUrl = 'https://' + process.env.CLOUDANT_USER + ':' + process.env.CLOUDANT_PASS + '@' + process.env.CLOUDANT_USER + '.cloudant.com';
var testDB;
var previous;

describe('Cloudant', function() {

  var apiKey;

  previous = BPromise.resolve();

  /* beforeEach(function(done) {
    previous.then(function() {
      done();
    })
  }); */

  it('should create the test DB', function(done) {
    previous.then(function() {
      testDB = new PouchDB(cloudantUrl + '/temp_test');
      return testDB;
    }).then(function() {
      done();
    });
  });

  it('should generate an API key', function(done) {
    this.timeout(5000);
    previous
      .then(function() {
        return cloudant.getAPIKey(testDB);
      })
      .then(function(result) {
        expect(result.ok).to.equal(true);
        expect(result.key).to.be.a('string');
        apiKey = result.key;
        done();
      });
  });

  it('should authorize keys', function(done) {
    this.timeout(10000);
    previous
      .then(function() {
        return cloudant.authorizeKeys('test_user', testDB, ['abc123', 'def456']);
      })
      .then(function() {
        return cloudant.getSecurityCloudant(testDB);
      })
      .then(function(secDoc) {
        expect(secDoc.cloudant.abc123[0]).to.equal('user:test_user');
        expect(secDoc.cloudant.abc123[1]).to.equal('_reader');
        done();
      });
  });

  it('should deauthorize a key', function(done) {
    this.timeout(10000);
    previous
      .then(function() {
        return cloudant.deauthorizeKeys(testDB, 'abc123');
      })
      .then(function() {
        return cloudant.getSecurityCloudant(testDB);
      })
      .then(function(secDoc) {
        expect(secDoc.cloudant.abc123).to.be.an('undefined');
        expect(secDoc.cloudant.def456[1]).to.equal('_reader');
        done();
      });
  });

  it('should clean up the test db', function(done) {
    this.timeout(5000);
    previous.finally(function() {
      // return testDB.destroy();
      return BPromise.resolve();
    })
      .then(function() {
        done();
      });
  });

});