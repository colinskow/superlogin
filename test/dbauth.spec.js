'use strict';
var PouchDB = require('pouchdb');
var BPromise = require('bluebird');
var seed = require('pouchdb-seed-design');
var request = require('superagent');
var expect = require('chai').expect;
var DBAuth = require('../lib/dbauth');
var Configure = require('../lib/configure');
var util = require('../lib/util.js');
var config = require('./test.config.js');

var dbUrl = util.getDBURL(config.dbServer);

var userDB = new PouchDB(dbUrl + "/cane_test_users");
var keysDB = new PouchDB(dbUrl + "/cane_test_keys");
var testDB =  new PouchDB(dbUrl + "/cane_test_test");

var userDesign = require('../designDocs/user-design');

var testUser = {
  _id: 'colinskow',
  roles: ['admin', 'user']
};

var userConfig = new Configure({
  test: true,
  confirmEmail: true,
  emailFrom: 'noreply@example.com',
  dbServer: {
    protocol: config.dbServer.protocol,
    host: config.dbServer.host,
    user: config.dbServer.user,
    password: config.dbServer.password
  },
  userDBs: {
    privatePrefix: 'test',
    designDocDir: __dirname + '/ddocs'
  }
});

var dbAuth = new DBAuth(userConfig, userDB, keysDB);

describe('DBAuth', function() {

  var key, previous;

  it('should create a database', function() {
    var testDBName = 'sl_test_create_db';
    return checkDBExists(testDBName)
      .then(function(result) {
        expect(result).to.equal(false);
        return dbAuth.createDB(testDBName);
      })
      .then(function() {
        return checkDBExists(testDBName);
      })
      .then(function(result) {
        expect(result).to.equal(true);
        var destroyDB = new PouchDB(dbUrl + '/' + testDBName);
        return destroyDB.destroy();
      });
  });

  it('should generate a database access key', function() {
    previous = BPromise.resolve();
    return previous
      .then(function() {
        return seed(userDB, userDesign);
      })
      .then(function() {
        return dbAuth.storeKey(testUser._id, 'testkey', 'testpass', Date.now() + 60000, testUser.roles);
      })
      .then(function(newKey){
        key = newKey;
        expect(key._id).to.be.a('string');
        return keysDB.get('org.couchdb.user:' + key._id);
      })
      .then(function(doc) {
        expect(doc.expires).to.equal(key.expires);
      });
  });

  it('should remove a database access key', function() {
    return previous
      .then(function() {
        return dbAuth.removeKeys('testkey');
      })
      .then(function(){
        return keysDB.get('org.couchdb.user:testkey');
      })
      .then(function() {
        throw new Error('Failed to delete testkey');
      }).catch(function(err) {
        if (err.reason && (err.reason === 'deleted' || err.reason === 'missing')) return;
        throw err;
      });
  });

  it('should authorize database keys', function() {
    return previous
      .then(function() {
        return dbAuth.authorizeKeys('testuser', testDB, ['key1', 'key2']);
      })
      .then(function(res) {
        return testDB.get('_security');
      })
      .then(function(secDoc) {
        expect(secDoc.members.names[0]).to.equal('key1');
        expect(secDoc.members.names[1]).to.equal('key2');
      });
  });

  it('should only authorize keys once', function() {
    return previous
      .then(function() {
        return dbAuth.authorizeKeys('testuser', testDB, ['key1', 'key2']);
      })
      .then(function() {
        return testDB.get('_security');
      })
      .then(function(secDoc) {
        expect(secDoc.members.names.length).to.equal(2);
      });
  });

  it('should deauthorize keys', function() {
    return previous
      .then(function() {
        return dbAuth.deauthorizeKeys(testDB, ['key1', 'key2']);
      })
      .then(function() {
        return testDB.get('_security');
      })
      .then(function(secDoc) {
        expect(secDoc.members.names.length).to.equal(0);
      });
  });

  it('should create a new user database', function() {
    var userDoc = {
      _id: 'TEST.user-31@cool.com',
      session: {
        key1: {expires: Date.now() + 50000},
        key2: {expires: Date.now() + 50000}
      }
    };
    var newDB;
    return previous
      .then(function() {
        return dbAuth.addUserDB(userDoc, 'personal', ['test'], 'private', [], ['admin_role'], ['member_role']);
      })
      .then(function(finalDBName) {
        expect(finalDBName).to.equal('test_personal$test(2e)user(2d)31(40)cool(2e)com');
        newDB = new PouchDB(dbUrl + '/' + finalDBName);
        return newDB.get('_security');
      }).then(function(secDoc) {
        expect(secDoc.admins.roles[0]).to.equal('admin_role');
        expect(secDoc.members.roles[0]).to.equal('member_role');
        expect(secDoc.members.names[1]).to.equal('key2');
        return newDB.get('_design/test');
      })
      .then(function(design){
        expect(design.views.mytest.map).to.be.a('string');
        return newDB.destroy();
      });
  });

  it('should delete all expired keys', function() {
    var now = Date.now();
    var db1, db2;
    var user1 = {
      _id: 'testuser1',
      session: {
        oldkey1: {expires: now + 50000},
        goodkey1: {expires: now + 50000}
      },
      personalDBs: {'test_expiretest$testuser1': {
        permissions: null,
        name: 'expiretest'
      }}
    };

    var user2 = {
      _id: 'testuser2',
      session: {
        oldkey2: {expires: now + 50000},
        goodkey2: {expires: now + 50000}
      },
      personalDBs: {'test_expiretest$testuser2': {
        permissions: null,
        name: 'expiretest'
      }}
    };

    return previous
      .then(function() {
        var promises = [];
        // Save the users
        promises.push(userDB.bulkDocs([user1, user2]));
        // Add their personal dbs
        promises.push(dbAuth.addUserDB(user1, 'expiretest'));
        promises.push(dbAuth.addUserDB(user2, 'expiretest'));
        // Store the keys
        promises.push(dbAuth.storeKey('testuser1', 'oldkey1', 'password', user1.session.oldkey1.expires));
        promises.push(dbAuth.storeKey('testuser1', 'goodkey1', 'password', user1.session.goodkey1.expires));
        promises.push(dbAuth.storeKey('testuser2', 'oldkey2', 'password', user2.session.oldkey2.expires));
        promises.push(dbAuth.storeKey('testuser2', 'goodkey2', 'password', user2.session.goodkey2.expires));
        return BPromise.all(promises);
      })
      .then(function() {
        // Now we will expire the keys
        var promises = [];
        promises.push(userDB.get('testuser1'));
        promises.push(userDB.get('testuser2'));
        return BPromise.all(promises);
      })
      .then(function(docs) {
        docs[0].session.oldkey1.expires = 100;
        docs[1].session.oldkey2.expires = 100;
        return userDB.bulkDocs(docs);
      })
      .then(function() {
        // Now we will remove the expired keys
        return dbAuth.removeExpiredKeys();
      })
      .then(function() {
        // Fetch the user docs to inspect them
        db1 = new PouchDB(dbUrl + "/test_expiretest$testuser1");
        db2 = new PouchDB(dbUrl + "/test_expiretest$testuser2");
        var promises = [];
        promises.push(userDB.get('testuser1'));
        promises.push(userDB.get('testuser2'));
        promises.push(keysDB.get('org.couchdb.user:goodkey1'));
        promises.push(keysDB.get('org.couchdb.user:goodkey2'));
        promises.push(db1.get('_security'));
        promises.push(db2.get('_security'));
        return BPromise.all(promises);
      })
      .then(function(docs) {
        // Sessions for old keys should have been deleted, unexpired keys should be there
        expect(docs[0].session.oldkey1).to.be.an('undefined');
        expect(docs[0].session.goodkey1.expires).to.be.a('number');
        expect(docs[1].session.oldkey2).to.be.an('undefined');
        expect(docs[1].session.goodkey2.expires).to.be.a('number');
        // The unexpired keys should still be in the keys database
        expect(docs[2].user_id).to.equal('testuser1');
        expect(docs[3].user_id).to.equal('testuser2');
        // The security document for each personal db should contain exactly the good keys
        expect(docs[4].members.names.length).to.equal(1);
        expect(docs[4].members.names[0]).to.equal('goodkey1');
        expect(docs[5].members.names.length).to.equal(1);
        expect(docs[5].members.names[0]).to.equal('goodkey2');
        // Now we'll make sure the expired keys have been deleted from the users database
        var promises = [];
        promises.push(keysDB.get('org.couchdb.user:oldkey1'));
        promises.push(keysDB.get('org.couchdb.user:oldkey2'));
        return BPromise.settle(promises);
      })
      .then(function(results) {
        /* jshint -W030 */
        expect(results[0].isRejected()).to.be.true;
        expect(results[1].isRejected()).to.be.true;
        /* jshint +W030 */
        // Finally clean up
        return BPromise.all([db1.destroy(), db2.destroy()]);
      });
  });

  it('should cleanup databases', function() {
    return previous
      .finally(function() {
        return BPromise.all([userDB.destroy(), keysDB.destroy(), testDB.destroy()]);
      });
  });

});

function checkDBExists(dbname) {
  var finalUrl = dbUrl + '/' + dbname;
  return BPromise.fromNode(function(callback) {
    request.get(finalUrl)
      .end(callback);
  })
    .then(function(res) {
      var result = JSON.parse(res.text);
      if(result.db_name) {
        return BPromise.resolve(true);
      }
    }, function(err) {
      if(err.status === 404) {
        return BPromise.resolve(false);
      }
    });
}
