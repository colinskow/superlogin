"use strict";
import * as util from "../src/util";
var path = require("path");
const PouchDB = require("pouchdb-core")
  .plugin(require("pouchdb-adapter-http"))
  .plugin(require("pouchdb-mapreduce"));
const axios = require("axios");
var BPromise = require("bluebird");
var seed = require("pouchdb-seed-design");
var expect = require("chai").expect;
var DBAuth = require("../src/dbauth").default;
var Configure = require("../src/configure").default;
var config = require("./test.config.js");

var dbUrl = util.getDBURL(config.dbServer);

var userDB = new PouchDB(dbUrl + "/cane_test_users");
var keysDB = new PouchDB(dbUrl + "/cane_test_keys");
var testDB = new PouchDB(dbUrl + "/cane_test_test");

var userDesign = require("../designDocs/user-design");
var couchDesign = require("../designDocs/couch-design");

seed(keysDB, couchDesign);

var testUser = {
  _id: "colinskow",
  roles: ["admin", "user"]
};

var userConfig = new Configure({
  test: true,
  confirmEmail: true,
  emailFrom: "noreply@example.com",
  dbServer: {
    protocol: config.dbServer.protocol,
    host: config.dbServer.host,
    user: config.dbServer.user,
    password: config.dbServer.password
  },
  userDBs: {
    privatePrefix: "test",
    designDocDir: path.join(__dirname, "/ddocs")
  }
});

var dbAuth = new DBAuth(userConfig, userDB, keysDB);

describe("DBAuth", function() {
  var key, previous;

  it("should create a database", function() {
    var testDBName = "sl_test_create_db";
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
        var destroyDB = new PouchDB(dbUrl + "/" + testDBName);
        return destroyDB.destroy();
      });
  });

  it("should generate a database access key", function() {
    previous = BPromise.resolve();
    return previous
      .then(function() {
        return seed(userDB, userDesign);
      })
      .then(function() {
        return dbAuth.storeKey(testUser._id, "testkey", "testpass", Date.now() + 60000, testUser.roles);
      })
      .then(function(newKey) {
        key = newKey;
        expect(key._id).to.be.a("string");
        return keysDB.get("org.couchdb.user:" + key._id);
      })
      .then(function(doc) {
        expect(doc.expires).to.equal(key.expires);
      });
  });

  it("should remove a database access key", function() {
    return previous
      .then(function() {
        return dbAuth.removeKeys("testkey");
      })
      .then(function() {
        return keysDB.get("org.couchdb.user:testkey");
      })
      .then(function() {
        throw new Error("Failed to delete testkey");
      }).catch(function(err) {
        if (err.reason && (err.reason === "deleted" || err.reason === "missing")) return;
        throw err;
      });
  });

  it("should authorize database keys", function() {
    return previous
      .then(function() {
        return dbAuth.authorizeKeys("testuser", testDB, ["key1", "key2"]);
      })
      .then(function(res) {
        return testDB.get("_security");
      })
      .then(function(secDoc) {
        expect(secDoc.members.names[0]).to.equal("key1");
        expect(secDoc.members.names[1]).to.equal("key2");
      });
  });

  it("should only authorize keys once", function() {
    return previous
      .then(function() {
        return dbAuth.authorizeKeys("testuser", testDB, ["key1", "key2"]);
      })
      .then(function() {
        return testDB.get("_security");
      })
      .then(function(secDoc) {
        expect(secDoc.members.names.length).to.equal(2);
      });
  });

  it("should deauthorize keys", function() {
    return previous
      .then(function() {
        return dbAuth.deauthorizeKeys(testDB, ["key1", "key2"]);
      })
      .then(function() {
        return testDB.get("_security");
      })
      .then(function(secDoc) {
        expect(secDoc.members.names.length).to.equal(0);
      });
  });

  it("should create a new user database", function() {
    var userDoc = {
      _id: "TEST.user-31@cool.com",
      session: {
        key1: {expires: Date.now() + 50000},
        key2: {expires: Date.now() + 50000}
      }
    };
    var newDB;
    return previous
      .then(function() {
        return dbAuth.addUserDB(userDoc, "personal", ["test"], "private", [], ["admin_role"], ["member_role"]);
      })
      .then(function(finalDBName) {
        expect(finalDBName).to.equal("test_personal$test(2e)user(2d)31(40)cool(2e)com");
        newDB = new PouchDB(dbUrl + "/" + finalDBName);
        return newDB.get("_security");
      }).then(function(secDoc) {
        expect(secDoc.admins.roles[0]).to.equal("admin_role");
        expect(secDoc.members.roles[0]).to.equal("member_role");
        expect(secDoc.members.names[1]).to.equal("key2");
        return newDB.get("_design/test");
      })
      .then(function(design) {
        expect(design.views.mytest.map).to.be.a("string");
        return newDB.destroy();
      });
  });

  it("should delete all expired keys", function() {
    var now = Date.now();
    var db1, db2;
    var user1 = {
      _id: "testuser1",
      personalDBs: {"test_expiretest$testuser1": {
        permissions: null,
        name: "expiretest"
      }}
    };

    var user2 = {
      _id: "testuser2",
      personalDBs: {"test_expiretest$testuser2": {
        permissions: null,
        name: "expiretest"
      }}
    };

    return previous
      .then(() => {
        var promises = [];
        // Save the users
        promises.push(userDB.bulkDocs([user1, user2]));
        // Add their personal dbs
        promises.push(dbAuth.addUserDB(user1, "expiretest"));
        promises.push(dbAuth.addUserDB(user2, "expiretest"));
        // Store the keys
        promises.push(dbAuth.storeKey("testuser1", "oldkey1", "password", 100));
        promises.push(dbAuth.storeKey("testuser1", "goodkey1", "password", now + 50000));
        promises.push(dbAuth.storeKey("testuser2", "oldkey2", "password", 100));
        promises.push(dbAuth.storeKey("testuser2", "goodkey2", "password", now + 50000));
        return BPromise.all(promises);
      })
      .then(() => {
        // Now we will remove the expired keys
        return dbAuth.removeExpiredKeys();
      })
      .then(() => {
        // Fetch the user docs to inspect them
        db1 = new PouchDB(dbUrl + "/test_expiretest$testuser1");
        db2 = new PouchDB(dbUrl + "/test_expiretest$testuser2");
        var promises = [];
        promises.push(keysDB.get("org.couchdb.user:goodkey1"));
        promises.push(keysDB.get("org.couchdb.user:goodkey2"));
        return BPromise.all(promises);
      })
      .then(docs => {
        // Sessions for old keys should have been deleted, unexpired keys should be there
        // The unexpired keys should still be in the keys database
        expect(docs[0].user_id).to.equal("testuser1");
        expect(docs[1].user_id).to.equal("testuser2");
        // Now we'll make sure the expired keys have been deleted from the users database
        var promises = [];
        promises.push(keysDB.get("org.couchdb.user:oldkey1"));
        promises.push(keysDB.get("org.couchdb.user:oldkey2"));
        return BPromise.all(promises);
      })
      .catch(() => {
        return BPromise.all([db1.destroy(), db2.destroy()]);
      });
  });

  it("should cleanup databases", function() {
    return previous
      .finally(function() {
        return BPromise.all([userDB.destroy(), keysDB.destroy(), testDB.destroy()]);
      });
  });
});

function checkDBExists(dbname) {
  var finalUrl = dbUrl + "/" + dbname;
  return axios.get(finalUrl).then(function(res) {
    if (res.data.db_name) {
      return BPromise.resolve(true);
    }
  }).catch(function(err) {
    if (err.response && err.response.status === 404) {
      return BPromise.resolve(false);
    }
  });
}
