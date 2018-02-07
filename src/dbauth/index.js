import BPromise from "bluebird";
import * as util from "./../util";
import axios from "axios";
import seed from "pouchdb-seed-design";

import CouchAdapter from "./couchdb";

const PouchDB = require("pouchdb-core")
  .plugin(require("pouchdb-adapter-http"))
  .plugin(require("pouchdb-mapreduce"));

export default function(config, userDB, couchAuthDB) {
  var adapter = new CouchAdapter(couchAuthDB);

  this.storeKey = function(username, key, password, expires, roles) {
    return adapter.storeKey(username, key, password, expires, roles);
  };

  this.removeKeys = function(keys) {
    return adapter.removeKeys(keys);
  };

  this.authorizeKeys = function(userId, db, keys, permissions, roles) {
    return adapter.authorizeKeys(userId, db, keys, permissions, roles);
  };

  this.deauthorizeKeys = function(db, keys) {
    return adapter.deauthorizeKeys(db, keys);
  };

  this.addUserDB = function(userDoc, dbName, designDocs, type, permissions, adminRoles, memberRoles) {
    var self = this;
    var promises = [];
    adminRoles = adminRoles || [];
    memberRoles = memberRoles || [];
    // Create and the database and seed it if a designDoc is specified
    var prefix = config.getItem("userDBs.privatePrefix") ? config.getItem("userDBs.privatePrefix") + "_" : "";
    var finalDBName, newDB;
    // Make sure we have a legal database name
    var username = userDoc._id;
    username = getLegalDBName(username);
    if (type === "shared") {
      finalDBName = dbName;
    }
    else {
      finalDBName = prefix + dbName + "$" + username;
    }
    return self.createDB(finalDBName).then(function() {
      // eslint-disable-next-line
      newDB = new PouchDB(util.getDBURL(config.getItem("dbServer")) + "/" + finalDBName);
      return adapter.initSecurity(newDB, adminRoles, memberRoles);
    }).then(function() {
      // Seed the design docs
      if (designDocs && designDocs instanceof Array) {
        designDocs.forEach(function(ddName) {
          var dDoc = self.getDesignDoc(ddName);
          if (dDoc) {
            promises.push(seed(newDB, dDoc));
          }
          else {
            console.warn("Failed to locate design doc: " + ddName);
          }
        });
      }
      // Authorize the user's existing DB keys to access the new database
      var keysToAuthorize = [];
      if (userDoc.session) {
        for (var key in userDoc.session) {
          if (userDoc.session.hasOwnProperty(key) && userDoc.session[key].expires > Date.now()) {
            keysToAuthorize.push(key);
          }
        }
      }
      if (keysToAuthorize.length > 0) {
        promises.push(self.authorizeKeys(userDoc._id, newDB, keysToAuthorize, permissions, userDoc.roles));
      }
      return BPromise.all(promises);
    }).then(function() {
      return BPromise.resolve(finalDBName);
    });
  };

  this.removeExpiredKeys = function() {
    var self = this;
    var expiredKeys = [];
    // query a list of expired keys by user
    return couchAuthDB.query("_superlogin/expired", {
      include_docs: true
    }).then(function(result) {
      let expiredKeys = result.rows.filter(i => {
        return i.doc.expires < Date.now();
      }).map(i => i.doc.name);
      return self.removeKeys(expiredKeys);
    })
      .then(function() {
        return BPromise.resolve(expiredKeys);
      });
  };

  this.getDesignDoc = function(docName) {
    if (!docName) {
      return null;
    }
    var designDoc;
    var designDocDir = config.getItem("userDBs.designDocDir");
    if (!designDocDir) {
      designDocDir = __dirname;
    }
    try {
      designDoc = require(designDocDir + "/" + docName);
    }
    catch (err) {
      console.warn("Design doc: " + designDocDir + "/" + docName + " not found.");
      designDoc = null;
    }
    return designDoc;
  };

  this.getDBConfig = function(dbName, type) {
    var dbConfig = {
      name: dbName
    };
    dbConfig.adminRoles = config.getItem("userDBs.defaultSecurityRoles.admins") || [];
    dbConfig.memberRoles = config.getItem("userDBs.defaultSecurityRoles.members") || [];
    var dbConfigRef = "userDBs.model." + dbName;
    if (config.getItem(dbConfigRef)) {
      dbConfig.permissions = config.getItem(dbConfigRef + ".permissions") || [];
      dbConfig.designDocs = config.getItem(dbConfigRef + ".designDocs") || [];
      dbConfig.type = type || config.getItem(dbConfigRef + ".type") || "private";
      var dbAdminRoles = config.getItem(dbConfigRef + ".adminRoles");
      var dbMemberRoles = config.getItem(dbConfigRef + ".memberRoles");
      if (dbAdminRoles && dbAdminRoles instanceof Array) {
        dbAdminRoles.forEach(function(role) {
          if (role && dbConfig.adminRoles.indexOf(role) === -1) {
            dbConfig.adminRoles.push(role);
          }
        });
      }
      if (dbMemberRoles && dbMemberRoles instanceof Array) {
        dbMemberRoles.forEach(function(role) {
          if (role && dbConfig.memberRoles.indexOf(role) === -1) {
            dbConfig.memberRoles.push(role);
          }
        });
      }
    }
    else if (config.getItem("userDBs.model._default")) {
      dbConfig.permissions = config.getItem("userDBs.model._default.permissions") || [];
      // Only add the default design doc to a private database
      if (!type || type === "private") {
        dbConfig.designDocs = config.getItem("userDBs.model._default.designDocs") || [];
      }
      else {
        dbConfig.designDocs = [];
      }
      dbConfig.type = type || "private";
    }
    else {
      dbConfig.type = type || "private";
    }
    return dbConfig;
  };

  this.createDB = function(dbName) {
    var finalUrl = util.getDBURL(config.getItem("dbServer")) + "/" + dbName;
    console.log(finalUrl);
    return axios.put(finalUrl).then(function(res) {
      return BPromise.resolve(res.data);
    }, function(err) {
      if (err.response.status === 412) {
        return BPromise.resolve(false);
      }
      else {
        return BPromise.reject(err.response);
      }
    });
  };

  this.removeDB = function(dbName) {
    // eslint-disable-next-line
    var db = new PouchDB(util.getDBURL(config.getItem("dbServer")) + "/" + dbName);
    return db.destroy();
  };

  return this;
};

// Escapes any characters that are illegal in a CouchDB database name using percent codes inside parenthesis
// Example: 'My.name@example.com' => 'my(2e)name(40)example(2e)com'
function getLegalDBName(input) {
  input = input.toLowerCase();
  var output = encodeURIComponent(input);
  output = output.replace(/\./g, "%2E");
  output = output.replace(/!/g, "%21");
  output = output.replace(/~/g, "%7E");
  output = output.replace(/\*/g, "%2A");
  output = output.replace(/'/g, "%27");
  output = output.replace(/\(/g, "%28");
  output = output.replace(/\)/g, "%29");
  output = output.replace(/-/g, "%2D");
  output = output.toLowerCase();
  output = output.replace(/(%..)/g, function(esc) {
    esc = esc.substr(1);
    return "(" + esc + ")";
  });
  return output;
}
