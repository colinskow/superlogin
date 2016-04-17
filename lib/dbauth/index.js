'use strict';
var BPromise = require('bluebird');
var PouchDB = require('pouchdb');
var util = require('./../util');
var seed = require('pouchdb-seed-design');
var request = require('superagent');

module.exports = function (config, userDB, couchAuthDB) {

  var cloudant = config.getItem('dbServer.cloudant');

  var adapter;

  if(cloudant) {
    adapter = require('./cloudant');
  } else {
    var CouchAdapter = require('./couchdb');
    adapter = new CouchAdapter(couchAuthDB);
  }

  this.storeKey = function (username, key, password, expires, roles) {
    return adapter.storeKey(username, key, password, expires, roles);
  };

  this.removeKeys = function(keys) {
    return adapter.removeKeys(keys);
  };

  this.authorizeKeys = function (user_id, db, keys, permissions, roles) {
    return adapter.authorizeKeys(user_id, db, keys, permissions, roles);
  };

  this.deauthorizeKeys = function (db, keys) {
    return adapter.deauthorizeKeys(db, keys);
  };

  this.authorizeUserSessions = function(user_id, personalDBs, sessionKeys, roles) {
    var self = this;
    var promises = [];
    sessionKeys = util.toArray(sessionKeys);
    Object.keys(personalDBs).forEach(function(personalDB) {
      var permissions = personalDBs[personalDB].permissions;
      if(!permissions) {
        permissions = config.getItem('userDBs.model.' + personalDBs[personalDB].name + '.permissions') || config.getItem('userDBs.model._default.permissions') || [];
      }
      var db = new PouchDB(util.getDBURL(config.getItem('dbServer')) + '/' + personalDB);
      promises.push(self.authorizeKeys(user_id, db, sessionKeys, permissions, roles));
    });
    return BPromise.all(promises);
  };

  this.addUserDB = function (userDoc, dbName, designDocs, type, permissions, adminRoles, memberRoles) {
    var self = this;
    var promises = [];
    adminRoles = adminRoles || [];
    memberRoles = memberRoles || [];
    // Create and the database and seed it if a designDoc is specified
    var prefix = config.getItem('userDBs.privatePrefix') ? config.getItem('userDBs.privatePrefix') + '_' : '';
    var finalDBName, newDB;
    // Make sure we have a legal database name
    var username = userDoc._id;
    username = getLegalDBName(username);
    if(type === 'shared') {
      finalDBName = dbName;
    } else {
      finalDBName = prefix + dbName + '$' + username;
    }
    return self.createDB(finalDBName)
      .then(function() {
        newDB = new PouchDB(util.getDBURL(config.getItem('dbServer')) + '/' + finalDBName);
        return adapter.initSecurity(newDB, adminRoles, memberRoles);
      })
      .then(function() {
        // Seed the design docs
        if (designDocs && designDocs instanceof Array) {
          designDocs.forEach(function(ddName) {
            var dDoc = self.getDesignDoc(ddName);
            if(dDoc) {
              promises.push(seed(newDB, dDoc));
            } else {
              console.warn('Failed to locate design doc: ' + ddName);
            }
          });
        }
        // Authorize the user's existing DB keys to access the new database
        var keysToAuthorize = [];
        if (userDoc.session) {
          for (var key in userDoc.session) {
            if(userDoc.session.hasOwnProperty(key) && userDoc.session[key].expires > Date.now()) {
              keysToAuthorize.push(key);
            }
          }
        }
        if (keysToAuthorize.length > 0) {
          promises.push(self.authorizeKeys(userDoc._id, newDB, keysToAuthorize, permissions, userDoc.roles));
        }
        return BPromise.all(promises);
      })
      .then(function() {
        return BPromise.resolve(finalDBName);
      });
  };

  this.removeExpiredKeys = function () {
    var self = this;
    var keysByUser = {};
    var userDocs = {};
    var expiredKeys = [];
    // query a list of expired keys by user
    return userDB.query('auth/expiredKeys', {endkey: Date.now(), include_docs: true})
      .then(function(results) {
        // group by user
        results.rows.forEach(function(row) {
          keysByUser[row.value.user] = row.value.key;
          expiredKeys.push(row.value.key);
          // Add the user doc if it doesn't already exist
          if(typeof userDocs[row.value.user] === 'undefined') {
            userDocs[row.value.user] = row.doc;
          }
          // remove each key from user.session
          if(userDocs[row.value.user].session) {
            Object.keys(userDocs[row.value.user].session).forEach(function(session) {
              if(row.value.key === session) {
                delete userDocs[row.value.user].session[session];
              }
            });
          }
        });
        return self.removeKeys(expiredKeys);
      })
      .then(function() {
        // - deauthorize keys for each personal database of each user
        var deauthorize = [];
        Object.keys(keysByUser).forEach(function(user) {
          deauthorize.push(self.deauthorizeUser(userDocs[user], keysByUser[user]));
        });
        return BPromise.all(deauthorize);
      })
      .then(function() {
        var userUpdates = [];
        Object.keys(userDocs).forEach(function(user) {
          userUpdates.push(userDocs[user]);
        });
        // Bulk save user doc updates
        return userDB.bulkDocs(userUpdates);
      })
      .then(function() {
        return BPromise.resolve(expiredKeys);
      });
  };

  this.deauthorizeUser = function(userDoc, keys) {
    var self = this;
    var promises = [];
    // If keys is not specified we will deauthorize all of the users sessions
    if(!keys) {
      keys = util.getSessions(userDoc);
    }
    keys = util.toArray(keys);
    if(userDoc.personalDBs && typeof userDoc.personalDBs === 'object') {
      Object.keys(userDoc.personalDBs).forEach(function(personalDB) {
        var db = new PouchDB(util.getDBURL(config.getItem('dbServer')) + '/' + personalDB);
        promises.push(self.deauthorizeKeys(db, keys));
      });
      return BPromise.all(promises);
    } else {
      return BPromise.resolve(false);
    }
  };

  this.getDesignDoc = function(docName) {
    if(!docName) {
      return null;
    }
    var designDoc;
    var designDocDir = config.getItem('userDBs.designDocDir');
    if(!designDocDir) {
      designDocDir = __dirname;
    }
    try {
      designDoc = require(designDocDir + '/' + docName);
    }
    catch(err) {
      console.warn('Design doc: ' + designDocDir + '/' + docName + ' not found.');
      designDoc = null;
    }
    return designDoc;
  };

  this.getDBConfig = function(dbName, type) {
    var dbConfig = {
      name: dbName
    };
    dbConfig.adminRoles = config.getItem('userDBs.defaultSecurityRoles.admins') || [];
    dbConfig.memberRoles = config.getItem('userDBs.defaultSecurityRoles.members') || [];
    var dbConfigRef = 'userDBs.model.' + dbName;
    if(config.getItem(dbConfigRef)) {
      dbConfig.permissions = config.getItem(dbConfigRef + '.permissions') || [];
      dbConfig.designDocs = config.getItem(dbConfigRef + '.designDocs') || [];
      dbConfig.type = type || config.getItem(dbConfigRef + '.type') || 'private';
      var dbAdminRoles = config.getItem(dbConfigRef + '.adminRoles');
      var dbMemberRoles = config.getItem(dbConfigRef + '.memberRoles');
      if(dbAdminRoles && dbAdminRoles instanceof Array) {
        dbAdminRoles.forEach(function(role) {
          if(role && dbConfig.adminRoles.indexOf(role) === -1) {
            dbConfig.adminRoles.push(role);
          }
        });
      }
      if(dbMemberRoles && dbMemberRoles instanceof Array) {
        dbMemberRoles.forEach(function(role) {
          if(role && dbConfig.memberRoles.indexOf(role) === -1) {
            dbConfig.memberRoles.push(role);
          }
        });
      }
    } else if(config.getItem('userDBs.model._default')) {
      dbConfig.permissions = config.getItem('userDBs.model._default.permissions') || [];
      // Only add the default design doc to a private database
      if(!type || type === 'private') {
        dbConfig.designDocs = config.getItem('userDBs.model._default.designDocs') || [];
      } else {
        dbConfig.designDocs = [];
      }
      dbConfig.type = type || 'private';
    } else {
      dbConfig.type = type || 'private';
    }
    return dbConfig;
  };

  this.createDB = function (dbName) {
    var finalUrl = util.getDBURL(config.getItem('dbServer')) + '/' + dbName;
    return BPromise.fromNode(function(callback) {
      request.put(finalUrl)
        .send({})
        .end(callback);
    })
      .then(function(res) {
        return BPromise.resolve(JSON.parse(res.text));
      }, function(err) {
        if(err.status === 412) {
          return BPromise.resolve(false);
        } else {
          return BPromise.reject(err.text);
        }
      });
  };

  this.removeDB = function(dbName) {
    var db = new PouchDB(util.getDBURL(config.getItem('dbServer')) + '/' + dbName);
    return db.destroy();
  };


  return this;
};

// Escapes any characters that are illegal in a CouchDB database name using percent codes inside parenthesis
// Example: 'My.name@example.com' => 'my(2e)name(40)example(2e)com'
function getLegalDBName(input) {
  input = input.toLowerCase();
  var output = encodeURIComponent(input);
  output = output.replace(/\./g, '%2E');
  output = output.replace(/!/g, '%21');
  output = output.replace(/~/g, '%7E');
  output = output.replace(/\*/g, '%2A');
  output = output.replace(/'/g, '%27');
  output = output.replace(/\(/g, '%28');
  output = output.replace(/\)/g, '%29');
  output = output.replace(/\-/g, '%2D');
  output = output.toLowerCase();
  output = output.replace(/(%..)/g, function(esc) {
    esc = esc.substr(1);
    return '(' + esc + ')';
  });
  return output;
}
