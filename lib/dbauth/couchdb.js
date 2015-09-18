'use strict';
var BPromise = require('bluebird');
var util = require('../util');

module.exports = function(couchAuthDB) {

  this.storeKey = function (username, key, password, expires, roles) {
    if(roles instanceof Array) {
      // Clone roles to not overwrite original
      roles = roles.slice(0);
    } else {
      roles = [];
    }
    roles.unshift('user:' + username);
    var newKey = {
      _id: 'org.couchdb.user:' + key,
      type: 'user',
      name: key,
      user_id: username,
      password: password,
      expires: expires,
      roles: roles
    };
    return couchAuthDB.put(newKey)
      .then(function () {
        newKey._id = key;
        return BPromise.resolve(newKey);
      });
  };

  this.removeKeys = function(keys) {
    keys = util.toArray(keys);
    var keylist = [];
    // Transform the list to contain the CouchDB _user ids
    keys.forEach(function(key) {
      keylist.push('org.couchdb.user:' + key);
    });
    var toDelete = [];
    return couchAuthDB.allDocs({keys: keylist})
      .then(function(keyDocs) {
        keyDocs.rows.forEach(function(row) {
          if(!row.error && !row.value.deleted) {
            var deletion = {
              _id: row.id,
              _rev: row.value.rev,
              _deleted: true
            };
            toDelete.push(deletion);
          }
        });
        if(toDelete.length) {
          return couchAuthDB.bulkDocs(toDelete);
        } else {
          return BPromise.resolve(false);
        }
      });
  };

  this.initSecurity = function(db, adminRoles, memberRoles) {
    var changes = false;
    return db.get('_security')
      .then(function (secDoc) {
        if (!secDoc.admins) {
          secDoc.admins = {names: [], roles: []};
        }
        if (!secDoc.admins.roles) {
          secDoc.admins.roles = [];
        }
        if (!secDoc.members) {
          secDoc.members = {names: [], roles: []};
        }
        if (!secDoc.members.roles) {
          secDoc.admins.roles = [];
        }
        adminRoles.forEach(function(role) {
          if(secDoc.admins.roles.indexOf(role) === -1) {
            changes = true;
            secDoc.admins.roles.push(role);
          }
        });
        memberRoles.forEach(function(role) {
          if(secDoc.members.roles.indexOf(role) === -1) {
            changes = true;
            secDoc.members.roles.push(role);
          }
        });
        if(changes) {
          return putSecurityCouch(db, secDoc);
        } else {
          return BPromise.resolve(false);
        }
      });
  };

  this.authorizeKeys = function (user_id, db, keys) {
    var secDoc;
    // Check if keys is an object and convert it to an array
    if(typeof keys === 'object' && !(keys instanceof Array)) {
      var keysArr = [];
      Object.keys(keys).forEach(function(theKey) {
        keysArr.push(theKey);
      });
      keys = keysArr;
    }
    // Convert keys to an array if it is just a string
    keys = util.toArray(keys);
    return db.get('_security')
      .then(function (doc) {
        secDoc = doc;
        if (!secDoc.members) {
          secDoc.members = {names: [], roles: []};
        }
        if (!secDoc.members.names) {
          secDoc.members.names = [];
        }
        var changes = false;
        keys.forEach(function (key) {
          var index = secDoc.members.names.indexOf(key);
          if (index === -1) {
            secDoc.members.names.push(key);
            changes = true;
          }
        });
        if (changes) {
          return putSecurityCouch(db, secDoc);
        } else {
          return BPromise.resolve(false);
        }
      });
  };

  this.deauthorizeKeys = function (db, keys) {
    var secDoc;
    keys = util.toArray(keys);
    return db.get('_security')
      .then(function (doc) {
        secDoc = doc;
        if (!secDoc.members || !secDoc.members.names) {
          return BPromise.resolve(false);
        }
        var changes = false;
        keys.forEach(function (key) {
          var index = secDoc.members.names.indexOf(key);
          if (index > -1) {
            secDoc.members.names.splice(index, 1);
            changes = true;
          }
        });
        if (changes) {
          return putSecurityCouch(db, secDoc);
        } else {
          return BPromise.resolve(false);
        }
      });
  };

  function putSecurityCouch(db, doc) {
    return db.request({
      method: 'PUT',
      url: '_security',
      body: doc
    });
  }

  return this;

};

