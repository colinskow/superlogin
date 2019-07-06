'use strict';
var url = require('url');
var request = require('superagent');
var util = require('./../util');

// This is not needed with Cloudant
exports.storeKey = function() {
  return Promise.resolve();
};

// This is not needed with Cloudant
exports.removeKeys = function() {
  return Promise.resolve();
};

// This is not needed with Cloudant
exports.initSecurity = function() {
  return Promise.resolve();
};

exports.authorizeKeys = function(user_id, db, keys, permissions, roles) {
  var keysObj = {};
  if(!permissions) {
    permissions = ['_reader', '_replicator'];
  }
  permissions = permissions.concat(roles || []);
  permissions.unshift('user:' + user_id);
  // If keys is a single value convert it to an Array
  keys = util.toArray(keys);
  // Check if keys is an array and convert it to an object
  if(keys instanceof Array) {
    keys.forEach(function(key) {
      keysObj[key] = permissions;
    });
  } else {
    keysObj = keys;
  }
  // Pull the current _security doc
  return getSecurityCloudant(db)
    .then(function(secDoc) {
      if(!secDoc._id) {
        secDoc._id = '_security';
      }
      if(!secDoc.cloudant) {
        secDoc.cloudant = {};
      }
      Object.keys(keysObj).forEach(function(key) {
        secDoc.cloudant[key] = keysObj[key];
      });
      return putSecurityCloudant(db, secDoc);
    });
};

exports.deauthorizeKeys = function(db, keys) {
  // cast keys to an Array
  keys = util.toArray(keys);
  return getSecurityCloudant(db)
    .then(function(secDoc) {
      var changes = false;
      if(!secDoc.cloudant) {
        return Promise.resolve(false);
      }
      keys.forEach(function(key) {
        if(secDoc.cloudant[key]) {
          changes = true;
          delete secDoc.cloudant[key];
        }
      });
      if(changes) {
        return putSecurityCloudant(db, secDoc);
      } else {
        return Promise.resolve(false);
      }
    });
};

exports.getAPIKey = function(db) {
  var parsedUrl = url.parse(db.getUrl());
  parsedUrl.pathname = '/_api/v2/api_keys';
  var finalUrl = url.format(parsedUrl);
  return request.post(finalUrl)
    .set(db.getHeaders())
    .then(function(res) {
      var result = JSON.parse(res.text);
      if(result.key && result.password && result.ok === true) {
        return Promise.resolve(result);
      } else {
        return Promise.reject(result);
      }
    });
};

var getSecurityCloudant = exports.getSecurityCloudant = function (db) {
  var finalUrl = getSecurityUrl(db);
  return request.get(finalUrl)
    .set(db.getHeaders())
    .then(function(res) {
      return Promise.resolve(JSON.parse(res.text));
    });
};

var putSecurityCloudant = exports.putSecurityCloudant = function (db, doc) {
  var finalUrl = getSecurityUrl(db);
  return request.put(finalUrl)
    .set(db.getHeaders())
    .send(doc)
    .then(function(res) {
      return Promise.resolve(JSON.parse(res.text));
    });
};

function getSecurityUrl(db) {
  var parsedUrl = url.parse(db.getUrl());
  parsedUrl.pathname = parsedUrl.pathname + '_security';
  return url.format(parsedUrl);
}