'use strict';
var url = require('url');
var urlParse = require('url-parse');
var BPromise = require('bluebird');
var request = require('superagent');
var util = require('./../util');

// This is not needed with Cloudant
exports.storeKey = function () {
  return BPromise.resolve();
};

// This is not needed with Cloudant
exports.removeKeys = function () {
  return BPromise.resolve();
};

// This is not needed with Cloudant
exports.initSecurity = function () {
  return BPromise.resolve();
};

exports.authorizeKeys = function (user_id, db, keys, permissions, roles) {
  var keysObj = {};
  if (!permissions) {
    permissions = ['_reader', '_replicator'];
  }
  permissions = permissions.concat(roles || []);
  permissions.unshift('user:' + user_id);
  // If keys is a single value convert it to an Array
  keys = util.toArray(keys);
  // Check if keys is an array and convert it to an object
  if (keys instanceof Array) {
    keys.forEach(function (key) {
      keysObj[key] = permissions;
    });
  } else {
    keysObj = keys;
  }
  // Pull the current _security doc
  return getSecurityCloudant(db)
    .then(function (secDoc) {
      if (!secDoc._id) {
        secDoc._id = '_security';
      }
      if (!secDoc.cloudant) {
        secDoc.cloudant = {};
      }
      Object.keys(keysObj).forEach(function (key) {
        secDoc.cloudant[key] = keysObj[key];
      });
      return putSecurityCloudant(db, secDoc);
    });
};

exports.deauthorizeKeys = function (db, keys) {
  // cast keys to an Array
  keys = util.toArray(keys);
  return getSecurityCloudant(db)
    .then(function (secDoc) {
      var changes = false;
      if (!secDoc.cloudant) {
        return BPromise.resolve(false);
      }
      keys.forEach(function (key) {
        if (secDoc.cloudant[key]) {
          changes = true;
          delete secDoc.cloudant[key];
        }
      });
      if (changes) {
        return putSecurityCloudant(db, secDoc);
      } else {
        return BPromise.resolve(false);
      }
    });
};

exports.getAPIKey = function (db) {
  var parsedUrl = url.parse(getBaseUrl(db));
  parsedUrl.pathname = '/_api/v2/api_keys';
  var finalUrl = url.format(parsedUrl);
  return BPromise.fromNode(function (callback) {
      request.post(finalUrl)
        .set(db.getHeaders())
        .end(callback);
    })
    .then(function (res) {
      var result = JSON.parse(res.text);
      if (result.key && result.password && result.ok === true) {
        return BPromise.resolve(result);
      } else {
        return BPromise.reject(result);
      }
    }, function (err) {
      console.log("Error getAPIKey(" + finalUrl + "): " + JSON.stringify(err));
    });
};

var getSecurityCloudant = exports.getSecurityCloudant = function (db) {
  var finalUrl = getSecurityUrl(db);
  return BPromise.fromNode(function (callback) {
      request.get(finalUrl)
        .set(db.getHeaders())
        .end(callback);
    })
    .then(function (res) {
      return BPromise.resolve(JSON.parse(res.text));
    }, function (err) {
      console.log("Error getSecurityCloudant(" + finalUrl + "): " + JSON.stringify(err));
    });
};

var putSecurityCloudant = exports.putSecurityCloudant = function (db, doc) {
  var finalUrl = getSecurityUrl(db);
  return BPromise.fromNode(function (callback) {
      request.put(finalUrl)
        .set(db.getHeaders())
        .send(doc)
        .end(callback);
    })
    .then(function (res) {
      return BPromise.resolve(JSON.parse(res.text));
    }, function (err) {
      console.log("Error putSecurityCloudant(" + finalUrl + "): " + JSON.stringify(err));
    });
};

function getSecurityUrl(db) {
  var parsedUrl = url.parse(getBaseUrl(db));
  parsedUrl.pathname = parsedUrl.pathname + '_security';
  return url.format(parsedUrl);
}

function getBaseUrl(db) {
  if (typeof db.getUrl === 'function') { // pouchdb pre-6.0.0
    // console.log("db.getUrl() = " + JSON.stringify(db.getUrl()));
    return db.getUrl();
  } else if (db.__opts && db.__opts.prefix) { // PouchDB.defaults
    // console.log("db.__opts.prefix = " + JSON.stringify(db.__opts.prefix));
    return db.__opts.prefix;
  } else { // pouchdb post-6.0.0
    // console.log("urlParse(db.name(" + db.name + ")).origin = " + JSON.stringify(urlParse(db.name).origin));
    return urlParse(db.name).origin;
  }
}