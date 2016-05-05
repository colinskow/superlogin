'use strict';
var util = require('./util');
var extend = require('util')._extend;
var BPromise = require('bluebird');
var RedisAdapter = require('./sessionAdapters/RedisAdapter');
var MemoryAdapter = require('./sessionAdapters/MemoryAdapter');
var FileAdapter = require('./sessionAdapters/FileAdapter');

var tokenPrefix = 'token';

function Session(config) {
  var adapter;
  var sessionAdapter = config.getItem('session.adapter');
  if(sessionAdapter === 'redis') {
    adapter = new RedisAdapter(config);
  } else if (sessionAdapter === 'file') {
    adapter = new FileAdapter(config);
  } else {
    adapter = new MemoryAdapter();
  }
  this._adapter = adapter;
}

module.exports = Session;

Session.prototype.storeToken = function(token) {
  var self = this;
  token = extend({}, token);
  if(!token.password && token.salt && token.derived_key) {
    return this._adapter.storeKey(tokenPrefix + ':' + token.key, (token.expires - Date.now()), JSON.stringify(token))
      .then(function() {
        delete token.salt;
        delete token.derived_key;
        return BPromise.resolve(token);
      });
  }
  return util.hashPassword(token.password)
    .then(function(hash) {
      token.salt = hash.salt;
      token.derived_key = hash.derived_key;
      delete token.password;
      return self._adapter.storeKey(tokenPrefix + ':' + token.key, (token.expires - Date.now()), JSON.stringify(token));
    })
    .then(function() {
      delete token.salt;
      delete token.derived_key;
      return BPromise.resolve(token);
    });
};

Session.prototype.deleteTokens = function(keys) {
  var entries = [];
  if(!(keys instanceof Array)) {
    keys = [keys];
  }
  keys.forEach(function(key) {
    entries.push(tokenPrefix + ':' + key);
  });
  return this._adapter.deleteKeys(entries);
};

Session.prototype.confirmToken = function(key, password) {
  var token;
  return this._adapter.getKey(tokenPrefix + ':' + key)
    .then(function(result) {
      if(!result) {
        return BPromise.reject('invalid token');
      }
      token = JSON.parse(result);
      return util.verifyPassword(token, password);
    })
    .then(function() {
      delete token.salt;
      delete token.derived_key;
      return BPromise.resolve(token);
    }, function() {
      return BPromise.reject('invalid token');
    });
};

Session.prototype.fetchToken = function(key) {
  return this._adapter.getKey(tokenPrefix + ':' + key)
    .then(function(result) {
      return BPromise.resolve(JSON.parse(result));
    });
};

Session.prototype.quit = function() {
  return this._adapter.quit();
};
