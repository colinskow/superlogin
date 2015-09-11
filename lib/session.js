'use strict';
var BPromise = require('bluebird');
var redis = BPromise.promisifyAll(require('redis'));
var util = require('./util');
var extend = require('util')._extend;

var tokenPrefix = 'token';

module.exports = function(config) {

  var adapter;

  if(config.getItem('session.adapter') === 'redis') {
    adapter = new RedisAdapter(config);
  } else {
    adapter = new MemoryAdapter();
  }

  this.storeToken = function(token) {
    token = extend({}, token);
    if(!token.password && token.salt && token.derived_key) {
      return adapter.storeKey(tokenPrefix + ':' + token.key, (token.expires - Date.now()), JSON.stringify(token))
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
        return adapter.storeKey(tokenPrefix + ':' + token.key, (token.expires - Date.now()), JSON.stringify(token));
      })
      .then(function() {
        delete token.salt;
        delete token.derived_key;
        return BPromise.resolve(token);
      });
  };

  this.deleteTokens = function(keys) {
    var entries = [];
    if(!(keys instanceof Array)) {
      keys = [keys];
    }
    keys.forEach(function(key) {
      entries.push(tokenPrefix + ':' + key);
    });
    return adapter.deleteKeys(entries);
  };

  this.confirmToken = function(key, password) {
    var token;
    return adapter.getKey(tokenPrefix + ':' + key)
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

  this.fetchToken = function(key) {
    return adapter.getKey(tokenPrefix + ':' + key)
      .then(function(result) {
        return BPromise.resolve(JSON.parse(result));
      });
  };

  this.quit = function() {
    return adapter.quit();
  };

  return this;

};

var RedisAdapter = function(config) {

  var redisClient;

  if(!config.getItem('session.redis.unix_socket')) {
    if(config.getItem('session.redis.url')) {
      redisClient = redis.createClient(config.getItem('session.redis.url'), config.getItem('session.redis.options'));
    } else {
      redisClient = redis.createClient(config.getItem('session.redis.port') || 6379,
        config.getItem('session.redis.host') || '127.0.0.1', config.getItem('session.redis.options'));
    }
  } else {
    redisClient = redis.createClient(config.getItem('session.redis.unix_socket'), config.getItem('session.redis.options'));
  }

  // Authenticate with Redis if necessary
  if(config.getItem('session.redis.password')) {
    redisClient.authAsync(config.getItem('session.redis.password'))
      .catch(function(err) {
        throw new Error(err);
      });
  }

  redisClient.on('error', function (err) {
    console.error('Redis error: ' + err);
  });

  redisClient.on('connect', function () {
    console.log('Redis is ready');
  });

  this.storeKey = function(key, life, data) {
    return redisClient.psetexAsync(key, life, data);
  };

  this.deleteKeys = function(keys) {
    return redisClient.delAsync(keys);
  };

  this.getKey = function(key) {
    return redisClient.getAsync(key);
  };

  this.quit = function() {
    return redisClient.quit();
  };

  return this;

};

var MemoryAdapter = function() {

  var keys = {};
  var expires = {};
  console.log('Memory Adapter loaded');

  this.storeKey = function(key, life, data) {
    var now = Date.now();
    keys[key] = data;
    expires[key] = now + life;
    removeExpired();
    return BPromise.resolve();
  };

  this.getKey = function(key) {
    var now = Date.now();
    if(keys[key] && expires[key] > now) {
      return BPromise.resolve(keys[key]);
    } else {
      return BPromise.resolve(false);
    }
  };

  this.deleteKeys = function(keys) {
    if(!(keys instanceof Array)) {
      keys = [keys];
    }
    keys.forEach(function(key) {
      delete keys[key];
      delete expires[key];
    });
    removeExpired();
    return BPromise.resolve(keys.length);
  };

  this.quit = function() {
    return BPromise.resolve();
  };

  function removeExpired() {
    var now = Date.now();
    Object.keys(expires).forEach(function(key) {
      if(expires[key] < now) {
        delete keys[key];
        delete expires[key];
      }
    });
  }

  return this;

};