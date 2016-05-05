var BPromise = require('bluebird');

function MemoryAdapter() {
  this._keys = {};
  this._expires = {};
  console.log('Memory Adapter loaded');
}

module.exports = MemoryAdapter;

MemoryAdapter.prototype.storeKey = function(key, life, data) {
  var now = Date.now();
  this._keys[key] = data;
  this._expires[key] = now + life;
  this._removeExpired();
  return BPromise.resolve();
};

MemoryAdapter.prototype.getKey = function(key) {
  var now = Date.now();
  if(this._keys[key] && this._expires[key] > now) {
    return BPromise.resolve(this._keys[key]);
  } else {
    return BPromise.resolve(false);
  }
};

MemoryAdapter.prototype.deleteKeys = function(keys) {
  if(!(keys instanceof Array)) {
    keys = [keys];
  }
  var self = this;
  keys.forEach(function(key) {
    delete self._keys[key];
    delete self._expires[key];
  });
  this._removeExpired();
  return BPromise.resolve(keys.length);
};

MemoryAdapter.prototype.quit = function() {
  return BPromise.resolve();
};

MemoryAdapter.prototype._removeExpired = function () {
  var now = Date.now();
  var self = this;
  Object.keys(this._expires).forEach(function(key) {
    if(self._expires[key] < now) {
      delete self._keys[key];
      delete self._expires[key];
    }
  });
};
