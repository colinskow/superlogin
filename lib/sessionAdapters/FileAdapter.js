var fs = require('fs-extra');
var path = require('path');
function FileAdapter(config) {
  var sessionsRoot = config.getItem('session.file.sessionsRoot');
  this._sessionFolder = path.join(process.env.PWD, sessionsRoot);
  console.log('File Adapter loaded');
}

module.exports = FileAdapter;

FileAdapter.prototype._getFilepath = function(key) {
  return path.format({
    dir: this._sessionFolder,
    base: key + '.json'
  });
};

FileAdapter.prototype.storeKey = function(key, life, data) {
  var now = Date.now();
  return fs.outputJson(this._getFilepath(key), {
      data: data,
      expire: now + life
    });
};

FileAdapter.prototype.getKey = function(key) {
  var now = Date.now();
  return fs.readJson(this._getFilepath(key))
    .then(function (session) {
      if (session.expire > now) {
        return session.data;
      }
      return false;
    })
    .catch(function () {
      return false;
    });
};

FileAdapter.prototype.deleteKeys = function(keys) {
  if(!(keys instanceof Array)) {
    keys = [keys];
  }
  var self = this;
  var deleteQueue = keys.map(function(key) {
    return fs.remove(self._getFilepath(key));
  });

  return Promise.all(deleteQueue).then(function (done) {
    // this._removeExpired();
    return done.length;
  });
};

FileAdapter.prototype.quit = function() {
  return Promise.resolve();
};

FileAdapter.prototype._removeExpired = function () {
  // open all files and check session expire date
};
