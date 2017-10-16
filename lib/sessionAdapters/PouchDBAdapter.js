var PouchDB = require("pouchdb");

function PouchDBAdapter(config) {
  var sessionDatabase;

  if(config.getItem('session.pouchdb.name')) {
    let name = config.getItem('session.pouchdb.name');
    let options = config.getItem('session.pouchdb.options');
    sessionDatabase = new PouchDB(name, options);
  }
  else {
    throw new Error("When using PouchDB session, you have to specify at least a database name");
  }
  this._db = sessionDatabase;
}

module.exports = PouchDBAdapter;

PouchDBAdapter.prototype.storeKey = function(key, life, data) {
  console.log("store", key, life, data);
  return new Promise((resolve, reject) => {
    var now = Date.now();
    this._db.put({
      _id: key,
      data: JSON.parse(data),
      expire: now + life
    }).then(res => {
      resolve();
    }).catch(err => {
      reject(err);
    })
  });
};

PouchDBAdapter.prototype.deleteKeys = function(keys) {
  console.log("delete", keys);
  return new Promise((resolve, reject) => {
    if(!(keys instanceof Array)) {
      keys = [keys];
    }
    this._db.allDocs({keys: keys, include_docs: true}).then(res => {
      let deleteDocs = res.rows;
      deleteDocs.forEach(doc => doc._deleted = true);
      this._db.bulkDocs(deleteDocs).then(res => {
        resolve(res.length);
      }).catch(err => {
        reject(err);
      });
    }).catch(err => {
      reject(err);
    })
  });
};

PouchDBAdapter.prototype.getKey = function(key) {
  console.log("get", key);
  return new Promise((resolve, reject) => {
    var now = Date.now();
    this._db.get(key).then(res => {
      if (res.expire > now) {
        resolve(JSON.stringify(res.data));
        return;
      }
      resolve(false);
    }).catch(err => {
      reject(err);
    })
  });
};

PouchDBAdapter.prototype.quit = function() {
  console.log("quit");
};
