'use strict';

const axios = require("axios");
const get = require("lodash").get;
const forEach = require("lodash").forEach;

function axiosDB(name, options) {
  this.instance = axios.create({
    baseURL: name || get(options, "name"),
    headers: get(options, "ajax.headers"),
    auth: get(options, "auth")
  });
}

axiosDB.prototype.get = function(key) {
  return new Promise((resolve, reject) => {
    this.instance.get(key).then(res => {
      resolve(res.data);
    }).catch(err => {
      reject(err);
    });
  })
}

axiosDB.prototype.put = function(doc) {
  return new Promise((resolve, reject) => {
    this.instance.put(doc._id, doc).then(res => {
      resolve(res.data);
    }).catch(err => {
      reject(err);
    });
  })
}

axiosDB.prototype.allDocs = function(options) {
  options = options || {};
  if ("keys" in options) {
    let keys = options.keys;
    delete options.keys;
    return new Promise((resolve, reject) => {
      this.instance.post("/_all_docs", {
        keys: keys
      }, {
        params: options
      }).then(res => {
        resolve(res.data);
      }).catch(err => {
        reject(err);
      });
    })
  }
  return new Promise((resolve, reject) => {
    this.instance.get("/_all_docs", {
      params: options
    }).then(res => {
      resolve(res.data);
    }).catch(err => {
      reject(err);
    });
  })
}

axiosDB.prototype.bulkDocs = function(docs) {
  if ("docs" in docs) {
    docs = docs.docs;
  }
  return new Promise((resolve, reject) => {
    this.instance.post("/_bulk_docs", {
      docs: docs
    }).then(res => {
      resolve(res.data);
    }).catch(err => {
      reject(err);
    });
  })
}

axiosDB.prototype.destroy = function(database) {
  return new Promise((resolve, reject) => {
    this.instance.delete("").then(res => {
      resolve(res.data);
    }).catch(err => {
      reject(err);
    });
  })
}

axiosDB.prototype.query = function(view, options) {
  return new Promise((resolve, reject) => {
    let splitted = view.split("/");
    if (options.key) options.key = JSON.stringify(options.key);
    this.instance.get("/_design/" + splitted[0] + "/_view/" + splitted[1], {
      params: options
    }).then(res => {
      resolve(res.data);
    }).catch(err => {
      reject(err);
    });
  });
}

axiosDB.prototype.request = function(options) {
  if (options.body) {
    options.data = options.body;
    delete options.body;
  }
  return this.instance(options);
}

axiosDB.prototype.put = function(doc) {
  return new Promise((resolve, reject) => {
    this.instance.put(doc._id, doc).then(res => {
      resolve(res.data);
    }).catch(err => {
      reject(err);
    });
  })
}

module.exports = axiosDB;