const db = require("./index");
var Configure = require("../lib/configure");
var config = new Configure(require("../config"), require("../default.config"));

module.exports.slUserDB = new db(
  config.getItem("dbServer.protocol")
  + config.getItem("dbServer.host") + "/"
  + config.getItem("dbServer.userDB"),
  {
    auth: {
      username: config.getItem("dbServer.user"),
      password: config.getItem("dbServer.password")
    }
  }
);

module.exports.couchUserDB = new db(
  config.getItem("dbServer.protocol")
  + config.getItem("dbServer.host") + "/_users",
  {
    auth: {
      username: config.getItem("dbServer.user"),
      password: config.getItem("dbServer.password")
    }
  }
);