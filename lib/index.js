(function webpackUniversalModuleDefinition(root, factory) {
	if(typeof exports === 'object' && typeof module === 'object')
		module.exports = factory();
	else if(typeof define === 'function' && define.amd)
		define([], factory);
	else if(typeof exports === 'object')
		exports["SuperLogin"] = factory();
	else
		root["SuperLogin"] = factory();
})(typeof self !== 'undefined' ? self : this, function() {
return /******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, {
/******/ 				configurable: false,
/******/ 				enumerable: true,
/******/ 				get: getter
/******/ 			});
/******/ 		}
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = 10);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var Promise = __webpack_require__(1);
var URLSafeBase64 = __webpack_require__(14);
var uuid = __webpack_require__(15);
var pwd = __webpack_require__(16);
var crypto = __webpack_require__(4);
const jwt = __webpack_require__(2);

exports.URLSafeUUID = function () {
  return URLSafeBase64.encode(uuid.v4(null, new Buffer(16)));
};

exports.hashToken = function (token) {
  return crypto.createHash("sha256").update(token).digest("hex");
};

exports.hashPassword = function (password) {
  return new Promise(function (resolve, reject) {
    pwd.hash(password, function (err, salt, hash) {
      if (err) {
        return reject(err);
      }
      return resolve({
        salt: salt,
        derived_key: hash
      });
    });
  });
};

exports.verifyPassword = function (hashObj, password) {
  var getHash = Promise.promisify(pwd.hash, { context: pwd });
  var iterations = hashObj.iterations;
  var salt = hashObj.salt;
  var derived_key = hashObj.derived_key;
  if (iterations) {
    pwd.iterations(iterations);
  }
  if (!salt || !derived_key) {
    return Promise.reject(false);
  }
  return getHash(password, salt).then(function (hash) {
    if (hash === derived_key) {
      return Promise.resolve(true);
    } else {
      return Promise.reject(false);
    }
  });
};

exports.getDBURL = function (db) {
  var url;
  if (db.user) {
    url = db.protocol + encodeURIComponent(db.user) + ":" + encodeURIComponent(db.password) + "@" + db.host;
  } else {
    url = db.protocol + db.host;
  }
  return url;
};

exports.getFullDBURL = function (dbConfig, dbName) {
  return exports.getDBURL(dbConfig) + "/" + dbName;
};

exports.toArray = function (obj) {
  if (!(obj instanceof Array)) {
    obj = [obj];
  }
  return obj;
};

// Takes a req object and returns the bearer token, or undefined if it is not found
exports.getSessionToken = function (req) {
  if (req.headers && req.headers.authorization) {
    var parts = req.headers.authorization.split(" ");
    if (parts.length == 2) {
      var scheme = parts[0];
      var credentials = parts[1];
      if (/^Bearer$/i.test(scheme)) {
        return credentials;
      }
    }
  }
};

// Generates views for each registered provider in the user design doc
exports.addProvidersToDesignDoc = function (config, ddoc) {
  var providers = config.getItem("providers");
  if (!providers) {
    return ddoc;
  }
  var ddocTemplate = "function(doc) {\n" + "  if(doc.%PROVIDER% && doc.%PROVIDER%.profile) {\n" + "    emit(doc.%PROVIDER%.profile.id, null);\n" + "  }\n" + "}";
  Object.keys(providers).forEach(function (provider) {
    ddoc.auth.views[provider] = ddocTemplate.replace(new RegExp("%PROVIDER%", "g"), provider);
  });
  return ddoc;
};

// Capitalizes the first letter of a string
exports.capitalizeFirstLetter = function (string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
};

/**
 * Access nested JavaScript objects with string key
 * http://stackoverflow.com/questions/6491463/accessing-nested-javascript-objects-with-string-key
 *
 * @param {object} obj The base object you want to get a reference to
 * @param {string} str The string addressing the part of the object you want
 * @return {object|undefined} a reference to the requested key or undefined if not found
 */

exports.getObjectRef = function (obj, str) {
  str = str.replace(/\[(\w+)\]/g, ".$1"); // convert indexes to properties
  str = str.replace(/^\./, ""); // strip a leading dot
  var pList = str.split(".");
  while (pList.length) {
    var n = pList.shift();
    if (n in obj) {
      obj = obj[n];
    } else {
      return;
    }
  }
  return obj;
};

/**
 * Dynamically set property of nested object
 * http://stackoverflow.com/questions/18936915/dynamically-set-property-of-nested-object
 *
 * @param {object} obj The base object you want to set the property in
 * @param {string} str The string addressing the part of the object you want
 * @param {*} val The value you want to set the property to
 * @return {*} the value the reference was set to
 */

exports.setObjectRef = function (obj, str, val) {
  str = str.replace(/\[(\w+)\]/g, ".$1"); // convert indexes to properties
  str = str.replace(/^\./, ""); // strip a leading dot
  var pList = str.split(".");
  var len = pList.length;
  for (var i = 0; i < len - 1; i++) {
    var elem = pList[i];
    if (!obj[elem]) {
      obj[elem] = {};
    }
    obj = obj[elem];
  }
  obj[pList[len - 1]] = val;
  return val;
};

/**
 * Dynamically delete property of nested object
 *
 * @param {object} obj The base object you want to set the property in
 * @param {string} str The string addressing the part of the object you want
 * @return {boolean} true if successful
 */

exports.delObjectRef = function (obj, str) {
  str = str.replace(/\[(\w+)\]/g, ".$1"); // convert indexes to properties
  str = str.replace(/^\./, ""); // strip a leading dot
  var pList = str.split(".");
  var len = pList.length;
  for (var i = 0; i < len - 1; i++) {
    var elem = pList[i];
    if (!obj[elem]) {
      return false;
    }
    obj = obj[elem];
  }
  delete obj[pList[len - 1]];
  return true;
};

/**
 * Concatenates two arrays and removes duplicate elements
 *
 * @param {array} a First array
 * @param {array} b Second array
 * @return {array} resulting array
 */

exports.arrayUnion = function (a, b) {
  var result = a.concat(b);
  for (var i = 0; i < result.length; ++i) {
    for (var j = i + 1; j < result.length; ++j) {
      if (result[i] === result[j]) {
        result.splice(j--, 1);
      }
    }
  }
  return result;
};

/***/ }),
/* 1 */
/***/ (function(module, exports) {

module.exports = require("bluebird");

/***/ }),
/* 2 */
/***/ (function(module, exports) {

module.exports = require("jsonwebtoken");

/***/ }),
/* 3 */
/***/ (function(module, exports) {

module.exports = require("axiosdb");

/***/ }),
/* 4 */
/***/ (function(module, exports) {

module.exports = require("crypto");

/***/ }),
/* 5 */
/***/ (function(module, exports) {

module.exports = require("nodemailer");

/***/ }),
/* 6 */
/***/ (function(module, exports) {

module.exports = require("pouchdb-seed-design");

/***/ }),
/* 7 */
/***/ (function(module, exports) {

module.exports = require("fs");

/***/ }),
/* 8 */
/***/ (function(module, exports) {

module.exports = require("path");

/***/ }),
/* 9 */
/***/ (function(module, exports) {

module.exports = require("ejs");

/***/ }),
/* 10 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});

var _events = __webpack_require__(11);

var _events2 = _interopRequireDefault(_events);

var _express = __webpack_require__(12);

var _express2 = _interopRequireDefault(_express);

var _axiosdb = __webpack_require__(3);

var _axiosdb2 = _interopRequireDefault(_axiosdb);

var _configure = __webpack_require__(13);

var _configure2 = _interopRequireDefault(_configure);

var _user = __webpack_require__(17);

var _user2 = _interopRequireDefault(_user);

var _oauth = __webpack_require__(29);

var _oauth2 = _interopRequireDefault(_oauth);

var _routes = __webpack_require__(31);

var _routes2 = _interopRequireDefault(_routes);

var _local = __webpack_require__(32);

var _local2 = _interopRequireDefault(_local);

var _mailer = __webpack_require__(35);

var _mailer2 = _interopRequireDefault(_mailer);

var _util = __webpack_require__(0);

var _util2 = _interopRequireDefault(_util);

var _pouchdbSeedDesign = __webpack_require__(6);

var _pouchdbSeedDesign2 = _interopRequireDefault(_pouchdbSeedDesign);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

class SuperLogin {
  constructor(configData, passport, userDB, couchAuthDB) {
    var config = new _configure2.default(configData, __webpack_require__(37));
    var router = _express2.default.Router();
    var emitter = new _events2.default.EventEmitter();

    if (!passport || typeof passport !== "object") {
      passport = __webpack_require__(38);
    }
    // var middleware = new Middleware(passport);

    // Some extra default settings if no config object is specified
    if (!configData) {
      config.setItem("testMode.noEmail", true);
      config.setItem("testMode.debugEmail", true);
    }

    // Create the DBs if they weren't passed in
    if (!userDB && config.getItem("dbServer.userDB")) {
      userDB = new _axiosdb2.default(_util2.default.getFullDBURL(config.getItem("dbServer"), config.getItem("dbServer.userDB")));
    }
    if (!couchAuthDB && config.getItem("dbServer.couchAuthDB")) {
      couchAuthDB = new _axiosdb2.default(_util2.default.getFullDBURL(config.getItem("dbServer"), config.getItem("dbServer.couchAuthDB")));
    }
    if (!userDB || typeof userDB !== "object") {
      throw new Error("userDB must be passed in as the third argument or specified in the config file under dbServer.userDB");
    }

    var mailer = new _mailer2.default(config);
    var user = new _user2.default(config, userDB, couchAuthDB, mailer, emitter);
    var oauth = new _oauth2.default(router, passport, user, config);

    // Seed design docs for the user database
    var userDesign = __webpack_require__(39);
    userDesign = _util2.default.addProvidersToDesignDoc(config, userDesign);
    (0, _pouchdbSeedDesign2.default)(userDB, userDesign);
    // Configure Passport local login and api keys
    (0, _local2.default)(config, passport, user);
    // Load the routes
    (0, _routes2.default)(config, router, passport, user);

    Object.assign(this, {
      config: config,
      router: router,
      mailer: mailer,
      passport: passport,
      userDB: userDB,
      couchAuthDB: couchAuthDB,
      registerProvider: oauth.registerProvider,
      registerOAuth2: oauth.registerOAuth2,
      registerTokenProvider: oauth.registerTokenProvider,
      validateUsername: user.validateUsername,
      validateEmail: user.validateEmail,
      validateEmailUsername: user.validateEmailUsername,
      getUser: user.get,
      createUser: user.create,
      createUserManual: user.createManual,
      onCreate: user.onCreate,
      onLink: user.onLink,
      socialAuth: user.socialAuth,
      hashPassword: _util2.default.hashPassword,
      verifyPassword: _util2.default.verifyPassword,
      createSession: user.createSession,
      changePassword: user.changePassword,
      changeEmail: user.changeEmail,
      resetPassword: user.resetPassword,
      forgotPassword: user.forgotPassword,
      verifyEmail: user.verifyEmail,
      addUserDB: user.addUserDB,
      removeUserDB: user.removeUserDB,
      logoutUser: user.logoutUser,
      logoutSession: user.logoutSession,
      logoutOthers: user.logoutOthers,
      removeUser: user.remove,
      confirmSession: user.confirmSession,
      removeExpiredKeys: user.removeExpiredKeys,
      sendEmail: mailer.sendEmail,
      quitRedis: user.quitRedis
      // authentication middleware
      // requireAuth: middleware.requireAuth,
      // requireRole: middleware.requireRole,
      // requireAnyRole: middleware.requireAnyRole,
      // requireAllRoles: middleware.requireAllRoles
    });
  }
}exports.default = SuperLogin;
// import Middleware from "./middleware";

;

/***/ }),
/* 11 */
/***/ (function(module, exports) {

module.exports = require("events");

/***/ }),
/* 12 */
/***/ (function(module, exports) {

module.exports = require("express");

/***/ }),
/* 13 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});

exports.default = function (data, defaults) {
  this.config = data || {};
  this.defaults = defaults || {};

  this.getItem = function (key) {
    var result = _util2.default.getObjectRef(this.config, key);
    if (typeof result === "undefined" || result === null) {
      result = _util2.default.getObjectRef(this.defaults, key);
    }
    return result;
  };

  this.setItem = function (key, value) {
    return _util2.default.setObjectRef(this.config, key, value);
  };

  this.removeItem = function (key) {
    return _util2.default.delObjectRef(this.config, key);
  };
};

var _util = __webpack_require__(0);

var _util2 = _interopRequireDefault(_util);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

;

/***/ }),
/* 14 */
/***/ (function(module, exports) {

module.exports = require("urlsafe-base64");

/***/ }),
/* 15 */
/***/ (function(module, exports) {

module.exports = require("uuid");

/***/ }),
/* 16 */
/***/ (function(module, exports) {

module.exports = require("couch-pwd");

/***/ }),
/* 17 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});

exports.default = function (config, userDB, couchAuthDB, mailer, emitter) {
  var self = this;
  var dbAuth = new _dbauth2.default(config, userDB, couchAuthDB);
  var onCreateActions = [];
  var onLinkActions = [];

  // Token valid for 24 hours by default
  // Forget password token life
  var tokenLife = config.getItem("security.tokenLife");
  tokenLife = typeof tokenLife === "string" ? (0, _ms2.default)(tokenLife) : tokenLife || (0, _ms2.default)("1h");
  // Session token life
  var sessionLife = config.getItem("security.sessionLife");
  sessionLife = typeof sessionLife === "string" ? (0, _ms2.default)(sessionLife) : sessionLife || (0, _ms2.default)("15m");

  var emailUsername = config.getItem("local.emailUsername");

  this.validateUsername = (() => {
    var _ref = _asyncToGenerator(function* (username) {
      if (!username) {
        return;
      }
      if (!username.match(USER_REGEXP)) {
        return "Invalid username";
      }
      const result = yield userDB.query("auth/username", { key: username });
      if (result.rows.length === 0) {
        // Pass!
        return;
      } else {
        return "already in use";
      }
    });

    return function (_x) {
      return _ref.apply(this, arguments);
    };
  })();

  this.validateEmail = (() => {
    var _ref2 = _asyncToGenerator(function* (email) {
      if (!email) {
        return;
      }
      if (!email.match(EMAIL_REGEXP)) {
        return;
      }
      const result = yield userDB.query("auth/email", { key: email });
      if (result.rows.length === 0) {
        // Pass!
        return;
      } else {
        return "already in use";
      }
    });

    return function (_x2) {
      return _ref2.apply(this, arguments);
    };
  })();

  this.validateEmailUsername = (() => {
    var _ref3 = _asyncToGenerator(function* (email) {
      if (!email) {
        return;
      }
      if (!email.match(EMAIL_REGEXP)) {
        return "invalid email";
      }
      const result = yield userDB.query("auth/emailUsername", { key: email });
      if (result.rows.length === 0) {
        return;
      } else {
        return "already in use";
      }
    });

    return function (_x3) {
      return _ref3.apply(this, arguments);
    };
  })();

  // Validation function for ensuring that two fields match
  this.matches = function (value, option, key, attributes) {
    if (attributes && attributes[option] !== value) {
      return "does not match " + option;
    }
  };

  var passwordConstraints = {
    presence: true,
    length: {
      minimum: 6,
      message: "must be at least 6 characters"
    },
    matches: "confirmPassword"
  };

  passwordConstraints = _lodash2.default.merge({}, passwordConstraints, config.getItem("local.passwordConstraints"));

  var userModel = {
    async: true,
    whitelist: ["name", "username", "email", "password", "confirmPassword"],
    customValidators: {
      validateEmail: self.validateEmail,
      validateUsername: self.validateUsername,
      validateEmailUsername: self.validateEmailUsername,
      matches: self.matches
    },
    sanitize: {
      name: ["trim"],
      username: ["trim", "toLowerCase"],
      email: ["trim", "toLowerCase"]
    },
    validate: {
      email: {
        presence: true,
        validateEmail: true
      },
      username: {
        presence: true,
        validateUsername: true
      },
      password: passwordConstraints,
      confirmPassword: {
        presence: true
      }
    },
    static: {
      type: "user",
      roles: config.getItem("security.defaultRoles"),
      providers: ["local"]
    },
    rename: {
      username: "_id"
    }
  };

  if (emailUsername) {
    delete userModel.validate.username;
    delete userModel.validate.email.validateEmail;
    delete userModel.rename.username;
    userModel.validate.email.validateEmailUsername = true;
  }

  var resetPasswordModel = {
    async: true,
    customValidators: {
      matches: self.matches
    },
    validate: {
      token: {
        presence: true
      },
      password: passwordConstraints,
      confirmPassword: {
        presence: true
      }
    }
  };

  var changePasswordModel = {
    async: true,
    customValidators: {
      matches: self.matches
    },
    validate: {
      newPassword: passwordConstraints,
      confirmPassword: {
        presence: true
      }
    }
  };

  this.onCreate = function (fn) {
    if (typeof fn === "function") {
      onCreateActions.push(fn);
    } else {
      throw new TypeError("onCreate: You must pass in a function");
    }
  };

  this.onLink = function (fn) {
    if (typeof fn === "function") {
      onLinkActions.push(fn);
    } else {
      throw new TypeError("onLink: You must pass in a function");
    }
  };

  function processTransformations(fnArray, userDoc, provider) {
    var promise;
    fnArray.forEach(function (fn) {
      if (!promise) {
        promise = fn.call(null, userDoc, provider);
      } else {
        if (!promise.then || typeof promise.then !== "function") {
          throw new Error("onCreate function must return a promise");
        }
        promise.then(function (newUserDoc) {
          return fn.call(null, newUserDoc, provider);
        });
      }
    });
    if (!promise) {
      promise = _bluebird2.default.resolve(userDoc);
    }
    return promise;
  }

  this.get = (() => {
    var _ref4 = _asyncToGenerator(function* (login) {
      var query;
      if (emailUsername) {
        query = "emailUsername";
      } else {
        query = EMAIL_REGEXP.test(login) ? "email" : "username";
      }
      const results = yield userDB.query("auth/" + query, {
        key: login,
        include_docs: true
      });
      if (results.rows.length > 0) {
        return results.rows[0].doc;
      } else {
        return null;
      }
    });

    return function (_x4) {
      return _ref4.apply(this, arguments);
    };
  })();

  this.create = (() => {
    var _ref5 = _asyncToGenerator(function* (form, req) {
      req = req || {};
      var finalUserModel = userModel;
      var newUserModel = config.getItem("userModel");
      if (typeof newUserModel === "object") {
        var whitelist;
        if (newUserModel.whitelist) {
          whitelist = _util2.default.arrayUnion(userModel.whitelist, newUserModel.whitelist);
        }
        finalUserModel = _lodash2.default.merge({}, userModel, config.getItem("userModel"));
        finalUserModel.whitelist = whitelist || finalUserModel.whitelist;
      }
      var UserModel = new _sofaModel2.default(finalUserModel);
      var user = new UserModel(form);
      try {
        const newUser = yield user.process();
      } catch (err) {
        return new Error({
          error: "Validation failed",
          validationErrors: err,
          status: 400
        });
      }
      if (emailUsername) {
        newUser._id = newUser.email;
      }
      if (config.getItem("local.sendConfirmEmail")) {
        newUser.unverifiedEmail = {
          email: newUser.email,
          token: _util2.default.URLSafeUUID()
        };
        delete newUser.email;
      }
      const hash = yield _util2.default.hashPassword(newUser.password);
      // Store password hash
      newUser.local = {};
      newUser.local.salt = hash.salt;
      newUser.local.derived_key = hash.derived_key;
      delete newUser.password;
      delete newUser.confirmPassword;
      newUser.signUp = {
        provider: "local",
        timestamp: new Date().toISOString(),
        ip: req.ip
      };
      const newUser = yield addUserDBs(newUser);
      yield self.logActivity(newUser._id, "signup", "local", req, newUser);
      yield processTransformations(onCreateActions, newUser, "local");
      const result = yield userDB.put(newUser);
      newUser._rev = result.rev;
      if (config.getItem("local.sendConfirmEmail")) {
        yield mailer.sendEmail("confirmEmail", newUser.unverifiedEmail.email, { req: req, user: newUser });
      }
      emitter.emit("signup", newUser, "local");
    });

    return function (_x5, _x6) {
      return _ref5.apply(this, arguments);
    };
  })();

  this.createManual = (() => {
    var _ref6 = _asyncToGenerator(function* (options, mergeDoc) {
      // options: {
      //    username: "customUser",
      //    password: "mySafePassword"
      //    roles: [],
      //    createPersonalDBs: bool
      // }
      var req = {};
      // declare id, generate random one if none is specified
      var user_id;
      // same applies to password
      var password;
      let manualModel = {
        type: "user",
        roles: options.roles || [],
        providers: ["local"],
        local: {},
        signUp: {
          provider: "local",
          timestamp: new Date().toJSON(),
          ip: null
        },
        email: null
      };
      Object.assign({}, manualModel, mergeDoc || {});
      // start Promise-chain
      if (!options.username) {
        // generate a valid username
        var user_id = _util2.default.URLSafeUUID();
        // Make sure our token doesn't start with illegal characters
        while (token[0] === "_" || token[0] === "-") {
          user_id = _util2.default.URLSafeUUID();
        }
        // we just generated a valid username
        // no need to check later
      } else {
        // use to specified username
        user_id = options.username;
        yield self.validateUsername(user_id);
      }
      // if no password is specified, generate one
      if (!password) password = _util2.default.URLSafeUUID();
      if (!user_id) {
        reject("Username must not be empty.");
      }
      manualModel._id = user_id;
      // username is valid, generate password hash
      const hash = yield _util2.default.hashPassword(password);
      manualModel.local.salt = hash.salt;
      manualModel.local.derived_key = hash.derived_key;
      // we only want to create personal dbs when explicitly specified
      if (options.createPersonalDBs) {
        yield addUserDBs(manualModel);
      }
      yield self.logActivity(manualModel._id, "signup", "local", req, manualModel);
      yield processTransformations(onCreateActions, manualModel, "local");
      yield userDB.put(manualModel);
      if (!options.password) {
        manualModel.password = password;
      }
      emitter.emit("signup", manualModel, "local");
      return manualModel;
    });

    return function (_x7, _x8) {
      return _ref6.apply(this, arguments);
    };
  })();

  this.socialAuth = (() => {
    var _ref7 = _asyncToGenerator(function* (provider, auth, profile, req) {
      var user;
      var newAccount = false;
      var action;
      var baseUsername;
      req = req || {};
      var ip = req.ip;
      // It is important that we return a Bluebird promise so oauth.js can call .nodeify()
      const results = yield userDB.query("auth/" + provider, { key: profile.id, include_docs: true });
      if (results.rows.length > 0) {
        user = results.rows[0].doc;
      } else {
        newAccount = true;
        user = {};
        user[provider] = {};
        if (profile.emails) {
          user.email = profile.emails[0].value;
        }
        user.providers = [provider];
        user.type = "user";
        user.roles = config.getItem("security.defaultRoles");
        user.signUp = {
          provider: provider,
          timestamp: new Date().toISOString(),
          ip: ip
        };
        var emailFail = function () {
          throw new Error({
            error: "Email already in use",
            message: "Your email is already in use. Try signing in first and then linking this account.",
            status: 409
          });
        };
        // Now we need to generate a username
        if (emailUsername) {
          if (!user.email) {
            throw new Error({
              error: "No email provided",
              message: "An email is required for registration, but " + provider + " didn't supply one.",
              status: 400
            });
          }
          const err = yield self.validateEmailUsername(user.email);
          if (err) {
            return emailFail();
          }
          user._id = user.email.toLowerCase();
        } else {
          if (profile.username) {
            baseUsername = profile.username.toLowerCase();
          } else {
            // If a username isn't specified we'll take it from the email
            if (user.email) {
              var parseEmail = user.email.split("@");
              baseUsername = parseEmail[0].toLowerCase();
            } else if (profile.displayName) {
              baseUsername = profile.displayName.replace(/\s/g, "").toLowerCase();
            } else {
              baseUsername = profile.id.toLowerCase();
            }
          }
          const err = yield self.validateEmail(user.email);
          if (err) {
            return emailFail();
          }
          user._id = generateUsername(baseUsername);
        }
      }
      user[provider].auth = auth;
      user[provider].profile = profile;
      if (!user.name) {
        user.name = profile.displayName;
      }
      delete user[provider].profile._raw;
      if (newAccount) {
        yield addUserDBs(user);
      }
      yield self.logActivity(user._id, newAccount ? "signup" : "login", provider, req, user);
      if (newAccount) {
        yield processTransformations(onCreateActions, user, provider);
      } else {
        yield processTransformations(onLinkActions, user, provider);
      }
      yield userDB.put(user);
      if (action === "signup") {
        emitter.emit("signup", user, provider);
      }
      return user;
    });

    return function (_x9, _x10, _x11, _x12) {
      return _ref7.apply(this, arguments);
    };
  })();

  this.linkSocial = (() => {
    var _ref8 = _asyncToGenerator(function* (user_id, provider, auth, profile, req) {
      req = req || {};
      // Load user doc
      const results = yield userDB.query("auth/" + provider, { key: profile.id });
      if (results.rows.length > 0) {
        if (results.rows[0].id !== user_id) {
          throw new Error({
            error: "Conflict",
            message: "This " + provider + " profile is already in use by another account.",
            status: 409
          });
        }
      }
      const user = yield userDB.get(user_id);
      // Check for conflicting provider
      if (user[provider] && user[provider].profile.id !== profile.id) {
        throw new Error({
          error: "Conflict",
          message: "Your account is already linked with another " + provider + "profile.",
          status: 409
        });
      }
      // Check email for conflict
      let emailRes;
      if (!profile.emails) {
        emailRes = { rows: [] };
      }
      if (emailUsername) {
        emailRes = yield userDB.query("auth/emailUsername", { key: profile.emails[0].value });
      } else {
        emailRes = yield userDB.query("auth/email", { key: profile.emails[0].value });
      }
      var passed;
      if (emailRes.rows.length === 0) {
        passed = true;
      } else {
        passed = true;
        emailRes.rows.forEach(function (row) {
          if (row.id !== user_id) {
            passed = false;
          }
        });
      }
      if (!passed) {
        throw new Error({
          error: "Conflict",
          message: "The email " + profile.emails[0].value + " is already in use by another account.",
          status: 409
        });
      }
      // Insert provider info
      user[provider] = {};
      user[provider].auth = auth;
      user[provider].profile = profile;
      if (!user.providers) {
        user.providers = [];
      }
      if (user.providers.indexOf(provider) === -1) {
        user.providers.push(provider);
      }
      if (!user.name) {
        user.name = profile.displayName;
      }
      delete user[provider].profile._raw;
      yield self.logActivity(user._id, "link", provider, req, user);
      yield processTransformations(onLinkActions, userDoc, provider);
      yield userDB.put(user);
      return user;
    });

    return function (_x13, _x14, _x15, _x16, _x17) {
      return _ref8.apply(this, arguments);
    };
  })();

  this.unlink = (() => {
    var _ref9 = _asyncToGenerator(function* (user_id, provider) {
      const user = yield userDB.get(user_id);
      if (!provider) {
        throw new Error({
          error: "Unlink failed",
          message: "You must specify a provider to unlink.",
          status: 400
        });
      }
      // We can only unlink if there are at least two providers
      if (!user.providers || !(user.providers instanceof Array) || user.providers.length < 2) {
        throw new Error({
          error: "Unlink failed",
          message: "You can't unlink your only provider!",
          status: 400
        });
      }
      // We cannot unlink local
      if (provider === "local") {
        throw new Error({
          error: "Unlink failed",
          message: "You can't unlink local.",
          status: 400
        });
      }
      // Check that the provider exists
      if (!user[provider] || typeof user[provider] !== "object") {
        throw new Error({
          error: "Unlink failed",
          message: "Provider: " + _util2.default.capitalizeFirstLetter(provider) + " not found.",
          status: 404
        });
      }
      delete user[provider];
      // Remove the unlinked provider from the list of providers
      user.providers.splice(user.providers.indexOf(provider), 1);
      yield userDB.put(user);
      return user;
    });

    return function (_x18, _x19) {
      return _ref9.apply(this, arguments);
    };
  })();

  this.createSession = (() => {
    var _ref10 = _asyncToGenerator(function* (provider, req, refreshToken) {
      // console.log("createSession", Date.now());
      const permanent = req.body.permanent;
      const user = req.user;
      const origUser = JSON.parse(JSON.stringify(req.user || {}));
      const newSession = {};
      let password;
      let jwtoken;
      let payload;
      req = req || {};
      const ip = req.ip;
      const newToken = yield generateSession(user._id, user.roles);
      // console.log("generated session", Date.now());
      password = newToken.password;
      newToken.provider = provider;
      yield dbAuth.storeKey(user._id, newToken.key, password, newToken.expires, user.roles);
      // console.log("stored new temp user", Date.now());
      // Clear any failed login attempts
      if (provider === "local") {
        if (!user.local) user.local = {};
        user.local.failedLoginAttempts = 0;
        delete user.local.lockedUntil;
      }
      yield self.logActivity(user._id, "login", provider, req, user);
      // console.log("logged out sessions", Date.now());
      if (JSON.stringify(user) != JSON.stringify(origUser)) {
        yield userDB.put(user);
      }
      // console.log("putted final user", Date.now());
      jwtoken = yield self.generateJWT(user, newToken.key, password, newToken.expires);
      if (refreshToken) {
        const rt = yield self.generateRefreshJWT(user, permanent);
        newSession.refreshToken = rt.token;
        if (rt.payload.exp) {
          newSession.refreshTokenExpires = rt.payload.exp * 1000;
        }
      }
      newSession.token = jwtoken.token;
      newSession.expires = jwtoken.payload.exp * 1000;
      newSession.issued = jwtoken.payload.iat * 1000;
      newSession.ip = req.ip;
      newSession.dbUser = newToken.key;
      newSession.dbPass = password;
      newSession.dbExpires = newToken.expires;
      newSession.user_id = user._id;
      newSession.roles = user.roles;
      // Inject the list of userDBs
      if (typeof user.personalDBs === "object") {
        var userDBs = {};
        var publicURL;
        if (config.getItem("dbServer.publicURL")) {
          var dbObj = _url2.default.parse(config.getItem("dbServer.publicURL"));
          publicURL = dbObj.format();
        } else {
          publicURL = config.getItem("dbServer.protocol") + config.getItem("dbServer.host") + "/";
        }
        Object.keys(user.personalDBs).forEach(function (finalDBName) {
          userDBs[user.personalDBs[finalDBName].name] = publicURL + finalDBName;
        });
        newSession.userDBs = userDBs;
      }
      if (user.profile) {
        newSession.profile = user.profile;
      }
      emitter.emit("login", newSession, provider);
      return newSession;
    });

    return function (_x20, _x21, _x22) {
      return _ref10.apply(this, arguments);
    };
  })();

  this.handleFailedLogin = (() => {
    var _ref11 = _asyncToGenerator(function* (user, req) {
      req = req || {};
      var maxFailedLogins = config.getItem("security.maxFailedLogins");
      if (!maxFailedLogins) {
        return _bluebird2.default.resolve();
      }
      if (!user.local) {
        user.local = {};
      }
      if (!user.local.failedLoginAttempts) {
        user.local.failedLoginAttempts = 0;
      }
      user.local.failedLoginAttempts++;
      if (user.local.failedLoginAttempts > maxFailedLogins) {
        user.local.failedLoginAttempts = 0;
        let lockoutTime = config.getItem("security.lockoutTime");
        lockoutTime = typeof lockoutTime === "string" ? (0, _ms2.default)(lockoutTime) : lockoutTime;
        user.local.lockedUntil = Date.now() + lockoutTime * 1000;
      }
      yield self.logActivity(user._id, "failed login", "local", req, user);
      yield userDB.put(finalUser);
      return !!user.local.lockedUntil;
    });

    return function (_x23, _x24) {
      return _ref11.apply(this, arguments);
    };
  })();

  this.logActivity = (() => {
    var _ref12 = _asyncToGenerator(function* (user_id, action, provider, req, userDoc, saveDoc) {
      var logSize = config.getItem("security.userActivityLogSize");
      if (!logSize) {
        return userDoc;
      }
      let user;
      if (!userDoc) {
        if (saveDoc !== false) {
          saveDoc = true;
        }
        userDoc = yield userDB.get(user_id);
      }
      userDoc = theUser;
      if (!userDoc.activity || !(userDoc.activity instanceof Array)) {
        userDoc.activity = [];
      }
      var entry = {
        timestamp: new Date().toISOString(),
        action: action,
        provider: provider,
        ip: req.ip
      };
      userDoc.activity.unshift(entry);
      while (userDoc.activity.length > logSize) {
        userDoc.activity.pop();
      }
      if (saveDoc) {
        yield userDB.put(userDoc);
      }
      return userDoc;
    });

    return function (_x25, _x26, _x27, _x28, _x29, _x30) {
      return _ref12.apply(this, arguments);
    };
  })();

  this.generateJWT = (() => {
    var _ref13 = _asyncToGenerator(function* (user, tempUser, tempPass, tempExpires) {
      let tokenid = (0, _v2.default)();
      let payload = {
        jti: tokenid,
        sub: user._id,
        iss: config.getItem("security.jwt.issuer"),
        iat: Math.floor(Date.now() / 1000),
        dbUser: tempUser,
        dbPass: tempPass,
        dbExpires: tempExpires,
        roles: user.roles,
        token_use: "access"
      };
      let jwtExpires = config.getItem("security.jwt.expires");
      jwtExpires = typeof jwtExpires === "string" ? Math.floor((0, _ms2.default)(jwtExpires) / 1000) : jwtExpires || Math.floor((0, _ms2.default)("15m") / 1000);
      payload["exp"] = Math.floor(Date.now() / 1000) + jwtExpires;
      const token = yield _bluebird2.default.promisify(_jsonwebtoken2.default.sign)(payload, config.getItem("security.jwt.secret"));
      return {
        token: token,
        payload: payload
      };
    });

    return function (_x31, _x32, _x33, _x34) {
      return _ref13.apply(this, arguments);
    };
  })();

  this.generateRefreshJWT = (() => {
    var _ref14 = _asyncToGenerator(function* (user, permanent) {
      let tokenid = (0, _v2.default)();
      let payload = {
        jti: tokenid,
        sub: user._id,
        iss: config.getItem("security.jwt.issuer"),
        iat: Math.floor(Date.now() / 1000),
        token_use: "refresh"
      };
      if (!permanent) {
        let jwtExpires = config.getItem("security.jwt.refreshExpires");
        jwtExpires = typeof jwtExpires === "string" ? Math.floor((0, _ms2.default)(jwtExpires) / 1000) : jwtExpires || Math.floor((0, _ms2.default)("30d") / 1000);
        payload["exp"] = Math.floor(Date.now() / 1000) + jwtExpires;
      }
      const token = yield _bluebird2.default.promisify(_jsonwebtoken2.default.sign)(payload, config.getItem("security.jwt.secret"));
      return {
        token: token,
        payload: payload
      };
    });

    return function (_x35, _x36) {
      return _ref14.apply(this, arguments);
    };
  })();

  this.refreshSession = (() => {
    var _ref15 = _asyncToGenerator(function* (req) {
      var user = req.user;
      var newSession = {};
      var newExpires;
      var provider = null;
      if (user.payload.token_use === "access" && user.payload.dbExpires < Date.now()) {
        const tempUser = yield couchAuthDB.get("org.couchdb.user:" + user.payload.dbUser);
        newExpires = Date.now() + sessionLife;
        tempUser.expires = newExpires;
        tempUser.roles = user.roles;
        yield couchAuthDB.put(tempUser);
        const jwt_ = yield self.generateJWT(user, user.payload.dbUser, user.payload.dbPass, newExpires);
        newSession.token = jwt_.token;
        newSession.expires = jwt_.payload.exp * 1000;
        newSession.issued = jwt_.payload.iat * 1000;
        newSession.ip = req.ip;
        newSession.dbUser = jwt_.payload.dbUser;
        newSession.dbPass = jwt_.payload.dbPass;
        newSession.dbExpires = jwt_.payload.dbExpires;
        newSession.user_id = user._id;
        newSession.roles = user.roles;
        // Inject the list of userDBs
        if (typeof user.personalDBs === "object") {
          var userDBs = {};
          var publicURL;
          if (config.getItem("dbServer.publicURL")) {
            var dbObj = _url2.default.parse(config.getItem("dbServer.publicURL"));
            dbObj.auth = newSession.token + ":" + newSession.password;
            publicURL = dbObj.format();
          } else {
            publicURL = config.getItem("dbServer.protocol") + newSession.token + ":" + newSession.password + "@" + config.getItem("dbServer.host") + "/";
          }
          Object.keys(user.personalDBs).forEach(function (finalDBName) {
            userDBs[user.personalDBs[finalDBName].name] = publicURL + finalDBName;
          });
          newSession.userDBs = userDBs;
        }
        if (user.profile) {
          newSession.profile = user.profile;
        }
        emitter.emit("refresh", newSession, provider);
        return newSession;
      } else if (user.payload.token_use === "refresh") {
        return this.createSession(null, req);
      } else {
        return this.createSession(null, req, true);
      }
    });

    return function (_x37) {
      return _ref15.apply(this, arguments);
    };
  })();

  this.resetPassword = (() => {
    var _ref16 = _asyncToGenerator(function* (form, req) {
      req = req || {};
      var ResetPasswordModel = new _sofaModel2.default(resetPasswordModel);
      var passwordResetForm = new ResetPasswordModel(form);
      var user;
      try {
        yield passwordResetForm.validate();
      } catch (err) {
        throw new Error({
          error: "Validation failed",
          validationErrors: err,
          status: 400
        });
      }
      var tokenHash = _util2.default.hashToken(form.token);
      const results = yield userDB.query("auth/passwordReset", { key: tokenHash, include_docs: true });
      if (!results.rows.length) {
        return _bluebird2.default.reject({ status: 400, error: "Invalid token" });
      }
      user = results.rows[0].doc;
      if (user.forgotPassword.expires < Date.now()) {
        return _bluebird2.default.reject({ status: 400, error: "Token expired" });
      }
      const hash = yield _util2.default.hashPassword(form.password);
      if (!user.local) {
        user.local = {};
      }
      user.local.salt = hash.salt;
      user.local.derived_key = hash.derived_key;
      if (user.providers.indexOf("local") === -1) {
        user.providers.push("local");
      }
      // logout user completely
      yield self.logoutUserSessions(user, "all");
      delete user.forgotPassword;
      yield self.logActivity(user._id, "reset password", "local", req, user);
      yield userDB.put(finalUser);
      emitter.emit("password-reset", user);
      return user;
    });

    return function (_x38, _x39) {
      return _ref16.apply(this, arguments);
    };
  })();

  this.changePasswordSecure = (() => {
    var _ref17 = _asyncToGenerator(function* (user_id, form, req) {
      req = req || {};
      var self = this;
      var ChangePasswordModel = new _sofaModel2.default(changePasswordModel);
      var changePasswordForm = new ChangePasswordModel(form);
      try {
        changePasswordForm.validate();
      } catch (err) {
        throw new Error({
          error: "Validation failed",
          validationErrors: err,
          status: 400
        });
      }
      const user = yield userDB.get(user_id);
      if (user.local && user.local.salt && user.local.derived_key) {
        // Password is required
        if (!form.currentPassword) {
          throw new Error({
            error: "Password change failed",
            message: "You must supply your current password in order to change it.",
            status: 400
          });
        }
        try {
          yield _util2.default.verifyPassword(user.local, form.currentPassword);
        } catch (err) {
          throw new Error(err || {
            error: "Password change failed",
            message: "The current password you supplied is incorrect.", status: 400
          });
        }
      }
      yield self.changePassword(user._id, form.newPassword, user, req);
      if (req.user && req.user.key) {
        yield self.logoutOthers(req.user.key);
      }
    });

    return function (_x40, _x41, _x42) {
      return _ref17.apply(this, arguments);
    };
  })();

  this.changePassword = (() => {
    var _ref18 = _asyncToGenerator(function* (user_id, newPassword, userDoc, req) {
      req = req || {};
      if (!userDoc) {
        userDoc = yield userDB.get(user_id);
      }
      const hash = yield _util2.default.hashPassword(newPassword);
      if (!user.local) {
        user.local = {};
      }
      user.local.salt = hash.salt;
      user.local.derived_key = hash.derived_key;
      if (user.providers.indexOf("local") === -1) {
        user.providers.push("local");
      }
      yield self.logActivity(user._id, "changed password", "local", req, user);
      yield userDB.put(user);
      emitter.emit("password-change", user);
    });

    return function (_x43, _x44, _x45, _x46) {
      return _ref18.apply(this, arguments);
    };
  })();

  this.forgotPassword = (() => {
    var _ref19 = _asyncToGenerator(function* (email, req) {
      req = req || {};
      let user;
      let token;
      let tokenHash;
      const result = yield userDB.query("auth/email", { key: email, include_docs: true });
      if (!result.rows.length) {
        throw new Error({
          error: "User not found",
          status: 404
        });
      }
      user = result.rows[0].doc;
      token = _util2.default.URLSafeUUID();
      tokenHash = _util2.default.hashToken(token);
      user.forgotPassword = {
        token: tokenHash, // Store secure hashed token
        issued: Date.now(),
        expires: Date.now() + tokenLife
      };
      yield self.logActivity(user._id, "forgot password", "local", req, user);
      yield userDB.put(user);
      yield mailer.sendEmail("forgotPassword", user.email || user.unverifiedEmail.email, {
        user: user,
        req: req,
        token: token
      }); // Send user the unhashed token
      emitter.emit("forgot-password", user);
      return user.forgotPassword;
    });

    return function (_x47, _x48) {
      return _ref19.apply(this, arguments);
    };
  })();

  this.verifyEmail = (() => {
    var _ref20 = _asyncToGenerator(function* (token, req) {
      req = req || {};
      var user;
      const result = userDB.query("auth/verifyEmail", { key: token, include_docs: true });
      if (!result.rows.length) {
        return _bluebird2.default.reject({ error: "Invalid token", status: 400 });
      }
      user = result.rows[0].doc;
      user.email = user.unverifiedEmail.email;
      delete user.unverifiedEmail;
      emitter.emit("email-verified", user);
      yield self.logActivity(user._id, "verified email", "local", req, user);
      yield userDB.put(finalUser);
    });

    return function (_x49, _x50) {
      return _ref20.apply(this, arguments);
    };
  })();

  this.changeEmail = (() => {
    var _ref21 = _asyncToGenerator(function* (user_id, newEmail, req) {
      req = req || {};
      if (!req.user) {
        req.user = { provider: "local" };
      }
      const err = yield self.validateEmail(newEmail);
      if (err) {
        throw new Error(err);
      }
      const user = yield userDB.get(user_id);
      if (config.getItem("local.sendConfirmEmail")) {
        user.unverifiedEmail = {
          email: newEmail,
          token: _util2.default.URLSafeUUID()
        };
        yield mailer.sendEmail("confirmEmail", user.unverifiedEmail.email, { req: req, user: user });
      } else {
        user.email = newEmail;
      }
      emitter.emit("email-changed", user);
      yield self.logActivity(user._id, "changed email", req.user.provider, req, user);
      yield userDB.put(finalUser);
    });

    return function (_x51, _x52, _x53) {
      return _ref21.apply(this, arguments);
    };
  })();

  this.addUserDB = function (user_id, dbName, type, designDocs, permissions) {
    var userDoc;
    var dbConfig = dbAuth.getDBConfig(dbName, type || "private");
    dbConfig.designDocs = designDocs || dbConfig.designDocs || "";
    dbConfig.permissions = permissions || dbConfig.permissions;
    dbConfig.memberRoles.push("user:" + user_id);
    // console.log(dbConfig.memberRoles);
    return userDB.get(user_id).then(function (result) {
      userDoc = result;
      return dbAuth.addUserDB(userDoc, dbName, dbConfig.designDocs, dbConfig.type, dbConfig.permissions, dbConfig.adminRoles, dbConfig.memberRoles);
    }).then(function (finalDBName) {
      if (!userDoc.personalDBs) {
        userDoc.personalDBs = {};
      }
      delete dbConfig.designDocs;
      // If permissions is specified explicitly it will be saved, otherwise will be taken from defaults every session
      if (!permissions) {
        delete dbConfig.permissions;
      }
      delete dbConfig.adminRoles;
      delete dbConfig.memberRoles;
      userDoc.personalDBs[finalDBName] = dbConfig;
      emitter.emit("user-db-added", user_id, dbName);
      return userDB.put(userDoc);
    });
  };

  this.removeUserDB = function (user_id, dbName, deletePrivate, deleteShared) {
    var user;
    var update = false;
    return userDB.get(user_id).then(function (userDoc) {
      user = userDoc;
      if (user.personalDBs && typeof user.personalDBs === "object") {
        Object.keys(user.personalDBs).forEach(function (db) {
          if (user.personalDBs[db].name === dbName) {
            var type = user.personalDBs[db].type;
            delete user.personalDBs[db];
            update = true;
            if (type === "private" && deletePrivate) {
              return dbAuth.removeDB(dbName);
            }
            if (type === "shared" && deleteShared) {
              return dbAuth.removeDB(dbName);
            }
          }
        });
      }
      return _bluebird2.default.resolve();
    }).then(function () {
      if (update) {
        emitter.emit("user-db-removed", user_id, dbName);
        return userDB.put(user);
      }
      return _bluebird2.default.resolve();
    });
  };

  this.logoutUser = function (user) {
    return self.logoutUserSessions(user, "all");
  };

  this.logoutSession = function (user) {
    // console.log(user);
    return new Promise((resolve, reject) => {
      var session_id = user.payload.dbUser;
      var promises = [];
      promises.push(dbAuth.removeKeys(session_id));
      resolve(_bluebird2.default.all(promises));
    }).then(function () {
      // Clean out expired sessions
      return self.logoutUserSessions(user, "expired");
    }).then(function (finalUser) {
      emitter.emit("logout", user._id);
      return _bluebird2.default.resolve(false);
    });
  };

  this.logoutOthers = function (user, session_id) {
    return self.logoutUserSessions(user, "other", session_id);
  };

  this.logoutUserSessions = function (userDoc, op, currentSession) {
    return new Promise((resolve, reject) => {
      // When op is 'other' it will logout all sessions except for the specified 'currentSession'
      var promises = [];
      var promise;
      var sessions;
      if (op === "all" || op === "other") {
        promise = self.getSessions(userDoc._id);
      } else if (op === "expired") {
        promise = self.getExpiredSessions(userDoc._id, Date.now());
      }
      return promise.then(sessions => {
        // console.log(sessions);
        if (op === "other" && currentSession) {
          // Remove the current session from the list of sessions we are going to delete
          var index = sessions.indexOf(currentSession);
          if (index > -1) {
            sessions.splice(index, 1);
          }
        }
        if (sessions.length) {
          // console.log(sessions.length);
          // Remove the keys from our couchDB auth database
          promises.push(dbAuth.removeKeys(sessions));
        }
        _bluebird2.default.all(promises).then(function () {
          resolve(userDoc);
        });
      }).catch(err => {
        reject(err);
      });
    });
  };

  this.remove = function (user_id, destroyDBs) {
    var user;
    var promises = [];
    return userDB.get(user_id).then(function (userDoc) {
      return self.logoutUserSessions(userDoc, "all");
    }).then(function (userDoc) {
      user = userDoc;
      if (destroyDBs !== true || !user.personalDBs) {
        return _bluebird2.default.resolve();
      }
      Object.keys(user.personalDBs).forEach(function (userdb) {
        if (user.personalDBs[userdb].type === "private") {
          promises.push(dbAuth.removeDB(userdb));
        }
      });
      return _bluebird2.default.all(promises);
    }).then(function () {
      return userDB.remove(user);
    });
  };

  this.removeExpiredKeys = dbAuth.removeExpiredKeys.bind(dbAuth);

  this.getSessions = function (user_id) {
    return couchAuthDB.query("_superlogin/user", {
      key: user_id,
      include_docs: true
    }).then(result => {
      return _bluebird2.default.resolve(result.rows.map(i => i.doc.name));
    }).catch(err => {
      return _bluebird2.default.reject(err);
    });
  };

  this.getExpiredSessions = function (user_id, date) {
    return couchAuthDB.query("_superlogin/expired", {
      include_docs: true
    }).then(result => {
      if (user_id) {
        return result.rows.filter(i => {
          return i.doc.user_id === user_id && i.doc.expires < Math.floor(Date.now() / 1000);
        }).map(i => i.doc.name);
      }
      return result.rows.filter(i => {
        return i.doc.expires < Math.floor(Date.now() / 1000);
      }).map(i => i.doc.name);
    });
  };

  this.confirmSession = function (token) {
    return new Promise((resolve, reject) => {
      _jsonwebtoken2.default.verify(token, config.getItem("security.jwt.secret"), (err, payload) => {
        if (err) {
          reject(err);
        }
        self.get(payload.sub).then(userDoc => {
          userDoc.payload = payload;
          resolve(userDoc);
        }).catch(err => {
          reject(err);
        });
      });
    });
  };

  this.quitRedis = function () {
    return session.quit();
  };

  function generateSession(username, roles) {
    var token = _util2.default.URLSafeUUID();
    // Make sure our token doesn't start with illegal characters
    while (token[0] === "_" || token[0] === "-") {
      token = _util2.default.URLSafeUUID();
    }
    console.log(sessionLife);
    var password = _util2.default.URLSafeUUID();
    var now = Date.now();
    return _bluebird2.default.resolve({
      _id: username,
      key: token,
      password: password,
      issued: now,
      expires: now + sessionLife,
      roles: roles
    });
  }

  // Adds numbers to a base name until it finds a unique database key
  function generateUsername(base) {
    base = base.toLowerCase();
    var entries = [];
    var finalName;
    return userDB.allDocs({ startkey: base, endkey: base + "\uffff", include_docs: false }).then(function (results) {
      if (results.rows.length === 0) {
        return _bluebird2.default.resolve(base);
      }
      for (var i = 0; i < results.rows.length; i++) {
        entries.push(results.rows[i].id);
      }
      if (entries.indexOf(base) === -1) {
        return _bluebird2.default.resolve(base);
      }
      var num = 0;
      while (!finalName) {
        num++;
        if (entries.indexOf(base + num) === -1) {
          finalName = base + num;
        }
      }
      return _bluebird2.default.resolve(finalName);
    });
  }

  function addUserDBs(newUser) {
    // Add personal DBs
    if (!config.getItem("userDBs.defaultDBs")) {
      return _bluebird2.default.resolve(newUser);
    }
    var promises = [];
    newUser.personalDBs = {};

    var processUserDBs = function (dbList, type) {
      dbList.forEach(function (userDBName) {
        var dbConfig = dbAuth.getDBConfig(userDBName);
        dbConfig.memberRoles.push("user:" + newUser._id);
        // console.log(dbConfig);
        promises.push(dbAuth.addUserDB(newUser, userDBName, dbConfig.designDocs, type, dbConfig.permissions, dbConfig.adminRoles, dbConfig.memberRoles).then(function (finalDBName) {
          delete dbConfig.permissions;
          delete dbConfig.adminRoles;
          delete dbConfig.memberRoles;
          delete dbConfig.designDocs;
          dbConfig.type = type;
          newUser.personalDBs[finalDBName] = dbConfig;
        }));
      });
    };

    // Just in case defaultDBs is not specified
    var defaultPrivateDBs = config.getItem("userDBs.defaultDBs.private");
    if (!Array.isArray(defaultPrivateDBs)) {
      defaultPrivateDBs = [];
    }
    processUserDBs(defaultPrivateDBs, "private");
    var defaultSharedDBs = config.getItem("userDBs.defaultDBs.shared");
    if (!Array.isArray(defaultSharedDBs)) {
      defaultSharedDBs = [];
    }
    processUserDBs(defaultSharedDBs, "shared");

    return _bluebird2.default.all(promises).then(function () {
      return _bluebird2.default.resolve(newUser);
    });
  }

  return this;
};

var _url = __webpack_require__(18);

var _url2 = _interopRequireDefault(_url);

var _bluebird = __webpack_require__(1);

var _bluebird2 = _interopRequireDefault(_bluebird);

var _sofaModel = __webpack_require__(19);

var _sofaModel2 = _interopRequireDefault(_sofaModel);

var _nodemailer = __webpack_require__(5);

var _nodemailer2 = _interopRequireDefault(_nodemailer);

var _util = __webpack_require__(0);

var _util2 = _interopRequireDefault(_util);

var _dbauth = __webpack_require__(20);

var _dbauth2 = _interopRequireDefault(_dbauth);

var _lodash = __webpack_require__(24);

var _lodash2 = _interopRequireDefault(_lodash);

var _jsonwebtoken = __webpack_require__(2);

var _jsonwebtoken2 = _interopRequireDefault(_jsonwebtoken);

var _v = __webpack_require__(25);

var _v2 = _interopRequireDefault(_v);

var _ms = __webpack_require__(28);

var _ms2 = _interopRequireDefault(_ms);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

// regexp from https://github.com/angular/angular.js/blob/master/src/ng/directive/input.js#L4
var EMAIL_REGEXP = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$/;
var USER_REGEXP = /^[a-z0-9_-]{3,16}$/;

;

/***/ }),
/* 18 */
/***/ (function(module, exports) {

module.exports = require("url");

/***/ }),
/* 19 */
/***/ (function(module, exports) {

module.exports = require("sofa-model");

/***/ }),
/* 20 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(__dirname) {

var BPromise = __webpack_require__(1);
var axiosDB = __webpack_require__(3);
var util = __webpack_require__(0);
var axios = __webpack_require__(21);
var seed = __webpack_require__(6);

module.exports = function (config, userDB, couchAuthDB) {

  var adapter;

  var CouchAdapter = __webpack_require__(22);
  adapter = new CouchAdapter(couchAuthDB);

  this.storeKey = function (username, key, password, expires, roles) {
    return adapter.storeKey(username, key, password, expires, roles);
  };

  this.removeKeys = function (keys) {
    return adapter.removeKeys(keys);
  };

  this.authorizeKeys = function (user_id, db, keys, permissions, roles) {
    return adapter.authorizeKeys(user_id, db, keys, permissions, roles);
  };

  this.deauthorizeKeys = function (db, keys) {
    return adapter.deauthorizeKeys(db, keys);
  };

  this.addUserDB = function (userDoc, dbName, designDocs, type, permissions, adminRoles, memberRoles) {
    var self = this;
    var promises = [];
    adminRoles = adminRoles || [];
    memberRoles = memberRoles || [];
    // Create and the database and seed it if a designDoc is specified
    var prefix = config.getItem('userDBs.privatePrefix') ? config.getItem('userDBs.privatePrefix') + '_' : '';
    var finalDBName, newDB;
    // Make sure we have a legal database name
    var username = userDoc._id;
    username = getLegalDBName(username);
    if (type === 'shared') {
      finalDBName = dbName;
    } else {
      finalDBName = prefix + dbName + '$' + username;
    }
    return self.createDB(finalDBName).then(function () {
      newDB = new axiosDB(util.getDBURL(config.getItem('dbServer')) + '/' + finalDBName);
      return adapter.initSecurity(newDB, adminRoles, memberRoles);
    }).then(function () {
      // Seed the design docs
      if (designDocs && designDocs instanceof Array) {
        designDocs.forEach(function (ddName) {
          var dDoc = self.getDesignDoc(ddName);
          if (dDoc) {
            promises.push(seed(newDB, dDoc));
          } else {
            console.warn('Failed to locate design doc: ' + ddName);
          }
        });
      }
      // Authorize the user's existing DB keys to access the new database
      var keysToAuthorize = [];
      if (userDoc.session) {
        for (var key in userDoc.session) {
          if (userDoc.session.hasOwnProperty(key) && userDoc.session[key].expires > Date.now()) {
            keysToAuthorize.push(key);
          }
        }
      }
      if (keysToAuthorize.length > 0) {
        promises.push(self.authorizeKeys(userDoc._id, newDB, keysToAuthorize, permissions, userDoc.roles));
      }
      return BPromise.all(promises);
    }).then(function () {
      return BPromise.resolve(finalDBName);
    });
  };

  this.removeExpiredKeys = function () {
    var self = this;
    var keysByUser = {};
    var userDocs = {};
    var expiredKeys = [];
    // query a list of expired keys by user
    return couchAuthDB.query("_superlogin/expired", {
      include_docs: true
    }).then(function (result) {
      let expiredKeys = result.rows.filter(i => {
        return i.doc.expires < Date.now();
      }).map(i => i.doc.name);
      return self.removeKeys(expiredKeys);
    }).then(function () {
      return BPromise.resolve(expiredKeys);
    });
  };

  this.getDesignDoc = function (docName) {
    if (!docName) {
      return null;
    }
    var designDoc;
    var designDocDir = config.getItem('userDBs.designDocDir');
    if (!designDocDir) {
      designDocDir = __dirname;
    }
    try {
      designDoc = !(function webpackMissingModule() { var e = new Error("Cannot find module \".\""); e.code = 'MODULE_NOT_FOUND'; throw e; }());
    } catch (err) {
      console.warn('Design doc: ' + designDocDir + '/' + docName + ' not found.');
      designDoc = null;
    }
    return designDoc;
  };

  this.getDBConfig = function (dbName, type) {
    var dbConfig = {
      name: dbName
    };
    dbConfig.adminRoles = config.getItem('userDBs.defaultSecurityRoles.admins') || [];
    dbConfig.memberRoles = config.getItem('userDBs.defaultSecurityRoles.members') || [];
    var dbConfigRef = 'userDBs.model.' + dbName;
    if (config.getItem(dbConfigRef)) {
      dbConfig.permissions = config.getItem(dbConfigRef + '.permissions') || [];
      dbConfig.designDocs = config.getItem(dbConfigRef + '.designDocs') || [];
      dbConfig.type = type || config.getItem(dbConfigRef + '.type') || 'private';
      var dbAdminRoles = config.getItem(dbConfigRef + '.adminRoles');
      var dbMemberRoles = config.getItem(dbConfigRef + '.memberRoles');
      if (dbAdminRoles && dbAdminRoles instanceof Array) {
        dbAdminRoles.forEach(function (role) {
          if (role && dbConfig.adminRoles.indexOf(role) === -1) {
            dbConfig.adminRoles.push(role);
          }
        });
      }
      if (dbMemberRoles && dbMemberRoles instanceof Array) {
        dbMemberRoles.forEach(function (role) {
          if (role && dbConfig.memberRoles.indexOf(role) === -1) {
            dbConfig.memberRoles.push(role);
          }
        });
      }
    } else if (config.getItem('userDBs.model._default')) {
      dbConfig.permissions = config.getItem('userDBs.model._default.permissions') || [];
      // Only add the default design doc to a private database
      if (!type || type === 'private') {
        dbConfig.designDocs = config.getItem('userDBs.model._default.designDocs') || [];
      } else {
        dbConfig.designDocs = [];
      }
      dbConfig.type = type || 'private';
    } else {
      dbConfig.type = type || 'private';
    }
    return dbConfig;
  };

  this.createDB = function (dbName) {
    var finalUrl = util.getDBURL(config.getItem('dbServer')) + '/' + dbName;
    console.log(finalUrl);
    return axios.put(finalUrl).then(function (res) {
      return BPromise.resolve(res.data);
    }, function (err) {
      if (err.response.status === 412) {
        return BPromise.resolve(false);
      } else {
        return BPromise.reject(err.response);
      }
    });
  };

  this.removeDB = function (dbName) {
    var db = new axiosDB(util.getDBURL(config.getItem('dbServer')) + '/' + dbName);
    return db.destroy();
  };

  return this;
};

// Escapes any characters that are illegal in a CouchDB database name using percent codes inside parenthesis
// Example: 'My.name@example.com' => 'my(2e)name(40)example(2e)com'
function getLegalDBName(input) {
  input = input.toLowerCase();
  var output = encodeURIComponent(input);
  output = output.replace(/\./g, '%2E');
  output = output.replace(/!/g, '%21');
  output = output.replace(/~/g, '%7E');
  output = output.replace(/\*/g, '%2A');
  output = output.replace(/'/g, '%27');
  output = output.replace(/\(/g, '%28');
  output = output.replace(/\)/g, '%29');
  output = output.replace(/\-/g, '%2D');
  output = output.toLowerCase();
  output = output.replace(/(%..)/g, function (esc) {
    esc = esc.substr(1);
    return '(' + esc + ')';
  });
  return output;
}
/* WEBPACK VAR INJECTION */}.call(exports, "src/dbauth"))

/***/ }),
/* 21 */
/***/ (function(module, exports) {

module.exports = require("axios");

/***/ }),
/* 22 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var BPromise = __webpack_require__(1);
var util = __webpack_require__(0);

module.exports = function (couchAuthDB) {

  this.storeKey = function (username, key, password, expires, roles) {
    if (roles instanceof Array) {
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
    return couchAuthDB.put(newKey).then(function () {
      newKey._id = key;
      return BPromise.resolve(newKey);
    });
  };

  this.removeKeys = function (keys) {
    keys = util.toArray(keys);
    var keylist = [];
    // Transform the list to contain the CouchDB _user ids
    keys.forEach(function (key) {
      keylist.push('org.couchdb.user:' + key);
    });
    var toDelete = [];
    return couchAuthDB.allDocs({ keys: keylist }).then(function (keyDocs) {
      console.log(keylist, keyDocs);
      keyDocs.rows.forEach(function (row) {
        if (!row.error && !row.value.deleted) {
          var deletion = {
            _id: row.id,
            _rev: row.value.rev,
            _deleted: true
          };
          toDelete.push(deletion);
        }
      });
      if (toDelete.length) {
        return couchAuthDB.bulkDocs(toDelete);
      } else {
        return BPromise.resolve(false);
      }
    });
  };

  this.initSecurity = function (db, adminRoles, memberRoles) {
    var changes = false;
    return db.get('_security').then(function (secDoc) {
      if (!secDoc.admins) {
        secDoc.admins = { names: [], roles: [] };
      }
      if (!secDoc.admins.roles) {
        secDoc.admins.roles = [];
      }
      if (!secDoc.members) {
        secDoc.members = { names: [], roles: [] };
      }
      if (!secDoc.members.roles) {
        secDoc.admins.roles = [];
      }
      adminRoles.forEach(function (role) {
        if (secDoc.admins.roles.indexOf(role) === -1) {
          changes = true;
          secDoc.admins.roles.push(role);
        }
      });
      memberRoles.forEach(function (role) {
        if (secDoc.members.roles.indexOf(role) === -1) {
          changes = true;
          secDoc.members.roles.push(role);
        }
      });
      if (changes) {
        return putSecurityCouch(db, secDoc);
      } else {
        return BPromise.resolve(false);
      }
    });
  };

  this.authorizeKeys = function (user_id, db, keys) {
    var secDoc;
    // Check if keys is an object and convert it to an array
    if (typeof keys === 'object' && !(keys instanceof Array)) {
      var keysArr = [];
      Object.keys(keys).forEach(function (theKey) {
        keysArr.push(theKey);
      });
      keys = keysArr;
    }
    // Convert keys to an array if it is just a string
    keys = util.toArray(keys);
    return db.get('_security').then(function (doc) {
      secDoc = doc;
      if (!secDoc.members) {
        secDoc.members = { names: [], roles: [] };
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
    return db.get('_security').then(function (doc) {
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

/***/ }),
/* 23 */
/***/ (function(module, exports) {

function webpackEmptyContext(req) {
	throw new Error("Cannot find module '" + req + "'.");
}
webpackEmptyContext.keys = function() { return []; };
webpackEmptyContext.resolve = webpackEmptyContext;
module.exports = webpackEmptyContext;
webpackEmptyContext.id = 23;

/***/ }),
/* 24 */
/***/ (function(module, exports) {

module.exports = require("lodash");

/***/ }),
/* 25 */
/***/ (function(module, exports, __webpack_require__) {

var rng = __webpack_require__(26);
var bytesToUuid = __webpack_require__(27);

function v4(options, buf, offset) {
  var i = buf && offset || 0;

  if (typeof(options) == 'string') {
    buf = options == 'binary' ? new Array(16) : null;
    options = null;
  }
  options = options || {};

  var rnds = options.random || (options.rng || rng)();

  // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`
  rnds[6] = (rnds[6] & 0x0f) | 0x40;
  rnds[8] = (rnds[8] & 0x3f) | 0x80;

  // Copy bytes to buffer, if provided
  if (buf) {
    for (var ii = 0; ii < 16; ++ii) {
      buf[i + ii] = rnds[ii];
    }
  }

  return buf || bytesToUuid(rnds);
}

module.exports = v4;


/***/ }),
/* 26 */
/***/ (function(module, exports, __webpack_require__) {

// Unique ID creation requires a high quality random # generator.  In node.js
// this is pretty straight-forward - we use the crypto API.

var rb = __webpack_require__(4).randomBytes;

function rng() {
  return rb(16);
}

module.exports = rng;


/***/ }),
/* 27 */
/***/ (function(module, exports) {

/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
var byteToHex = [];
for (var i = 0; i < 256; ++i) {
  byteToHex[i] = (i + 0x100).toString(16).substr(1);
}

function bytesToUuid(buf, offset) {
  var i = offset || 0;
  var bth = byteToHex;
  return bth[buf[i++]] + bth[buf[i++]] +
          bth[buf[i++]] + bth[buf[i++]] + '-' +
          bth[buf[i++]] + bth[buf[i++]] + '-' +
          bth[buf[i++]] + bth[buf[i++]] + '-' +
          bth[buf[i++]] + bth[buf[i++]] + '-' +
          bth[buf[i++]] + bth[buf[i++]] +
          bth[buf[i++]] + bth[buf[i++]] +
          bth[buf[i++]] + bth[buf[i++]];
}

module.exports = bytesToUuid;


/***/ }),
/* 28 */
/***/ (function(module, exports) {

module.exports = require("ms");

/***/ }),
/* 29 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(__dirname) {

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _fs = __webpack_require__(7);

var _fs2 = _interopRequireDefault(_fs);

var _path = __webpack_require__(8);

var _path2 = _interopRequireDefault(_path);

var _bluebird = __webpack_require__(1);

var _bluebird2 = _interopRequireDefault(_bluebird);

var _ejs = __webpack_require__(9);

var _ejs2 = _interopRequireDefault(_ejs);

var _util = __webpack_require__(30);

var _util2 = __webpack_require__(0);

var _util3 = _interopRequireDefault(_util2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

var stateRequired = ["google", "linkedin"];

var self;

class Oauth {

  constructor(router, passport, user, config) {
    this.router = router;
    this.passport = passport;
    this.user = user;
    this.config = config;
    self = this;
  }

  // Function to initialize a session following authentication from a socialAuth provider
  initSession(req, res, next) {
    return _asyncToGenerator(function* () {
      var provider = self.getProvider(req.path);
      try {
        const mySession = yield self.user.createSession(provider, req);
        const results = {
          error: null,
          session: mySession,
          link: null
        };
        var template;
        if (self.config.getItem("testMode.oauthTest")) {
          template = _fs2.default.readFileSync(_path2.default.join(__dirname, "../templates/oauth/auth-callback-test.ejs"), "utf8");
        } else {
          template = _fs2.default.readFileSync(_path2.default.join(__dirname, "../templates/oauth/auth-callback.ejs"), "utf8");
        }
        var html = _ejs2.default.render(template, results);
        res.status(200).send(html);
      } catch (err) {
        return next(err);
      }
    })();
  }

  // Function to initialize a session following authentication from a socialAuth provider
  initTokenSession(req, res, next) {
    return _asyncToGenerator(function* () {
      var provider = getProviderToken(req.path);
      try {
        const mySession = yield self.user.createSession(provider, req);
        res.status(200).json(session);
      } catch (err) {
        return next(err);
      }
    })();
  }

  // Called after an account has been succesfully linked
  linkSuccess(req, res, next) {
    var provider = self.getProvider(req.path);
    var result = {
      error: null,
      session: null,
      link: provider
    };
    var template;
    if (self.config.getItem("testMode.oauthTest")) {
      template = _fs2.default.readFileSync(_path2.default.join(__dirname, "../templates/oauth/auth-callback-test.ejs"), "utf8");
    } else {
      template = _fs2.default.readFileSync(_path2.default.join(__dirname, "../templates/oauth/auth-callback.ejs"), "utf8");
    }
    var html = _ejs2.default.render(template, result);
    res.status(200).send(html);
  }

  // Called after an account has been succesfully linked using access_token provider
  linkTokenSuccess(req, res, next) {
    var provider = self.getProviderToken(req.path);
    res.status(200).json({
      ok: true,
      success: _util3.default.capitalizeFirstLetter(provider) + " successfully linked",
      provider: provider
    });
  }

  // Handles errors if authentication fails
  oauthErrorHandler(err, req, res, next) {
    var template;
    if (self.config.getItem("testMode.oauthTest")) {
      template = _fs2.default.readFileSync(_path2.default.join(__dirname, "../templates/oauth/auth-callback-test.ejs"), "utf8");
    } else {
      template = _fs2.default.readFileSync(_path2.default.join(__dirname, "../templates/oauth/auth-callback.ejs"), "utf8");
    }
    var html = _ejs2.default.render(template, { error: err.message, session: null, link: null });
    console.error(err);
    if (err.stack) {
      console.error(err.stack);
    }
    res.status(400).send(html);
  }

  // Handles errors if authentication from access_token provider fails
  tokenAuthErrorHandler(err, req, res, next) {
    var status;
    if (req.user && req.self.user._id) {
      status = 403;
    } else {
      status = 401;
    }
    console.error(err);
    if (err.stack) {
      console.error(err.stack);
      delete err.stack;
    }
    res.status(status).json(err);
  }

  // Framework to register OAuth providers with passport
  registerProvider(provider, configFunction) {
    console.log(provider, this);
    provider = provider.toLowerCase();
    var configRef = "providers." + provider;
    if (self.config.getItem(configRef + ".credentials")) {
      var credentials = self.config.getItem(configRef + ".credentials");
      credentials.passReqToCallback = true;
      var options = self.config.getItem(configRef + ".options") || {};
      configFunction.call(null, credentials, self.passport, self.authHandler);
      // register provider routes
      self.router.get("/" + provider, self.passportCallback(provider, options, "login"));
      // register provider callbacks
      self.router.get("/" + provider + "/callback", self.passportCallback(provider, options, "login"), self.initSession, self.oauthErrorHandler);
      if (!self.config.getItem("security.disableLinkAccounts")) {
        // register link route
        self.router.get("/link/" + provider, self.passport.authenticate("bearer", { session: false }), self.passportCallback(provider, options, "link"));
        // register link callback
        self.router.get("/link/" + provider + "/callback", self.passport.authenticate("bearer", { session: false }), self.passportCallback(provider, options, "link"), self.linkSuccess, self.oauthErrorHandler);
      }
      console.log(provider + " loaded.");
    }
  }

  // A shortcut to register OAuth2 providers that follow the exact accessToken, refreshToken pattern.
  registerOAuth2(providerName, Strategy) {
    self.registerProvider(providerName, (credentials, passport, authHandler) => {
      self.passport.use(new Strategy(credentials, (() => {
        var _ref = _asyncToGenerator(function* (req, accessToken, refreshToken, profile, done) {
          try {
            const res = yield self.authHandler(req, providerName, {
              accessToken: accessToken,
              refreshToken: refreshToken
            }, profile);
            done(res);
          } catch (err) {
            done(err);
          }
        });

        return function (_x, _x2, _x3, _x4, _x5) {
          return _ref.apply(this, arguments);
        };
      })()));
    });
  }

  // Registers a provider that accepts an access_token directly from the client, skipping the popup window and callback
  // This is for supporting Cordova, native IOS and Android apps, as well as other devices
  registerTokenProvider(providerName, Strategy) {
    providerName = providerName.toLowerCase();
    var configRef = "providers." + providerName;
    if (self.config.getItem(configRef + ".credentials")) {
      var credentials = self.config.getItem(configRef + ".credentials");
      credentials.passReqToCallback = true;
      var options = self.config.getItem(configRef + ".options") || {};
      // Configure the Passport Strategy
      self.passport.use(providerName + "-token", new Strategy(credentials, (() => {
        var _ref2 = _asyncToGenerator(function* (req, accessToken, refreshToken, profile, done) {
          try {
            const res = yield self.authHandler(req, providerName, {
              accessToken: accessToken,
              refreshToken: refreshToken
            }, profile);
            done(res);
          } catch (err) {
            done(err);
          }
        });

        return function (_x6, _x7, _x8, _x9, _x10) {
          return _ref2.apply(this, arguments);
        };
      })()));
      self.router.post("/" + providerName + "/token", self.passportTokenCallback(providerName, options), self.initTokenSession, self.tokenAuthErrorHandler);
      if (!self.config.getItem("security.disableLinkAccounts")) {
        self.router.post("/link/" + providerName + "/token", self.passport.authenticate("bearer", { session: false }), self.passportTokenCallback(providerName, options), self.linkTokenSuccess, self.tokenAuthErrorHandler);
      }
      console.log(providerName + "-token loaded.");
    }
  }

  // This is called after a user has successfully authenticated with a provider
  // If a user is authenticated with a bearer token we will link an account, otherwise log in
  // auth is an object containing 'access_token' and optionally 'refresh_token'
  authHandler(req, provider, auth, profile) {
    if (req.user && req.self.user._id && req.self.user.key) {
      return self.user.linkSocial(req.self.user._id, provider, auth, profile, req);
    } else {
      return self.user.socialAuth(provider, auth, profile, req);
    }
  }

  // Configures the self.passport.authenticate for the given provider, passing in options
  // Operation is 'login' or 'link'
  passportCallback(provider, options, operation) {
    // console.log(provider, options, operation);
    return (req, res, next) => {
      var theOptions = (0, _util._extend)({}, options);
      if (provider === "linkedin") {
        theOptions.state = true;
      }
      var accessToken = req.query.bearer_token || req.query.state;
      if (accessToken && (stateRequired.indexOf(provider) > -1 || self.config.getItem("providers." + provider + ".stateRequired") === true)) {
        theOptions.state = accessToken;
      }
      theOptions.callbackURL = self.getLinkCallbackURLs(provider, req, operation, accessToken);
      theOptions.session = false;
      self.passport.authenticate(provider, theOptions)(req, res, next);
    };
  }

  // Configures the self.passport.authenticate for the given access_token provider, passing in options
  passportTokenCallback(provider, options) {
    return (req, res, next) => {
      var theOptions = (0, _util._extend)({}, options);
      theOptions.session = false;
      self.passport.authenticate(provider + "-token", theOptions)(req, res, next);
    };
  }

  getLinkCallbackURLs(provider, req, operation, accessToken) {
    if (accessToken) {
      accessToken = encodeURIComponent(accessToken);
    }
    var protocol = (req.get("X-Forwarded-Proto") || req.protocol) + "://";
    if (operation === "login") {
      return protocol + req.get("host") + req.baseUrl + "/" + provider + "/callback";
    }
    if (operation === "link") {
      var reqUrl;
      if (accessToken && (stateRequired.indexOf(provider) > -1 || self.config.getItem("providers." + provider + ".stateRequired") === true)) {
        reqUrl = protocol + req.get("host") + req.baseUrl + "/link/" + provider + "/callback";
      } else {
        reqUrl = protocol + req.get("host") + req.baseUrl + "/link/" + provider + "/callback?state=" + accessToken;
      }
      return reqUrl;
    }
  }

  // Gets the provider name from a callback path
  getProvider(pathname) {
    var items = pathname.split("/");
    var index = items.indexOf("callback");
    if (index > 0) {
      return items[index - 1];
    }
  }

  // Gets the provider name from a callback path for access_token strategy
  getProviderToken(pathname) {
    var items = pathname.split("/");
    var index = items.indexOf("token");
    if (index > 0) {
      return items[index - 1];
    }
  }

}exports.default = Oauth;
;
/* WEBPACK VAR INJECTION */}.call(exports, "src"))

/***/ }),
/* 30 */
/***/ (function(module, exports) {

module.exports = require("util");

/***/ }),
/* 31 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});

exports.default = function (config, router, passport, user) {
  const env = process.env.NODE_ENV || "development";

  router.post("/login", function (req, res, next) {
    passport.authenticate("local", function (err, user, info) {
      if (err) {
        return next(err);
      }
      if (!user) {
        // Authentication failed
        return res.status(401).json(info);
      }
      // Success
      req.logIn(user, { session: false }, function (err) {
        // console.log("Passport logged in", Date.now());
        if (err) {
          return next(err);
        }
      });
      return next();
    })(req, res, next);
  }, (() => {
    var _ref = _asyncToGenerator(function* (req, res, next) {
      // Success handler
      try {
        const mySession = yield user.createSession("local", req, true);
        res.status(200).json(mySession);
      } catch (err) {
        return next(err);
      }
    });

    return function (_x, _x2, _x3) {
      return _ref.apply(this, arguments);
    };
  })());

  router.post("/refresh", passport.authenticate("bearer", { session: false }), (() => {
    var _ref2 = _asyncToGenerator(function* (req, res, next) {
      try {
        const mySession = yield user.refreshSession(req);
        res.status(200).json(mySession);
      } catch (err) {
        return next(err);
      }
    });

    return function (_x4, _x5, _x6) {
      return _ref2.apply(this, arguments);
    };
  })());

  router.post("/logout", passport.authenticate("bearer", { session: false }), (() => {
    var _ref3 = _asyncToGenerator(function* (req, res, next) {
      try {
        yield user.logoutSession(req.user);
        res.status(200).json({
          ok: true,
          success: "Logged out"
        });
      } catch (err) {
        console.error("Logout failed");
        return next(err);
      }
    });

    return function (_x7, _x8, _x9) {
      return _ref3.apply(this, arguments);
    };
  })());

  router.post("/logout-others", passport.authenticate("bearer", { session: false }), (() => {
    var _ref4 = _asyncToGenerator(function* (req, res, next) {
      console.log(req.user);
      try {
        yield user.logoutOthers(req.user, req.user.payload.dbUser);
        res.status(200).json({
          ok: true,
          success: "Other sessions logged out"
        });
      } catch (err) {
        console.error("Logout failed");
        return next(err);
      }
    });

    return function (_x10, _x11, _x12) {
      return _ref4.apply(this, arguments);
    };
  })());

  router.post("/logout-all", passport.authenticate("bearer", { session: false }), (() => {
    var _ref5 = _asyncToGenerator(function* (req, res, next) {
      try {
        yield user.logoutUser(req.user);
        res.status(200).json({ success: "Logged out" });
      } catch (err) {
        console.error("Logout-all failed");
        return next(err);
      }
    });

    return function (_x13, _x14, _x15) {
      return _ref5.apply(this, arguments);
    };
  })());

  // Setting up the auth api
  router.post("/register", (() => {
    var _ref6 = _asyncToGenerator(function* (req, res, next) {
      try {
        const newUser = yield user.create(req.body, req);
        console.log(newUser);
        req.user = newUser;
        if (config.getItem("security.loginOnRegistration")) {
          try {
            const mySession = yield user.createSession("local", req, true);
            res.status(200).json(mySession);
          } catch (err) {
            return next(err);
          }
        } else {
          res.status(201).json({
            ok: true,
            success: "User created."
          });
        }
      } catch (err) {
        return next(err);
      }
    });

    return function (_x16, _x17, _x18) {
      return _ref6.apply(this, arguments);
    };
  })());

  router.post("/forgot-password", (() => {
    var _ref7 = _asyncToGenerator(function* (req, res, next) {
      try {
        yield user.forgotPassword(req.body.email, req);
        res.status(200).json({ success: "Password recovery email sent." });
      } catch (err) {
        return next(err);
      }
    });

    return function (_x19, _x20, _x21) {
      return _ref7.apply(this, arguments);
    };
  })());

  router.post("/password-reset", (() => {
    var _ref8 = _asyncToGenerator(function* (req, res, next) {
      try {
        const currentUser = yield user.resetPassword(req.body, req);
        if (config.getItem("security.loginOnPasswordReset")) {
          try {
            const mySession = yield user.createSession("local", req);
            res.status(200).json(mySession);
          } catch (err) {
            return next(err);
          }
        } else {
          res.status(200).json({ success: "Password successfully reset." });
        }
      } catch (err) {
        return next(err);
      }
    });

    return function (_x22, _x23, _x24) {
      return _ref8.apply(this, arguments);
    };
  })());

  router.post("/password-change", passport.authenticate("bearer", { session: false }), (() => {
    var _ref9 = _asyncToGenerator(function* (req, res, next) {
      try {
        yield user.changePasswordSecure(req.user._id, req.body, req);
        res.status(200).json({ success: "password changed" });
      } catch (err) {
        return next(err);
      }
    });

    return function (_x25, _x26, _x27) {
      return _ref9.apply(this, arguments);
    };
  })());

  router.post("/unlink/:provider", passport.authenticate("bearer", { session: false }), (() => {
    var _ref10 = _asyncToGenerator(function* (req, res, next) {
      const provider = req.params.provider;
      try {
        yield user.unlink(req.user._id, provider);
        res.status(200).json({
          success: _util2.default.capitalizeFirstLetter(provider) + " unlinked"
        });
      } catch (err) {
        return next(err);
      }
    });

    return function (_x28, _x29, _x30) {
      return _ref10.apply(this, arguments);
    };
  })());

  router.get("/confirm-email/:token", (() => {
    var _ref11 = _asyncToGenerator(function* (req, res, next) {
      var redirectURL = config.getItem("local.confirmEmailRedirectURL");
      if (!req.params.token) {
        var err = { error: "Email verification token required" };
        if (redirectURL) {
          return res.status(201).redirect(redirectURL + "?error=" + encodeURIComponent(err.error));
        }
        return res.status(400).send(err);
      }
      try {
        yield user.verifyEmail(req.params.token, req);
        if (redirectURL) {
          return res.status(201).redirect(redirectURL + "?success=true");
        }
        res.status(200).send({ ok: true, success: "Email verified" });
      } catch (err) {
        if (redirectURL) {
          var query = "?error=" + encodeURIComponent(err.error);
          if (err.message) {
            query += "&message=" + encodeURIComponent(err.message);
          }
          return res.status(201).redirect(redirectURL + query);
        }
        return next(err);
      }
    });

    return function (_x31, _x32, _x33) {
      return _ref11.apply(this, arguments);
    };
  })());

  router.get("/validate-username/:username", (() => {
    var _ref12 = _asyncToGenerator(function* (req, res, next) {
      if (!req.params.username) {
        return next({
          ok: false,
          error: "Username required",
          status: 400
        });
      }
      try {
        const err = yield user.validateUsername(req.params.username);
        if (!err) {
          res.status(200).json({ ok: true });
        } else {
          res.status(409).json({ error: "Username already in use" });
        }
      } catch (err) {
        return next(err);
      }
    });

    return function (_x34, _x35, _x36) {
      return _ref12.apply(this, arguments);
    };
  })());

  router.get("/validate-email/:email", (() => {
    var _ref13 = _asyncToGenerator(function* (req, res, next) {
      if (!req.params.email) {
        return next({ error: "Email required", status: 400 });
      }
      try {
        if (config.getItem("local.emailUsername")) {
          const err = yield user.validateEmailUsername(req.params.email);
        } else {
          const err = yield user.validateEmail(req.params.email);
        }
        if (!err) {
          res.status(200).json({ ok: true });
        } else {
          res.status(409).json({ error: "Email already in use" });
        }
      } catch (err) {
        return next(err);
      }
    });

    return function (_x37, _x38, _x39) {
      return _ref13.apply(this, arguments);
    };
  })());

  router.post("/change-email", passport.authenticate("bearer", { session: false }), (() => {
    var _ref14 = _asyncToGenerator(function* (req, res, next) {
      try {
        yield user.changeEmail(req.user._id, req.body.newEmail, req);
        res.status(200).json({ ok: true, success: "Email changed" });
      } catch (err) {
        return next(err);
      }
    });

    return function (_x40, _x41, _x42) {
      return _ref14.apply(this, arguments);
    };
  })());

  // route to test token authentication
  router.get("/session", passport.authenticate("bearer", { session: false }), function (req, res) {
    var user = req.user;
    user.user_id = user._id;
    delete user._id;
    // user.token = user.key;
    delete user.key;
    res.status(200).json({
      token: req.get("Authorization").split(" ")[1],
      expires: user.payload.exp * 1000,
      issued: user.payload.iat * 1000,
      ip: req.ip,
      dbUser: user.payload.dbUser,
      dbPass: user.payload.dbPass,
      dbExpires: user.payload.dbExpires,
      user_id: user.user_id,
      roles: user.roles,
      userDBs: user.userDBs
    });
  });

  // Error handling
  router.use(function (err, req, res, next) {
    console.error(err);
    if (err.stack) {
      console.error(err.stack);
    }
    res.status(err.status || 500);
    if (err.stack && env !== "development") {
      delete err.stack;
    }
    res.json(err);
  });
};

var _util = __webpack_require__(0);

var _util2 = _interopRequireDefault(_util);

var _jsonwebtoken = __webpack_require__(2);

var _jsonwebtoken2 = _interopRequireDefault(_jsonwebtoken);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

;

/***/ }),
/* 32 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});

exports.default = function (config, passport, user) {
  let handleFailedLogin = (() => {
    var _ref3 = _asyncToGenerator(function* (userDoc, req, done) {
      const invalid = {
        error: "Unauthorized",
        message: "Invalid username or password"
      };
      const locked = yield user.handleFailedLogin(userDoc, req);
      if (locked) {
        let securityLockoutTime = config.getItem("security.lockoutTime");
        let time = typeof securityLockoutTime === "string" ? ms(securityLockoutTime) : securityLockoutTime;
        invalid.message = "Maximum failed login attempts exceeded. Your account has been locked for " + ms(securityLockoutTime);
      }
      return done(null, false, invalid);
    });

    return function handleFailedLogin(_x7, _x8, _x9) {
      return _ref3.apply(this, arguments);
    };
  })();

  // API token strategy
  passport.use(new _passportHttpBearerSl.Strategy((() => {
    var _ref = _asyncToGenerator(function* (tokenPass, done) {
      // console.log(tokenPass);
      const token = tokenPass;
      try {
        const theuser = yield user.confirmSession(token);
        done(null, theuser);
      } catch (err) {
        if (err instanceof Error && err.message !== "jwt expired") {
          done(err, false);
        } else {
          done(null, false, { message: err.message });
        }
      }
    });

    return function (_x, _x2) {
      return _ref.apply(this, arguments);
    };
  })()));

  // Use local strategy
  passport.use(new _passportLocal2.default({
    usernameField: config.getItem("local.usernameField") || "username",
    passwordField: config.getItem("local.passwordField") || "password",
    session: false,
    passReqToCallback: true
  }, (() => {
    var _ref2 = _asyncToGenerator(function* (req, username, password, done) {
      // console.log("Passport", Date.now());
      try {
        const theuser = yield user.get(username);
        // console.log("Passport got user", Date.now());
        if (theuser) {
          // Check if the account is locked
          if (theuser.local && theuser.local.lockedUntil && theuser.local.lockedUntil > Date.now()) {
            return done(null, false, {
              error: "Unauthorized",
              message: "Your account is currently locked. Please wait a few minutes and try again."
            });
          }
          if (!theuser.local || !theuser.local.derived_key) {
            return done(null, false, {
              error: "Unauthorized",
              message: "Invalid username or password"
            });
          }
          try {
            yield _util2.default.verifyPassword(theuser.local, password);
            // console.log("Passport verified password", Date.now());
            // Check if the email has been confirmed if it is required
            if (config.getItem("local.requireEmailConfirm") && !theuser.email) {
              return done(null, false, {
                error: "Unauthorized",
                message: "You must confirm your email address."
              });
            }
            // Success!!!
            return done(null, theuser);
          } catch (err) {
            if (!err) {
              // Password didn't authenticate
              return handleFailedLogin(theuser, req, done);
            } else {
              // Hashing function threw an error
              return done(err);
            }
          }
        } else {
          // user not found
          return done(null, false, {
            error: "Unauthorized",
            message: "Invalid username or password"
          });
        }
      } catch (err) {
        // Database threw an error
        return done(err);
      }
    });

    return function (_x3, _x4, _x5, _x6) {
      return _ref2.apply(this, arguments);
    };
  })()));
};

var _util = __webpack_require__(0);

var _util2 = _interopRequireDefault(_util);

var _passportLocal = __webpack_require__(33);

var _passportLocal2 = _interopRequireDefault(_passportLocal);

var _passportHttpBearerSl = __webpack_require__(34);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

;

/***/ }),
/* 33 */
/***/ (function(module, exports) {

module.exports = require("passport-local");

/***/ }),
/* 34 */
/***/ (function(module, exports) {

module.exports = require("passport-http-bearer-sl");

/***/ }),
/* 35 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});

var _fs = __webpack_require__(7);

var _fs2 = _interopRequireDefault(_fs);

var _bluebird = __webpack_require__(1);

var _bluebird2 = _interopRequireDefault(_bluebird);

var _nodemailer = __webpack_require__(5);

var _nodemailer2 = _interopRequireDefault(_nodemailer);

var _ejs = __webpack_require__(9);

var _ejs2 = _interopRequireDefault(_ejs);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = class {

  constructor(config) {
    // Initialize the transport mechanism with nodermailer
    let transporter;
    this.config = config;
    const customTransport = config.getItem("mailer.transport");
    if (config.getItem("testMode.noEmail")) {
      this.transporter = _nodemailer2.default.createTransport(__webpack_require__(36)());
    } else if (customTransport) {
      this.transporter = _nodemailer2.default.createTransport(customTransport(config.getItem("mailer.options")));
    } else {
      this.transporter = _nodemailer2.default.createTransport(config.getItem("mailer.options"));
    }
  }

  sendEmail(templateName, email, locals) {
    // load the template and parse it
    var templateFile = this.config.getItem("emails." + templateName + ".template");
    if (!templateFile) {
      return _bluebird2.default.reject("No template found for \"" + templateName + "\".");
    }
    var template = _fs2.default.readFileSync(templateFile, "utf8");
    if (!template) {
      return _bluebird2.default.reject("Failed to locate template file: " + templateFile);
    }
    var body = _ejs2.default.render(template, locals);
    // form the email
    var subject = this.config.getItem("emails." + templateName + ".subject");
    var format = this.config.getItem("emails." + templateName + ".format");
    var mailOptions = {
      from: this.config.getItem("mailer.fromEmail"),
      to: email,
      subject: subject
    };
    if (format === "html") {
      mailOptions.html = body;
    } else {
      mailOptions.text = body;
    }
    if (this.config.getItem("testMode.debugEmail")) {
      console.log(mailOptions);
    }
    // send the message
    var sendEmail = _bluebird2.default.promisify(this.transporter.sendMail, { context: this.transporter });
    return sendEmail(mailOptions);
  }
};
;

/***/ }),
/* 36 */
/***/ (function(module, exports) {

module.exports = require("nodemailer-stub-transport");

/***/ }),
/* 37 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(__dirname) {

var path = __webpack_require__(8);

// These are the default settings that will be used if you don't override them in your config
module.exports = {
  security: {
    defaultRoles: ['user'],
    maxFailedLogins: 4,
    lockoutTime: "5m",
    sessionLife: "1d",
    tokenLife: "1d",
    loginOnRegistration: false,
    loginOnPasswordReset: false
  },
  local: {
    usernameField: 'username',
    passwordField: 'password'
  },
  session: {
    adapter: 'memory',
    file: {
      sessionsRoot: '.sessions'
    }
  },
  dbServer: {
    protocol: 'http://',
    host: 'localhost:5984',
    designDocDir: path.join(__dirname, '/designDocs'),
    userDB: 'sl_users',
    // CouchDB's _users database. Each session generates the user a unique login and password. This is not used with Cloudant.
    couchAuthDB: '_users'
  },
  emails: {
    confirmEmail: {
      subject: 'Please confirm your email',
      template: path.join(__dirname, '../templates/email/confirm-email.ejs'),
      format: 'text'
    },
    forgotPassword: {
      subject: 'Your password reset link',
      template: path.join(__dirname, '../templates/email/forgot-password.ejs'),
      format: 'text'
    }
  }
};
/* WEBPACK VAR INJECTION */}.call(exports, "config"))

/***/ }),
/* 38 */
/***/ (function(module, exports) {

module.exports = require("passport");

/***/ }),
/* 39 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = {
  auth: {
    views: {
      email: function (doc) {
        if (doc.email) {
          emit(doc.email, null);
        } else if (doc.unverifiedEmail.email) {
          emit(doc.unverifiedEmail.email, null);
        }
      },
      username: function (doc) {
        emit(doc._id, null);
      },
      verifyEmail: function (doc) {
        if (doc.unverifiedEmail && doc.unverifiedEmail.token) {
          emit(doc.unverifiedEmail.token, null);
        }
      },
      emailUsername: function (doc) {
        emit(doc._id, null);
        if (doc.email) {
          emit(doc.email, null);
        } else if (doc.unverifiedEmail.email) {
          emit(doc.unverifiedEmail.email, null);
        }
      },
      passwordReset: function (doc) {
        if (doc.forgotPassword && doc.forgotPassword.token) {
          emit(doc.forgotPassword.token, null);
        }
      },
      session: function (doc) {
        if (doc.session) {
          for (var key in doc.session) {
            if (doc.session.hasOwnProperty(key)) {
              emit(key, doc._id);
            }
          }
        }
      },
      expiredKeys: function (doc) {
        if (doc.session) {
          for (var key in doc.session) {
            if (doc.session.hasOwnProperty(key) && doc.session[key].expires) {
              emit(doc.session[key].expires, { key: key, user: doc._id });
            }
          }
        }
      }
    }
  }
};

/***/ })
/******/ ]);
});