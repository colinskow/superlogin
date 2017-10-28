"use strict";

var url = require("url");
var BPromise = require("bluebird");
var Model = require("sofa-model");
var nodemailer = require("nodemailer");
var util = require("./util");
var DBAuth = require("./dbauth");
const _ = require("lodash");
const jwt = require("jsonwebtoken");
const uuidv4 = require("uuid/v4");
const ms = require("ms");

// regexp from https://github.com/angular/angular.js/blob/master/src/ng/directive/input.js#L4
var EMAIL_REGEXP = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$/;
var USER_REGEXP = /^[a-z0-9_-]{3,16}$/;

module.exports = function(config, userDB, couchAuthDB, mailer, emitter) {
  var self = this;
  var dbAuth = new DBAuth(config, userDB, couchAuthDB);
  var onCreateActions = [];
  var onLinkActions = [];

  // Token valid for 24 hours by default
  // Forget password token life
  var tokenLife = config.getItem("security.tokenLife");
  tokenLife = typeof tokenLife === "string" ? Math.floor(ms(tokenLife) / 1000) : tokenLife || Math.floor(ms("1d") / 1000);
  // Session token life
  var sessionLife = config.getItem("security.sessionLife");
  sessionLife = typeof sessionLife === "string" ? Math.floor(ms(sessionLife) / 1000) : sessionLife || Math.floor(ms("1d") / 1000);

  var emailUsername = config.getItem("local.emailUsername");

  this.validateUsername = function(username) {
    if (!username) {
      return BPromise.resolve();
    }
    if (!username.match(USER_REGEXP)) {
      return BPromise.resolve("Invalid username");
    }
    return userDB.query("auth/username", {key: username})
      .then(function(result) {
        if (result.rows.length === 0) {
          // Pass!
          return BPromise.resolve();
        }
        else {
          return BPromise.resolve("already in use");
        }
      }, function(err) {
        throw new Error(err);
      });
  };

  this.validateEmail = function(email) {
    if (!email) {
      return BPromise.resolve();
    }
    if (!email.match(EMAIL_REGEXP)) {
      return BPromise.resolve("invalid email");
    }
    return userDB.query("auth/email", {key: email})
      .then(function(result) {
        if (result.rows.length === 0) {
          // Pass!
          return BPromise.resolve();
        }
        else {
          return BPromise.resolve("already in use");
        }
      }, function(err) {
        throw new Error(err);
      });
  };

  this.validateEmailUsername = function(email) {
    if (!email) {
      return BPromise.resolve();
    }
    if (!email.match(EMAIL_REGEXP)) {
      return BPromise.resolve("invalid email");
    }
    return userDB.query("auth/emailUsername", {key: email})
      .then(function(result) {
        if (result.rows.length === 0) {
          return BPromise.resolve();
        }
        else {
          return BPromise.resolve("already in use");
        }
      }, function(err) {
        throw new Error(err);
      });
  };

  // Validation function for ensuring that two fields match
  this.matches = function(value, option, key, attributes) {
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

  passwordConstraints = _.merge({}, passwordConstraints, config.getItem("local.passwordConstraints"));

  var userModel = {
    async: true,
    whitelist: [
      "name",
      "username",
      "email",
      "password",
      "confirmPassword"
    ],
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

  this.onCreate = function(fn) {
    if (typeof fn === "function") {
      onCreateActions.push(fn);
    }
    else {
      throw new TypeError("onCreate: You must pass in a function");
    }
  };

  this.onLink = function(fn) {
    if (typeof fn === "function") {
      onLinkActions.push(fn);
    }
    else {
      throw new TypeError("onLink: You must pass in a function");
    }
  };

  function processTransformations(fnArray, userDoc, provider) {
    var promise;
    fnArray.forEach(function(fn) {
      if (!promise) {
        promise = fn.call(null, userDoc, provider);
      }
      else {
        if (!promise.then || typeof promise.then !== "function") {
          throw new Error("onCreate function must return a promise");
        }
        promise.then(function(newUserDoc) {
          return fn.call(null, newUserDoc, provider);
        });
      }
    });
    if (!promise) {
      promise = BPromise.resolve(userDoc);
    }
    return promise;
  }

  this.get = function(login) {
    var query;
    if (emailUsername) {
      query = "emailUsername";
    }
    else {
      query = EMAIL_REGEXP.test(login) ? "email" : "username";
    }
    return userDB.query("auth/" + query, {key: login, include_docs: true})
      .then(function(results) {
        if (results.rows.length > 0) {
          return BPromise.resolve(results.rows[0].doc);
        }
        else {
          return BPromise.resolve(null);
        }
      });
  };

  this.create = function(form, req) {
    req = req || {};
    var finalUserModel = userModel;
    var newUserModel = config.getItem("userModel");
    if (typeof newUserModel === "object") {
      var whitelist;
      if (newUserModel.whitelist) {
        whitelist = util.arrayUnion(userModel.whitelist, newUserModel.whitelist);
      }
      finalUserModel = _.merge({}, userModel, config.getItem("userModel"));
      finalUserModel.whitelist = whitelist || finalUserModel.whitelist;
    }
    var UserModel = new Model(finalUserModel);
    var user = new UserModel(form);
    var newUser;
    return user.process()
      .then(function(result) {
        newUser = result;
        if (emailUsername) {
          newUser._id = newUser.email;
        }
        if (config.getItem("local.sendConfirmEmail")) {
          newUser.unverifiedEmail = {
            email: newUser.email,
            token: util.URLSafeUUID()
          };
          delete newUser.email;
        }
        return util.hashPassword(newUser.password);
      }, function(err) {
        return BPromise.reject({error: "Validation failed", validationErrors: err, status: 400});
      })
      .then(function(hash) {
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
        return addUserDBs(newUser);
      })
      .then(function(newUser) {
        return self.logActivity(newUser._id, "signup", "local", req, newUser);
      })
      .then(function(newUser) {
        return processTransformations(onCreateActions, newUser, "local");
      })
      .then(function(finalNewUser) {
        return userDB.put(finalNewUser);
      })
      .then(function(result) {
        newUser._rev = result.rev;
        if (!config.getItem("local.sendConfirmEmail")) {
          return BPromise.resolve();
        }
        return mailer.sendEmail("confirmEmail", newUser.unverifiedEmail.email, {req: req, user: newUser});
      })
      .then(function() {
        emitter.emit("signup", newUser, "local");
        return BPromise.resolve(newUser);
      });
  };

  this.createManual = function(options, mergeDoc) {
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
      providers: [
        "local"
      ],
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
    return new Promise((resolve, reject) => {
      var validatePromise;
      if (!options.username) {
        // generate a valid username
        var user_id = util.URLSafeUUID();
        // Make sure our token doesn't start with illegal characters
        while (token[0] === "_" || token[0] === "-") {
          user_id = util.URLSafeUUID();
        }
        // we just generated a valid username
        // no need to check later
        validatePromise = BPromise.resolve();
      }
      else {
        // use to specified username
        user_id = options.username;
        validatePromise = self.validateUsername(user_id);
      }
      // if no password is specified, generate one
      if (!password) password = util.URLSafeUUID();
      if (!user_id) {
        reject("Username must not be empty.");
      }
      // check if username is valid
      validatePromise.then(err => {
        if (err) {
          reject(err);
        }
        manualModel._id = user_id;
        // username is valid, generate password hash
        util.hashPassword(password).then(hash => {
          manualModel.local.salt = hash.salt;
          manualModel.local.derived_key = hash.derived_key;
          // we only want to create personal dbs when explicitly specified
          if (options.createPersonalDBs) {
            resolve(addUserDBs(manualModel));
          }
          resolve(manualModel);
        }).catch(err => {
          reject(err);
        })
      });
    }).then(function(newUser) {
      return self.logActivity(newUser._id, "signup", "local", req, newUser);
    })
    .then(function(newUser) {
      return processTransformations(onCreateActions, newUser, "local");
    })
    .then(function(finalNewUser) {
      return userDB.put(finalNewUser);
    }).then(function(finalNewUser) {
      if (!options.password) {
        finalNewUser.password = password;
      }
      emitter.emit("signup", finalNewUser, "local");
      return BPromise.resolve(finalNewUser);
    });
  }

  this.socialAuth = function(provider, auth, profile, req) {
    var user;
    var newAccount = false;
    var action;
    var baseUsername;
    req = req || {};
    var ip = req.ip;
    // It is important that we return a Bluebird promise so oauth.js can call .nodeify()
    return BPromise.resolve()
      .then(function() {
        return userDB.query("auth/" + provider, {key: profile.id, include_docs: true});
      })
      .then(function(results) {
        if (results.rows.length > 0) {
          user = results.rows[0].doc;
          return BPromise.resolve();
        }
        else {
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
          var emailFail = function() {
            return BPromise.reject({
              error: "Email already in use",
              message: "Your email is already in use. Try signing in first and then linking this account.",
              status: 409
            });
          };
          // Now we need to generate a username
          if (emailUsername) {
            if (!user.email) {
              return BPromise.reject({
                error: "No email provided",
                message: "An email is required for registration, but " + provider + " didn't supply one.",
                status: 400
              });
            }
            return self.validateEmailUsername(user.email)
              .then(function(err) {
                if (err) {
                  return emailFail();
                }
                return BPromise.resolve(user.email.toLowerCase());
              });
          }
          else {
            if (profile.username) {
              baseUsername = profile.username.toLowerCase();
            }
            else {
              // If a username isn't specified we'll take it from the email
              if (user.email) {
                var parseEmail = user.email.split("@");
                baseUsername = parseEmail[0].toLowerCase();
              }
              else if (profile.displayName) {
                baseUsername = profile.displayName.replace(/\s/g, "").toLowerCase();
              }
              else {
                baseUsername = profile.id.toLowerCase();
              }
            }
            return self.validateEmail(user.email)
              .then(function(err) {
                if (err) {
                  return emailFail();
                }
                return generateUsername(baseUsername);
              });
          }
        }
      })
      .then(function(finalUsername) {
        if (finalUsername) {
          user._id = finalUsername;
        }
        user[provider].auth = auth;
        user[provider].profile = profile;
        if (!user.name) {
          user.name = profile.displayName;
        }
        delete user[provider].profile._raw;
        if (newAccount) {
          return addUserDBs(user);
        }
        else {
          return BPromise.resolve(user);
        }
      })
      .then(function(userDoc) {
        action = newAccount ? "signup" : "login";
        return self.logActivity(userDoc._id, action, provider, req, userDoc);
      })
      .then(function(userDoc) {
        if (newAccount) {
          return processTransformations(onCreateActions, userDoc, provider);
        }
        else {
          return processTransformations(onLinkActions, userDoc, provider);
        }
      })
      .then(function(finalUser) {
        return userDB.put(finalUser);
      })
      .then(function() {
        if (action === "signup") {
          emitter.emit("signup", user, provider);
        }
        return BPromise.resolve(user);
      });
  };

  this.linkSocial = function(user_id, provider, auth, profile, req) {
    req = req || {};
    var user;
    // Load user doc
    return BPromise.resolve()
      .then(function() {
        return userDB.query("auth/" + provider, {key: profile.id});
      })
      .then(function(results) {
        if (results.rows.length === 0) {
          return BPromise.resolve();
        }
        else {
          if (results.rows[0].id !== user_id) {
            return BPromise.reject({
              error: "Conflict",
              message: "This " + provider + " profile is already in use by another account.",
              status: 409
            });
          }
        }
      })
      .then(function() {
        return userDB.get(user_id);
      })
      .then(function(theUser) {
        user = theUser;
        // Check for conflicting provider
        if (user[provider] && (user[provider].profile.id !== profile.id)) {
          return BPromise.reject({
            error: "Conflict",
            message: "Your account is already linked with another " + provider + "profile.",
            status: 409
          });
        }
        // Check email for conflict
        if (!profile.emails) {
          return BPromise.resolve({rows: []});
        }
        if (emailUsername) {
          return userDB.query("auth/emailUsername", {key: profile.emails[0].value});
        }
        else {
          return userDB.query("auth/email", {key: profile.emails[0].value});
        }
      })
      .then(function(results) {
        var passed;
        if (results.rows.length === 0) {
          passed = true;
        }
        else {
          passed = true;
          results.rows.forEach(function(row) {
            if (row.id !== user_id) {
              passed = false;
            }
          });
        }
        if (!passed) {
          return BPromise.reject({
            error: "Conflict",
            message: "The email " + profile.emails[0].value + " is already in use by another account.",
            status: 409
          });
        }
        else {
          return BPromise.resolve();
        }
      })
      .then(function() {
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
        return self.logActivity(user._id, "link", provider, req, user);
      })
      .then(function(userDoc) {
        return processTransformations(onLinkActions, userDoc, provider);
      })
      .then(function(finalUser) {
        return userDB.put(finalUser);
      })
      .then(function() {
        return BPromise.resolve(user);
      });
  };

  this.unlink = function(user_id, provider) {
    var user;
    return userDB.get(user_id)
      .then(function(theUser) {
        user = theUser;
        if (!provider) {
          return BPromise.reject({
            error: "Unlink failed",
            message: "You must specify a provider to unlink.",
            status: 400
          });
        }
        // We can only unlink if there are at least two providers
        if (!user.providers || !(user.providers instanceof Array) || user.providers.length < 2) {
          return BPromise.reject({
            error: "Unlink failed",
            message: "You can't unlink your only provider!",
            status: 400
          });
        }
        // We cannot unlink local
        if (provider === "local") {
          return BPromise.reject({
            error: "Unlink failed",
            message: "You can't unlink local.",
            status: 400
          });
        }
        // Check that the provider exists
        if (!user[provider] || typeof user[provider] !== "object") {
          return BPromise.reject({
            error: "Unlink failed",
            message: "Provider: " + util.capitalizeFirstLetter(provider) + " not found.",
            status: 404
          });
        }
        delete user[provider];
        // Remove the unlinked provider from the list of providers
        user.providers.splice(user.providers.indexOf(provider), 1);
        return userDB.put(user);
      })
      .then(function() {
        return BPromise.resolve(user);
      });
  };

  this.createSession = function(provider, req, refreshToken) {
    // console.log("createSession", Date.now());
    var permanent = req.body.permanent;
    var user = req.user;
    let origUser = JSON.parse(JSON.stringify(req.user || {}));
    var newToken;
    var newSession = {};
    var password;
    var jwtoken;
    var payload;
    req = req || {};
    var ip = req.ip;
    return generateSession(user._id, user.roles).then(function(token) {
      // console.log("generated session", Date.now());
      newToken = token;
      password = token.password;
      newToken.provider = provider;
      return dbAuth.storeKey(user._id, newToken.key, password, newToken.expires, user.roles);
    }).then(function() {
      // console.log("stored new temp user", Date.now());
      // Clear any failed login attempts
      if (provider === "local") {
        if (!user.local) user.local = {};
        user.local.failedLoginAttempts = 0;
        delete user.local.lockedUntil;
      }
      return self.logActivity(user._id, "login", provider, req, user);
    }).then(function() {
      // console.log("logged out sessions", Date.now());
      if (JSON.stringify(user) != JSON.stringify(origUser)) {
        return userDB.put(user);
      }
      return BPromise.resolve();
    }).then(function() {
      // console.log("putted final user", Date.now());
      return self.generateJWT(user, newToken.key, password, newToken.expires);
    }).then(function(jwt_, payload) {
      jwtoken = jwt_;
      if (refreshToken) {
        return self.generateRefreshJWT(user, permanent);
      }
      return BPromise.resolve();
    }).then(function(refreshToken) {
      // console.log("generated JWT", Date.now());
      if (refreshToken) {
        newSession.refreshToken = refreshToken.token;
        if (refreshToken.payload.exp) {
          newSession.refreshTokenExpires = refreshToken.payload.exp * 1000;
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
          var dbObj = url.parse(config.getItem("dbServer.publicURL"));
          publicURL = dbObj.format();
        }
        else {
          publicURL = config.getItem("dbServer.protocol") + config.getItem("dbServer.host") + "/";
        }
        Object.keys(user.personalDBs).forEach(function(finalDBName) {
          userDBs[user.personalDBs[finalDBName].name] = publicURL + finalDBName;
        });
        newSession.userDBs = userDBs;
      }
      if (user.profile) {
        newSession.profile = user.profile;
      }
      emitter.emit("login", newSession, provider);
      return BPromise.resolve(newSession, provider);
    });
  };

  this.handleFailedLogin = function(user, req) {
    req = req || {};
    var maxFailedLogins = config.getItem("security.maxFailedLogins");
    if (!maxFailedLogins) {
      return BPromise.resolve();
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
      lockoutTime = typeof lockoutTime === "string" ? ms(lockoutTime) : lockoutTime;
      user.local.lockedUntil = Date.now() + lockoutTime * 1000;
    }
    return self.logActivity(user._id, "failed login", "local", req, user)
      .then(function(finalUser) {
        return userDB.put(finalUser);
      })
      .then(function() {
        return BPromise.resolve(!!user.local.lockedUntil);
      });
  };

  this.logActivity = function(user_id, action, provider, req, userDoc, saveDoc) {
    var logSize = config.getItem("security.userActivityLogSize");
    if (!logSize) {
      return BPromise.resolve(userDoc);
    }
    var promise;
    if (userDoc) {
      promise = BPromise.resolve(userDoc);
    }
    else {
      if (saveDoc !== false) {
        saveDoc = true;
      }
      promise = userDB.get(user_id);
    }
    return promise
      .then(function(theUser) {
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
          return userDB.put(userDoc)
            .then(function() {
              return BPromise.resolve(userDoc);
            });
        }
        else {
          return BPromise.resolve(userDoc);
        }
      });
  };

  this.generateJWT = function(user, tempUser, tempPass, tempExpires) {
    return new Promise((resolve, reject) => {
      let tokenid = uuidv4();
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
      jwtExpires = typeof jwtExpires === "string" ? Math.floor(ms(jwtExpires) / 1000) : jwtExpires || Math.floor(ms("15m") / 1000);
      payload["exp"] = Math.floor(Date.now() / 1000) + jwtExpires;
      jwt.sign(payload, config.getItem("security.jwt.secret"), (err, token) => {
        if (err) {
          reject(err);
        }
        resolve({
          token: token,
          payload: payload
        });
      });
    });
  };

  this.generateRefreshJWT = function(user, permanent) {
    return new Promise((resolve, reject) => {
      let tokenid = uuidv4();
      let payload = {
        jti: tokenid,
        sub: user._id,
        iss: config.getItem("security.jwt.issuer"),
        iat: Math.floor(Date.now() / 1000),
        token_use: "refresh"
      };
      if (!permanent) {
        let jwtExpires = config.getItem("security.jwt.refreshExpires");
        jwtExpires = typeof jwtExpires === "string" ? Math.floor(ms(jwtExpires) / 1000) : jwtExpires || Math.floor(ms("30d") / 1000);
        payload["exp"] = Math.floor(Date.now() / 1000) + jwtExpires;
      }
      jwt.sign(payload, config.getItem("security.jwt.secret"), (err, token) => {
        if (err) {
          reject(err);
        }
        resolve({
          token: token,
          payload: payload
        });
      });
    });
  };

  this.refreshSession = function(req) {
    var user = req.user;
    var newSession;
    if (user.payload.token_use === "access" && user.payload.dbExpires < Math.floor(Date.now() / 1000)) {
      // console.log("dbSession still valid");
      return couchAuthDB.get("org.couchdb.user:" + user.payload.dbUser).then(function(tempUser) {
        tempUser.expires = Date.now() + sessionLife * 1000;
        tempUser.roles = user.roles;
        return couchAuthDB.put(tempUser);
      }).then(function() {
        return self.generateJWT(user, user.payload.dbUser, user.payload.dbPass, tempUser.expires);
      }).then(function(jwt_) {
        newSession.token = jwt_.token;
        newSession.expires = jwt_.payload.exp * 1000;
        newSession.issued = jwt._payload.iat * 1000;
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
            var dbObj = url.parse(config.getItem("dbServer.publicURL"));
            dbObj.auth = newSession.token + ":" + newSession.password;
            publicURL = dbObj.format();
          }
          else {
            publicURL = config.getItem("dbServer.protocol") + newSession.token + ":" + newSession.password + "@" +
              config.getItem("dbServer.host") + "/";
          }
          Object.keys(user.personalDBs).forEach(function(finalDBName) {
            userDBs[user.personalDBs[finalDBName].name] = publicURL + finalDBName;
          });
          newSession.userDBs = userDBs;
        }
        if (user.profile) {
          newSession.profile = user.profile;
        }
        emitter.emit("refresh", newSession, provider);
        return BPromise.resolve(newSession, provider);
      });
    }
    else if (user.payload.token_use === "refresh") {
      return this.createSession(null, req);
    }
    else {
      return this.createSession(null, req, true);
    }
  };

  this.resetPassword = function(form, req) {
    req = req || {};
    var ResetPasswordModel = new Model(resetPasswordModel);
    var passwordResetForm = new ResetPasswordModel(form);
    var user;
    return passwordResetForm.validate()
      .then(function() {
        var tokenHash = util.hashToken(form.token);
        return userDB.query("auth/passwordReset", {key: tokenHash, include_docs: true});
      }, function(err) {
        return BPromise.reject({
          error: "Validation failed",
          validationErrors: err,
          status: 400
        });
      })
      .then(function(results) {
        if (!results.rows.length) {
          return BPromise.reject({status: 400, error: "Invalid token"});
        }
        user = results.rows[0].doc;
        if (user.forgotPassword.expires < Date.now()) {
          return BPromise.reject({status: 400, error: "Token expired"});
        }
        return util.hashPassword(form.password);
      })
      .then(function(hash) {
        if (!user.local) {
          user.local = {};
        }
        user.local.salt = hash.salt;
        user.local.derived_key = hash.derived_key;
        if (user.providers.indexOf("local") === -1) {
          user.providers.push("local");
        }
        // logout user completely
        return self.logoutUserSessions(user, "all");
      })
      .then(function(userDoc) {
        user = userDoc;
        delete user.forgotPassword;
        return self.logActivity(user._id, "reset password", "local", req, user);
      })
      .then(function(finalUser) {
        return userDB.put(finalUser);
      })
      .then(function() {
        emitter.emit("password-reset", user);
        return BPromise.resolve(user);
      });
  };

  this.changePasswordSecure = function(user_id, form, req) {
    req = req || {};
    var self = this;
    var ChangePasswordModel = new Model(changePasswordModel);
    var changePasswordForm = new ChangePasswordModel(form);
    var user;
    return changePasswordForm.validate()
      .then(function() {
        return userDB.get(user_id);
      }, function(err) {
        return BPromise.reject({error: "Validation failed", validationErrors: err, status: 400});
      })
      .then(function() {
        return userDB.get(user_id);
      })
      .then(function(userDoc) {
        user = userDoc;
        if (user.local && user.local.salt && user.local.derived_key) {
          // Password is required
          if (!form.currentPassword) {
            return BPromise.reject({error: "Password change failed", message: "You must supply your current password in order to change it.", status: 400});
          }
          return util.verifyPassword(user.local, form.currentPassword);
        }
        else {
          return BPromise.resolve();
        }
      })
      .then(function() {
        return self.changePassword(user._id, form.newPassword, user, req);
      }, function(err) {
        return BPromise.reject(err || {error: "Password change failed", message: "The current password you supplied is incorrect.", status: 400});
      })
      .then(function() {
        if (req.user && req.user.key) {
          return self.logoutOthers(req.user.key);
        }
        else {
          return BPromise.resolve();
        }
      });
  };

  this.changePassword = function(user_id, newPassword, userDoc, req) {
    req = req || {};
    var promise, user;
    if (userDoc) {
      promise = BPromise.resolve(userDoc);
    }
    else {
      promise = userDB.get(user_id);
    }
    return promise
      .then(function(doc) {
        user = doc;
        return util.hashPassword(newPassword);
      }, function(err) {
        return BPromise.reject({
          error: "User not found",
          status: 404
        });
      })
      .then(function(hash) {
        if (!user.local) {
          user.local = {};
        }
        user.local.salt = hash.salt;
        user.local.derived_key = hash.derived_key;
        if (user.providers.indexOf("local") === -1) {
          user.providers.push("local");
        }
        return self.logActivity(user._id, "changed password", "local", req, user);
      })
      .then(function(finalUser) {
        return userDB.put(finalUser);
      })
      .then(function() {
        emitter.emit("password-change", user);
      });
  };

  this.forgotPassword = function(email, req) {
    req = req || {};
    var user, token, tokenHash;
    return userDB.query("auth/email", {key: email, include_docs: true})
      .then(function(result) {
        if (!result.rows.length) {
          return BPromise.reject({
            error: "User not found",
            status: 404
          });
        }
        user = result.rows[0].doc;
        token = util.URLSafeUUID();
        tokenHash = util.hashToken(token);
        user.forgotPassword = {
          token: tokenHash, // Store secure hashed token
          issued: Date.now(),
          expires: Date.now() + tokenLife * 1000
        };
        return self.logActivity(user._id, "forgot password", "local", req, user);
      })
      .then(function(finalUser) {
        return userDB.put(finalUser);
      })
      .then(function() {
        return mailer.sendEmail("forgotPassword", user.email || user.unverifiedEmail.email,
          {user: user, req: req, token: token}); // Send user the unhashed token
      }).then(function() {
        emitter.emit("forgot-password", user);
        return BPromise.resolve(user.forgotPassword);
      });
  };

  this.verifyEmail = function(token, req) {
    req = req || {};
    var user;
    return userDB.query("auth/verifyEmail", {key: token, include_docs: true})
      .then(function(result) {
        if (!result.rows.length) {
          return BPromise.reject({error: "Invalid token", status: 400});
        }
        user = result.rows[0].doc;
        user.email = user.unverifiedEmail.email;
        delete user.unverifiedEmail;
        emitter.emit("email-verified", user);
        return self.logActivity(user._id, "verified email", "local", req, user);
      })
      .then(function(finalUser) {
        return userDB.put(finalUser);
      });
  };

  this.changeEmail = function(user_id, newEmail, req) {
    req = req || {};
    if (!req.user) {
      req.user = {provider: "local"};
    }
    var user;
    return self.validateEmail(newEmail)
      .then(function(err) {
        if (err) {
          return BPromise.reject(err);
        }
        return userDB.get(user_id);
      })
      .then(function(userDoc) {
        user = userDoc;
        if (config.getItem("local.sendConfirmEmail")) {
          user.unverifiedEmail = {
            email: newEmail,
            token: util.URLSafeUUID()
          };
          return mailer.sendEmail("confirmEmail", user.unverifiedEmail.email, {req: req, user: user});
        }
        else {
          user.email = newEmail;
          return BPromise.resolve();
        }
      })
      .then(function() {
        emitter.emit("email-changed", user);
        return self.logActivity(user._id, "changed email", req.user.provider, req, user);
      })
      .then(function(finalUser) {
        return userDB.put(finalUser);
      });
  };

  this.addUserDB = function(user_id, dbName, type, designDocs, permissions) {
    var userDoc;
    var dbConfig = dbAuth.getDBConfig(dbName, type || "private");
    dbConfig.designDocs = designDocs || dbConfig.designDocs || "";
    dbConfig.permissions = permissions || dbConfig.permissions;
    dbConfig.memberRoles.push("user:" + user_id);
    // console.log(dbConfig.memberRoles);
    return userDB.get(user_id)
      .then(function(result) {
        userDoc = result;
        return dbAuth.addUserDB(userDoc, dbName, dbConfig.designDocs, dbConfig.type, dbConfig.permissions,
          dbConfig.adminRoles, dbConfig.memberRoles);
      })
      .then(function(finalDBName) {
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

  this.removeUserDB = function(user_id, dbName, deletePrivate, deleteShared) {
    var user;
    var update = false;
    return userDB.get(user_id)
      .then(function(userDoc) {
        user = userDoc;
        if (user.personalDBs && typeof user.personalDBs === "object") {
          Object.keys(user.personalDBs).forEach(function(db) {
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
        return BPromise.resolve();
      })
      .then(function() {
        if (update) {
          emitter.emit("user-db-removed", user_id, dbName);
          return userDB.put(user);
        }
        return BPromise.resolve();
      });
  };

  this.logoutUser = function(user) {
    return self.logoutUserSessions(user, "all");
  };

  this.logoutSession = function(user) {
    // console.log(user);
    return new Promise((resolve, reject) => {
      var session_id = user.payload.dbUser;
      var promises = [];
      promises.push(dbAuth.removeKeys(session_id));
      resolve(BPromise.all(promises));
    }).then(function() {
      // Clean out expired sessions
      return self.logoutUserSessions(user, "expired");
    }).then(function(finalUser) {
      emitter.emit("logout", user._id);
      return BPromise.resolve(false);
    });
  };

  this.logoutOthers = function(user, session_id) {
    return self.logoutUserSessions(user, "other", session_id);
  };

  this.logoutUserSessions = function(userDoc, op, currentSession) {
    return new Promise((resolve, reject) => {
      // When op is 'other' it will logout all sessions except for the specified 'currentSession'
      var promises = [];
      var promise;
      var sessions;
      if (op === "all" || op === "other") {
        promise = self.getSessions(userDoc._id);
      }
      else if (op === "expired") {
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
        BPromise.all(promises).then(function() {
          resolve(userDoc);
        });
      }).catch(err => {
        reject(err);
      });
    });
  };

  this.remove = function(user_id, destroyDBs) {
    var user;
    var promises = [];
    return userDB.get(user_id)
      .then(function(userDoc) {
        return self.logoutUserSessions(userDoc, "all");
      })
      .then(function(userDoc) {
        user = userDoc;
        if (destroyDBs !== true || !user.personalDBs) {
          return BPromise.resolve();
        }
        Object.keys(user.personalDBs).forEach(function(userdb) {
          if (user.personalDBs[userdb].type === "private") {
            promises.push(dbAuth.removeDB(userdb));
          }
        });
        return BPromise.all(promises);
      })
      .then(function() {
        return userDB.remove(user);
      });
  };

  this.removeExpiredKeys = dbAuth.removeExpiredKeys.bind(dbAuth);

  this.getSessions = function(user_id) {
    return couchAuthDB.query("_superlogin/user", {
      key: user_id,
      include_docs: true
    }).then(result => {
      return BPromise.resolve(result.rows.map(i => i.doc.name));
    }).catch(err => {
      return BPromise.reject(err);
    });
  };

  this.getExpiredSessions = function(user_id, date) {
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

  this.confirmSession = function(token) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, config.getItem("security.jwt.secret"), (err, payload) => {
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

  this.quitRedis = function() {
    return session.quit();
  };

  function generateSession(username, roles) {
    var token = util.URLSafeUUID();
    // Make sure our token doesn't start with illegal characters
    while (token[0] === "_" || token[0] === "-") {
      token = util.URLSafeUUID();
    }
    var password = util.URLSafeUUID();
    var now = Date.now();
    return BPromise.resolve({
      _id: username,
      key: token,
      password: password,
      issued: now,
      expires: now + sessionLife * 1000,
      roles: roles
    });
  }

  // Adds numbers to a base name until it finds a unique database key
  function generateUsername(base) {
    base = base.toLowerCase();
    var entries = [];
    var finalName;
    return userDB.allDocs({startkey: base, endkey: base + "\uffff", include_docs: false})
      .then(function(results) {
        if (results.rows.length === 0) {
          return BPromise.resolve(base);
        }
        for (var i = 0; i < results.rows.length; i++) {
          entries.push(results.rows[i].id);
        }
        if (entries.indexOf(base) === -1) {
          return BPromise.resolve(base);
        }
        var num = 0;
        while (!finalName) {
          num++;
          if (entries.indexOf(base + num) === -1) {
            finalName = base + num;
          }
        }
        return BPromise.resolve(finalName);
      });
  }

  function addUserDBs(newUser) {
    // Add personal DBs
    if (!config.getItem("userDBs.defaultDBs")) {
      return BPromise.resolve(newUser);
    }
    var promises = [];
    newUser.personalDBs = {};

    var processUserDBs = function(dbList, type) {
      dbList.forEach(function(userDBName) {
        var dbConfig = dbAuth.getDBConfig(userDBName);
        dbConfig.memberRoles.push("user:" + newUser._id);
        // console.log(dbConfig);
        promises.push(
          dbAuth.addUserDB(newUser, userDBName, dbConfig.designDocs, type, dbConfig.permissions, dbConfig.adminRoles,
            dbConfig.memberRoles)
            .then(function(finalDBName) {
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

    return BPromise.all(promises).then(function() {
      return BPromise.resolve(newUser);
    });
  }

  return this;
};
