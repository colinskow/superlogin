import url from "url";
import BPromise from "bluebird";
import Model from "sofa-model";
import * as util from "./util";
import DBAuth from "./dbauth";
import _ from "lodash";
import jwt from "jsonwebtoken";
import uuidv4 from "uuid/v4";
import ms from "ms";

// regexp from https://github.com/angular/angular.js/blob/master/src/ng/directive/input.js#L4
let EMAIL_REGEXP = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$/;
let USER_REGEXP = /^[a-z0-9_-]{3,16}$/;

export default function(config, userDB, couchAuthDB, mailer, emitter) {
  let self = this;
  let dbAuth = new DBAuth(config, userDB, couchAuthDB);
  let onCreateActions = [];
  let onLinkActions = [];

  // Token valid for 24 hours by default
  // Forget password token life
  let tokenLife = config.getItem("security.tokenLife");
  tokenLife = typeof tokenLife === "string" ? ms(tokenLife) : tokenLife || ms("1h");
  // Session token life
  let sessionLife = config.getItem("security.sessionLife");
  sessionLife = typeof sessionLife === "string" ? ms(sessionLife) : sessionLife || ms("15m");

  let emailUsername = config.getItem("local.emailUsername");

  this.validateUsername = async function(username) {
    if (!username) {
      return;
    }
    if (!username.match(USER_REGEXP)) {
      return "Invalid username";
    }
    const result = await userDB.query("auth/username", { key: username });
    if (result.rows.length === 0) {
      // Pass!

    }
    else {
      return "already in use";
    }
  };

  this.validateEmail = async function(email) {
    if (!email) {
      return;
    }
    if (!email.match(EMAIL_REGEXP)) {
      return;
    }
    const result = await userDB.query("auth/email", { key: email });
    if (result.rows.length === 0) {
      // Pass!

    }
    else {
      return "already in use";
    }
  };

  this.validateEmailUsername = async function(email) {
    if (!email) {
      return;
    }
    if (!email.match(EMAIL_REGEXP)) {
      return "invalid email";
    }
    const result = await userDB.query("auth/emailUsername", { key: email });
    if (result.rows.length === 0) {

    }
    else {
      return "already in use";
    }
  };

  // Validation function for ensuring that two fields match
  this.matches = function(value, option, key, attributes) {
    if (attributes && attributes[option] !== value) {
      return "does not match " + option;
    }
  };

  let passwordConstraints = {
    presence: true,
    length: {
      minimum: 6,
      message: "must be at least 6 characters"
    },
    matches: "confirmPassword"
  };

  passwordConstraints = _.merge({}, passwordConstraints, config.getItem("local.passwordConstraints"));

  let userModel = {
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

  let resetPasswordModel = {
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

  let changePasswordModel = {
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
    // console.log("processTransformations", fnArray, userDoc, provider);
    let promise;
    fnArray.forEach(function(fn) {
      if (!promise) {
        promise = fn(userDoc, provider);
      }
      else {
        if (!promise.then || typeof promise.then !== "function") {
          throw new Error("onCreate function must return a promise");
        }
        promise.then(function(newUserDoc) {
          return fn(newUserDoc, provider);
        });
      }
    });
    if (!promise) {
      promise = BPromise.resolve(userDoc);
    }
    return promise;
  }

  this.get = async function(login) {
    let query;
    if (emailUsername) {
      query = "emailUsername";
    }
    else {
      query = EMAIL_REGEXP.test(login) ? "email" : "username";
    }
    const results = await userDB.query("auth/" + query, {
      key: login,
      include_docs: true
    });
    if (results.rows.length > 0) {
      return results.rows[0].doc;
    }
    else {
      return null;
    }
  };

  this.create = async function(form, req) {
    req = req || {};
    let newUser;
    let finalUserModel = userModel;
    let newUserModel = config.getItem("userModel");
    if (typeof newUserModel === "object") {
      let whitelist;
      if (newUserModel.whitelist) {
        whitelist = util.arrayUnion(userModel.whitelist, newUserModel.whitelist);
      }
      finalUserModel = _.merge({}, userModel, config.getItem("userModel"));
      finalUserModel.whitelist = whitelist || finalUserModel.whitelist;
    }
    let UserModel = new Model(finalUserModel);
    let user = new UserModel(form);
    try {
      newUser = await user.process();
    }
    catch (err) {
      let error = new Error("Validation failed");
      error.validationErrors = err;
      error.status = 400;
      throw error;
    }
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
    const hash = await util.hashPassword(newUser.password);
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
    await addUserDBs(newUser);
    await self.logActivity(newUser._id, "signup", "local", req, newUser);
    await processTransformations(onCreateActions, newUser, "local");
    const result = await userDB.put(newUser);
    newUser._rev = result.rev;
    if (config.getItem("local.sendConfirmEmail")) {
      await mailer.sendEmail("confirmEmail", newUser.unverifiedEmail.email, {req: req, user: newUser});
    }
    emitter.emit("signup", newUser, "local");
    return newUser;
  };

  this.createManual = async function(options, mergeDoc) {
    // options: {
    //    username: "customUser",
    //    password: "mySafePassword"
    //    roles: [],
    //    createPersonalDBs: bool
    // }
    let req = {};
    // declare id, generate random one if none is specified
    let userId;
    // same applies to password
    let password;
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
    if (!options.username) {
      // generate a valid username
      userId = util.URLSafeUUID();
      // Make sure our token doesn't start with illegal characters
      while (userId[0] === "_" || userId[0] === "-") {
        userId = util.URLSafeUUID();
      }
      // we just generated a valid username
      // no need to check later
    }
    else {
      // use to specified username
      userId = options.username;
      await self.validateUsername(userId);
    }
    // if no password is specified, generate one
    if (!password) password = util.URLSafeUUID();
    if (!userId) {
      throw new Error("Username must not be empty.");
    }
    manualModel._id = userId;
    // username is valid, generate password hash
    const hash = await util.hashPassword(password);
    manualModel.local.salt = hash.salt;
    manualModel.local.derived_key = hash.derived_key;
    // we only want to create personal dbs when explicitly specified
    if (options.createPersonalDBs) {
      await addUserDBs(manualModel);
    }
    await self.logActivity(manualModel._id, "signup", "local", req, manualModel);
    await processTransformations(onCreateActions, manualModel, "local");
    await userDB.put(manualModel);
    if (!options.password) {
      manualModel.password = password;
    }
    emitter.emit("signup", manualModel, "local");
    return manualModel;
  };

  this.socialAuth = async function(provider, auth, profile, req) {
    let user;
    let newAccount = false;
    let action;
    let baseUsername;
    req = req || {};
    let ip = req.ip;
    // It is important that we return a Bluebird promise so oauth.js can call .nodeify()
    const results = await userDB.query("auth/" + provider, { key: profile.id, include_docs: true });
    if (results.rows.length > 0) {
      user = results.rows[0].doc;
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
      let emailFail = function() {
        let error = new Error("Your email is already in use. Try signing in first and then linking this account.");
        error.status = 409;
        error.name = "Email already in use";
        throw error;
      };
      // Now we need to generate a username
      if (emailUsername) {
        if (!user.email) {
          let error = new Error("An email is required for registration, but " + provider + " didn't supply one.");
          error.status = 400;
          error.name = "No email provided";
          throw error;
        }
        const err = await self.validateEmailUsername(user.email);
        if (err) {
          return emailFail();
        }
        user._id = user.email.toLowerCase();
      }
      else {
        if (profile.username) {
          baseUsername = profile.username.toLowerCase();
        }
        else {
          // If a username isn't specified we'll take it from the email
          if (user.email) {
            let parseEmail = user.email.split("@");
            baseUsername = parseEmail[0].toLowerCase();
          }
          else if (profile.displayName) {
            baseUsername = profile.displayName.replace(/\s/g, "").toLowerCase();
          }
          else {
            baseUsername = profile.id.toLowerCase();
          }
        }
        const err = await self.validateEmail(user.email);
        if (err) {
          return emailFail();
        }
        user._id = await generateUsername(baseUsername);
      }
    }
    user[provider].auth = auth;
    user[provider].profile = profile;
    if (!user.name) {
      user.name = profile.displayName;
    }
    delete user[provider].profile._raw;
    if (newAccount) {
      await addUserDBs(user);
    }
    action = newAccount ? "signup" : "login";
    await self.logActivity(user._id, action, provider, req, user);
    if (newAccount) {
      await processTransformations(onCreateActions, user, provider);
    }
    else {
      await processTransformations(onLinkActions, user, provider);
    }
    await userDB.put(user);
    if (action === "signup") {
      emitter.emit("signup", user, provider);
    }
    return user;
  };

  this.linkSocial = async function(userId, provider, auth, profile, req) {
    req = req || {};
    // Load user doc
    const results = await userDB.query("auth/" + provider, { key: profile.id });
    if (results.rows.length > 0) {
      if (results.rows[0].id !== userId) {
        let error = new Error("This " + provider + " profile is already in use by another account.");
        error.name = "Conflict";
        error.status = 409;
        throw error;
      }
    }
    const user = await userDB.get(userId);
    // Check for conflicting provider
    if (user[provider] && (user[provider].profile.id !== profile.id)) {
      let error = new Error("Your account is already linked with another " + provider + "profile.");
      error.name = "Conflict";
      error.status = 409;
      throw error;
    }
    // Check email for conflict
    let emailRes;
    if (!profile.emails) {
      emailRes = { rows: [] };
    }
    if (emailUsername) {
      emailRes = await userDB.query("auth/emailUsername", {key: profile.emails[0].value});
    }
    else {
      emailRes = await userDB.query("auth/email", {key: profile.emails[0].value});
    }
    let passed;
    if (emailRes.rows.length === 0) {
      passed = true;
    }
    else {
      passed = true;
      emailRes.rows.forEach(function(row) {
        if (row.id !== userId) {
          passed = false;
        }
      });
    }
    if (!passed) {
      let error = new Error("The email " + profile.emails[0].value + " is already in use by another account.");
      error.name = "Conflict";
      error.status = 409;
      throw error;
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
    await self.logActivity(user._id, "link", provider, req, user);
    await processTransformations(onLinkActions, user, provider);
    await userDB.put(user);
    return user;
  };

  this.unlink = async function(userId, provider) {
    const user = await userDB.get(userId);
    if (!provider) {
      let error = new Error("You must specify a provider to unlink.");
      error.name = "Unlink failed";
      error.status = 400;
      throw error;
    }
    // We can only unlink if there are at least two providers
    if (!user.providers || !(user.providers instanceof Array) || user.providers.length < 2) {
      let error = new Error("You can't unlink your only provider!");
      error.name = "Unlink failed";
      error.status = 400;
      throw error;
    }
    // We cannot unlink local
    if (provider === "local") {
      let error = new Error("You can't unlink local.");
      error.name = "Unlink failed";
      error.status = 400;
      throw error;
    }
    // Check that the provider exists
    if (!user[provider] || typeof user[provider] !== "object") {
      let error = new Error("Provider: " + util.capitalizeFirstLetter(provider) + " not found.");
      error.name = "Unlink failed";
      error.status = 404;
      throw error;
    }
    delete user[provider];
    // Remove the unlinked provider from the list of providers
    user.providers.splice(user.providers.indexOf(provider), 1);
    await userDB.put(user);
    return user;
  };

  this.createSession = async function(userId, provider, req, refreshToken) {
    // console.log("createSession", Date.now());
    req = req || {};
    const permanent = req.body && req.body.permanent;
    let user = req.user;
    if (!user) {
      user = await this.get(userId);
    }
    const origUser = JSON.parse(JSON.stringify(req.user || {}));
    const newSession = {};
    let password;
    let jwtoken;
    req = req || {};
    const newToken = await generateSession(user._id, user.roles);
    // console.log("generated session", Date.now());
    password = newToken.password;
    newToken.provider = provider;
    await dbAuth.storeKey(user._id, newToken.key, password, newToken.expires, user.roles);
    // console.log("stored new temp user", Date.now());
    // Clear any failed login attempts
    if (provider === "local") {
      if (!user.local) user.local = {};
      user.local.failedLoginAttempts = 0;
      delete user.local.lockedUntil;
    }
    await self.logActivity(user._id, "login", provider, req, user);
    // console.log("logged out sessions", Date.now());
    if (JSON.stringify(user) !== JSON.stringify(origUser)) {
      await userDB.put(user);
    }
    // console.log("putted final user", Date.now());
    jwtoken = await self.generateJWT(user, newToken.key, password, newToken.expires);
    if (refreshToken) {
      const rt = await self.generateRefreshJWT(user, permanent);
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
      let userDBs = {};
      let publicURL;
      if (config.getItem("dbServer.publicURL")) {
        let dbObj = url.parse(config.getItem("dbServer.publicURL"));
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
    return newSession;
  };

  this.handleFailedLogin = async function(user, req) {
    req = req || {};
    let maxFailedLogins = config.getItem("security.maxFailedLogins");
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
    await self.logActivity(user._id, "failed login", "local", req, user);
    await userDB.put(user);
    return !!user.local.lockedUntil;
  };

  this.logActivity = async function(userId, action, provider, req, userDoc, saveDoc) {
    let logSize = config.getItem("security.userActivityLogSize");
    if (!logSize) {
      return userDoc;
    }
    if (!userDoc) {
      if (saveDoc !== false) {
        saveDoc = true;
      }
      userDoc = await userDB.get(userId);
    }
    if (!userDoc.activity || !(userDoc.activity instanceof Array)) {
      userDoc.activity = [];
    }
    let entry = {
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
      await userDB.put(userDoc);
    }
    return userDoc;
  };

  this.generateJWT = async function(user, tempUser, tempPass, tempExpires) {
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
    const token = await BPromise.promisify(jwt.sign)(payload, config.getItem("security.jwt.secret"));
    return {
      token: token,
      payload: payload
    };
  };

  this.generateRefreshJWT = async function(user, permanent) {
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
    const token = await BPromise.promisify(jwt.sign)(payload, config.getItem("security.jwt.secret"));
    return {
      token: token,
      payload: payload
    };
  };

  this.refreshSession = async function(req) {
    let user = req.user;
    let newSession = {};
    let newExpires;
    let provider = null;
    if (user.payload.token_use === "access" && user.payload.dbExpires < Date.now()) {
      const tempUser = await couchAuthDB.get("org.couchdb.user:" + user.payload.dbUser);
      newExpires = Date.now() + sessionLife;
      tempUser.expires = newExpires;
      tempUser.roles = user.roles;
      await couchAuthDB.put(tempUser);
      const jwt_ = await self.generateJWT(user, user.payload.dbUser, user.payload.dbPass, newExpires);
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
        let userDBs = {};
        let publicURL;
        if (config.getItem("dbServer.publicURL")) {
          let dbObj = url.parse(config.getItem("dbServer.publicURL"));
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
      return newSession;
    }
    else if (user.payload.token_use === "refresh") {
      const newSession = await this.createSession(user._id, null, req);
      emitter.emit("refresh", newSession, provider);
      return newSession;
    }
    else {
      const newSession = await this.createSession(user._id, null, req, true);
      emitter.emit("refresh", newSession, provider);
      return newSession;
    }
  };

  this.resetPassword = async function(form, req) {
    req = req || {};
    let ResetPasswordModel = new Model(resetPasswordModel);
    let passwordResetForm = new ResetPasswordModel(form);
    let user;
    try {
      await passwordResetForm.validate();
    }
    catch (err) {
      let error = new Error("Validation failed");
      error.validationErrors = err;
      throw error;
    }
    let tokenHash = util.hashToken(form.token);
    const results = await userDB.query("auth/passwordReset", {key: tokenHash, include_docs: true});
    if (!results.rows.length) {
      return BPromise.reject({status: 400, error: "Invalid token"});
    }
    user = results.rows[0].doc;
    if (user.forgotPassword.expires < Date.now()) {
      return BPromise.reject({status: 400, error: "Token expired"});
    }
    const hash = await util.hashPassword(form.password);
    if (!user.local) {
      user.local = {};
    }
    user.local.salt = hash.salt;
    user.local.derived_key = hash.derived_key;
    if (user.providers.indexOf("local") === -1) {
      user.providers.push("local");
    }
    // logout user completely
    await self.logoutUserSessions(user, "all");
    delete user.forgotPassword;
    await self.logActivity(user._id, "reset password", "local", req, user);
    await userDB.put(user);
    emitter.emit("password-reset", user);
    return user;
  };

  this.changePasswordSecure = async function(userId, form, req) {
    req = req || {};
    let self = this;
    let ChangePasswordModel = new Model(changePasswordModel);
    let changePasswordForm = new ChangePasswordModel(form);
    try {
      changePasswordForm.validate();
    }
    catch (err) {
      let error = new Error("Validation failed");
      error.validationErrors = err;
      throw error;
    }
    const user = await userDB.get(userId);
    if (user.local && user.local.salt && user.local.derived_key) {
      // Password is required
      if (!form.currentPassword) {
        let error = new Error("You must supply your current password in order to change it.");
        error.name = "You must supply your current password in order to change it.";
        throw error;
      }
      try {
        await util.verifyPassword(user.local, form.currentPassword);
      }
      catch (err) {
        let error = new Error("The current password you supplied is incorrect.");
        error.name = "Password change failed";
        throw error;
      }
    }
    await self.changePassword(user._id, form.newPassword, user, req);
    if (req.user && req.user.key) {
      await self.logoutOthers(req.user.key);
    }
  };

  this.changePassword = async function(userId, newPassword, userDoc, req) {
    req = req || {};
    let user;
    if (!userDoc) {
      user = await userDB.get(userId);
    }
    else {
      user = userDoc;
    }
    const hash = await util.hashPassword(newPassword);
    if (!user.local) {
      user.local = {};
    }
    user.local.salt = hash.salt;
    user.local.derived_key = hash.derived_key;
    if (user.providers.indexOf("local") === -1) {
      user.providers.push("local");
    }
    await self.logActivity(user._id, "changed password", "local", req, user);
    await userDB.put(user);
    emitter.emit("password-change", user);
  };

  this.forgotPassword = async function(email, req) {
    req = req || {};
    let user;
    let token;
    let tokenHash;
    const result = await userDB.query("auth/email", {key: email, include_docs: true});
    if (!result.rows.length) {
      throw new Error("User not found");
    }
    user = result.rows[0].doc;
    token = util.URLSafeUUID();
    tokenHash = util.hashToken(token);
    user.forgotPassword = {
      token: tokenHash, // Store secure hashed token
      issued: Date.now(),
      expires: Date.now() + tokenLife
    };
    await self.logActivity(user._id, "forgot password", "local", req, user);
    await userDB.put(user);
    await mailer.sendEmail(
      "forgotPassword",
      user.email || user.unverifiedEmail.email,
      {
        user: user,
        req: req,
        token: token
      }
    ); // Send user the unhashed token
    emitter.emit("forgot-password", user);
    return user.forgotPassword;
  };

  this.verifyEmail = async function(token, req) {
    req = req || {};
    let user;
    const result = await userDB.query("auth/verifyEmail", { key: token, include_docs: true });
    if (!result.rows.length) {
      return BPromise.reject({error: "Invalid token", status: 400});
    }
    user = result.rows[0].doc;
    user.email = user.unverifiedEmail.email;
    delete user.unverifiedEmail;
    emitter.emit("email-verified", user);
    await self.logActivity(user._id, "verified email", "local", req, user);
    await userDB.put(user);
  };

  this.changeEmail = async function(userId, newEmail, req) {
    req = req || {};
    if (!req.user) {
      req.user = {provider: "local"};
    }
    const err = await self.validateEmail(newEmail);
    if (err) {
      throw new Error(err);
    }
    const user = await userDB.get(userId);
    if (config.getItem("local.sendConfirmEmail")) {
      user.unverifiedEmail = {
        email: newEmail,
        token: util.URLSafeUUID()
      };
      await mailer.sendEmail("confirmEmail", user.unverifiedEmail.email, { req: req, user: user });
    }
    else {
      user.email = newEmail;
    }
    emitter.emit("email-changed", user);
    await self.logActivity(user._id, "changed email", req.user.provider, req, user);
    await userDB.put(user);
  };

  this.addUserDB = async function(userId, dbName, type, designDocs, permissions) {
    let dbConfig = dbAuth.getDBConfig(dbName, type || "private");
    dbConfig.designDocs = designDocs || dbConfig.designDocs || "";
    dbConfig.permissions = permissions || dbConfig.permissions;
    dbConfig.memberRoles.push("user:" + userId);
    // console.log(dbConfig.memberRoles);
    const userDoc = await userDB.get(userId);
    const finalDBName = await dbAuth.addUserDB(
      userDoc,
      dbName,
      dbConfig.designDocs,
      dbConfig.type,
      dbConfig.permissions,
      dbConfig.adminRoles,
      dbConfig.memberRoles
    );
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
    emitter.emit("user-db-added", userId, dbName);
    await userDB.put(userDoc);
  };

  this.removeUserDB = async function(userId, dbName, deletePrivate, deleteShared) {
    let update = false;
    const user = await userDB.get(userId);
    if (user.personalDBs && typeof user.personalDBs === "object") {
      Object.keys(user.personalDBs).forEach(function(db) {
        if (user.personalDBs[db].name === dbName) {
          let type = user.personalDBs[db].type;
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
    if (update) {
      emitter.emit("user-db-removed", userId, dbName);
      await userDB.put(user);
    }
  };

  this.logoutUser = async function(user) {
    await self.logoutUserSessions(user, "all");
    emitter.emit("logout-all", user._id);
  };

  this.logoutSession = async function(user, sessionId) {
    await dbAuth.removeKeys(sessionId);
    await self.logoutUserSessions(user, "expired");
    emitter.emit("logout", user._id);
    return false;
  };

  this.logoutOthers = function(user, sessionId) {
    return self.logoutUserSessions(user, "other", sessionId);
  };

  this.logoutUserSessions = function(userDoc, op, currentSession) {
    return new Promise((resolve, reject) => {
      // When op is 'other' it will logout all sessions except for the specified 'currentSession'
      let promises = [];
      let promise;
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
          let index = sessions.indexOf(currentSession);
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

  this.remove = function(userId, destroyDBs) {
    let user;
    let promises = [];
    return userDB.get(userId)
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

  this.getSessions = function(userId) {
    return couchAuthDB.query("_superlogin/user", {
      key: userId,
      include_docs: true
    }).then(result => {
      return BPromise.resolve(result.rows.map(i => i.doc.name));
    }).catch(err => {
      return BPromise.reject(err);
    });
  };

  this.getExpiredSessions = function(userId, date) {
    return couchAuthDB.query("_superlogin/expired", {
      include_docs: true
    }).then(result => {
      if (userId) {
        return result.rows.filter(i => {
          return i.doc.user_id === userId && i.doc.expires < Math.floor(Date.now() / 1000);
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

  this.getPayload = function(token) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, config.getItem("security.jwt.secret"), (err, payload) => {
        if (err) {
          reject(err);
        }
        resolve(payload);
      });
    });
  };

  function generateSession(username, roles) {
    let token = util.URLSafeUUID();
    // Make sure our token doesn't start with illegal characters
    while (token[0] === "_" || token[0] === "-") {
      token = util.URLSafeUUID();
    }
    // console.log(sessionLife);
    let password = util.URLSafeUUID();
    let now = Date.now();
    return BPromise.resolve({
      _id: username,
      key: token,
      password: password,
      issued: now,
      expires: now + sessionLife,
      roles: roles
    });
  }

  // Adds numbers to a base name until it finds a unique database key
  async function generateUsername(base) {
    console.log(base);
    base = base.toLowerCase();
    let entries = [];
    let finalName;
    const results = await userDB.allDocs({
      startkey: base,
      endkey: base + "\ufff0",
      include_docs: false
    });
    console.log(results);
    if (results.rows.length === 0) {
      return base;
    }
    results.rows.forEach(e => {
      console.log(e.id);
      entries.push(e.id);
    });
    console.log(entries);
    if (entries.indexOf(base) === -1) {
      return base;
    }
    let num = 0;
    while (!finalName) {
      num++;
      if (entries.indexOf(base + num) === -1) {
        finalName = base + num;
      }
    }
    console.log(finalName);
    return finalName;
  }

  function addUserDBs(newUser) {
    // Add personal DBs
    if (!config.getItem("userDBs.defaultDBs")) {
      return BPromise.resolve(newUser);
    }
    let promises = [];
    newUser.personalDBs = {};

    let processUserDBs = function(dbList, type) {
      dbList.forEach(function(userDBName) {
        let dbConfig = dbAuth.getDBConfig(userDBName);
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
    let defaultPrivateDBs = config.getItem("userDBs.defaultDBs.private");
    if (!Array.isArray(defaultPrivateDBs)) {
      defaultPrivateDBs = [];
    }
    processUserDBs(defaultPrivateDBs, "private");
    let defaultSharedDBs = config.getItem("userDBs.defaultDBs.shared");
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
