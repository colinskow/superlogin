import events from "events";
import express from "express";

import Configure from "./configure";
import User from "./user";
import Oauth from "./oauth";
import loadRoutes from "./routes";
import localConfig from "./local";
import Middleware from "./middleware";
import Mailer from "./mailer";
import * as util from "./util";
import seed from "pouchdb-seed-design";

const PouchDB = require("pouchdb-core")
  .plugin(require("pouchdb-adapter-http"))
  .plugin(require("pouchdb-mapreduce"));

export default class {
  constructor(configData, passport, userDB, couchAuthDB) {
    const config = new Configure(configData, require("../config/default.config"));
    const router = express.Router();
    const emitter = new events.EventEmitter();

    if (!passport || typeof passport !== "object") {
      passport = require("passport");
    }
    const middleware = new Middleware(passport);

    // Some extra default settings if no config object is specified
    if (!configData) {
      config.setItem("testMode.noEmail", true);
      config.setItem("testMode.debugEmail", true);
    }

    // Create the DBs if they weren't passed in
    if (!userDB && config.getItem("dbServer.userDB")) {
      userDB = new PouchDB(util.getFullDBURL(config.getItem("dbServer"), config.getItem("dbServer.userDB")));
    }
    if (!couchAuthDB && config.getItem("dbServer.couchAuthDB")) {
      couchAuthDB = new PouchDB(util.getFullDBURL(config.getItem("dbServer"), config.getItem("dbServer.couchAuthDB")));
    }
    if (!userDB || typeof userDB !== "object") {
      throw new Error("userDB must be passed in as the third argument or specified in the config file under dbServer.userDB");
    }

    const mailer = new Mailer(config);
    const user = new User(config, userDB, couchAuthDB, mailer, emitter);
    const oauth = new Oauth(router, passport, user, config);

    // Seed design docs for the user database
    var userDesign = require("../designDocs/user-design");
    var couchDesign = require("../designDocs/couch-design");
    userDesign = util.addProvidersToDesignDoc(config, userDesign);
    seed(userDB, userDesign);
    seed(couchAuthDB, couchDesign);
    // Configure Passport local login and api keys
    localConfig(config, passport, user);
    // Load the routes
    loadRoutes(config, router, passport, user);

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
      hashPassword: util.hashPassword,
      verifyPassword: util.verifyPassword,
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
      // authentication middleware
      requireAuth: middleware.requireAuth,
      requireRole: middleware.requireRole,
      requireAnyRole: middleware.requireAnyRole,
      requireAllRoles: middleware.requireAllRoles
    });
  }
};
