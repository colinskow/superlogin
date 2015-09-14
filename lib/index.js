'use strict';
var events = require('events');
var express = require('express');
var BPromise = require('bluebird');
var PouchDB = require('pouchdb');
var seed = require('pouchdb-seed-design');

var Configure = require('./configure');
var User = require('./user');
var Oauth = require('./oauth');
var loadRoutes = require('./routes');
var localConfig = (require('./local'));
var Middleware = require('./middleware');
var Mailer = require('./mailer');
var util = require('./util');

module.exports = function (configData, passport, userDB, couchAuthDB) {

  var config = new Configure(configData, require('../config/default.config'));
  var router = express.Router();
  var emitter = new events.EventEmitter();

  if(!passport || typeof passport !== 'object') {
    passport = require('passport');
  }
  var middleware = new Middleware(passport);

  // Some extra default settings if no config object is specified
  if(!configData) {
    config.setItem('testMode.noEmail', true);
    config.setItem('testMode.debugEmail', true);
  }

  // Create the DBs if they weren't passed in
  if(!userDB && config.getItem('dbServer.userDB')) {
    userDB = new PouchDB(util.getFullDBURL(config.getItem('dbServer'), config.getItem('dbServer.userDB')));
  }
  if(!couchAuthDB && config.getItem('dbServer.couchAuthDB') && !config.getItem('dbServer.cloudant')) {
    couchAuthDB = new PouchDB(util.getFullDBURL(config.getItem('dbServer'), config.getItem('dbServer.couchAuthDB')));
  }
  if(!userDB || typeof userDB !== 'object') {
    throw new Error('userDB must be passed in as the third argument or specified in the config file under dbServer.userDB');
  }

  var mailer = new Mailer(config);
  var user = new User(config, userDB, couchAuthDB, mailer, emitter);
  var oauth = new Oauth(router, passport, user, config);

  // Seed design docs for the user database
  var userDesign = require('../designDocs/user-design');
  userDesign = util.addProvidersToDesignDoc(config, userDesign);
  seed(userDB, userDesign);
  // Configure Passport local login and api keys
  localConfig(config, passport, user);
  // Load the routes
  loadRoutes(config, router, passport, user);

  var superlogin = {
    config: config,
    router: router,
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
    onCreate: user.onCreate,
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
    confirmSession: user.confirmToken,
    removeExpiredKeys: user.removeExpiredKeys,
    sendEmail: mailer.sendEmail,
    quitRedis: user.quitRedis,
    // authentication middleware
    requireAuth: middleware.requireAuth,
    requireRole: middleware.requireRole,
    requireAnyRole: middleware.requireAnyRole,
    requireAllRoles: middleware.requireAllRoles,
  };

  // Inherit emitter
  for(var key in emitter) {
    superlogin[key] = emitter[key];
  }
  return superlogin;

};