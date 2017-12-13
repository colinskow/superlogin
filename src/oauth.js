import fs from "fs";
import path from "path";
import BPromise from "bluebird";
import ejs from "ejs";
import { _extend as extend } from "util";
import util from "./util";

var stateRequired = ["google", "linkedin"];

var self;

export default class Oauth {

  constructor(router, passport, user, config) {
    this.router = router;
    this.passport = passport;
    this.user = user;
    this.config = config;
    self = this;
  }

  // Function to initialize a session following authentication from a socialAuth provider
  async initSession(req, res, next) {
    var provider = self.getProvider(req.path);
    try {
      const mySession = await self.user.createSession(provider, req);
      const results = {
        error: null,
        session: mySession,
        link: null
      };
      var template;
      if (self.config.getItem("testMode.oauthTest")) {
        template = fs.readFileSync(path.join(__dirname, "../templates/oauth/auth-callback-test.ejs"), "utf8");
      }
      else {
        template = fs.readFileSync(path.join(__dirname, "../templates/oauth/auth-callback.ejs"), "utf8");
      }
      var html = ejs.render(template, results);
      res.status(200).send(html);
    }
    catch(err) {
      return next(err);
    }
  }

  // Function to initialize a session following authentication from a socialAuth provider
  async initTokenSession(req, res, next) {
    var provider = getProviderToken(req.path);
    try {
      const mySession = await self.user.createSession(provider, req)
      res.status(200).json(session);
    }
    catch(err) {
      return next(err);
    }
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
      template = fs.readFileSync(path.join(__dirname, "../templates/oauth/auth-callback-test.ejs"), "utf8");
    }
    else {
      template = fs.readFileSync(path.join(__dirname, "../templates/oauth/auth-callback.ejs"), "utf8");
    }
    var html = ejs.render(template, result);
    res.status(200).send(html);
  }

  // Called after an account has been succesfully linked using access_token provider
  linkTokenSuccess(req, res, next) {
    var provider = self.getProviderToken(req.path);
    res.status(200).json({
      ok: true,
      success: util.capitalizeFirstLetter(provider) + " successfully linked",
      provider: provider
    });
  }

  // Handles errors if authentication fails
  oauthErrorHandler(err, req, res, next) {
    var template;
    if (self.config.getItem("testMode.oauthTest")) {
      template = fs.readFileSync(path.join(__dirname, "../templates/oauth/auth-callback-test.ejs"), "utf8");
    }
    else {
      template = fs.readFileSync(path.join(__dirname, "../templates/oauth/auth-callback.ejs"), "utf8");
    }
    var html = ejs.render(template, {error: err.message, session: null, link: null});
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
    }
    else {
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
      self.router.get(
        "/" + provider,
        self.passportCallback(provider, options, "login")
      );
      // register provider callbacks
      self.router.get(
        "/" + provider + "/callback",
        self.passportCallback(provider, options, "login"),
        self.initSession,
        self.oauthErrorHandler
      );
      if (!self.config.getItem("security.disableLinkAccounts")) {
        // register link route
        self.router.get(
          "/link/" + provider,
          self.passport.authenticate("bearer", {session: false}),
          self.passportCallback(provider, options, "link")
        );
        // register link callback
        self.router.get(
          "/link/" + provider + "/callback",
          self.passport.authenticate("bearer", {session: false}),
          self.passportCallback(provider, options, "link"),
          self.linkSuccess,
          self.oauthErrorHandler
        );
      }
      console.log(provider + " loaded.");
    }
  }

  // A shortcut to register OAuth2 providers that follow the exact accessToken, refreshToken pattern.
  registerOAuth2(providerName, Strategy) {
    self.registerProvider(providerName, (credentials, passport, authHandler) => {
      self.passport.use(new Strategy(credentials,
        async (req, accessToken, refreshToken, profile, done) => {
          try {
            const res = await self.authHandler(
              req,
              providerName,
              {
                accessToken: accessToken,
                refreshToken: refreshToken
              },
              profile
            );
            done(res);
          }
          catch (err) {
            done(err);
          }
        }
      ));
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
      self.passport.use(providerName + "-token", new Strategy(credentials,
        async (req, accessToken, refreshToken, profile, done) => {
          try {
            const res = await self.authHandler(
              req,
              providerName,
              {
                accessToken: accessToken,
                refreshToken: refreshToken
              },
              profile
            );
            done(res);
          }
          catch (err) {
            done(err);
          }
        }));
      self.router.post(
        "/" + providerName + "/token",
        self.passportTokenCallback(providerName, options),
        self.initTokenSession,
        self.tokenAuthErrorHandler
      );
      if (!self.config.getItem("security.disableLinkAccounts")) {
        self.router.post(
          "/link/" + providerName + "/token",
          self.passport.authenticate("bearer", {session: false}),
          self.passportTokenCallback(providerName, options),
          self.linkTokenSuccess,
          self.tokenAuthErrorHandler
        );
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
    }
    else {
      return self.user.socialAuth(provider, auth, profile, req);
    }
  }

  // Configures the self.passport.authenticate for the given provider, passing in options
  // Operation is 'login' or 'link'
  passportCallback(provider, options, operation) {
    // console.log(provider, options, operation);
    return (req, res, next) => {
      var theOptions = extend({}, options);
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
      var theOptions = extend({}, options);
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
      }
      else {
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

};
