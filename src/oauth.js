import fs from "fs";
import path from "path";
import ejs from "ejs";
import * as util from "./util";

var stateRequired = ["google", "linkedin"];

export default function(router, passport, user, config) {
  // Function to initialize a session following authentication from a socialAuth provider
  async function initSession(req, res, next) {
    var provider = getProvider(req.path);
    try {
      const mySession = await user.createSession(provider, req);
      const results = {
        error: null,
        session: mySession,
        link: null
      };
      var template;
      if (config.getItem("testMode.oauthTest")) {
        template = fs.readFileSync(path.join(__dirname, "../templates/oauth/auth-callback-test.ejs"), "utf8");
      }
      else {
        template = fs.readFileSync(path.join(__dirname, "../templates/oauth/auth-callback.ejs"), "utf8");
      }
      var html = ejs.render(template, results);
      res.status(200).send(html);
    }
    catch (err) {
      return next(err);
    }
  }

  // Function to initialize a session following authentication from a socialAuth provider
  async function initTokenSession(req, res, next) {
    var provider = getProviderToken(req.path);
    try {
      const session = await user.createSession(provider, req);
      res.status(200).json(session);
    }
    catch (err) {
      return next(err);
    }
  }

  // Called after an account has been succesfully linked
  function linkSuccess(req, res, next) {
    var provider = getProvider(req.path);
    var result = {
      error: null,
      session: null,
      link: provider
    };
    var template;
    if (config.getItem("testMode.oauthTest")) {
      template = fs.readFileSync(path.join(__dirname, "../templates/oauth/auth-callback-test.ejs"), "utf8");
    }
    else {
      template = fs.readFileSync(path.join(__dirname, "../templates/oauth/auth-callback.ejs"), "utf8");
    }
    var html = ejs.render(template, result);
    res.status(200).send(html);
  }

  // Called after an account has been succesfully linked using access_token provider
  function linkTokenSuccess(req, res, next) {
    var provider = getProviderToken(req.path);
    res.status(200).json({
      ok: true,
      success: util.capitalizeFirstLetter(provider) + " successfully linked",
      provider: provider
    });
  }

  // Handles errors if authentication fails
  function oauthErrorHandler(err, req, res, next) {
    var template;
    if (config.getItem("testMode.oauthTest")) {
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
  function tokenAuthErrorHandler(err, req, res, next) {
    var status;
    if (req.user && req.user._id) {
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
  function registerProvider(provider, configFunction) {
    console.log(provider, this);
    provider = provider.toLowerCase();
    var configRef = "providers." + provider;
    if (config.getItem(configRef + ".credentials")) {
      var credentials = config.getItem(configRef + ".credentials");
      credentials.passReqToCallback = true;
      var options = config.getItem(configRef + ".options") || {};
      configFunction(credentials, passport, authHandler);
      // register provider routes
      router.get(
        "/" + provider,
        passportCallback(provider, options, "login")
      );
      // register provider callbacks
      router.get(
        "/" + provider + "/callback",
        passportCallback(provider, options, "login"),
        initSession,
        oauthErrorHandler
      );
      if (!config.getItem("security.disableLinkAccounts")) {
        // register link route
        router.get(
          "/link/" + provider,
          passport.authenticate("bearer", {session: false}),
          passportCallback(provider, options, "link")
        );
        // register link callback
        router.get(
          "/link/" + provider + "/callback",
          passport.authenticate("bearer", {session: false}),
          passportCallback(provider, options, "link"),
          linkSuccess,
          oauthErrorHandler
        );
      }
      console.log(provider + " loaded.");
    }
  }

  // A shortcut to register OAuth2 providers that follow the exact accessToken, refreshToken pattern.
  function registerOAuth2(providerName, Strategy) {
    registerProvider(providerName, (credentials, passport, authHandler) => {
      passport.use(new Strategy(credentials,
        async(req, accessToken, refreshToken, profile, done) => {
          try {
            const res = await authHandler(
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
  function registerTokenProvider(providerName, Strategy) {
    providerName = providerName.toLowerCase();
    var configRef = "providers." + providerName;
    if (config.getItem(configRef + ".credentials")) {
      var credentials = config.getItem(configRef + ".credentials");
      credentials.passReqToCallback = true;
      var options = config.getItem(configRef + ".options") || {};
      // Configure the Passport Strategy
      passport.use(providerName + "-token", new Strategy(credentials,
        async(req, accessToken, refreshToken, profile, done) => {
          try {
            const res = await authHandler(
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
      router.post(
        "/" + providerName + "/token",
        passportTokenCallback(providerName, options),
        initTokenSession,
        tokenAuthErrorHandler
      );
      if (!config.getItem("security.disableLinkAccounts")) {
        router.post(
          "/link/" + providerName + "/token",
          passport.authenticate("bearer", {session: false}),
          passportTokenCallback(providerName, options),
          linkTokenSuccess,
          tokenAuthErrorHandler
        );
      }
      console.log(providerName + "-token loaded.");
    }
  }

  // This is called after a user has successfully authenticated with a provider
  // If a user is authenticated with a bearer token we will link an account, otherwise log in
  // auth is an object containing 'access_token' and optionally 'refresh_token'
  function authHandler(req, provider, auth, profile) {
    if (req.user && req.user._id && req.user.key) {
      return user.linkSocial(req.user._id, provider, auth, profile, req);
    }
    else {
      return user.socialAuth(provider, auth, profile, req);
    }
  }

  // Configures the passport.authenticate for the given provider, passing in options
  // Operation is 'login' or 'link'
  function passportCallback(provider, options, operation) {
    // console.log(provider, options, operation);
    return (req, res, next) => {
      var theOptions = Object.assign({}, options);
      if (provider === "linkedin") {
        theOptions.state = true;
      }
      var accessToken = req.query.bearer_token || req.query.state;
      if (accessToken && (stateRequired.indexOf(provider) > -1 || config.getItem("providers." + provider + ".stateRequired") === true)) {
        theOptions.state = accessToken;
      }
      theOptions.callbackURL = getLinkCallbackURLs(provider, req, operation, accessToken);
      theOptions.session = false;
      passport.authenticate(provider, theOptions)(req, res, next);
    };
  }

  // Configures the passport.authenticate for the given access_token provider, passing in options
  function passportTokenCallback(provider, options) {
    return (req, res, next) => {
      var theOptions = Object.assign({}, options);
      theOptions.session = false;
      passport.authenticate(provider + "-token", theOptions)(req, res, next);
    };
  }

  function getLinkCallbackURLs(provider, req, operation, accessToken) {
    if (accessToken) {
      accessToken = encodeURIComponent(accessToken);
    }
    var protocol = (req.get("X-Forwarded-Proto") || req.protocol) + "://";
    if (operation === "login") {
      return protocol + req.get("host") + req.baseUrl + "/" + provider + "/callback";
    }
    if (operation === "link") {
      var reqUrl;
      if (accessToken && (stateRequired.indexOf(provider) > -1 || config.getItem("providers." + provider + ".stateRequired") === true)) {
        reqUrl = protocol + req.get("host") + req.baseUrl + "/link/" + provider + "/callback";
      }
      else {
        reqUrl = protocol + req.get("host") + req.baseUrl + "/link/" + provider + "/callback?state=" + accessToken;
      }
      return reqUrl;
    }
  }

  // Gets the provider name from a callback path
  function getProvider(pathname) {
    var items = pathname.split("/");
    var index = items.indexOf("callback");
    if (index > 0) {
      return items[index - 1];
    }
  }

  // Gets the provider name from a callback path for access_token strategy
  function getProviderToken(pathname) {
    var items = pathname.split("/");
    var index = items.indexOf("token");
    if (index > 0) {
      return items[index - 1];
    }
  }

  this.registerOAuth2 = registerOAuth2;
  this.registerProvider = registerProvider;
  this.registerTokenProvider = registerTokenProvider;
};
