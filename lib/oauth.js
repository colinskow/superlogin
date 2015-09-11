'use strict';
var fs = require('fs');
var path = require('path');
var BPromise = require('bluebird');
var ejs  = require('ejs');
var extend = require('util')._extend;

var stateRequired = ['google', 'linkedin'];

module.exports = function(router, passport, user, config) {

  // Function to initialize a session following authentication from a socialAuth provider
  function initSession(req, res, next) {
    var provider = getProvider(req.path);
    return user.createSession(req.user._id, provider, req)
      .then(function(mySession) {
        return BPromise.resolve({
          error: null,
          session: mySession,
          link: null
        });
      })
      .then(function (results) {
        var template;
        if(config.getItem('testMode.oauthTest')) {
          template = fs.readFileSync(path.join(__dirname, '../templates/oauth/auth-callback-test.ejs'), 'utf8');
        } else {
          template = fs.readFileSync(path.join(__dirname, '../templates/oauth/auth-callback.ejs'), 'utf8');
        }
        var html = ejs.render(template, results);
        res.status(200).send(html);
      }, function (err) {
        return next(err);
      });
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
    if(config.getItem('testMode.oauthTest')) {
      template = fs.readFileSync(path.join(__dirname, '../templates/oauth/auth-callback-test.ejs'), 'utf8');
    } else {
      template = fs.readFileSync(path.join(__dirname, '../templates/oauth/auth-callback.ejs'), 'utf8');
    }
    var html = ejs.render(template, result);
    res.status(200).send(html);
  }

  // Handles errors if authentication provides
  function oauthErrorHandler(err,req,res,next) {
    var template;
    if(config.getItem('testMode.oauthTest')) {
      template = fs.readFileSync(path.join(__dirname, '../templates/oauth/auth-callback-test.ejs'), 'utf8');
    } else {
      template = fs.readFileSync(path.join(__dirname, '../templates/oauth/auth-callback.ejs'), 'utf8');
    }
    var html = ejs.render(template, {error: err.message, session: null, link: null});
    console.error(err);
    if(err.stack) {
      console.error(err.stack);
    }
    res.status(400).send(html);
  }

  // Framework to register OAuth providers with passport
  function registerProvider(provider, configFunction) {
    provider = provider.toLowerCase();
    var configRef = 'providers.' + provider;
    if (config.getItem(configRef + '.credentials')) {
      var credentials = config.getItem(configRef + '.credentials');
      credentials.passReqToCallback = true;
      var options = config.getItem(configRef + '.options') || {};
      configFunction.call(null, credentials, passport, authHandler);
      router.get('/' + provider, passportCallback(provider, options, 'login'));
      router.get('/' + provider + '/callback', passportCallback(provider, options, 'login'), initSession, oauthErrorHandler);
      if(!config.getItem('security.disableLinkAccounts')) {
        router.get('/link/' + provider, passport.authenticate('bearer', {session: false}), passportCallback(provider, options, 'link'));
        router.get('/link/' + provider + '/callback', passport.authenticate('bearer', {session: false}),
          passportCallback(provider, options, 'link'), linkSuccess, oauthErrorHandler);
      }
      console.log(provider + ' loaded.');
    }
  }

  // A shortcut to register OAuth2 providers that follow the exact accessToken, refreshToken pattern.
  function registerOAuth2 (providerName, Strategy) {
    registerProvider(providerName, function (credentials, passport, authHandler) {
      passport.use(new Strategy(credentials,
        function (req, accessToken, refreshToken, profile, done) {
          authHandler(req, providerName, {accessToken: accessToken, refreshToken: refreshToken}, profile)
            .nodeify(done);
        }
      ));
    });
  }

  // If a user is authenticated we will link an account, otherwise log in
  function authHandler(req, provider, auth, profile) {
    if(req.user && req.user._id && req.user.key) {
      return user.linkSocial(req.user._id, provider, auth, profile, req);
    } else {
      return user.socialAuth(provider, auth, profile, req);
    }
  }

  function passportCallback(provider, options, operation) {
    return function(req, res, next) {
      var theOptions = extend({}, options);
      if(provider === 'linkedin') {
        theOptions.state = true;
      }
      var accessToken = req.query.bearer_token || req.query.state;
      if(accessToken && (stateRequired.indexOf(provider) > -1 || config.getItem('providers.' + provider + '.stateRequired') === true)) {
        theOptions.state = accessToken;
      }
      theOptions.callbackURL = getLinkCallbackURLs(provider, req, operation, accessToken);
      theOptions.session = false;
      passport.authenticate(provider, theOptions)(req, res, next);
    };
  }

  function getLinkCallbackURLs(provider, req, operation, accessToken) {
    if(accessToken) {
      accessToken = encodeURIComponent(accessToken);
    }
    var protocol = (req.get('X-Forwarded-Proto') || req.protocol) + '://';
    if(operation === 'login') {
      return protocol + req.get('host') + req.baseUrl + '/' + provider + '/callback';
    }
    if(operation === 'link') {
      var reqUrl;
      if(accessToken && (stateRequired.indexOf(provider) > -1 || config.getItem('providers.' + provider + '.stateRequired') === true)) {
        reqUrl = protocol + req.get('host') + req.baseUrl + '/link/' + provider + '/callback';
      } else {
        reqUrl = protocol + req.get('host') + req.baseUrl + '/link/' + provider + '/callback?state=' + accessToken;
      }
      return reqUrl;
    }
  }

  // Gets the provider name from a callback path
  function getProvider(pathname) {
    var items = pathname.split('/');
    var index = items.indexOf('callback');
    if(index > 0) {
      return items[index-1];
    }
  }

  return {
    registerProvider: registerProvider,
    registerOAuth2: registerOAuth2
  };

};
