'use strict';
var util = require('./util');

module.exports = function(config, router, passport, user) {

  var env = process.env.NODE_ENV || 'development';

  router.post('/login', function(req, res, next) {
    passport.authenticate('local', function(err, user, info) {
      if(err) {
        return next(err);
      }
      if(!user) {
        // Authentication failed
        return res.status(401).json(info);
      }
      // Success
      req.logIn(user, {session: false}, function(err) {
        if (err) {
          return next(err);
        }
      });
      return next();
    })(req, res, next);
    }, function (req, res, next) {
      // Success handler
      return user.createSession(req.user._id, 'local', req)
        .then(function (mySession) {
          res.status(200).json(mySession);
        }, function (err) {
          return next(err);
        });
    });

  router.post('/refresh',
    passport.authenticate('bearer', {session: false}),
    function (req, res, next) {
      return user.refreshSession(req.user.key)
        .then(function (mySession) {
          res.status(200).json(mySession);
        }, function (err) {
          return next(err);
        });
    });

  router.post('/logout',
    function (req, res, next) {
      var sessionToken = util.getSessionToken(req);
      if(!sessionToken) {
        return next({
          error: 'unauthorized',
          status: 401
        });
      }
      user.logoutSession(sessionToken)
        .then(function () {
          res.status(200).json({ok: true, success: 'Logged out'});
        }, function (err) {
          console.error('Logout failed');
          return next(err);
        });
    });

  router.post('/logout-others',
    passport.authenticate('bearer', {session: false}),
    function (req, res, next) {
      user.logoutOthers(req.user.key)
        .then(function () {
          res.status(200).json({success: 'Other sessions logged out'});
        }, function (err) {
          console.error('Logout failed');
          return next(err);
        });
    });

  router.post('/logout-all',
    function (req, res, next) {
      var sessionToken = util.getSessionToken(req);
      if(!sessionToken) {
        return next({
          error: 'unauthorized',
          status: 401
        });
      }
      user.logoutUser(null, sessionToken)
        .then(function () {
          res.status(200).json({success: 'Logged out'});
        }, function (err) {
          console.error('Logout-all failed');
          return next(err);
        });
    });

  // Setting up the auth api
  router.post('/register', function (req, res, next) {
      user.create(req.body, req)
        .then(function (newUser) {
          if(config.getItem('security.loginOnRegistration')) {
            return user.createSession(newUser._id, 'local', req.ip)
              .then(function (mySession) {
                res.status(200).json(mySession);
              }, function (err) {
                return next(err);
              });
          } else {
            res.status(201).json({success: 'User created.'});
          }
        }, function (err) {
          return next(err);
        });
    });

  router.post('/forgot-password', function (req, res, next) {
      user.forgotPassword(req.body.email, req).then(function () {
        res.status(200).json({success: 'Password recovery email sent.'});
      }, function (err) {
        return next(err);
      });
    });

  router.post('/password-reset', function (req, res, next) {
      user.resetPassword(req.body, req)
        .then(function (user) {
          if(config.getItem('security.loginOnPasswordReset')) {
            return user.createSession(user._id, 'local', req.ip)
              .then(function (mySession) {
                res.status(200).json(mySession);
              }, function (err) {
                return next(err);
              });
          } else {
            res.status(200).json({success: 'Password successfully reset.'});
          }
        }, function (err) {
          return next(err);
        });
    });

  router.post('/password-change',
    passport.authenticate('bearer', {session: false}),
    function (req, res, next) {
      user.changePasswordSecure(req.user._id, req.body, req)
        .then(function () {
          res.status(200).json({success: 'password changed'});
        }, function (err) {
          return next(err);
        });
    });

  router.post('/unlink/:provider',
    passport.authenticate('bearer', {session: false}),
    function(req, res, next) {
      var provider = req.params.provider;
      user.unlink(req.user._id, provider)
        .then(function() {
          res.status(200).json({success: util.capitalizeFirstLetter(provider) + ' unlinked'});
        }, function (err) {
          return next(err);
        });
    });

  router.get('/confirm-email/:token', function (req, res, next) {
    var redirectURL = config.getItem('local.confirmEmailRedirectURL');
    if (!req.params.token) {
      var err = {error: 'Email verification token required'};
      if(redirectURL) {
        return res.status(201).redirect(redirectURL + '?error=' + encodeURIComponent(err.error));
      }
      return res.status(400).send(err);
    }
    user.verifyEmail(req.params.token, req).then(function () {
      if(redirectURL) {
        return res.status(201).redirect(redirectURL + '?success=true');
      }
      res.status(200).send({ok: true, success: 'Email verified'});
    }, function (err) {
      if(redirectURL) {
        var query = '?error=' + encodeURIComponent(err.error);
        if(err.message) {
          query += '&message=' + encodeURIComponent(err.message);
        }
        return res.status(201).redirect(redirectURL + query);
      }
      return next(err);
    });
  });

  router.get('/validate-username/:username',
    function(req, res, next) {
      if(!req.params.username) {
        return next({error: 'Username required', status: 400});
      }
      user.validateUsername(req.params.username)
        .then(function(err) {
          if(!err) {
            res.status(200).json({ok: true});
          } else {
            res.status(409).json({error: 'Username already in use'});
          }
        }, function(err) {
          return next(err);
        });
    }
  );

  router.get('/validate-email/:email',
    function(req, res, next) {
      var promise;
      if(!req.params.email) {
        return next({error: 'Email required', status: 400});
      }
      if(config.getItem('local.emailUsername')) {
        promise = user.validateEmailUsername(req.params.email);
      } else {
        promise = user.validateEmail(req.params.email);
      }
      promise
        .then(function(err) {
          if(!err) {
            res.status(200).json({ok: true});
          } else {
            res.status(409).json({error: 'Email already in use'});
          }
        }, function(err) {
          return next(err);
        });
    }
  );

  router.post('/change-email',
    passport.authenticate('bearer', {session: false}),
    function (req, res, next) {
      user.changeEmail(req.user._id, req.body.newEmail, req)
        .then(function () {
          res.status(200).json({ok: true, success: 'Email changed'});
        }, function (err) {
          return next(err);
        });
    });

  // route to test token authentication
  router.get('/session',
    passport.authenticate('bearer', {session: false}),
    function (req, res) {
      var user = req.user;
      user.user_id = user._id;
      delete user._id;
      // user.token = user.key;
      delete user.key;
      res.status(200).json(user);
    });

  // Error handling
  router.use(function(err, req, res, next) {
    console.error(err);
    if(err.stack) {
      console.error(err.stack);
    }
    res.status(err.status || 500);
    if(err.stack && env !== 'development') {
      delete err.stack;
    }
    res.json(err);
  });

};
