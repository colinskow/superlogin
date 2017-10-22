"use strict";
var util = require("./util");
var LocalStrategy = require("passport-local");
var BearerStrategy = require("passport-http-bearer-sl").Strategy;

module.exports = function(config, passport, user) {
  // API token strategy
  passport.use(new BearerStrategy(
    function(tokenPass, done) {
      // console.log(tokenPass);
      var token = tokenPass;
      user.confirmSession(token).then(function(theuser) {
        done(null, theuser);
      }).catch(function(err) {
        if (err instanceof Error && err.message !== "jwt expired") {
          done(err, false);
        }
        else {
          done(null, false, {message: err.message});
        }
      });
    }
  ));

  // Use local strategy
  passport.use(new LocalStrategy({
    usernameField: config.getItem("local.usernameField") || "username",
    passwordField: config.getItem("local.passwordField") || "password",
    session: false,
    passReqToCallback: true
  },
  function(req, username, password, done) {
    // console.log("Passport", Date.now());
    user.get(username).then(function(theuser) {
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
        util.verifyPassword(theuser.local, password)
          .then(function() {
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
          }, function(err) {
            if (!err) {
              // Password didn't authenticate
              return handleFailedLogin(theuser, req, done);
            }
            else {
              // Hashing function threw an error
              return done(err);
            }
          });
      }
      else {
        // user not found
        return done(null, false, {
          error: "Unauthorized",
          message: "Invalid username or password"
        });
      }
    }).catch(function(err) {
      // Database threw an error
      return done(err);
    });
  }
  ));

  function handleFailedLogin(userDoc, req, done) {
    var invalid = {
      error: "Unauthorized",
      message: "Invalid username or password"
    };
    return user.handleFailedLogin(userDoc, req)
      .then(function(locked) {
        if (locked) {
          invalid.message = "Maximum failed login attempts exceeded. Your account has been locked for " +
              Math.round(config.getItem("security.lockoutTime") / 60) + " minutes.";
        }
        return done(null, false, invalid);
      });
  }
};
