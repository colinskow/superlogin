import * as util from "./util";
import LocalStrategy from "passport-local";
import { Strategy as BearerStrategy } from "passport-http-bearer-sl";
import ms from "ms";

export default function(config, passport, user) {
  // API token strategy
  passport.use(new BearerStrategy(
    async function(tokenPass, done) {
      // console.log(tokenPass);
      const token = tokenPass;
      try {
        const theuser = await user.confirmSession(token);
        done(null, theuser);
      }
      catch (err) {
        if (err instanceof Error && err.message !== "jwt expired") {
          done(err, false);
        }
        else {
          done(null, false, {message: err.message});
        }
      }
    }
  ));

  // Use local strategy
  passport.use(
    new LocalStrategy({
      usernameField: config.getItem("local.usernameField") || "username",
      passwordField: config.getItem("local.passwordField") || "password",
      session: false,
      passReqToCallback: true
    },
    async function(req, username, password, done) {
      try {
        const theuser = await user.get(username);
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
            await util.verifyPassword(theuser.local, password);
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
          }
          catch (err) {
            if (!err) {
              // Password didn't authenticate
              return handleFailedLogin(theuser, req, done);
            }
            else {
              // Hashing function threw an error
              return done(err);
            }
          }
        }
        else {
          // user not found
          return done(null, false, {
            error: "Unauthorized",
            message: "Invalid username or password"
          });
        }
      }
      catch (err) {
        // Database threw an error
        return done(err);
      }
    }
    ));

  async function handleFailedLogin(userDoc, req, done) {
    const invalid = {
      error: "Unauthorized",
      message: "Invalid username or password"
    };
    const locked = await user.handleFailedLogin(userDoc, req);
    if (locked) {
      let securityLockoutTime = config.getItem("security.lockoutTime");
      securityLockoutTime = typeof securityLockoutTime === "string" ? ms(securityLockoutTime) : securityLockoutTime;
      invalid.message = "Maximum failed login attempts exceeded. Your account has been locked for " +
          ms(securityLockoutTime);
    }
    return done(null, false, invalid);
  }
};
