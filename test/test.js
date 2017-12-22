"use strict";
var chai = require("chai");
var sinon = require("sinon");
var expect = chai.expect;
chai.use(require("sinon-chai"));

var BPromise = require("bluebird");
global.Promise = BPromise;
const axios = require("axios");

describe("SuperLogin", function() {
  var app;
  var userDB, keysDB;
  var accessToken;
  var expireCompare;
  var resetToken = null;

  var config = require("./test.config");
  var server = "http://localhost:5000";

  var newUser = {
    name: "Kewl Uzer",
    username: "kewluzer",
    email: "kewluzer@example.com",
    password: "1s3cret",
    confirmPassword: "1s3cret"
  };

  var newUser2 = {
    name: "Kewler Uzer",
    username: "kewleruzer",
    email: "kewleruzer@example.com",
    password: "1s3cret",
    confirmPassword: "1s3cret"
  };

  before(function() {
    app = require("./test-server")(config);
    app.superlogin.onCreate(function(userDoc, provider) {
      console.log(userDoc, provider);
      userDoc.profile = {name: userDoc.name};
      return BPromise.resolve(userDoc);
    });
    userDB = app.superlogin.userDB;
    keysDB = app.superlogin.couchAuthDB;
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        resolve();
      }, 1000);
    });
  });

  after(function() {
    return BPromise.all([userDB.destroy(), keysDB.destroy()])
      .then(function() {
        // console.log('DBs Destroyed');
        app.shutdown();
      });
  });

  it("should create a new user", function() {
    return axios.post(server + "/auth/register", newUser).then(function(res) {
      expect(res.status).to.equal(201);
      expect(res.data.ok).to.equal(true);
      expect(res.data.success).to.equal("User created.");
    });
  });

  it("should verify the email", function() {
    var emailToken;
    return userDB.get("kewluzer")
      .then(function(record) {
        emailToken = record.unverifiedEmail.token;
      })
      .then(function() {
        return axios.get(server + "/auth/confirm-email/" + emailToken).then(function(res) {
          expect(res.status).to.equal(200);
        });
      });
  });

  it("should login the user", function() {
    return axios.post(server + "/auth/login", { username: newUser.username, password: newUser.password }).then(function(res) {
      console.log("lalalala", res.data);
      accessToken = res.data.token;
      expect(res.status).to.equal(200);
      expect(res.data.roles[0]).to.equal("user");
      expect(res.data.token.length).to.be.above(10);
      expect(res.data.profile.name).to.equal(newUser.name);
      // console.log('User successfully logged in');
    });
  });

  it("should access a protected endpoint", function() {
    return axios.get(server + "/auth/session", {
      headers: {
        "Authorization": "Bearer " + accessToken
      }
    }).then(function(res) {
      expect(res.status).to.equal(200);
      // console.log('Secure endpoint successfully accessed.');
    });
  });

  it("should require a role", function() {
    return axios.get(server + "/user", {
      headers: {
        "Authorization": "Bearer " + accessToken
      }
    }).then(function(res) {
      expect(res.status).to.equal(200);
      // console.log('Role successfully required.');
    });
  });

  it("should deny access when a required role is not present", function() {
    return axios.get(server + "/admin", {
      headers: {
        "Authorization": "Bearer " + accessToken
      }
    }).catch(function(error) {
      // if (err) return reject(err);
      expect(error.response.status).to.equal(403);
      // console.log('Admin access successfully denied.');
    });
  });

  it("should generate a forgot password token", function() {
    var spySendMail = sinon.spy(app.superlogin.mailer, "sendEmail");

    return axios.post(server + "/auth/forgot-password", {email: newUser.email}).then(function(res) {
      expect(res.status).to.equal(200);
      // keep unhashed token emailed to user.
      var sendEmailArgs = spySendMail.getCall(0).args;
      resetToken = sendEmailArgs[2].token;
      // console.log('Password token successfully generated.');
    });
  });

  it("should reset the password", function() {
    return userDB.get(newUser.username).then(function(resetUser) {
      return axios.post(server + "/auth/password-reset", {token: resetToken, password: "newpass", confirmPassword: "newpass"}).then(function(res) {
        expect(res.status).to.equal(200);
        // console.log('Password successfully reset.');
      });
    });
  });

  it("should logout the user upon password reset", function() {
    return axios.get(server + "/auth/session", {
      headers: {
        "Authorization": "Bearer " + accessToken
      }
    }).then(function(res) {
      // if (err) return reject(err);
      expect(res.status).to.equal(401);
      // console.log('User has been successfully logged out on password reset.');
    });
  });

  it("should login with the new password", function() {
    return axios.post(server + "/auth/login", { username: newUser.username, password: "newpass" }).then(function(res) {
      accessToken = res.data.token;
      expireCompare = res.data.expires;
      expect(res.status).to.equal(200);
      expect(res.data.roles[0]).to.equal("user");
      expect(res.data.token.length).to.be.above(10);
      // console.log('User successfully logged in with new password');
    });
  });

  it("should refresh the session", function() {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        axios.post(server + "/auth/refresh", null, {
          headers: {
            "Authorization": "Bearer " + accessToken
          }
        }).then(function(res) {
          expect(res.status).to.equal(200);
          expect(res.data.expires).to.be.above(expireCompare);
          resolve();
        });
      }, 1000);
    });
  });

  it("should change the password", function() {
    return userDB.get(newUser.username).then(function(resetUser) {
      return axios.post(server + "/auth/password-change", {currentPassword: "newpass", newPassword: "newpass2", confirmPassword: "newpass2"}, {
        headers: {
          "Authorization": "Bearer " + accessToken
        }
      }).then(function(res) {
        expect(res.status).to.equal(200);
        // console.log('Password successfully changed.');
      });
    });
  });

  it("should logout the user", function() {
    return axios.post(server + "/auth/logout", null, {
      headers: {
        "Authorization": "Bearer " + accessToken
      }
    }).then(function(res) {
      expect(res.status).to.equal(200);
    }).then(function() {
      return axios.get(server + "/auth/session", {
        headers: {
          "Authorization": "Bearer " + accessToken
        }
      }).catch(function(err) {
        expect(err.response.status).to.equal(401);
        // console.log('User has been successfully logged out.');
      });
    });
  });

  it("should login after creating a new user", function() {
    app.config.setItem("security.loginOnRegistration", true);
    return axios.post(server + "/auth/register", newUser2).then(function(res) {
      expect(res.status).to.equal(200);
      /* jshint -W030 */
      expect(res.data.token).to.be.a("string");
      /* jshint +W030 */
      // console.log('User created and logged in');
    });
  });

  it("should validate a username", function() {
    return axios.get(server + "/auth/validate-username/idontexist").then(function(res) {
      expect(res.status).to.equal(200);
      expect(res.data.ok).to.equal(true);
    }).then(function() {
      return axios.get(server + "/auth/validate-username/kewluzer").catch(function(error) {
        expect(error.response.status).to.equal(409);
        // console.log('Validate Username is working');
      });
    });
  });

  it("should validate an email", function() {
    return axios.get(server + "/auth/validate-email/nobody@example.com").then(function(res) {
      expect(res.status).to.equal(200);
      expect(res.data.ok).to.equal(true);
    }).then(function() {
      return axios.get(server + "/auth/validate-username/kewluzer@example.com").catch(function(error) {
        expect(error.response.status).to.equal(409);
        // console.log('Validate Email is working');
      });
    });
  });

  function attemptLogin(username, password) {
    return axios.post(server + "/auth/login", { username: username, password: password });
  }

  it("should respond unauthorized if a user logs in and no password is set", function() {
    return userDB.put({
      _id: "nopassword",
      email: "nopassword@example.com"
    }).then(function() {
      return attemptLogin("nopassword", "wrongpassword");
    })
      .catch(function(error) {
        expect(error.response.status).to.equal(401);
        expect(error.response.data.message).to.equal("Invalid username or password");
      });
  });

  it("should block a user after failed logins", function() {
    return attemptLogin("kewluzer", "wrong").catch(function(error) {
      expect(error.response.status).to.equal(401);
      expect(error.response.data.message).to.equal("Invalid username or password");
      return attemptLogin("kewluzer", "wrong");
    })
      .catch(function(error) {
        expect(error.response.status).to.equal(401);
        expect(error.response.data.message).to.equal("Invalid username or password");
        return attemptLogin("kewluzer", "wrong");
      })
      .catch(function(error) {
        expect(error.response.status).to.equal(401);
        expect(error.response.data.message.search("Maximum failed login")).to.equal(0);
        return attemptLogin("kewluzer", "newpass");
      })
      .catch(function(error) {
        expect(error.response.status).to.equal(401);
        expect(error.response.data.message.search("Your account is currently locked")).to.equal(0);
        return BPromise.resolve();
      });
  });
});
