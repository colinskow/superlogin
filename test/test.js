"use strict";
import * as util from "../src/util";
var chai = require("chai");
var sinon = require("sinon");
var expect = chai.expect;
chai.use(require("sinon-chai"));

var BPromise = require("bluebird");
global.Promise = BPromise;
const PouchDB = require("pouchdb-core")
  .plugin(require("pouchdb-adapter-http"))
  .plugin(require("pouchdb-mapreduce"));
var seed = require("pouchdb-seed-design");
const axios = require("axios");

describe("SuperLogin", function() {
  var app;
  var userDB, keysDB;
  var previous;
  var accessToken;
  var expireCompare;
  var resetToken = null;

  var config = require("./test.config");
  var server = "http://localhost:5000";
  var dbUrl = util.getDBURL(config.dbServer);

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
    userDB = new PouchDB(dbUrl + "/sl_test-users");
    keysDB = new PouchDB(dbUrl + "/sl_test-keys");
    app = require("./test-server")(config);
    app.superlogin.onCreate(function(userDoc, provider) {
      userDoc.profile = {name: userDoc.name};
      return BPromise.resolve(userDoc);
    });

    previous = seed(userDB, require("../designDocs/user-design"));
    return previous;
  });

  after(function() {
    return previous
      .then(function() {
        return BPromise.all([userDB.destroy(), keysDB.destroy()]);
      })
      .then(function() {
        // console.log('DBs Destroyed');
        app.shutdown();
      });
  });

  it("should create a new user", function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        axios.post(server + "/auth/register", newUser).then(function(res) {
          expect(res.status).to.equal(201);
          expect(res.data.success).to.equal("User created.");
          // console.log('User created');
          resolve();
        });
      });
    });
  });

  it("should verify the email", function() {
    var emailToken;
    return previous.then(function() {
      return userDB.get("kewluzer")
        .then(function(record) {
          emailToken = record.unverifiedEmail.token;
          return 1;
        })
        .then(function() {
          return new BPromise(function(resolve, reject) {
            axios.get(server + "/auth/confirm-email/" + emailToken).then(function(res) {
              expect(res.status).to.equal(200);
              // console.log('Email successfully verified.');
              resolve();
            });
          });
        });
    });
  });

  it("should login the user", function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        axios.post(server + "/auth/login", { username: newUser.username, password: newUser.password }).then(function(res) {
          accessToken = res.data.token;
          expect(res.status).to.equal(200);
          expect(res.data.roles[0]).to.equal("user");
          expect(res.data.token.length).to.be.above(10);
          expect(res.data.profile.name).to.equal(newUser.name);
          // console.log('User successfully logged in');
          resolve();
        });
      });
    });
  });

  it("should access a protected endpoint", function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        axios.get(server + "/auth/session", {
          headers: {
            "Authorization": "Bearer " + accessToken
          }
        }).then(function(res) {
          expect(res.status).to.equal(200);
          // console.log('Secure endpoint successfully accessed.');
          resolve();
        });
      });
    });
  });

  it("should require a role", function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        axios.get(server + "/user", {
          headers: {
            "Authorization": "Bearer " + accessToken
          }
        }).then(function(res) {
          expect(res.status).to.equal(200);
          // console.log('Role successfully required.');
          resolve();
        });
      });
    });
  });

  it("should deny access when a required role is not present", function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        axios.get(server + "/admin", {
          headers: {
            "Authorization": "Bearer " + accessToken
          }
        }).then(function(res) {
          // if (err) return reject(err);
          expect(res.status).to.equal(403);
          // console.log('Admin access successfully denied.');
          resolve();
        });
      });
    });
  });

  it("should generate a forgot password token", function() {
    var spySendMail = sinon.spy(app.superlogin.mailer, "sendEmail");

    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        axios.post(server + "/auth/forgot-password", {email: newUser.email}).then(function(res) {
          expect(res.status).to.equal(200);
          // keep unhashed token emailed to user.
          var sendEmailArgs = spySendMail.getCall(0).args;
          resetToken = sendEmailArgs[2].token;
          // console.log('Password token successfully generated.');
          resolve();
        });
      });
    });
  });

  it("should reset the password", function() {
    return previous.then(function() {
      return userDB.get(newUser.username)
        .then(function(resetUser) {
          return new BPromise(function(resolve, reject) {
            axios.post(server + "/auth/password-reset", {token: resetToken, password: "newpass", confirmPassword: "newpass"}).then(function(res) {
              expect(res.status).to.equal(200);
              // console.log('Password successfully reset.');
              resolve();
            });
          });
        });
    });
  });

  it("should logout the user upon password reset", function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        axios.get(server + "/auth/session", {
          headers: {
            "Authorization": "Bearer " + accessToken
          }
        }).then(function(res) {
          // if (err) return reject(err);
          expect(res.status).to.equal(401);
          // console.log('User has been successfully logged out on password reset.');
          resolve();
        });
      });
    });
  });

  it("should login with the new password", function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        axios.post(server + "/auth/login", { username: newUser.username, password: "newpass" }).then(function(res) {
          accessToken = res.data.token;
          expireCompare = res.data.expires;
          expect(res.status).to.equal(200);
          expect(res.data.roles[0]).to.equal("user");
          expect(res.data.token.length).to.be.above(10);
          // console.log('User successfully logged in with new password');
          resolve();
        });
      });
    });
  });

  it("should refresh the session", function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        axios.post(server + "/auth/refresh", {
          headers: {
            "Authorization": "Bearer " + accessToken
          }
        }).then(function(res) {
          expect(res.status).to.equal(200);
          expect(res.data.expires).to.be.above(expireCompare);
          // console.log('Session successfully refreshed.');
          resolve();
        });
      });
    });
  });

  it("should change the password", function() {
    return previous.then(function() {
      return userDB.get(newUser.username)
        .then(function(resetUser) {
          return new BPromise(function(resolve, reject) {
            axios.post(server + "/auth/password-change", {currentPassword: "newpass", newPassword: "newpass2", confirmPassword: "newpass2"}, {
              headers: {
                "Authorization": "Bearer " + accessToken
              }
            }).then(function(res) {
              expect(res.status).to.equal(200);
              // console.log('Password successfully changed.');
              resolve();
            });
          });
        });
    });
  });

  it("should logout the user", function() {
    return previous
      .then(function() {
        return new BPromise(function(resolve, reject) {
          axios.post(server + "/auth/logout", {
            headers: {
              "Authorization": "Bearer " + accessToken
            }
          }).then(function(res) {
            expect(res.status).to.equal(200);
            resolve();
          });
        }).then(function() {
          return new BPromise(function(resolve, reject) {
            axios.get(server + "/auth/session", {
              headers: {
                "Authorization": "Bearer " + accessToken
              }
            }).catch(function(err) {
              expect(err.status).to.equal(401);
              // console.log('User has been successfully logged out.');
              resolve();
            });
          });
        });
      });
  });

  it("should login after creating a new user", function() {
    return previous.then(function() {
      app.config.setItem("security.loginOnRegistration", true);
      return new BPromise(function(resolve, reject) {
        axios.post(server + "/auth/register", newUser2).then(function(res) {
          expect(res.status).to.equal(200);
          /* jshint -W030 */
          expect(res.data.token).to.be.a("string");
          /* jshint +W030 */
          // console.log('User created and logged in');
          resolve();
        });
      });
    });
  });

  it("should validate a username", function() {
    return previous
      .then(function() {
        return new BPromise(function(resolve, reject) {
          axios.get(server + "/auth/validate-username/idontexist").then(function(res) {
            expect(res.status).to.equal(200);
            expect(res.data.ok).to.equal(true);
            resolve();
          });
        });
      })
      .then(function() {
        return new BPromise(function(resolve, reject) {
          axios.get(server + "/auth/validate-username/kewluzer").catch(function(error) {
            expect(error.status).to.equal(409);
            // console.log('Validate Username is working');
            resolve();
          });
        });
      });
  });

  it("should validate an email", function() {
    return previous
      .then(function() {
        return new BPromise(function(resolve, reject) {
          axios.get(server + "/auth/validate-email/nobody@example.com").then(function(res) {
            expect(res.status).to.equal(200);
            expect(res.data.ok).to.equal(true);
            resolve();
          });
        });
      })
      .then(function() {
        return new BPromise(function(resolve, reject) {
          axios.get(server + "/auth/validate-username/kewluzer@example.com").catch(function(error) {
            expect(error.status).to.equal(409);
            // console.log('Validate Email is working');
            resolve();
          });
        });
      });
  });

  function attemptLogin(username, password) {
    return new BPromise(function(resolve, reject) {
      axios.post(server + "/auth/login", { username: username, password: password }).then(function(res) {
        resolve({status: res.status, message: res.data.message});
      });
    });
  }

  it("should respond unauthorized if a user logs in and no password is set", function() {
    return previous
      .then(function() {
        return userDB.put({
          _id: "nopassword",
          email: "nopassword@example.com"
        });
      })
      .then(function() {
        return attemptLogin("nopassword", "wrongpassword");
      })
      .then(function(result) {
        expect(result.status).to.equal(401);
        expect(result.message).to.equal("Invalid username or password");
      });
  });

  it("should block a user after failed logins", function() {
    return previous
      .then(function() {
        return attemptLogin("kewluzer", "wrong");
      })
      .then(function(result) {
        expect(result.status).to.equal(401);
        expect(result.message).to.equal("Invalid username or password");
        return attemptLogin("kewluzer", "wrong");
      })
      .then(function(result) {
        expect(result.status).to.equal(401);
        expect(result.message).to.equal("Invalid username or password");
        return attemptLogin("kewluzer", "wrong");
      })
      .then(function(result) {
        expect(result.status).to.equal(401);
        expect(result.message.search("Maximum failed login")).to.equal(0);
        return attemptLogin("kewluzer", "newpass");
      })
      .then(function(result) {
        expect(result.status).to.equal(401);
        expect(result.message.search("Your account is currently locked")).to.equal(0);
        return BPromise.resolve();
      });
  });
});
