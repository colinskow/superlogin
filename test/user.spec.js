"use strict";
import * as util from "../src/util";
var events = require("events");
var path = require("path");
const PouchDB = require("pouchdb-core")
  .plugin(require("pouchdb-adapter-http"))
  .plugin(require("pouchdb-mapreduce"));
const axios = require("axios");
var BPromise = require("bluebird");
var Configure = require("../src/configure").default;
var User = require("../src/user").default;
var Mailer = require("../src/mailer").default;
var seed = require("pouchdb-seed-design");
var config = require("./test.config.js");

var chai = require("chai");
var sinon = require("sinon");
var expect = chai.expect;
chai.use(require("sinon-chai"));

var dbUrl = util.getDBURL(config.dbServer);

var emitter = new events.EventEmitter();

PouchDB.setMaxListeners(20);
var userDB = new PouchDB(dbUrl + "/superlogin_test_users");
var keysDB = new PouchDB(dbUrl + "/superlogin_test_keys");

var couchDesign = require("../designDocs/couch-design");
seed(keysDB, couchDesign);

var testUserForm = {
  name: "Super",
  username: "superuser",
  email: "superuser@example.com",
  password: "superlogin",
  confirmPassword: "superlogin",
  age: "32",
  zipcode: "ABC123"
};

var emailUserForm = {
  name: "Awesome",
  email: "awesome@example.com",
  password: "supercool",
  confirmPassword: "supercool"
};

var userConfig = new Configure({
  testMode: {
    noEmail: true
  },
  security: {
    defaultRoles: ["user"],
    userActivityLogSize: 3,
    jwt: {
      issuer: "https://api.example.com",
      secret: "test"
    }
  },
  local: {
    sendConfirmEmail: true,
    requireEmailConfirm: false,
    passwordConstraints: {
      length: {
        minimum: 8,
        message: "must be at least 8 characters"
      },
      matches: "confirmPassword"
    }
  },
  mailer: {
    fromEmail: "noreply@example.com"
  },
  emails: {
    confirmEmail: {
      subject: "Please confirm your email",
      template: path.join(__dirname, "../templates/email/confirm-email.ejs"),
      format: "text"
    },
    forgotPassword: {
      subject: "Your password reset link",
      template: "templates/email/forgot-password.ejs",
      format: "text"
    }
  },
  dbServer: {
    protocol: config.dbServer.protocol,
    host: config.dbServer.host,
    user: config.dbServer.user,
    password: config.dbServer.password,
    publicURL: "https://mydb.example.com"
  },
  session: {
    adapter: "memory"
  },
  userDBs: {
    defaultSecurityRoles: {
      admins: ["admin_role"],
      members: ["member_role"]
    },
    model: {
      _default: {
        designDocs: ["test"],
        permissions: ["_reader", "_writer", "_replicator"]
      }
    },
    defaultDBs: {
      private: ["usertest"]
    },
    privatePrefix: "test",
    designDocDir: path.join(__dirname, "/ddocs")
  },
  providers: {
    facebook: {
      clientID: "FAKE_ID",
      clientSecret: "FAKE_SECRET",
      callbackURL: "http://localhost:5000/auth/facebook/callback"
    }
  },
  userModel: {
    static: {
      modelTest: true
    },
    whitelist: ["age", "zipcode"]
  }
});

var req = {
  headers: {
    host: "example.com"
  },
  protocol: "http",
  ip: "1.1.1.1",
  body: {}
};

describe("User Model", function() {
  var mailer = new Mailer(userConfig);
  var user = new User(userConfig, userDB, keysDB, mailer, emitter);
  var userTestDB;
  var previous;
  var verifyEmailToken;

  before(function() { // 'should prepare the database'
    // console.log('Seeding design docs');
    var userDesign = require("../designDocs/user-design");
    userDesign = util.addProvidersToDesignDoc(userConfig, userDesign);
    previous = BPromise.resolve();

    return previous.then(function() {
      return seed(userDB, userDesign);
    });
  });

  after(function() { // 'should destroy all the test databases'
    return previous.finally(function() {
      // console.log('Destroying database');
      var userTestDB1 = new PouchDB(dbUrl + "/test_usertest$superuser");
      var userTestDB2 = new PouchDB(dbUrl + "/test_usertest$misterx");
      var userTestDB3 = new PouchDB(dbUrl + "/test_usertest$misterx3");
      var userTestDB4 = new PouchDB(dbUrl + "/test_superdb");
      return BPromise.all([userDB.destroy(), keysDB.destroy(), userTestDB1.destroy(), userTestDB2.destroy(), userTestDB3.destroy(), userTestDB4.destroy()]);
    });
  });

  it("should save a new user", function() {
    // console.log('Creating User');
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once("signup", function(user) {
        expect(user._id).to.equal("superuser");
        resolve();
      });
    });

    return previous.then(function() {
      user.onCreate(function(userDoc) {
        userDoc.onCreate1 = true;
        return BPromise.resolve(userDoc);
      });
      user.onCreate(function(userDoc) {
        userDoc.onCreate2 = true;
        return BPromise.resolve(userDoc);
      });
      return user.create(testUserForm, req);
    })
      .then(function() {
        // console.log('User created');
        return userDB.get(testUserForm.username);
      })
      .then(function(newUser) {
        verifyEmailToken = newUser.unverifiedEmail.token;
        expect(newUser._id).to.equal("superuser");
        expect(newUser.roles[0]).to.equal("user");
        expect(newUser.local.salt).to.be.a("string");
        expect(newUser.local.derived_key).to.be.a("string");
        expect(newUser.modelTest).to.equal(true);
        expect(newUser.roles[0]).to.equal("user");
        expect(newUser.activity[0].action).to.equal("signup");
        expect(newUser.onCreate1).to.equal(true);
        expect(newUser.onCreate2).to.equal(true);
        expect(newUser.age).to.equal("32");
        expect(newUser.zipcode).to.equal("ABC123");
        return emitterPromise;
      });
  });

  it("should have created a user db with design doc and _security", function() {
    // console.log('Checking user db and design doc');
    userTestDB = new PouchDB(dbUrl + "/test_usertest$superuser");
    return previous
      .then(function() {
        return userTestDB.get("_design/test");
      })
      .then(function(ddoc) {
        expect(ddoc.views.mytest.map).to.be.a("string");
        return userTestDB.get("_security");
      })
      .then(function(secDoc) {
        expect(secDoc.admins.roles[0]).to.equal("admin_role");
        expect(secDoc.members.roles[0]).to.equal("member_role");
      });
  });

  it("should authenticate the password", function() {
    // console.log('Authenticating password');
    return previous.then(function() {
      // console.log('Fetching created user');
      return userDB.get(testUserForm.username);
    })
      .then(function(newUser) {
        return util.verifyPassword(newUser.local, "superlogin");
      })
      .then(function(result) {
        // console.log('Password authenticated');
      });
  });

  it("should generate a validation error trying to save the same user again", function() {
    return previous.then(function() {
      // console.log('Trying to create the user again');
      return user.create(testUserForm, req);
    })
      .then(function() {
        throw new Error("Validation errors should have been generated");
      })
      .catch(function(err) {
        if (err.validationErrors) {
          expect(err.validationErrors.email[0]).to.equal("Email already in use");
          expect(err.validationErrors.username[0]).to.equal("Username already in use");
        }
        else {
          throw err;
        }
      });
  });

  // eslint-disable-next-line
  var session, token, refreshToken, firstExpires, dbUser;

  it("should generate a new session for the user", function() {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once("login", function(session) {
        expect(session.user_id).to.equal("superuser");
        resolve();
      });
    });

    return previous
      .then(function() {
        // console.log('Creating session');
        return user.createSession(testUserForm.username, null, req);
      })
      .then(function(result) {
        token = result.token;
        // eslint-disable-next-line
        refreshToken = result.refreshToken;
        session = result.dbUser;
        firstExpires = result.expires;
        dbUser = result.dbUser;
        expect(token).to.be.a("string");
        expect(result.userDBs.usertest).to.equal("https://mydb.example.com/test_usertest$superuser");
        return (userDB.get(testUserForm.username));
      })
      .then(function(user) {
        expect(user.activity[0].action).to.equal("login");
        return emitterPromise;
      })
      .then(function() {
        // save user to req for later use
        return user.confirmSession(token).then(user => {
          req.user = user;
        });
      });
  });

  it("should have authorized the session in the usertest database", function() {
    return previous
      .then(function() {
        // console.log('Verifying session is authorized in personal db');
        return userTestDB.get("_security");
      })
      .then(function(secDoc) {
        expect(secDoc.members.roles.indexOf("user:superuser")).to.be.above(-1);
      });
  });

  it("should refresh a session", function() {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once("refresh", function(session) {
        expect(session.user_id).to.equal("superuser");
        resolve();
      });
    });

    return previous
      .then(function() {
        console.log("Refreshing session", req, token);
        return user.refreshSession(req, token);
      })
      .then(function(result) {
        // we are executing too fast
        // jwt expiries in seconds, so we won't see a difference here
        expect(result.expires + 1).to.be.above(firstExpires);
        expect(result.token).to.not.equal(token);
        return emitterPromise;
      });
  });

  it("should log out of a session", function() {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once("logout", function(userId) {
        expect(userId).to.equal("superuser");
        resolve();
      });
    });

    console.log(userDB);

    return previous
      .then(function() {
        // console.log('Logging out of the session');
        return user.logoutSession(req.user, dbUser);
      })
      .then(function() {
        return keysDB.get("org.couchdb.user:" + dbUser);
      })
      .then(function() {
        throw new Error("Failed to log out of session");
      }, function(err) {
        if (err.error) {
          expect(err.error).to.equal("not_found");
        }
        else {
          throw err;
        }
        return emitterPromise;
      });
  });

  // it("should have deauthorized the session in the usertest database after logout", function() {
  //   return previous
  //     .then(function() {
  //       return userTestDB.get("_security");
  //     })
  //     .then(function(secDoc) {
  //       expect(secDoc.members.names.length).to.equal(0);
  //     });
  // });

  it("should log the user out of all sessions", function() {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once("logout-all", function(userId) {
        expect(userId).to.equal("superuser");
        resolve();
      });
    });

    return previous
      .then(function() {
        // console.log('Logging user out completely');
        return user.logoutUser(req.user);
      })
      .then(function() {
        return keysDB.query("_superlogin/user", {
          key: req.user._id
        });
      })
      .then(function(results) {
        expect(results.rows.length).to.equal(0);
        return emitterPromise;
      });
  });

  it("should verify the email", function() {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once("email-verified", function(user) {
        expect(user._id).to.equal("superuser");
        resolve();
      });
    });

    return previous.then(function() {
      // console.log('Verifying email with token');
      return user.verifyEmail(verifyEmailToken);
    })
      .then(function() {
        return userDB.get(testUserForm.username);
      })
      .then(function(verifiedUser) {
        expect(verifiedUser.email).to.equal(testUserForm.email);
        expect(verifiedUser.activity[0].action).to.equal("verified email");
        return emitterPromise;
      });
  });

  var resetToken;
  var resetTokenHashed;

  it("should generate a password reset token", function() {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once("forgot-password", function(user) {
        expect(user._id).to.equal("superuser");
        resolve();
      });
    });

    var spySendMail = sinon.spy(mailer, "sendEmail");

    return previous.then(function() {
      // console.log('Generating password reset token');
      return user.forgotPassword(testUserForm.email, req);
    })
      .then(function() {
        return userDB.get(testUserForm.username);
      })
      .then(function(result) {
        resetTokenHashed = result.forgotPassword.token; // hashed token stored in db

        expect(result.forgotPassword.token).to.be.a("string");
        expect(result.forgotPassword.expires).to.be.above(Date.now());
        expect(result.activity[0].action).to.equal("forgot password");

        expect(spySendMail.callCount).to.equal(1);

        var args = spySendMail.getCall(0).args;
        expect(args[0]).to.equal("forgotPassword");
        expect(args[1]).to.equal(testUserForm.email);
        expect(args[2].user._id).to.equal(testUserForm.username);
        expect(args[2].token).to.be.a("string");

        resetToken = args[2].token; // keep unhashed token emailed to user.
        expect(resetTokenHashed).to.not.equal(resetToken);
        return emitterPromise;
      });
  });

  it("should not reset the password", function() {
    // eslint-disable-next-line
    return previous.then(function() {
      // console.log('Resetting the password');
      var form = {
        token: resetToken,
        password: "secret",
        confirmPassword: "secret"
      };
      return user.resetPassword(form);
    })
      .then(function() {
        throw new Error("Validation errors should have been generated");
      }, function(err) {
        expect(err.message).to.equal("Validation failed");
        if (err.validationErrors) {
          expect(err.validationErrors.password[0]).to.equal("Password must be at least 8 characters");
        }
        else {
          console.log("nenenene", err.message);
          throw err;
        }
      });
  });

  it("should reset the password", function() {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once("password-reset", function(user) {
        expect(user._id).to.equal("superuser");
        resolve();
      });
    });

    return previous.then(function() {
      // console.log('Resetting the password');
      var form = {
        token: resetToken,
        password: "newSecret",
        confirmPassword: "newSecret"
      };
      return user.resetPassword(form);
    })
      .then(function() {
        return userDB.get(testUserForm.username);
      })
      .then(function(userAfterReset) {
        // It should delete the password reset token completely
        /* jshint -W030 */
        expect(userAfterReset.forgotPassword).to.be.an("undefined");
        /* jshint +W030 */
        expect(userAfterReset.activity[0].action).to.equal("reset password");
        return util.verifyPassword(userAfterReset.local, "newSecret");
      })
      .then(function() {
        return emitterPromise;
      });
  });

  it("should change the password", function() {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once("password-change", function(user) {
        expect(user._id).to.equal("superuser");
        resolve();
      });
    });

    return previous.then(function() {
      // console.log('Changing the password');
      var form = {
        currentPassword: "newSecret",
        newPassword: "superpassword2",
        confirmPassword: "superpassword2"
      };
      return user.changePasswordSecure(testUserForm.username, form);
    })
      .then(function() {
        return userDB.get(testUserForm.username);
      })
      .then(function(userAfterChange) {
        expect(userAfterChange.activity[0].action).to.equal("changed password");
        return util.verifyPassword(userAfterChange.local, "superpassword2");
      })
      .then(function() {
        return emitterPromise;
      });
  });

  it("should change the email", function() {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once("email-changed", function(user) {
        expect(user._id).to.equal("superuser");
        resolve();
      });
    });

    return previous.then(function() {
      // console.log('Changing the email');
      return user.changeEmail(testUserForm.username, "superuser2@example.com", req);
    })
      .then(function() {
        return userDB.get(testUserForm.username);
      })
      .then(function(userAfterChange) {
        expect(userAfterChange.activity[0].action).to.equal("changed email");
        expect(userAfterChange.unverifiedEmail.email).to.equal("superuser2@example.com");
        return emitterPromise;
      });
  });

  it("should create a new account from facebook auth", function() {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once("signup", function(user) {
        expect(user._id).to.equal("misterx");
        resolve();
      });
    });

    var auth = {token: "x"};
    var profile = {
      id: "abc123",
      username: "misterx",
      emails: [{value: "misterx@example.com"}]
    };

    return previous.then(function() {
      // console.log('Authenticating new facebook user');
      return user.socialAuth("facebook", auth, profile, req);
    })
      .then(function() {
        return userDB.get("misterx");
      })
      .then(function(result) {
        expect(result.facebook.auth.token).to.equal("x");
        expect(result.email).to.equal("misterx@example.com");
        expect(result.providers[0]).to.equal("facebook");
        expect(result.facebook.profile.username).to.equal("misterx");
        expect(result.activity[0].action).to.equal("signup");
        expect(result.activity[0].provider).to.equal("facebook");
        return emitterPromise;
      });
  });

  it("should refresh an existing account from facebook auth", function() {
    var auth = {token: "y"};
    var profile = {
      id: "abc123",
      username: "misterx",
      emails: [{value: "misterx@example.com"}]
    };

    return previous.then(function() {
      // console.log('Authenticating existing facebook user');
      return user.socialAuth("facebook", auth, profile, req);
    })
      .then(function() {
        return userDB.get("misterx");
      })
      .then(function(result) {
        expect(result.facebook.auth.token).to.equal("y");
      });
  });

  it("should reject an email already in use", function() {
    var auth = {token: "y"};
    var profile = {
      id: "cde456",
      username: "misterx2",
      emails: [{value: "misterx@example.com"}]
    };

    return previous.then(function() {
      // console.log('Making sure an existing email is rejected');
      return user.socialAuth("facebook", auth, profile, req);
    })
      .then(function() {
        throw new Error("existing email should have been rejected");
      }, function(err) {
        expect(err.status).to.equal(409);
      });
  });

  it("should generate a username in case of conflict", function() {
    var auth = {token: "y"};
    var profile = {
      id: "cde456",
      username: "misterx",
      emails: [{value: "misterx99@example.com"}]
    };
    var docs = [
      {_id: "misterx1"},
      {_id: "misterx2"},
      {_id: "misterx4"}
    ];

    return previous
      .then(function() {
        // console.log('Generating username after conflict');
        return userDB.bulkDocs(docs);
      })
      .then(function(res) {
        return user.socialAuth("facebook", auth, profile, req);
      })
      .then(function(result) {
        expect(result._id).to.equal("misterx3");
      });
  });

  it("should link a social profile to an existing user", function() {
    var auth = {token: "y"};
    var profile = {
      id: "efg789",
      username: "superuser",
      emails: [{value: "superuser@example.com"}]
    };

    return previous
      .then(function() {
        // console.log('Linking social profile to existing user');
        return user.linkSocial("superuser", "facebook", auth, profile, {});
      })
      .then(function(theUser) {
        expect(theUser.facebook.profile.username).to.equal("superuser");
        expect(theUser.activity[0].action).to.equal("link");
        expect(theUser.activity[0].provider).to.equal("facebook");
        // Test that the activity list is limited to the maximum value
        expect(theUser.activity.length).to.equal(3);
      });
  });

  it("should unlink a social profile", function() {
    return previous
      .then(function() {
        // console.log('Unlinking a social profile');
        return user.unlink("superuser", "facebook");
      })
      .then(function(theUser) {
        expect(typeof theUser.facebook).to.equal("undefined");
        expect(theUser.providers.length).to.equal(1);
        expect(theUser.providers.indexOf("facebook")).to.equal(-1);
      });
  });

  it("should clean all expired sessions", function() {
    var testUser = {
      _id: "testuser"
    };

    return previous
      .then(function() {
        // console.log('Cleaning expired sessions');
        return userDB.bulkDocs([testUser]);
      })
      .then(function() {
        // Create first session
        return user.createSession(testUser._id);
      })
      .then(function(session) {
        return keysDB.get("org.couchdb.user:" + session.dbUser);
      })
      .then(function(doc) {
        // expire first session
        doc.expires = 100;
        return keysDB.put(doc);
      })
      .then(function() {
        // Create second session
        return user.createSession(testUser._id);
      })
      .then(function() {
        return user.logoutUserSessions(testUser, "expired");
      })
      .then(function() {
        return keysDB.query("_superlogin/user", {
          key: testUser._id
        });
      })
      .then(function(results) {
        // there should only be one session left
        expect(results.rows.length).to.equal(1);
      });
  });

  it("should log out of all other sessions", function() {
    var testUser = {
      _id: "testuser"
    };

    var keepSession;

    return previous
      .then(function() {
        // Create first session
        return user.createSession(testUser._id);
      })
      .then(function(session) {
        keepSession = session.dbUser;
      })
      .then(function() {
        // Create second session
        return user.createSession(testUser._id);
      })
      .then(function() {
        return user.logoutOthers(testUser, keepSession);
      })
      .then(function() {
        return keysDB.query("_superlogin/user", {
          key: testUser._id
        });
      })
      .then(function(results) {
        // the keepSession and the session from above
        expect(results.rows.length).to.equal(1);
        expect(results.rows[0].id).to.equal("org.couchdb.user:" + keepSession);
      });
  });

  it("should add a new user database", function() {
    return previous
      .then(function() {
        // console.log('Adding a new user database');
        return user.addUserDB("superuser", "test_superdb", "shared");
      })
      .then(function() {
        return userDB.get("superuser");
      })
      .then(function(userDoc) {
        expect(userDoc.personalDBs.test_superdb.type).to.equal("shared");
        return checkDBExists("test_superdb");
      })
      .then(function(result) {
        expect(result).to.equal(true);
      });
  });

  it("should remove a user database", function() {
    return previous
      .then(function() {
        // console.log('Removing a user database');
        return user.removeUserDB("superuser", "test_superdb", false, true);
      })
      .then(function() {
        return userDB.get("superuser");
      })
      .then(function(userDoc) {
        expect(typeof userDoc.personalDBs.test_superdb).to.equal("undefined");
        return checkDBExists("test_superdb");
      })
      .then(function(result) {
        expect(result).to.equal(false);
      });
  });

  it("should delete a user and all databases", function() {
    return previous
      .then(function() {
        // console.log('Deleting user');
        return checkDBExists("test_usertest$superuser");
      })
      .then(function(result) {
        expect(result).to.equal(true);
        return user.remove("superuser", true);
      })
      .then(function() {
        return userDB.get("superuser");
      })
      .then(function(result) {
        throw new Error({ message: "User should have been deleted!" });
      }, function(err) {
        expect(err.name).to.equal("not_found");
        return checkDBExists("test_usertest$superuser");
      })
      .then(function(result) {
        expect(result).to.equal(false);
      });
  });

  it("should create a new user in userEmail mode", function() {
    return previous
      .then(function() {
        userConfig.setItem("local.emailUsername", true);
        // Don't create any more userDBs
        userConfig.removeItem("userDBs.defaultDBs");
        // Create a new instance of user with the new config
        user = new User(userConfig, userDB, keysDB, mailer, emitter);
        return user.create(emailUserForm, req);
      })
      .then(function(newUser) {
        expect(newUser.unverifiedEmail.email).to.equal(emailUserForm.email);
        expect(newUser._id).to.equal(emailUserForm.email);
      });
  });

  it("should not create a user with conflicting email", function() {
    return previous
      .then(function() {
        return user.create(emailUserForm, req);
      })
      .then(function(newUser) {
        throw new Error({ message: "Should not have created the user!" });
      }, function(err) {
        if (err.message) {
          expect(err.message).to.equal("Validation failed");
        }
        else {
          throw err;
        }
      });
  });

  function checkDBExists(dbname) {
    var finalUrl = dbUrl + "/" + dbname;
    return axios.get(finalUrl).then(function(res) {
      if (res.data.db_name) {
        console.log(res);
        return BPromise.resolve(true);
      }
    }).catch(function(err) {
      if (err.response && err.response.status === 404) {
        return BPromise.resolve(false);
      }
    });
  }
});
