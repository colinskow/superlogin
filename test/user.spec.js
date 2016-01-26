'use strict';
var events = require('events');
var path = require('path');
var PouchDB = require('pouchdb');
var BPromise = require('bluebird');
var Configure = require('../lib/configure');
var User = require('../lib/user');
var Session = require('../lib/session');
var Mailer = require('../lib/mailer');
var util = require('../lib/util');
var seed = require('pouchdb-seed-design');
var request = require('superagent');
var expect = require('chai').expect;
var helper = require('./helper.js');
var config = require('./test.config.js');
var dbUrl = helper.getDBUrl(config.dbServer);

var emitter = new events.EventEmitter();

PouchDB.setMaxListeners(20);
var userDB = new PouchDB(dbUrl + "/superlogin_test_users");
var keysDB = new PouchDB(dbUrl + "/superlogin_test_keys");

var testUserForm = {
  name: 'Super',
  username: 'superuser',
  email: 'superuser@example.com',
  password: 'secret',
  confirmPassword: 'secret'
};

var emailUserForm = {
  name: 'Awesome',
  email: 'awesome@example.com',
  password: 'supercool',
  confirmPassword: 'supercool'
};

var userConfig = new Configure({
  testMode: {
    noEmail: true
  },
  security: {
    defaultRoles: ['user'],
    userActivityLogSize: 3
  },
  local: {
    sendConfirmEmail: true,
    requireEmailConfirm: false,
  },
  mailer: {
    fromEmail: 'noreply@example.com'
  },
  emails: {
    confirmEmail: {
      subject: 'Please confirm your email',
      template: path.join(__dirname, '../templates/email/confirm-email.ejs'),
      format: 'text'
    },
    forgotPassword: {
      subject: 'Your password reset link',
      template: 'templates/email/forgot-password.ejs',
      format: 'text'
    }
  },
  dbServer: {
    protocol: config.dbServer.protocol,
    host: config.dbServer.host,
    user: config.dbServer.user,
    password: config.dbServer.password
  },
  session: {
    adapter: 'memory'
  },
  userDBs: {
    defaultSecurityRoles: {
      admins: ['admin_role'],
      members: ['member_role']
    },
    model: {
      _default: {
        designDocs: ['test'],
        permissions: ['_reader', '_writer', '_replicator']
      }
    },
    defaultDBs: {
      private: ['usertest']
    },
    privatePrefix: 'test',
    designDocDir: __dirname + '/ddocs'
  },
  providers: {
    facebook: {
      clientID: 'FAKE_ID',
      clientSecret: 'FAKE_SECRET',
      callbackURL: 'http://localhost:5000/auth/facebook/callback'
    }
  },
  userModel: {
    static: {
      modelTest: true
    }
  }
});

var req = {
  headers: {
    host: 'example.com'
  },
  protocol: 'http',
  ip: '1.1.1.1'
};

describe('User Model', function() {
  var mailer = new Mailer(userConfig);
  var user = new User(userConfig, userDB, keysDB, mailer, emitter);
  var userTestDB;
  var previous;

  it('should prepare the database', function(done) {
    console.log('Seeding design docs');
    var userDesign = require('../designDocs/user-design');
    userDesign = util.addProvidersToDesignDoc(userConfig, userDesign);
    previous = BPromise.resolve();
    previous.then(function() {
      return seed(userDB, userDesign).then(function(){
        done();
      });
    })
      .catch(function(err) {
        done(err);
      });
  });

  var verifyEmailToken;

  it('should save a new user', function(done) {
    console.log('Creating User');
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once('signup', function(user) {
        expect(user._id).to.equal('superuser');
        resolve();
      });
    });
    previous.then(function() {
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
        console.log('User created');
        return userDB.get(testUserForm.username);
      })
      .then(function(newUser) {
        verifyEmailToken = newUser.unverifiedEmail.token;
        expect(newUser._id).to.equal('superuser');
        expect(newUser.roles[0]).to.equal('user');
        expect(newUser.local.salt).to.be.a('string');
        expect(newUser.local.derived_key).to.be.a('string');
        expect(newUser.modelTest).to.equal(true);
        expect(newUser.roles[0]).to.equal('user');
        expect(newUser.activity[0].action).to.equal('signup');
        expect(newUser.onCreate1).to.equal(true);
        expect(newUser.onCreate2).to.equal(true);
        return emitterPromise;
      })
      .then(function() {
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should have created a user db with design doc and _security', function(done) {
    console.log('Checking user db and design doc');
    userTestDB = new PouchDB(dbUrl + '/test_usertest$superuser');
    previous
      .then(function() {
        return userTestDB.get('_design/test');
      })
      .then(function(ddoc) {
        expect(ddoc.views.mytest.map).to.be.a('string');
        return userTestDB.get('_security');
      })
      .then(function(secDoc) {
        expect(secDoc.admins.roles[0]).to.equal('admin_role');
        expect(secDoc.members.roles[0]).to.equal('member_role');
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should authenticate the password', function(done) {
    console.log('Authenticating password');
    previous.then(function() {
      console.log('Fetching created user');
      return userDB.get(testUserForm.username);
    })
      .then(function(newUser) {
        return util.verifyPassword(newUser.local, 'secret');
      })
      .then(function(result) {
        console.log('Password authenticated');
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should generate a validation error trying to save the same user again', function(done) {
    previous.then(function() {
      console.log('Trying to create the user again');
      return user.create(testUserForm);
    })
      .then(function() {
        throw new Error('Validation errors should have been generated');
      })
      .catch(function(err) {
        if(err.validationErrors) {
          expect(err.validationErrors.email[0]).to.equal('Email already in use');
          expect(err.validationErrors.username[0]).to.equal('Username already in use');
          done();
        } else {
          done(err);
        }
      });
  });

  var sessionKey, sessionPass, firstExpires;

  it('should generate a new session for the user', function(done) {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once('login', function(session) {
        expect(session.user_id).to.equal('superuser');
        resolve();
      });
    });

    previous
      .then(function() {
        console.log('Creating session');
        return user.createSession(testUserForm.username, 'local', req);
      })
      .then(function(result) {
        sessionKey = result.token;
        sessionPass = result.password;
        firstExpires = result.expires;
        expect(sessionKey).to.be.a('string');
        expect(result.userDBs.usertest).to.equal('http://' + result.token + ':' + result.password + '@' + config.dbServer.host + '/test_usertest$superuser');
        return(userDB.get(testUserForm.username));
      })
      .then(function(user) {
        expect(user.session[sessionKey].ip).to.equal('1.1.1.1');
        expect(user.activity[0].action).to.equal('login');
        return emitterPromise;
      }).then(function() {
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should have authorized the session in the usertest database', function(done) {
    previous
      .then(function() {
        console.log('Verifying session is authorized in personal db');
        return userTestDB.get('_security');
      })
      .then(function(secDoc) {
        expect(secDoc.members.names.length).to.equal(1);
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should refresh a session', function(done) {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once('refresh', function(session) {
        expect(session.user_id).to.equal('superuser');
        resolve();
      });
    });

    previous
      .then(function() {
        console.log('Refreshing session');
        return user.refreshSession(sessionKey, sessionPass);
      })
      .then(function(result) {
        expect(result.expires).to.be.above(firstExpires);
        return emitterPromise;
      })
      .then(function() {
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should log out of a session', function(done) {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once('logout', function(user_id) {
        expect(user_id).to.equal('superuser');
        resolve();
      });
    });

    previous
      .then(function() {
        console.log('Logging out of the session');
        return user.logoutSession(sessionKey);
      })
      .then(function() {
        return user.confirmSession(sessionKey, sessionPass);
      })
      .then(function() {
        throw new Error('Failed to log out of session');
      }, function(err) {
        expect(err).to.equal('invalid token');
        return(userDB.get(testUserForm.username));
      })
      .then(function(user) {
        expect(user.session[sessionKey]).to.be.an('undefined');
        return emitterPromise;
      })
      .then(function() {
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should have deauthorized the session in the usertest database after logout', function(done) {
    previous
      .then(function() {
        return userTestDB.get('_security');
      })
      .then(function(secDoc) {
        expect(secDoc.members.names.length).to.equal(0);
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should log the user out of all sessions', function(done) {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once('logout-all', function(user_id) {
        expect(user_id).to.equal('superuser');
        resolve();
      });
    });

    var sessions = [];
    var passes = [];
    previous
      .then(function() {
        console.log('Logging user out completely');
        return user.createSession(testUserForm.username, 'local', req);
      })
      .then(function(session1) {
        sessions[0] = session1.token;
        passes[0] = session1.password;
        return user.createSession(testUserForm.username, 'local', req);
      })
      .then(function(session2) {
        sessions[1] = session2.token;
        passes[1] = session2.password;
        return user.logoutUser(null, sessions[0]);
      })
      .then(function() {
        return BPromise.all([
          user.confirmSession(sessions[0], passes[0]),
          user.confirmSession(sessions[1], passes[1])
        ]);
      })
      .then(function(results) {
        throw new Error('Failed to delete user sessions');
      }, function(error) {
        expect(error).to.equal('invalid token');
        return userDB.get(testUserForm.username);
      })
      .then(function(user) {
        expect(user.session).to.be.an('undefined');
        // Make sure the sessions are deauthorized in the usertest db
        return userTestDB.get('_security');
      })
      .then(function(secDoc) {
        expect(secDoc.members.names.length).to.equal(0);
        return emitterPromise;
      })
      .then(function() {
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should verify the email', function(done) {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once('email-verified', function(user) {
        expect(user._id).to.equal('superuser');
        resolve();
      });
    });

    previous.then(function() {
      console.log('Verifying email with token');
      return user.verifyEmail(verifyEmailToken);
    })
      .then(function() {
        return userDB.get(testUserForm.username);
      })
      .then(function(verifiedUser) {
        expect(verifiedUser.email).to.equal(testUserForm.email);
        expect(verifiedUser.activity[0].action).to.equal('verified email');
        return emitterPromise;
      })
      .then(function() {
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  var resetToken;

  it('should generate a password reset token', function(done) {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once('forgot-password', function(user) {
        expect(user._id).to.equal('superuser');
        resolve();
      });
    });

    previous.then(function() {
      console.log('Generating password reset token');
      return user.forgotPassword(testUserForm.email, req);
    })
      .then(function() {
        return userDB.get(testUserForm.username);
      })
      .then(function(result) {
        resetToken = result.forgotPassword.token;
        expect(result.forgotPassword.token).to.be.a('string');
        expect(result.forgotPassword.expires).to.be.above(Date.now());
        expect(result.activity[0].action).to.equal('forgot password');
        return emitterPromise;
      }).then(function() {
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should reset the password', function(done) {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once('password-reset', function(user) {
        expect(user._id).to.equal('superuser');
        resolve();
      });
    });

    previous.then(function() {
      console.log('Resetting the password');
      var form = {
        token: resetToken,
        password: 'newSecret',
        confirmPassword: 'newSecret'
      };
      return user.resetPassword(form);
    })
      .then(function() {
        return userDB.get(testUserForm.username);
      })
      .then(function(userAfterReset) {
        // It should delete the password reset token completely
        /* jshint -W030 */
        expect(userAfterReset.forgotPassword).to.be.an.undefined;
        /* jshint +W030 */
        expect(userAfterReset.activity[0].action).to.equal('reset password');
        return util.verifyPassword(userAfterReset.local, 'newSecret');
      })
      .then(function() {
        return emitterPromise;
      }).then(function() {
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should change the password', function(done) {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once('password-change', function(user) {
        expect(user._id).to.equal('superuser');
        resolve();
      });
    });

    previous.then(function() {
      console.log('Changing the password');
      var form = {
        currentPassword: 'newSecret',
        newPassword: 'superpassword2',
        confirmPassword: 'superpassword2'
      };
      return user.changePasswordSecure(testUserForm.username, form);
    })
      .then(function() {
        return userDB.get(testUserForm.username);
      })
      .then(function(userAfterChange) {
        expect(userAfterChange.activity[0].action).to.equal('changed password');
        return util.verifyPassword(userAfterChange.local, 'superpassword2');
      })
      .then(function() {
        return emitterPromise;
      }).then(function() {
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should change the email', function(done) {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once('email-changed', function(user) {
        expect(user._id).to.equal('superuser');
        resolve();
      });
    });

    previous.then(function() {
      console.log('Changing the email');
      return user.changeEmail(testUserForm.username, 'superuser2@example.com', req);
    })
      .then(function() {
        return userDB.get(testUserForm.username);
      })
      .then(function(userAfterChange) {
        expect(userAfterChange.activity[0].action).to.equal('changed email');
        expect(userAfterChange.unverifiedEmail.email).to.equal('superuser2@example.com');
        return emitterPromise;
      })
      .then(function() {
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should create a new account from facebook auth', function(done) {
    var emitterPromise = new BPromise(function(resolve) {
      emitter.once('signup', function(user) {
        expect(user._id).to.equal('misterx');
        resolve();
      });
    });

    var auth = {token: 'x'};
    var profile = {
      id: 'abc123',
      username: 'misterx',
      emails: [{value: 'misterx@example.com'}]
    };
    previous.then(function() {
      console.log('Authenticating new facebook user');
      return user.socialAuth('facebook', auth, profile, req);
    })
      .then(function() {
        return userDB.get('misterx');
      })
      .then(function(result) {
        expect(result.facebook.auth.token).to.equal('x');
        expect(result.email).to.equal('misterx@example.com');
        expect(result.providers[0]).to.equal('facebook');
        expect(result.facebook.profile.username).to.equal('misterx');
        expect(result.activity[0].action).to.equal('signup');
        expect(result.activity[0].provider).to.equal('facebook');
        return emitterPromise;
      }).then(function() {
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should refresh an existing account from facebook auth', function(done) {
    var auth = {token: 'y'};
    var profile = {
      id: 'abc123',
      username: 'misterx',
      emails: [{value: 'misterx@example.com'}]
    };
    previous.then(function() {
      console.log('Authenticating existing facebook user');
      return user.socialAuth('facebook', auth, profile, req);
    })
      .then(function() {
        return userDB.get('misterx');
      })
      .then(function(result) {
        expect(result.facebook.auth.token).to.equal('y');
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should reject an email already in use', function(done) {
    var auth = {token: 'y'};
    var profile = {
      id: 'cde456',
      username: 'misterx2',
      emails: [{value: 'misterx@example.com'}]
    };
    previous.then(function() {
      console.log('Making sure an existing email is rejected');
      return user.socialAuth('facebook', auth, profile, req);
    })
      .then(function() {
        throw new Error('existing email should have been rejected');
      }, function(err) {
        expect(err.status).to.equal(409);
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should generate a username in case of conflict', function(done) {
    var auth = {token: 'y'};
    var profile = {
      id: 'cde456',
      username: 'misterx',
      emails: [{value: 'misterx99@example.com'}]
    };
    var docs = [
      {_id: 'misterx1'},
      {_id: 'misterx2'},
      {_id: 'misterx4'}
    ];
    previous
      .then(function() {
        console.log('Generating username after conflict');
        userDB.bulkDocs(docs);
      })
      .then(function() {
        return user.socialAuth('facebook', auth, profile, req);
      })
      .then(function(result) {
        expect(result._id).to.equal('misterx3');
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should link a social profile to an existing user', function(done) {
    var auth = {token: 'y'};
    var profile = {
      id: 'efg789',
      username: 'superuser',
      emails: [{value: 'superuser@example.com'}]
    };
    previous
      .then(function() {
        console.log('Linking social profile to existing user');
        return user.linkSocial('superuser', 'facebook', auth, profile, {});
      })
      .then(function(theUser) {
        expect(theUser.facebook.profile.username).to.equal('superuser');
        expect(theUser.activity[0].action).to.equal('link');
        expect(theUser.activity[0].provider).to.equal('facebook');
        // Test that the activity list is limited to the maximum value
        expect(theUser.activity.length).to.equal(3);
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should unlink a social profile', function(done) {
    previous
      .then(function() {
        console.log('Unlinking a social profile');
        return user.unlink('superuser', 'facebook');
      })
      .then(function(theUser) {
        expect(typeof theUser.facebook).to.equal('undefined');
        expect(theUser.providers.length).to.equal(1);
        expect(theUser.providers.indexOf('facebook')).to.equal(-1);
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should clean all expired sessions', function(done) {
    var now = Date.now();
    var testUser = {
      _id: 'testuser',
      session: {
        good1: {
          expires: now + 100000
        },
        bad1: {
          expires: now - 100000
        },
        bad2: {
          expires: now - 100000
        }
      }
    };
    previous
      .then(function() {
        console.log('Cleaning expired sessions');
        return user.logoutUserSessions(testUser, 'expired');
      })
      .then(function(finalDoc) {
        expect(Object.keys(finalDoc.session).length).to.equal(1);
        expect(finalDoc.session).to.include.keys('good1');
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should log out of all other sessions', function(done) {
    var now = Date.now();
    var testUser = {
      _id: 'testuser',
      session: {
        this1: {},
        other1: {},
        other2: {}
      }
    };
    previous
      .then(function() {
        console.log('Logging out of other sessions');
        return userDB.put(testUser);
      })
      .then(function() {
        return user.logoutOthers('this1');
      })
      .then(function() {
        return userDB.get('testuser');
      })
      .then(function(finalDoc) {
        expect(Object.keys(finalDoc.session).length).to.equal(1);
        expect(finalDoc.session).to.include.keys('this1');
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should add a new user database', function(done) {
    previous
      .then(function() {
        console.log('Adding a new user database');
        return user.addUserDB('superuser', 'test_superdb', 'shared');
      })
      .then(function() {
        return userDB.get('superuser');
      })
      .then(function(userDoc) {
        // console.log(userDoc.personalDBs);
        expect(userDoc.personalDBs.test_superdb.type).to.equal('shared');
        return checkDBExists('test_superdb');
      })
      .then(function(result) {
        expect(result).to.equal(true);
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should remove a user database', function(done) {
    previous
      .then(function() {
        console.log('Removing a user database');
        return user.removeUserDB('superuser', 'test_superdb', false, true);
      })
      .then(function() {
        return userDB.get('superuser');
      })
      .then(function(userDoc) {
        expect(typeof userDoc.personalDBs.test_superdb).to.equal('undefined');
        return checkDBExists('test_superdb');
      })
      .then(function(result) {
        expect(result).to.equal(false);
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should delete a user and all databases', function(done) {
    previous
      .then(function() {
        console.log('Deleting user');
        return checkDBExists('test_usertest$superuser');
      })
      .then(function(result) {
        expect(result).to.equal(true);
        return user.remove('superuser', true);
      })
      .then(function() {
        return userDB.get('superuser');
      })
      .then(function(result) {
        throw 'User should have been deleted!';
      }, function(err) {
        expect(err.name).to.equal('not_found');
        return checkDBExists('test_usertest$superuser');
      })
      .then(function(result) {
        expect(result).to.equal(false);
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should create a new user in userEmail mode', function(done) {
    previous
      .then(function() {
        userConfig.setItem('local.emailUsername', true);
        // Don't create any more userDBs
        userConfig.removeItem('userDBs.defaultDBs');
        // Create a new instance of user with the new config
        user = new User(userConfig, userDB, keysDB, mailer, emitter);
        return user.create(emailUserForm, req);
      })
      .then(function(newUser) {
        expect(newUser.unverifiedEmail.email).to.equal(emailUserForm.email);
        expect(newUser._id).to.equal(emailUserForm.email);
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  it('should not create a user with conflicting email', function(done) {
    previous
      .then(function() {
        return user.create(emailUserForm, req);
      })
      .then(function(newUser) {
        throw "Should not have created the user!";
      }, function(err) {
        if(err.error) {
          expect(err.error).to.equal('Validation failed');
          done();
        } else {
          done(err);
        }
      });
  });

  it('should destroy all the test databases', function(done) {
    previous.finally(function() {
      console.log('Destroying database');
      var userTestDB1 = new PouchDB(dbUrl + "/test_usertest$superuser");
      var userTestDB2 = new PouchDB(dbUrl + "/test_usertest$misterx");
      var userTestDB3 = new PouchDB(dbUrl + "/test_usertest$misterx3");
      var userTestDB4 = new PouchDB(dbUrl + "/test_superdb");
      return BPromise.all([userDB.destroy(), keysDB.destroy(), userTestDB1.destroy(), userTestDB2.destroy(), userTestDB3.destroy(), userTestDB4.destroy()]);
    })
      .then(function() {
        done();
      })
      .catch(function(err) {
        done(err);
      });
  });

  function checkDBExists(dbname) {
    var finalUrl = dbUrl + '/' + dbname;
    return BPromise.fromNode(function(callback) {
      request.get(finalUrl)
        .end(callback);
    })
      .then(function(res) {
        var result = JSON.parse(res.text);
        if(result.db_name) {
          return BPromise.resolve(true);
        }
      }, function(err) {
        if(err.status === 404) {
          return BPromise.resolve(false);
        }
      });
  }

});
