'use strict';

var request = require('superagent');
var chai = require('chai');
var sinon = require('sinon');
var expect= chai.expect;
chai.use(require('sinon-chai'));

var BPromise = require('bluebird');
global.Promise = BPromise;
var PouchDB = require('pouchdb');
var seed = require('pouchdb-seed-design');
var util = require('../lib/util.js');
var DBAuth = require('../lib/dbauth');
var Configure = require('../lib/configure');

describe('SuperLogin', function() {

  var app;
  var superlogin;
  var userDB, keysDB;
  var previous;
  var accessToken;
  var accessPass;
  var expireCompare;
  var resetToken = null;
  var dbAuth;

  var config = require('./test.config');
  var server = 'http://localhost:5000';
  var dbUrl = util.getDBURL(config.dbServer);

  var newUser = {
    name: 'Kewl Uzer',
    username: 'kewluzer',
    email: 'kewluzer@example.com',
    password: '1s3cret',
    confirmPassword: '1s3cret'
  };

  var newUser2 = {
    name: 'Kewler Uzer',
    username: 'kewleruzer',
    email: 'kewleruzer@example.com',
    password: '1s3cret',
    confirmPassword: '1s3cret'
  };
  
  

  before(function() {
    userDB = new PouchDB(dbUrl + "/sl_test-users");
    keysDB = new PouchDB(dbUrl + "/sl_test-keys");
    dbAuth = new DBAuth(new Configure(config), userDB, keysDB);
    app = require('./test-server')(config);
    app.superlogin.onCreate(function(userDoc, provider) {
      userDoc.profile = {name: userDoc.name};      
      return BPromise.resolve(userDoc);
    });

    previous = seed(userDB, require('../designDocs/user-design'));
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

  it('should create a new user', function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        request
          .post(server + '/auth/register')
          .send(newUser)
          .end(function(err, res) {
            if (err) return reject(err);
            expect(res.status).to.equal(201);
            expect(res.body.success).to.equal('User created.');
            // console.log('User created');
            resolve();
          });
      });
    });
  });

  it('should verify the email', function() {
    var emailToken;
    return previous.then(function() {
      return userDB.get('kewluzer')
        .then(function(record) {
          emailToken = record.unverifiedEmail.token;
          return 1;
        })
        .then(function() {
          return new BPromise(function(resolve, reject) {
            request
              .get(server + '/auth/confirm-email/' + emailToken)
              .end(function(err, res) {
                if (err) return reject(err);
                expect(res.status).to.equal(200);
                // console.log('Email successfully verified.');
                resolve();
              });
          });
        });
    });
  });

  it('should login the user', function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        request
          .post(server + '/auth/login')
          .send({ username: newUser.username, password: newUser.password })
          .end(function(err, res) {
            if (err) return reject(err);
            accessToken = res.body.token;
            accessPass = res.body.password;
            expect(res.status).to.equal(200);
            expect(res.body.roles[0]).to.equal('user');
            expect(res.body.token.length).to.be.above(10);
            expect(res.body.profile.name).to.equal(newUser.name);
            // console.log('User successfully logged in');
            resolve();
          });
      });
    });
  });

  it('should access a protected endpoint', function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        request
          .get(server + '/auth/session')
          .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
          .end(function(err, res) {
            if (err) return reject(err);
            expect(res.status).to.equal(200);
            // console.log('Secure endpoint successfully accessed.');
            resolve();
          });
      });
    });
  });

  it('should require a role', function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        request
          .get(server + '/user')
          .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
          .end(function(err, res) {
            if (err) return reject(err);
            expect(res.status).to.equal(200);
            // console.log('Role successfully required.');
            resolve();
          });
      });
    });
  });

  it('should deny access when a required role is not present', function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        request
          .get(server + '/admin')
          .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
          .end(function(err, res) {
            //if (err) return reject(err);
            expect(res.status).to.equal(403);
            // console.log('Admin access successfully denied.');
            resolve();
          });
      });
    });
  });

  it('should generate a forgot password token', function() {
    var spySendMail = sinon.spy(app.superlogin.mailer, "sendEmail");

    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        request
          .post(server + '/auth/forgot-password')
          .send({email: newUser.email})
          .end(function(err, res) {
            if (err) return reject(err);
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

  it('should reset the password', function() {
    return previous.then(function() {
      return userDB.get(newUser.username)
        .then(function(resetUser) {
          return new BPromise(function(resolve, reject) {
            request
              .post(server + '/auth/password-reset')
              .send({token: resetToken, password: 'newpass', confirmPassword: 'newpass'})
              .end(function(error, res) {
                if(error || res.status !== 200) {
                  throw new Error('Failed to reset the password.');
                }
                expect(res.status).to.equal(200);
                // console.log('Password successfully reset.');
                resolve();
              });
          });
        });
    });
  });

  it('should logout the user upon password reset', function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        request
          .get(server + '/auth/session')
          .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
          .end(function(err, res) {
            //if (err) return reject(err);
            expect(res.status).to.equal(401);
            // console.log('User has been successfully logged out on password reset.');
            resolve();
          });
      });
    });
  });

  it('should login with the new password', function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        request
          .post(server + '/auth/login')
          .send({ username: newUser.username, password: 'newpass' })
          .end(function(err, res) {
            if (err) return reject('Failed to log in. ' + err);
            accessToken = res.body.token;
            accessPass = res.body.password;
            expireCompare = res.body.expires;
            expect(res.status).to.equal(200);
            expect(res.body.roles[0]).to.equal('user');
            expect(res.body.token.length).to.be.above(10);
            // console.log('User successfully logged in with new password');
            resolve();
          });
      });
    });
  });

  it('should refresh the session', function() {
    return previous.then(function() {
      return new BPromise(function(resolve, reject) {
        request
          .post(server + '/auth/refresh')
          .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
          .end(function(err, res) {
            if (err) return reject(err);
            expect(res.status).to.equal(200);
            expect(res.body.expires).to.be.above(expireCompare);
            // console.log('Session successfully refreshed.');
            resolve();
          });
      });
    });
  });

  it('should change the password', function() {
    return previous.then(function() {
      return userDB.get(newUser.username)
        .then(function(resetUser) {
          return new BPromise(function(resolve, reject) {
            request
              .post(server + '/auth/password-change')
              .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
              .send({currentPassword: 'newpass', newPassword: 'newpass2', confirmPassword: 'newpass2'})
              .end(function(error, res) {
                if(error || res.status !== 200) {
                  throw new Error('Failed to change the password.');
                }
                expect(res.status).to.equal(200);
                // console.log('Password successfully changed.');
                resolve();
              });
          });
        });
    });
  });

  it('should logout the user', function() {
    return previous
      .then(function() {
        return new BPromise(function(resolve, reject) {
          request
            .post(server + '/auth/logout')
            .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
            .end(function(error, res) {
              if(error || res.status !== 200) {
                throw new Error('Failed to logout the user.');
              }
              expect(res.status).to.equal(200);
              resolve();
            });
      })
        .then(function() {
          return new BPromise(function(resolve, reject) {
            request
              .get(server + '/auth/session')
              .set('Authorization', 'Bearer ' + accessToken + ':' + accessPass)
              .end(function(error, res) {
                expect(res.status).to.equal(401);
                // console.log('User has been successfully logged out.');
                resolve();
              });
          });
        });
    });
  });

  it('should login after creating a new user', function() {
    return previous.then(function() {
      app.config.setItem('security.loginOnRegistration', true);
      return new BPromise(function(resolve, reject) {
        request
          .post(server + '/auth/register')
          .send(newUser2)
          .end(function(error, res) {
            expect(res.status).to.equal(200);
            /* jshint -W030 */
            expect(res.body.token).to.be.a.string;
            /* jshint +W030 */
            // console.log('User created and logged in');
            resolve();
          });
      });
    });
  });

  it('should validate a username', function() {
    return previous
      .then(function() {
        return new BPromise(function(resolve, reject) {
          request
            .get(server + '/auth/validate-username/idontexist')
            .end(function(error, res) {
              expect(res.status).to.equal(200);
              expect(res.body.ok).to.equal(true);
              resolve();
            });
        });
      })
      .then(function() {
        return new BPromise(function(resolve, reject) {
          request
            .get(server + '/auth/validate-username/kewluzer')
            .end(function(error, res) {
              expect(res.status).to.equal(409);
              // console.log('Validate Username is working');
              resolve();
            });
        });
      });
  });

  it('should validate an email', function() {
    return previous
      .then(function() {
        return new BPromise(function(resolve, reject) {
          request
            .get(server + '/auth/validate-email/nobody@example.com')
            .end(function(error, res) {
              expect(res.status).to.equal(200);
              expect(res.body.ok).to.equal(true);
              resolve();
            });
        });
      })
      .then(function() {
        return new BPromise(function(resolve, reject) {
          request
            .get(server + '/auth/validate-username/kewluzer@example.com')
            .end(function(error, res) {
              expect(res.status).to.equal(409);
              // console.log('Validate Email is working');
              resolve();
            });
        });
      });
  });

  function attemptLogin(username, password) {
    return new BPromise(function(resolve, reject) {
      request
        .post(server + '/auth/login')
        .send({ username: username, password: password })
        .end(function(error, res) {
          resolve({status: res.status, message: res.body.message});
        });
    });
  }

  it('should respond unauthorized if a user logs in and no password is set', function() {
    return previous
      .then(function() {
        return userDB.put({
          _id: 'nopassword',
          email: 'nopassword@example.com'
        });
      })
      .then(function() {
        return attemptLogin('nopassword', 'wrongpassword');
      })
      .then(function(result) {
        expect(result.status).to.equal(401);
        expect(result.message).to.equal('Invalid username or password');
      });
  });

  it('should block a user after failed logins', function() {
    return previous
      .then(function() {
        return attemptLogin('kewluzer', 'wrong');
      })
      .then(function(result) {
        expect(result.status).to.equal(401);
        expect(result.message).to.equal('Invalid username or password');
        return attemptLogin('kewluzer', 'wrong');
      })
      .then(function(result) {
        expect(result.status).to.equal(401);
        expect(result.message).to.equal('Invalid username or password');
        return attemptLogin('kewluzer', 'wrong');
      })
      .then(function(result) {
        expect(result.status).to.equal(401);
        expect(result.message.search('Maximum failed login')).to.equal(0);
        return attemptLogin('kewluzer', 'newpass');
      })
      .then(function(result) {
        expect(result.status).to.equal(401);
        expect(result.message.search('Your account is currently locked')).to.equal(0);        
        return BPromise.resolve();
      });
  });
  
  it('should delete all expired keys', function() {
    var now = Date.now();
    var db1, db2;
    var user1 = {
      _id: 'testuser1',
      session: {
        oldkey1: {expires: now + 50000},
        goodkey1: {expires: now + 50000}
      },
      personalDBs: {'test_expiretest$testuser1': {
        permissions: null,
        name: 'expiretest'
      }}
    };

    var user2 = {
      _id: 'testuser2',
      session: {
        oldkey2: {expires: now + 50000},
        goodkey2: {expires: now + 50000}
      },
      personalDBs: {'test_expiretest$testuser2': {
        permissions: null,
        name: 'expiretest'
      }}
    };

    return previous
      .then(function() {
        var promises = [];
        // Save the users
        promises.push(userDB.bulkDocs([user1, user2]));
        // Add their personal dbs
        promises.push(dbAuth.addUserDB(user1, 'expiretest'));
        promises.push(dbAuth.addUserDB(user2, 'expiretest'));
        // Store the keys
        promises.push(dbAuth.storeKey('testuser1', 'oldkey1', 'password', user1.session.oldkey1.expires));
        promises.push(dbAuth.storeKey('testuser1', 'goodkey1', 'password', user1.session.goodkey1.expires));
        promises.push(dbAuth.storeKey('testuser2', 'oldkey2', 'password', user2.session.oldkey2.expires));
        promises.push(dbAuth.storeKey('testuser2', 'goodkey2', 'password', user2.session.goodkey2.expires));
        return BPromise.all(promises);
      })
      .then(function() {
        // Now we will expire the keys
        var promises = [];
        promises.push(userDB.get('testuser1'));
        promises.push(userDB.get('testuser2'));
        return BPromise.all(promises);
      })
      .then(function(docs) {
        docs[0].session.oldkey1.expires = 100;
        docs[1].session.oldkey2.expires = 100;
        return userDB.bulkDocs(docs);
      })
      .then(function() {
        // Now we will remove the expired keys
        return app.superlogin.removeExpiredKeys();
      })
      .then(function() {
        // Fetch the user docs to inspect them
        db1 = new PouchDB(dbUrl + "/test_expiretest$testuser1");
        db2 = new PouchDB(dbUrl + "/test_expiretest$testuser2");
        var promises = [];
        promises.push(userDB.get('testuser1'));
        promises.push(userDB.get('testuser2'));
        promises.push(keysDB.get('org.couchdb.user:goodkey1'));
        promises.push(keysDB.get('org.couchdb.user:goodkey2'));
        promises.push(db1.get('_security'));
        promises.push(db2.get('_security'));
        return BPromise.all(promises);
      })
      .then(function(docs) {
        // Sessions for old keys should have been deleted, unexpired keys should be there
        expect(docs[0].session.oldkey1).to.be.an('undefined');
        expect(docs[0].session.goodkey1.expires).to.be.a('number');
        expect(docs[1].session.oldkey2).to.be.an('undefined');
        expect(docs[1].session.goodkey2.expires).to.be.a('number');
        // The unexpired keys should still be in the keys database
        expect(docs[2].user_id).to.equal('testuser1');
        expect(docs[3].user_id).to.equal('testuser2');
        // The security document for each personal db should contain exactly the good keys
        expect(docs[4].members.names.length).to.equal(1);
        expect(docs[4].members.names[0]).to.equal('goodkey1');
        expect(docs[5].members.names.length).to.equal(1);
        expect(docs[5].members.names[0]).to.equal('goodkey2');
        // Now we'll make sure the expired keys have been deleted from the users database
        var promises = [];
        promises.push(keysDB.get('org.couchdb.user:oldkey1'));
        promises.push(keysDB.get('org.couchdb.user:oldkey2'));
        return BPromise.settle(promises);
      })
      .then(function(results) {
        /* jshint -W030 */
        expect(results[0].isRejected()).to.be.true;
        expect(results[1].isRejected()).to.be.true;
        /* jshint +W030 */
        // Finally clean up
        return BPromise.all([db1.destroy(), db2.destroy()]);
      });
  });

});
