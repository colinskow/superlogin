'use strict';
var events = require('events');
var path = require('path');
var PouchDB = require('pouchdb');
var BPromise = require('bluebird');
var Configure = require('../lib/configure');
var User = require('../lib/user');
var Mailer = require('../lib/mailer');
var util = require('../lib/util');
var seed = require('pouchdb-seed-design');
var request = require('superagent');
var config = require('./test.config.js');


var chai = require('chai');
var sinon = require('sinon');
var expect = chai.expect;
chai.use(require('sinon-chai'));

var dbUrl = util.getDBURL(config.dbServer);
var emitter = new events.EventEmitter();

PouchDB.setMaxListeners(20);
var userDB = new PouchDB(dbUrl + "/superlogin_test_users");
var keysDB = new PouchDB(dbUrl + "/superlogin_test_keys");

var testUserForm = {
    name: 'Super',
    username: 'superuser',
    email: 'superuser@example.com',
    password: 'superlogin',
    confirmPassword: 'superlogin',
    roles: ['user', 'client', 'inspector', 'inspector1']
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
        sendConfirmEmail: false,
        requireEmailConfirm: false,
        passwordConstraints: {
            length: {
                minimum: 8,
                message: "must be at least 8 characters"
            },
            matches: 'confirmPassword'
        }
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
        password: config.dbServer.password,
        publicURL: 'https://mydb.example.com'
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
            private: ['usertest1'],
            shared: ['usertest1']
        },

        customDBs: [
            {
                roles: "client",
                DBs: {

                    shared: ['usertest1']
                },
                //approach:'rename'
            },
            {
                roles: "inspector",
                DBs: {
                    private: ['usertest2']
                },
                // approach:'rename'
            },
            {
                roles: "inspector1",
                DBs: {
                    private: ['usertest1'],
                    shared: ['usertest3', 'usertest2']
                },

                approach: 'rename'
            }
        ],

        privatePrefix: 'test',
        designDocDir: __dirname + '/ddocs'
    },

    userModel: {
        whitelist: ['roles'],
        validate: {
            roles: {
                presence: true
            }
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

describe('CustomDbs', function () {


    var mailer = new Mailer(userConfig);
    var user = new User(userConfig, userDB, keysDB, mailer, emitter);
    var previous;

    before(function () { // 'should prepare the database'
        console.log('Seeding design docs');
        var userDesign = require('../designDocs/user-design');
        userDesign = util.addProvidersToDesignDoc(userConfig, userDesign);
        previous = BPromise.resolve();

        return previous.then(function () {
            return seed(userDB, userDesign);
        });
    });
    /*
     after(function() {  // 'should destroy all the test databases'
     return previous.finally(function() {
     // console.log('Destroying database');
     var userTestDB1 = new PouchDB(dbUrl + "/test_usertest2$superuser");
     var userTestDB2 = new PouchDB(dbUrl + "/test_usertest1_private$superuser");
     var userTestDB3 = new PouchDB(dbUrl + "/test_usertest1");
     var userTestDB4 = new PouchDB(dbUrl + "/usertest2_shared");
     var userTestDB5 = new PouchDB(dbUrl + "/usertest3");
     return BPromise.all([userDB.destroy(), keysDB.destroy(), userTestDB1.destroy(), userTestDB2.destroy(),
     userTestDB3.destroy(), userTestDB4.destroy(),userTestDB5.destroy()]);
     });
     });
     */
    it('should save a new user with customs data bases according to the role of the users', function () {
        // console.log('Creating User');
        var emitterPromise = new BPromise(function (resolve) {
            emitter.once('signup', function (user) {
                expect(user._id).to.equal('superuser');
                resolve();
            });
        });

        return user.create(testUserForm, req).then(function () {
            // console.log('User created');
            return userDB.get(testUserForm.username);
        })
            .then(function (newUser) {
                //verifyEmailToken = newUser.unverifiedEmail.token;
                expect(newUser._id).to.equal('superuser');
                expect(newUser.local.salt).to.be.a('string');
                expect(newUser.local.derived_key).to.be.a('string');
                expect(newUser.roles[0]).to.equal('user');
                expect(newUser.roles[1]).to.equal('client');
                expect(newUser.roles[2]).to.equal('inspector');
                expect(newUser.roles[3]).to.equal('inspector1');
                expect(newUser.personalDBs.usertest3.type).to.equal('shared');
                expect(newUser.personalDBs.usertest2_shared.type).to.equal('shared');
                expect(newUser.personalDBs.usertest1.type).to.equal('shared');
                expect(newUser.personalDBs.test_usertest1_private$superuser.type).to.equal('private');
                expect(newUser.personalDBs.test_usertest2$superuser.type).to.equal('private');
                expect(newUser.activity[0].action).to.equal('signup');
                return emitterPromise;
            });
    });

    var sessionKey, sessionPass, firstExpires;
    it('should generate a new session for the user with customs data bases according to the role of the users', function () {
        var emitterPromise = new BPromise(function (resolve) {
            emitter.once('login', function (session) {
                expect(session.user_id).to.equal('superuser');
                resolve();
            });
        });

        return previous
            .then(function () {
                // console.log('Creating session');
                return user.createSession(testUserForm.username, 'local', req);
            })
            .then(function (result) {
                console.log(result);
                console.log('\n');
                sessionKey = result.token;
                sessionPass = result.password;
                firstExpires = result.expires;
                expect(sessionKey).to.be.a('string');
                expect(result.userDBs.usertest2).to.equal('https://' + sessionKey + ':' + sessionPass + '@' +
                    'mydb.example.com/test_usertest2$superuser');
                expect(result.userDBs.usertest1_private).to.equal('https://' + sessionKey + ':' + sessionPass + '@' +
                    'mydb.example.com/test_usertest1_private$superuser');
                expect(result.userDBs.usertest2_shared).to.equal('https://' + sessionKey + ':' + sessionPass + '@' +
                    'mydb.example.com/usertest2_shared');
                expect(result.userDBs.usertest3).to.equal('https://' + sessionKey + ':' + sessionPass + '@' +
                    'mydb.example.com/usertest3');
                expect(result.userDBs.usertest1).to.equal('https://' + sessionKey + ':' + sessionPass + '@' +
                    'mydb.example.com/usertest1');
                return (userDB.get(testUserForm.username));
            })
            .then(function (user) {
                expect(user.session[sessionKey].ip).to.equal('1.1.1.1');
                expect(user.activity[0].action).to.equal('login');
                return emitterPromise;
            });
    });
});
