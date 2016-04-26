# SuperLogin

[![Build Status](https://travis-ci.org/colinskow/superlogin.png?branch=master)](https://travis-ci.org/colinskow/superlogin)

SuperLogin is a full-featured NodeJS/Express user authentication solution for APIs and Single Page Apps (SPA) using CouchDB or Cloudant.

User authentication is often the hardest part of building any web app, especially if you want to integrate multiple providers. Now all the tough work has been done for you so you can relax and create with less boilerplate!

**([Live Demo](https://superlogin-demo.herokuapp.com))**

For issues and feature requests visit the [issue tracker](https://github.com/colinskow/superlogin/issues).

## Contents

- [Features](#features)
- [Client Tools and Demo](#client-tools-and-demo)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Securing Your Routes](#securing-your-routes)
- [Database Security](#database-security)
- [CouchDB Document Update Validation](#couchdb-document-update-validation)
- [Adding Providers](#adding-providers)
- [Advanced Configuration](#advanced-configuration)
- [Routes](#routes)
- [Event Emitter](#event-emitter)
- [Main API](#main-api)
- [Releases](#releases)

## Features

* Ideal authentication and security solution for modern APIs and Single Page Apps
* Supports local login with username and password using best security practices
* Sends system emails for account confirmation, password reset, or anything else you want to configure
* Add any [Passport](http://passportjs.org) OAuth2 strategy with literally just a couple lines of code
* Facebook, WindowsLive, Google, Github, and LinkedIn integration fully tested
* Link multiple authentication strategies to the same account for user convenience
* 100% cookie free, which means that [CSRF](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_\(CSRF\)_Prevention_Cheat_Sheet) attacks are impossible against your app
* Fast and massively scalable with a Redis session store
* Provides seamless token access to both your CouchDB server (or Cloudant) and your private API
* Manages permissions on an unlimited number of private or shared user databases and seeds them with the correct design documents

## Client Tools and Demo

* [NG-SuperLogin](https://github.com/colinskow/ng-superlogin)
   Helps you easily integrate a SuperLogin backend into your single page AngularJS applications.

* [SuperLogin Demo](https://github.com/colinskow/superlogin-demo)
   A full-stack demo of how to integrate SuperLogin and Express with AngularJS and CouchDB.

* [SuperLogin-client](https://github.com/micky2be/superlogin-client)
   Helps you easily integrate a SuperLogin backend into your Javascript applications.

## How It Works

Simply authenticate yourself with SuperLogin using any supported strategy and you will be issued a temporary access token and password. Then include the access token and password in an Authorization Bearer header on every request to access protected endpoints. The same credentials will authenticate you on any CouchDB or Cloudant database you have been authorized to use.

Session storage is handled by Redis for production environments, but SuperLogin includes a memory adapter for testing purposes. When you logout or the token expires, your session is invalidated and those credentials are also removed from any database you had access to.

## Quick Start

Here's a simple minimalist configuration that will get you up and running right away:

First:
```
npm install superlogin
```
Then...

```javascript
var express = require('express');
var http = require('http');
var bodyParser = require('body-parser');
var logger = require('morgan');
var SuperLogin = require('superlogin');

var app = express();
app.set('port', process.env.PORT || 3000);
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

var config = {
  dbServer: {
    protocol: 'http://',
    host: 'localhost:5984',
    user: '',
    password: '',
    userDB: 'sl-users',
    couchAuthDB: '_users'
  },
  mailer: {
    fromEmail: 'gmail.user@gmail.com',
    options: {
      service: 'Gmail',
        auth: {
          user: 'gmail.user@gmail.com',
          pass: 'userpass'
        }
    }
  },
  userDBs: {
    defaultDBs: {
      private: ['supertest']
    }
  }
}

// Initialize SuperLogin
var superlogin = new SuperLogin(config);

// Mount SuperLogin's routes to our app
app.use('/auth', superlogin.router);

http.createServer(app).listen(app.get('port'));
```

Now get a request tool like [Postman](https://www.getpostman.com) and let's create our first user.

```json
{
  "name": "Joe Smith",
  "username": "joesmith",
  "email": "joesmith@example.com",
  "password": "bigsecret",
  "confirmPassword": "bigsecret"
}
```
POST the form to `http://localhost:3000/auth/register` (using `x-www-form-urlencoded`) and you should get the response `{"success": "User created."}`.

Now to login, simply post your username and password to `http://localhost:3000/auth/login`. You should get a response similar to this:
```json
{
  "issued": 1440232999594,
  "expires": 1440319399594,
  "provider": "local",
  "ip": "127.0.0.1",
  "token": "aViSVnaDRFKFfdepdXtiEg",
  "password": "p7l9VCNbTbOVeuvEBhYW_A",
  "user_id": "joesmith",
  "roles": [
    "user"
  ],
  "userDBs": {
      "supertest": "http://aViSVnaDRFKFfdepdXtiEg:p7l9VCNbTbOVeuvEBhYW_A@localhost:5984/supertest$joesmith"
    }
}
```

You have now been issued an access token. Let's use it to access a protected endpoint. Make a request to `http://localhost:3000/auth/session` and you'll see it was unauthorized. Now add a header to your request: `"Authorization": "Bearer {token}:{password}"` and you should see information about your session. That was easy!

If your user document contains a field called `profile`, this will automatically be included with the session information.

You can also use the same token and password combination to access your personal database. But as soon as you log out your session that access will be revoked.

**Note:** Session tokens for your API will be unusable as soon as they expire. However, there is no mechanism to automatically revoke expired credentials with CouchDB. Whenever a user logs in, logs out, or refreshes the session, SuperLogin will automatically clean up any expired credentials for that user. For additional security, periodically run `superlogin.removeExpiredKeys()` either with `setInterval` or a cron job. This will deauthorize every single expired credential that exists in the system.

## Securing Your Routes

Securing your routes is very simple:
```js
app.get('/admin', superlogin.requireAuth, superlogin.requireRole('admin'),
  function(req, res) {
    res.send('Welcome Admin');
  });
```
Note that you must use `requireAuth` prior to checking any roles or an error will be thrown.

##### `superlogin.requireAuth`
Middleware that authenticates a user with a token and password in the request header. (`"Authorization": "Bearer {token}:{password}"`)

##### `superlogin.requireRole(role)`
Middleware that makes sure the authenticated user possesses the specified `role` (string).

##### `superlogin.requireAnyRole(possibleRoles)`
Middleware that makes sure the user possesses at least one of the specified `possibleRoles` (array).

##### `superlogin.requireAllRoles(requiredRoles)`
Middleware that makes sure the user possesses ALL of the specified `requiredRoles` (array).

## Database Security

If you are using [Cloudant](https://cloudant.com), then your databases are secure by default and all you have to do is ensure the correct permissions are specified under `userDBs.model` in your config.

If, however, you are using regular CouchDB, then Admin Party is default and all your databases are readable and writable by the public until you implement the correct security measures. It is your responsibility to study up on [best security practices](http://blog.mattwoodward.com/2012/03/definitive-guide-to-couchdb.html) and apply them. To block anonymous reads across all databases you can set `require_valid_user` to `true` under `[couch_httpd_auth]` in your CouchDB config.

SuperLogin also allows you to specify default `_security` roles for members and admins in the `userDBs` section of your config file. See [`config.example.js`](https://github.com/colinskow/superlogin/blob/master/config.example.js) for details.

## CouchDB Document Update Validation

CouchDB can save your API a lot of traffic by handling both reads and writes. CouchDB provides the [validate_doc_update function](http://guide.couchdb.org/draft/validation.html) to approve or disapprove what gets written. However, since your CouchDB users are temporary random API keys, you have no idea which user is requesting to write. SuperLogin has inserted the original `user_id` into `userCtx.roles[0]`, prefixed by `user:` (e.g. `user:superman`).

If you are using Cloudant authentication, the prefixed `user_id` is inserted as the first item on the `permissions` array, which will also appear inside `roles` in your `userCtx` object. You will also find all the `roles` from your user doc here.

If you wish to give a user special Cloudant permissions other than the ones specified in your config, you can edit the user doc from the `sl-users` database and under `personalDBs` add an array called `permissions` under the corresponding DB for that user.

## Adding Providers

You can add support for any Passport OAuth2 strategy to SuperLogin with just a few lines of code. (OAuth1 strategies generally require a cookie-based session to work, so are not currently supported by SuperLogin which is sessionless.)

##### Configuration

The first step is to add credentials to your config file. You can skip the callback URL as it will be generated automatically. Here is how to add support for Dropbox:

```js
providers: {
  dropbox: {
    // Credentials here will be passed in on the call to passport.use
    credentials: {
      consumerKey: DROPBOX_APP_KEY,
      consumerSecret: DROPBOX_APP_SECRET
    },
    options: {
      // Options here will be passed in on the call to passport.authenticate
    }
  }
}
```

SuperLogin supports two types of workflows for OAuth2 providers: popup window and client access token.

##### Popup Window Workflow for web browsers (desktop and mobile)

Your client must create a popup window and point it to `/{provider}`, where the user will be directed to authenticate with that provider. After authentication succeeds or fails, it will call a Javascript callback on the parent window called `superlogin.oauthSession`.

After completing the configuration step above, all you have to do is register your new provider with SuperLogin. Simply follow this pattern:

```js
var DropboxStrategy = require('passport-dropbox-oauth2').Strategy;
superlogin.registerOAuth2('dropbox', DroboxStrategy);
```

Now, assuming your credentials are valid, you should be able to authenticate with Dropbox by opening a popup window to `/dropbox`. See below in the Routes documentation for more detail.

##### Client Access Token for Cordova / Phonegap and Native Apps

Cordova and most native app frameworks (including iOS and Android) have plugins which authenticate a user with a provider and provide an `access_token` to the client app. All you have to do is post a request to `/{provider}/token` and include your `access_token` in the request body. SuperLogin will respond with a new session or an error message.

You must use Passport strategies that accept `access_token` posted in the body of the request, such as `passport-facebook-token`, `passport-google-token`, etc.

Here is how to setup the Client Access Token strategy:

```js
var FacebookTokenStrategy = require('passport-facebook-token').Strategy;
superlogin.registerTokenProvider('facebook', FacebookTokenStrategy);
```

Note that this uses the exact settings in your config as the popup window workflow.

## Advanced Configuration

Take a look at [`config.example.js`](https://github.com/colinskow/superlogin/blob/master/config.example.js) for a complete tour of all available configuration options. You'll find a lot of cool hidden features there that aren't documented here.

`/config/default.config.js` contains a list of default settings that will be assumed if you don't specify anything.

## Routes

##### `POST /register`
Creates a new account with a username and password. Required fields are: `username`, `email`, `password` and `confirmPassword`. `name` is optional. Any additional fields you want to include need to be white listed under `userModel` in your config. See [`config.example.js`](https://github.com/colinskow/superlogin/blob/master/config.example.js) for details.

If `local.sendConfirmEmail` is true, a confirmation email will be sent with a verify link. If `local.requireEmailConfirm` is true, the user will not be able to login until the confirmation is complete. If `security.loginOnRegistration` is true a session will be automatically created and sent as the response.

##### `POST /login`
Include `username` and `password` fields to authenticate and initiate a session. The field names can be customized in your config under `local.usernameField` and `local.passwordField`.

##### `GET /confirm-email/{token}`
This link is included in the confirmation email, and will mark the user as confirmed. If `local.confirmEmailRedirectURL` is specified in your config, it will redirect to that location with `?success=true` if successful or `error={error}&message={msg}` if it failed. Otherwise it will generate a standard JSON response.

##### `POST /refresh`
Authentication token required. Extends the life of your current token and returns updated token information. The only field that will change is `expires`. Token life is configurable under `security.sessionLife` and is measured in seconds.
 
##### `POST /logout`
Authentication required. Logs out the current session and deauthorizes the token on all user databases.

##### `POST /logout-others`
Authentication required. Logs out and deauthorizes all user sessions except the current one.

##### `POST /logout-all`
Authentication required. Logs out every session the user has open and deauthorizes the user completely on all databases.

##### `POST /forgot-password`
Sends the forgot password email containing a password reset token. The life of the token can be set under `security.tokenLife` (in seconds).

##### `POST /password-reset`
Resets the password. Required fields: `token`, `password`, and `confirmPassword`.

##### `POST /password-change`
Authentication required. Changes the user's password or creates one if it doesn't exist. Required fields: `newPassword`, and `confirmPassword`. If the user already has a password set then `currentPassword` is required.

##### `GET /validate-username/{username}`
Checks a username to make sure it is correctly formed and not already in use. Responds with status 200 if successful, or status 409 if unsuccessful.

##### `GET /validate-email/{email}`
Checks an email to make sure it is valid and not already in use. Responds with status 200 if successful, or status 409 if unsuccessful.

##### `POST /change-email`
Authentication required. Changes the user's email. Required field: `newEmail`.

##### `GET /session`
Returns information on the current session if it is valid. Otherwise you will get a 401 unauthorized response.

##### `GET /{provider}`
Open this in a popup window to initiate authentication with Facebook, Google, etc. After authentication, the callback will call a javascript function on the parent window called `superlogin.oauthSession` which takes 3 arguments: `error`, `session`, and `link`. `error` explains anything that went wrong. `session` includes the same session object that is generated by `/login`. `link` simply contains the name of the provider that was successfully linked.

##### `GET /link/{provider}?bearer_token={token:password}`
This popup window is opened by a user that is already authenticated in order to link additional providers to the account.

There is a security concern here that the session token is exposed as a query parameter in the URL. While this is secure from interception under HTTPS, it can be stored in the user's browser history and your server logs. If you are concerned about this you can either force your user to log out the session after linking an account, or disable link functionality completely by setting `security.disableLinkAccounts` to `true`.

##### `POST /unlink/{provider}`
Authentication required. Removes the specified provider from the user's account. Local cannot be removed. If there is only one provider left it will fail.

##### `POST /{provider}/token`
This will invoke the client `access_token` strategy for the specified provider if you have registered it. You should include the `access_token` for the provider in the body of your request.

##### `POST /link/{provider}/token`
This will link additional providers to an already authenticated user using the client `access_token` strategy.

## Event Emitter

SuperLogin also acts as an [event emitter](https://nodejs.org/api/events.html), which allows you to receive notifications when important things happen.

**Example:**
```js
superlogin.on('login', function(userDoc, provider){
  console.log('User: ' + userDoc._id + ' logged in with ' + provider);
});
```

Here is a full list of the events that SuperLogin emits, and parameters provided:

- `signup`: (`userDoc`, `provider`)
- `login`: (`newSession`, `provider`)
- `refresh`: (`newSession`)
- `signup`: (`userDoc`, `provider`)
- `password-reset`: (`userDoc`)
- `password-change`: (`userDoc`)
- `forgot-password`: (`userDoc`)
- `email-verified`: (`userDoc`)
- `email-changed`: (`userDoc`)
- `user-db-added`: (`dbName`)
- `user-db-removed`: (`dbName`)
- `logout`: (`user_id`)
- `logout-all`: (`user_id`)

## Main API

##### `new SuperLogin(config, passport, userDB, couchAuthDB)`
Constructs a new instance of SuperLogin. All arguments are optional. If you don't supply any config object, default settings will be used for a local CouchDB instance in admin party mode. Emails will be logged to the console but not sent.

* `config`: Your full configuration object.
* `passport`: You can pass in your own instance of Passport or SuperLogin will generate one if you do not.
* `userDB`: This is the database that SuperLogin uses to keep track of users, distinct from CouchDB's `_users` database. You can pass in a [PouchDB](http://pouchdb.com) instance here or otherwise specify your database name in the config under `dbServer.userDB`.
* `couchAuthDB`: This should point to your CouchDB `_users` database or something else if you just want to test. Specify in config or pass in a PouchDB object here.

**Returns:** the complete SuperLogin API.

##### `superlogin.config`
A reference to the configuration object. Use this to lookup and change configuration settings at runtime. `key` is a dot path string to the item you want to look up. For example `'emails.confirmEmail.subject'`

* `superlogin.config.getItem(key)`
* `superlogin.config.setItem(key, value)`
* `superlogin.config.removeItem(key)`

##### `superlogin.router`
A reference to the Express Router that contains all of SuperLogin's routes.

##### `superlogin.passport`
A reference to Passport

##### `superlogin.userDB`
A PouchDB instance that gives direct access to the SuperLogin users database

##### `superlogin.couchAuthDB`
A PouchDB instance that gives direct access to the CouchDB authentication (`_users`) database. (Not used with Cloudant.)

##### `superlogin.registerProvider(provider, configFunction)`
Adds support for additional Passport strategies. See below under Adding Providers for more information.

##### `superlogin.validateUsername(username)`
Checks that a username is valid and not in use. Resolves with nothing if successful. Resolves with an error object in failed.

##### `superlogin.validateEmail(email)`
Checks that an email is valid and not in use. Resolves with nothing if successful. Resolves with an error object in failed.

##### `superlogin.validateEmailUsername(email)`
The same as above, but for use when you are using email as the username. (`local.emailUsername` set to true.)

##### `superlogin.getUser(login)`
Fetches a user document by either username or email.

##### `superlogin.createUser(form, req)`
Creates a new local user with a username and password.

`form` requires the following: `username`, `email`, `password`, and `confirmPassword`. `name` is optional. Any additional fields must be whitelisted in your config under `userModel` or they will be removed.

`req` should contain `protocol` and `headers.host` to properly generate the confirmation email link. `ip` will be logged if given.

##### `superlogin.onCreate(fn)`
Use this to add as many functions as you want to transform the new user document before it is saved. Your function should accept two arguments `(userDoc, provider)` and return a `Promise` that resolves to the modified user document. onCreate functions will be chained in the order they were added.

##### `superlogin.onLink(fn)`
Does the same thing as `onCreate`, but is called every time a user links a new provider, or their profile information is refreshed. This allows you to process profile information and, for example, create a master profile. If an object called `profile` exists inside the user doc it will be passed to the client along with session information at each login.

##### `superlogin.socialAuth(provider, auth, profile, req)`
Creates a new user following authentication from an OAuth provider. If the user already exists it will update the profile.

* `provider`: the name of the provider in lowercase, (e.g. 'facebook')
* `auth`: credentials supplied by the provider
* `profile`: the profile supplied by the provider
* `req`: used just to log the user's ip if supplied

##### `superlogin.hashPassword(password)`
Hashes a password using PBKDF2 and returns an object containing `salt` and `derived_key`.

##### `superlogin.verifyPassword(hashObj, password)`
Verifies a password using a hash object. If you have a user doc, pass in `local` as the hash object.

##### `superlogin.createSession(user_id, provider, req)`
Creates a new session for a user. `provider` is the name of the provider. (eg. 'local', 'facebook', twitter.) `req` is used to log the IP if provided.

##### `superlogin.changePassword(user_id, password)`
Changes the user's password.

##### `superlogin.forgotPassword(email, req)`
Sends out the forgot password email and issues a reset token.

##### `superlogin.resetPassword(form, req)`
Resets the user's password. Required fields are `token` (from the forgot password email), `password`, and `confirmPassword`.

##### `superlogin.changeEmail(user_id, newEmail)`
Changes the user's email. If email verification is enabled (`local.sendConfirmEmail`) then a new confirmation email will be sent out.

##### `superlogin.verifyEmail(token, req)`
Marks the user's email as verified. `token` comes from the confirmation email.

##### `superlogin.addUserDB(user_id, dbName, type, designDoc, permissions)`
Associates a new database with the user's account. Will also authenticate all existing sessions with the new database.

* `dbName`: the name of the database. For a shared db, this is the actual path. For a private db `userDBs.privatePrefix` will be prepended, and `${user_id}` appended. **(required)**
* `type`: 'private' (default) or 'shared' (optional)
* `designDoc`: the name of the designDoc (if any) that will be seeded. (optional)
* `permissions`: an array of [permissions](https://docs.cloudant.com/authorization.html) for use with Cloudant. (optional)

If the optional fields are not specified they will be taken from `userDBs.model.{dbName}` or `userDBs.model._default` in your config.

##### `superlogin.removeUserDB(user_id, dbName, deletePrivate, deleteShared)`
Deauthorizes the specified database from the user's account, and optionally destroys it.

* `dbName`: the full path for a shared db, or the base name for a private db
* `deletePrivate`: when `true`, will destroy a db if it is marked as private
* `deleteShared`: when `true`, will destroy a db if it is marked as shared. Caution: may destroy other users' data!

##### `superlogin.logoutUser(user_id, session_id)`
Logs out all of a user's sessions at once. If `user_id` is not specified SuperLogin will look it up from the `session_id`.

##### `superlogin.logoutSession(session_id)`
Logs out the specified session.

##### `superlogin.logoutOthers(session_id)`
Logs out all of a user's sessions, except for the one specified.

##### `superlogin.removeUser(user_id, destroyDBs)`
Deletes a user, deauthorizes all the sessions, and optionally destroys all private databases if `destroyDBs` is true.

##### `superlogin.confirmSession(token, password)`
Logs out all of a user's sessions, except for the one specified.

##### `superlogin.removeExpiredKeys()`
Deauthorizes every single expired session found in the user database.

##### `superlogin.sendEmail(templateName, email, locals)`
Renders an email and sends it out. Server settings are specified under `mailer` in your config.

* `templateName`: the name of a template object specified under `emails` in your config. See [`config.example.js`](https://github.com/colinskow/superlogin/blob/master/config.example.js) for details.
* `email`: the email address that the email
* `locals`: local variables that will be passed into the ejs template to be rendered

##### `superlogin.quitRedis()`
Quits Redis if that is the session adapter you are using. This is useful for cleanup when your server shuts down.

## Releases

Moved to [CHANGELOG.md](https://github.com/colinskow/superlogin/blob/master/CHANGELOG.md)
