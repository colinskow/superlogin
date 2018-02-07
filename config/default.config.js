var path = require('path');

// These are the default settings that will be used if you don't override them in your config
module.exports = {
  security: {
    defaultRoles: ['user'],
    maxFailedLogins: 4,
    lockoutTime: "5m",
    sessionLife: "1d",
    tokenLife: "1d",
    loginOnRegistration: false,
    loginOnPasswordReset: false,
    jwt: {
      issuer: null,
      // change!
      secret: null
    }
  },
  local: {
    usernameField: 'username',
    passwordField: 'password',
    disableSignup: false
  },
  dbServer: {
    protocol: 'http://',
    host: 'localhost:5984',
    designDocDir: path.join(__dirname, '/designDocs'),
    userDB: 'sl_users',
    // CouchDB's _users database. Each session generates the user a unique login and password. This is not used with Cloudant.
    couchAuthDB: '_users'
  },
  emails: {
    confirmEmail: {
      subject: 'Please confirm your email',
      template: path.join(__dirname, '../templates/email/confirm-email.ejs'),
      format: 'text'
    },
    forgotPassword: {
      subject: 'Your password reset link',
      template: path.join(__dirname, '../templates/email/forgot-password.ejs'),
      format: 'text'
    }
  }
};
