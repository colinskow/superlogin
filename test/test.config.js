module.exports = {
  testMode: {
    noEmail: true,
    oauthDebug: true
  },
  dbServer: {
    protocol: 'http://',
    host: 'localhost:5984',
    user: '',
    password: '',
    userDB: 'sl_test-users',
    couchAuthDB: 'sl_test-keys'
  },
  security: {
    maxFailedLogins: 2,
    lockoutTime: 600
  },
  local: {
    sendConfirmEmail: true
  },
  session: {
    adapter: 'redis'
  },
  mailer: {
    fromEmail: 'me@example.com'
  },
  userDBs: {
    designDocDir: __dirname + '/ddocs',
    privatePrefix: 'test'
  },
  providers: {
    facebook: {
      clientID: 'FAKE_ID',
      clientSecret: 'FAKE_SECRET'
    },
    twitter: {
      consumerKey: 'FAKE_KEY',
      consumerSecret: 'FAKE_SECRET'
    }
  }
};