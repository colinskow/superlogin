// This is a tour of all possible SuperLogin configuration options and what they do

var path = require('path');

module.exports = {
  // Useful settings for testing and debugging your app
  testMode: {
    // Use a stub transport so no email is actually sent
    noEmail: false,
    // Displays debug information in the oauth dialogs
    oauthDebug: false,
    // Logs out-going emails to the console
    debugEmail: false
  },
  security: {
    // Default roles given to a new user
    defaultRoles: ['user'],
    // Disables the ability to link additional providers to an account when set to true
    disableLinkAccounts: false,
    // Maximum number of failed logins before the account is locked
    maxFailedLogins: 3,
    // The amount of time the account will be locked for (in seconds) after the maximum failed logins is exceeded
    lockoutTime: 600,
    // The amount of time a new session is valid for (default: 24 hours)
    sessionLife: 86400,
    // The amount of time a password reset token is valid for
    tokenLife: 86400,
    // The maximum number of entries in the activity log in each user doc. Zero to disable completely
    userActivityLogSize: 10,
    // If set to true, the user will be logged in automatically after registering
    loginOnRegistration: false,
    // If set to true, the user will be logged in automatically after resetting the password
    loginOnPasswordReset: false
  },
  local: {
    // Send out a confirm email after each user signs up with local login
    sendConfirmEmail: true,
    // Require the email be confirmed before the user can login
    requireEmailConfirm: false,
    // If this is set, the user will be redirected to this location after confirming email instead of JSON response
    confirmEmailRedirectURL: '/',
    // Set this to true to disable usernames and use emails instead
    emailUsername: false,
    // Custom names for the username and password fields in your sign-in form
    usernameField: 'user',
    passwordField: 'pass'
  },
  dbServer: {
    // The CouchDB compatible server where all your databases are stored on
    protocol: 'http://',
    host: 'localhost:5984',
    user: '',
    password: '',
    // If the public uses a separate URL from your Node.js server to access the database specify it here.
    // This will be the access URL for all your user's personalDBs
    publicURL: 'https://mydb.example.com',
    // Set this to true if you are using Cloudant
    cloudant: false,
    // The name for the database that stores all your user information. This is distinct from CouchDB's _user database.
    // Alternatively you can pass in a PouchDB object to the SuperLogin constructor and leave this blank
    userDB: 'sl_users',
    // CouchDB's _users database. Each session generates the user a unique login and password. This is not used with Cloudant.
    couchAuthDB: '_users'
  },
  session: {
    // 'redis' or 'memory'
    adapter: 'redis',
    redis: {
      // If url is supplied, port and host will be ignored
      url: 'redis://user:pass@host:port',
      port: 6379,
      host: 'localhost',
      // If a UNIX domain socket is specified, port, host and url will be ignored
      unix_socket: '/tmp/echo.sock',
      options: {},
      password: process.env.REDIS_PASSWORD
    }
  },
  mailer: {
    // Email address that all your system emails will be from
    fromEmail: 'noreply@example.com',
    // Use this if you want to specify a custom Nodemailer transport. Defaults to SMTP or sendmail.
    transport: require('nodemailer-sendgrid-transport'),
    // The options object that will be passed into your transport. These should usually be your SMTP settings.
    // If this is left blank, it will default to sendmail.
    options: {
      auth: {
        api_user: process.env.SENDGRID_USERNAME,
        api_key: process.env.SENDGRID_PASSWORD
      }
    }
  },
  emails: {
    // Customize the templates for the emails that SuperLogin sends out
    confirmEmail: {
      subject: 'Please confirm your email',
      // Remember to use the correct path relative to where your custom config file is located
      template: path.join(__dirname, './templates/email/confirm-email.ejs'),
      // 'text' or 'html'
      format: 'text'
    },
    forgotPassword: {
      subject: 'Your password reset link',
      template: path.join(__dirname, './templates/email/forgot-password.ejs'),
      format: 'text'
    }
  },
  // Custom settings to manage personal databases for your users
  userDBs: {
    // These databases will be set up automatically for each new user
    defaultDBs: {
      // Private databases are personal to each user. They will be prefixed with your setting below and postfixed with $USERNAME.
      private: ['test'],
      // Shared databases that you want the user to be authorized to use. These will not be prefixed, so type the exact name.
      shared: ['']
    },
    // If you specify default roles here (and use CouchDB not Cloudant) then these will be added to the _security object
    // of each new user database created. This is useful for preventing anonymous access.
    defaultSecurityRoles: {
      admins: ['$slAdmin'],
      members: []
    },
    // These are settings for each personal database
    model: {
     // If your database is not listed below, these default settings will be applied
      _default: {
        // Array containing name of the design doc files (omitting .js extension), in the directory configured below
        designDocs: ['mydesign'],
        // these permissions only work with the Cloudant API
        permissions: ['_reader', '_replicator'],
      },
      test: {
        designDocs: ['test'],
        permissions: ['_reader', '_replicator'],
        // 'private' or 'shared'
        type: 'private',
        // Roles that will be automatically added to the db's _security object of this specific db
        adminRoles: [],
        memberRoles: []
      }
    },
    // Your private user databases will be prefixed with this:
    privatePrefix: 'test',
    // Directory that contains all your design docs
    designDocDir: path.join(__dirname, './designDocs')
  },
  // Configure all your authentication providers here
  providers: {
    // Each provider follows the following pattern
    facebook: {
      // Supply your app's credentials here. The callback url is generated automatically.
      // See the Passport documentation for your specific strategy for details.
      credentials: {
        // Anything under credentials will be passed in to passport.use
        // It is a best practice to put any sensitive credentials in environment variables rather than your code
        clientID: process.env.facebook_client_id,
        clientSecret: process.env.facebook_client_secret
      },
      // Any additional options you want to supply your authentication strategy such as requested permissions
      options: {
        // Anything under options will be passed in with passport.authenticate
        scope: ['email']
      },
      // This will pass in the user's auth token as a variable called 'state' when linking to this provider
      // Defaults to true for Google and LinkedIn, but you can enable it for other providers if needed
      requireState: false
    }
  },
  // Anything here will be merged with the userModel that validates your local sign-up form.
  // See [Sofa Model documentation](http://github.com/colinskow/sofa-model) for details.
  userModel: {
    // For example, this will require each new user to specify a valid age on the sign-up form or registration will fail
    whitelist: ['age'],
    validate: {
      age: {
        presence: true,
        numericality: {
          onlyInteger: true,
          greaterThanOrEqualTo: 18,
          lessThan: 150,
          message: 'You must be an adult, but not dead yet.'
        }
      }
    }
  }
};
