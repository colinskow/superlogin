const { src, series }= require('gulp'),
  jshint = require('gulp-jshint'),
  stylish = require('jshint-stylish'),
  mocha = require('gulp-mocha');

function lint() {
  return src(['./lib/**/*.js', './test/*.js'])
    .pipe(jshint({node: true, mocha: true}))
    .pipe(jshint.reporter(stylish))
    .pipe(jshint.reporter('fail'));
};

function middleware_test() {
  return src(['test/middleware.spec.js'], {read: false})
    .pipe(mocha({timeout: 2000}));
};

function dbauth_test() {
    return src(['test/dbauth.spec.js'], {read: false})
      .pipe(mocha({timeout: 2000}));
};

// these three tasks all just need dbauth
function session_test() {
    return src(['test/session.spec.js'], {read: false})
      .pipe(mocha({timeout: 2000}));
};

function mailer_test() {
  return src(['test/mailer.spec.js'], {read: false})
    .pipe(mocha({timeout: 2000}));
};

function user_test() {
  return src(['test/user.spec.js'], {read: false})
    .pipe(mocha({timeout: 2000}));
};

// depends on user-test
function final_test() {
  return src(['test/test.js'], {read: false})
    .pipe(mocha({timeout: 2000}));
};

exports.default = series(lint, middleware_test, dbauth_test, session_test, user_test, final_test);