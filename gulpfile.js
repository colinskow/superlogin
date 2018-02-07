var gulp   = require('gulp'),
  eslint = require('gulp-eslint'),
  mocha = require('gulp-mocha');

var babel = require('babel-core/register');

gulp.task('lint', function() {
  return gulp.src(['./src/**/*.js', './test/*.js'])
    .pipe(eslint())
    .pipe(eslint.format())
    .pipe(eslint.failAfterError());
});

gulp.task('middleware-test', ['lint'], function () {
  return gulp.src(['test/middleware.spec.js'], {read: false}).pipe(mocha({
    timeout: 2000,
    compilers: ["js:babel-core/register"]
  }));
});

gulp.task('dbauth-test', ['middleware-test'], function () {
  return gulp.src(['test/dbauth.spec.js'], {read: false}).pipe(mocha({
    timeout: 2000,
    compilers: ["js:babel-core/register"]
  }));
});

gulp.task('mailer-test', ['dbauth-test'], function () {
  return gulp.src(['test/mailer.spec.js'], {read: false}).pipe(mocha({
    timeout: 2000,
    compilers: ["js:babel-core/register"]
  }));
});

gulp.task('user-test', ['dbauth-test'], function () {
  return gulp.src(['test/user.spec.js'], {read: false}).pipe(mocha({
    timeout: 4000,
    compilers: ["js:babel-core/register"]
  }));
});

gulp.task('final-test', ['user-test'], function () {
  return gulp.src(['test/test.js'], {read: false}).pipe(mocha({
    timeout: 2000,
    compilers: ["js:babel-core/register"]
  }));
});

gulp.task('default', ['final-test', 'user-test', 'mailer-test', 'middleware-test', 'lint']);