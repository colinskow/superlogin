'use strict';
var expect = require('chai').expect;
var Middleware = require('../lib/middleware');

var middleware = new Middleware({});

var noCall = function(){
  throw new Error('This should not have been called.');
};

var noop = function(){};

describe('middleware', function() {

  describe('requireRole', function() {

    it('should pass when a required role is present', function(done) {
      var req = {
        user: {
          roles: ['user']
        }
      };
      var res = {
        status: noCall,
        json: noop
      };
      var next = function() {
        done();
      };
      middleware.requireRole('user')(req, res, next);
    });

    it('should fail when a required role is missing', function(done) {
      var req = {
        user: {
          roles: ['user']
        }
      };
      var res = {
        status: function(num) {
          expect(num).to.equal(403);
          done();
        },
        json: noop
      };
      middleware.requireRole('admin')(req, res, noCall);
    });
  });

  describe('requireAnyRole', function() {

    it('should pass when at least one of the required roles is present', function(done) {
      var req = {
        user: {
          roles: ['user']
        }
      };
      var res = {
        status: noCall,
        json: noop
      };
      var next = function() {
        done();
      };
      middleware.requireAnyRole(['user', 'admin'])(req, res, next);
    });

    it('should fail when no required role is present', function(done) {
      var req = {
        user: {
          roles: ['user']
        }
      };
      var res = {
        status: function(num) {
          expect(num).to.equal(403);
          done();
        },
        json: noop
      };
      middleware.requireAnyRole(['admin', 'superman'])(req, res, noCall);
    });
  });

  describe('requireAllRoles', function() {

    it('should pass when all of the roles are present', function(done) {
      var req = {
        user: {
          roles: ['user', 'admin', 'superman']
        }
      };
      var res = {
        status: noCall,
        json: noop
      };
      var next = function() {
        done();
      };
      middleware.requireAllRoles(['user', 'admin'])(req, res, next);
    });

    it('should fail when just one required role is missing', function(done) {
      var req = {
        user: {
          roles: ['user', 'admin']
        }
      };
      var res = {
        status: function(num) {
          expect(num).to.equal(403);
          done();
        },
        json: noop
      };
      middleware.requireAllRoles(['admin', 'superman'])(req, res, noCall);
    });
  });



});
