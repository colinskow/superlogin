// Contains middleware useful for securing your routes
'use strict';
module.exports = function(passport) {

  var forbiddenError = {
    error: 'Forbidden',
    message: 'You do not have permission to access this resource.',
    status: 403
  };

  var superloginError = {
    error: 'superlogin',
    message: 'requireAuth must be used before checking roles',
    status: 500
  };

  // Requires that the user be authenticated with a bearer token
  function requireAuth(req, res, next) {
    passport.authenticate('bearer', {session: false})(req, res, next);
  }

  // Requires that the user have the specified role
  function requireRole(requiredRole) {
    return function(req, res, next) {
      if(!req.user) {
        return next(superloginError);
      }
      var roles = req.user.roles;
      if(!roles || !roles.length || roles.indexOf(requiredRole) === -1) {
        res.status(forbiddenError.status);
        res.json(forbiddenError);
      } else {
        next();
      }
    };
  }

  // Requires that the user have at least one of the specified roles
  function requireAnyRole(possibleRoles) {
    return function(req, res, next) {
      if(!req.user) {
        return next(superloginError);
      }
      var denied = true;
      var roles = req.user.roles;
      if (roles && roles.length) {
        for (var i = 0; i < possibleRoles.length; i++) {
          if (roles.indexOf(possibleRoles[i]) !== -1) {
            denied = false;
          }
        }
      }
      if(denied) {
        res.status(forbiddenError.status);
        res.json(forbiddenError);
      } else {
        next();
      }
    };
  }

  function requireAllRoles(requiredRoles) {
    return function(req, res, next) {
      if(!req.user) {
        return next(superloginError);
      }
      var denied = false;
      var roles = req.user.roles;
      if (!roles || !roles.length) {
        denied = true;
      } else {
        for (var i = 0; i < requiredRoles.length; i++) {
          if (roles.indexOf(requiredRoles[i]) === -1) {
            denied = true;
          }
        }
      }
      if(denied) {
        res.status(forbiddenError.status);
        res.json(forbiddenError);
      } else {
        next();
      }
    };
  }

  return {
    requireAuth: requireAuth,
    requireRole: requireRole,
    requireAnyRole: requireAnyRole,
    requireAllRoles: requireAllRoles
  };

};

