module.exports = {
  auth: {
    views: {
      email: function(doc) {
        if(doc.email) {
          emit(doc.email, null);
        } else if(doc.unverifiedEmail.email) {
          emit(doc.unverifiedEmail.email, null);
        }
      },
      username: function(doc) {
        emit(doc._id, null);
      },
      verifyEmail: function(doc) {
        if(doc.unverifiedEmail && doc.unverifiedEmail.token) {
          emit(doc.unverifiedEmail.token, null);
        }
      },
      emailUsername: function(doc) {
        emit(doc._id, null);
        if(doc.email) {
          emit(doc.email, null);
        } else if(doc.unverifiedEmail.email) {
          emit(doc.unverifiedEmail.email, null);
        }
      },
      passwordReset: function(doc) {
        if(doc.forgotPassword && doc.forgotPassword.token) {
          emit(doc.forgotPassword.token, null);
        }
      },
      session: function(doc) {
        if(doc.session) {
          for(var key in doc.session) {
            if(doc.session.hasOwnProperty(key)) {
              emit(key, doc._id);
            }
          }
        }
      },
      expiredKeys: function(doc) {
        if(doc.session) {
          for(var key in doc.session) {
            if(doc.session.hasOwnProperty(key) && doc.session[key].expires) {
              emit(doc.session[key].expires, {key: key, user: doc._id});
            }
          }
        }
      }
    }
  }
};
