module.exports = {
  auth: {
    views: {
      email: {
        map: function(doc) {
          if(doc.email) {
            emit(doc.email, null);
          } else if(doc.unverifiedEmail.email) {
            emit(doc.unverifiedEmail.email, null);
          }
        }
      },
      username: {
        map: function(doc) {
          emit(doc._id, null);
        }
      },
      verifyEmail: {
        map: function(doc) {
          if(doc.unverifiedEmail && doc.unverifiedEmail.token) {
            emit(doc.unverifiedEmail.token, null);
          }
        }
      },
      emailUsername: {
        map: function(doc) {
          emit(doc._id, null);
          if(doc.email) {
            emit(doc.email, null);
          } else if(doc.unverifiedEmail.email) {
            emit(doc.unverifiedEmail.email, null);
          }
        }
      },
      passwordReset: {
        map: function(doc) {
          if(doc.forgotPassword && doc.forgotPassword.token) {
            emit(doc.forgotPassword.token, null);
          }
        }
      },
      session: {
        map: function(doc) {
          if(doc.session) {
            for(var key in doc.session) {
              if(doc.session.hasOwnProperty(key)) {
                emit(key, doc._id);
              }
            }
          }
        }
      },
      expiredKeys: {
        map: function(doc) {
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
  }
};
