module.exports = {
  _superlogin: {
    views: {
      user: {
        map: function (doc) {
          if (doc.user_id) {
            emit(doc.user_id, doc.name);
          }
        }
      },
      expired: {
        map: function (doc) {
          if (doc.expires) {
            emit(doc._id, doc.expires)
          }
        }
      }
    }
  }
};
