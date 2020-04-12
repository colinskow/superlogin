module.exports = {
  test: {
    views: {
      mytest: {
        map: function (doc) {
          emit(doc._id);
        }
      }
    }
  }
};