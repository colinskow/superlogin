module.exports = {
  test: {
    views: {
      mytest: function(doc) {
        emit(doc._id);
      }
    }
  }
};