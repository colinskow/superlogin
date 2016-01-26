module.exports = {
  getDBUrl: function (config) {
    var host;
    if (config.user)
      host = encodeURIComponent(config.user) + ':' + encodeURIComponent(config.password) + '@' + config.host;
    else
      host = config.host;

    return config.protocol + host;
  }
};
