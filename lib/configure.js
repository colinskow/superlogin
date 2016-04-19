'use strict';
var util = require('./util');

module.exports = function(data, defaults) {

  this.config = data || {};
  this.defaults = defaults || {};

  this.getItem = function(key) {
    var result = util.getObjectRef(this.config, key);
    if(typeof result === 'undefined' || result === null) {
      result = util.getObjectRef(this.defaults, key);
    }
    return result;
  };

  var _signatures = [];

  this.refreshSignature = function(key)
  {
    var item = this.getItem(key);
    _signatures[key] = util.hashObjectOrVariable(item);
    return _signatures[key];
  };

  this.getSignature = function(key)
  {
    if(!_signatures[key])
      return this.refreshSignature(key);
    return _signatures[key];
  };


  this.setItem = function(key, value) {
    return util.setObjectRef(this.config, key, value);
  };

  this.removeItem = function(key) {
    return util.delObjectRef(this.config, key);
  };

};
