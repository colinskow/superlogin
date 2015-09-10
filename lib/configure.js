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

  this.setItem = function(key, value) {
    return util.setObjectRef(this.config, key, value);
  };

  this.removeItem = function(key) {
    return util.delObjectRef(this.config, key);
  };

};