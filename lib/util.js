'use strict';

var BPromise = require('bluebird');
var URLSafeBase64 = require('urlsafe-base64');
var uuid = require('node-uuid');
var pwd = require('couch-pwd');
var crypto = require('crypto');

exports.URLSafeUUID = function() {
  return URLSafeBase64.encode(uuid.v4(null, new Buffer(16)));
};

exports.hashPassword = function (password) {
  return new BPromise(function (resolve, reject) {
    pwd.hash(password, function (err, salt, hash) {
      if (err) {
        return reject(err);
      }
      return resolve({
        salt: salt,
        derived_key: hash
      });
    });
  });
};

exports.verifyPassword = function (hashObj, password) {
  var getHash = BPromise.promisify(pwd.hash, {context: pwd});
  var iterations = hashObj.iterations;
  var salt = hashObj.salt;
  var derived_key = hashObj.derived_key;
  if (iterations) {
    pwd.iterations(iterations);
  }
  if(!salt || !derived_key) {
    return BPromise.reject(false);
  }
  return getHash(password, salt)
    .then(function (hash) {
      if (hash === derived_key) {
        return BPromise.resolve(true);
      } else {
        return BPromise.reject(false);
      }
    });
};

exports.getDBURL = function(db) {
  var url;
  if(db.user) {
    url = db.protocol + encodeURIComponent(db.user) + ':' + encodeURIComponent(db.password) + '@' + db.host;
  } else {
    url = db.protocol + db.host;
  }
  return url;
};

exports.getFullDBURL = function(dbConfig, dbName) {
  return exports.getDBURL(dbConfig) + '/' + dbName;
};

exports.toArray = function(obj) {
  if(!(obj instanceof Array)) {
    obj = [obj];
  }
  return obj;
};

exports.getSessions = function(userDoc) {
  var sessions = [];
  if(userDoc.session) {
    Object.keys(userDoc.session).forEach(function(mySession) {
      sessions.push(mySession);
    });
  }
  return sessions;
};

exports.getExpiredSessions = function(userDoc, now) {
  var sessions = [];
  if(userDoc.session) {
    Object.keys(userDoc.session).forEach(function(mySession) {
      if(userDoc.session[mySession].expires <= now) {
        sessions.push(mySession);
      }
    });
  }
  return sessions;
};

// Takes a req object and returns the bearer token, or undefined if it is not found
exports.getSessionToken = function(req) {
  if (req.headers && req.headers.authorization) {
    var parts = req.headers.authorization.split(' ');
    if (parts.length == 2) {
      var scheme = parts[0];
      var credentials = parts[1];
      if (/^Bearer$/i.test(scheme)) {
        var parse = credentials.split(':');
        if(parse.length < 2) {
          return;
        }
        return parse[0];
      }
    }
  }
};

exports.getSessionTokenPromise = function(req, user)
{
  return new BPromise(function (resolve, reject) {
    if (req.headers && req.headers.authorization) {
      var parts = req.headers.authorization.split(' ');
      if (parts.length == 2) {
        var scheme = parts[0];
        var credentials = parts[1];
        if (/^Bearer$/i.test(scheme)) {
          var parse = credentials.split(':');
          if(parse.length < 2) {
            reject(null);
          }
          return resolve(parse[0]);
        }
      }
    }
    else if (req.body && req.body.token && req.body.password)
    {
      return user.confirmSession(req.body.token, req.body.password)
      .then(function(){
          return resolve(req.body.token);
      })
      .catch(function(err){
        return reject(null);
      });
    }
    return reject(null);
  });
};

// Generates views for each registered provider in the user design doc
exports.addProvidersToDesignDoc = function(config, ddoc) {
  var providers = config.getItem('providers');
  if(!providers) {
    return ddoc;
  }
  var ddocTemplate =
    "function(doc) {\n" +
    "  if(doc.%PROVIDER% && doc.%PROVIDER%.profile) {\n" +
    "    emit(doc.%PROVIDER%.profile.id, null);\n" +
    "  }\n" +
    "}";
  Object.keys(providers).forEach(function(provider) {
    ddoc.auth.views[provider] = ddocTemplate.replace(new RegExp('%PROVIDER%', 'g'), provider);
  });
  return ddoc;
};

// Capitalizes the first letter of a string
exports.capitalizeFirstLetter = function(string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
};

/**
 * Access nested JavaScript objects with string key
 * http://stackoverflow.com/questions/6491463/accessing-nested-javascript-objects-with-string-key
 *
 * @param {object} obj The base object you want to get a reference to
 * @param {string} str The string addressing the part of the object you want
 * @return {object|undefined} a reference to the requested key or undefined if not found
 */

exports.getObjectRef = function(obj, str) {
  str = str.replace(/\[(\w+)\]/g, '.$1'); // convert indexes to properties
  str = str.replace(/^\./, '');           // strip a leading dot
  var pList = str.split('.');
  while (pList.length) {
    var n = pList.shift();
    if (n in obj) {
      obj = obj[n];
    } else {
      return;
    }
  }
  return obj;
};

/**
 * Dynamically set property of nested object
 * http://stackoverflow.com/questions/18936915/dynamically-set-property-of-nested-object
 *
 * @param {object} obj The base object you want to set the property in
 * @param {string} str The string addressing the part of the object you want
 * @param {*} val The value you want to set the property to
 * @return {*} the value the reference was set to
 */

exports.setObjectRef = function(obj, str, val) {
  str = str.replace(/\[(\w+)\]/g, '.$1'); // convert indexes to properties
  str = str.replace(/^\./, '');           // strip a leading dot
  var pList = str.split('.');
  var len = pList.length;
  for(var i = 0; i < len-1; i++) {
    var elem = pList[i];
    if( !obj[elem] ) {
      obj[elem] = {};
    }
    obj = obj[elem];
  }
  obj[pList[len-1]] = val;
  return val;
};

/**
 * Dynamically delete property of nested object
 *
 * @param {object} obj The base object you want to set the property in
 * @param {string} str The string addressing the part of the object you want
 * @return {boolean} true if successful
 */

exports.delObjectRef = function(obj, str) {
  str = str.replace(/\[(\w+)\]/g, '.$1'); // convert indexes to properties
  str = str.replace(/^\./, '');           // strip a leading dot
  var pList = str.split('.');
  var len = pList.length;
  for(var i = 0; i < len-1; i++) {
    var elem = pList[i];
    if( !obj[elem] ) {
      return false;
    }
    obj = obj[elem];
  }
  delete obj[pList[len-1]];
  return true;
};

/**
 * Concatenates two arrays and removes duplicate elements
 *
 * @param {array} a First array
 * @param {array} b Second array
 * @return {array} resulting array
 */

exports.arrayUnion = function (a, b) {
  var result = a.concat(b);
  for(var i=0; i<result.length; ++i) {
    for(var j=i+1; j<result.length; ++j) {
      if(result[i] === result[j])
        result.splice(j--, 1);
    }
  }
  return result;
};


/**
 * Hash object to md5
 *
 * @param {array} an array / object
* @param {string} crypto's hash method (md5, sha1, ...)
 * @return {string} resulting hash
 */
function hashObject(object, hashMethod) {
  var cHashMethod = hashMethod || "md5";
  var hash = crypto.createHash(cHashMethod)
    .update(JSON.stringify(object, function (k, v) {
      if (k[0] === "_") return undefined; // remove api stuff
      else if (typeof v === "function") // consider functions
        return v.toString();
      else return v;
    }))
    .digest('hex');
  return hash;
}

exports.hashObject = hashObject;

/**
* Automaticaly detect if it has to hash an object or a variable (string, int, ...) to md5
*
* @param {all} the item to hash (Array, Object, Int, String)
* @param {string} crypto's hash method (md5, sha1, ...)
* @return {string} resulting hash
*/
exports.hashObjectOrVariable = function(item, hashMethod)
{
  if(!item)
  {
    return null;
  }
  var cHashMethod = hashMethod || "md5";
  if(typeof item === "object" || item instanceof Array)
  {
    return hashObject(item, cHashMethod);
  }
  else
  {
    return crypto.createHash(cHashMethod).update(item).digest('hex');
  }
};

// Escapes any characters that are illegal in a CouchDB database name using percent codes inside parenthesis
// Example: 'My.name@example.com' => 'my(2e)name(40)example(2e)com'
function getLegalDBName(input) {
  input = input.toLowerCase();
  var output = encodeURIComponent(input);
  output = output.replace(/\./g, '%2E');
  output = output.replace(/!/g, '%21');
  output = output.replace(/~/g, '%7E');
  output = output.replace(/\*/g, '%2A');
  output = output.replace(/'/g, '%27');
  output = output.replace(/\(/g, '%28');
  output = output.replace(/\)/g, '%29');
  output = output.replace(/\-/g, '%2D');
  output = output.toLowerCase();
  output = output.replace(/(%..)/g, function(esc) {
    esc = esc.substr(1);
    return '(' + esc + ')';
  });
  return output;
}

exports.getLegalDBName = getLegalDBName;

exports.getFinalDBName = function(prefix, dbName, type, userDoc)
{

  var finalDBName;
  // Make sure we have a legal database name
  var username = userDoc._id;
  username = getLegalDBName(username);
  if(type === 'shared') {
    return dbName;
  } else {
    finalDBName = prefix + dbName + '$' + username;
  }
  return finalDBName;
};

exports.castFinalToDefaultDBName = function(prefix, finalDBName, type, userDoc)
{
  var defaultDBName;

  var username = userDoc._id;
  username = getLegalDBName(username);
  if(type === 'shared') {
    return finalDBName;
  } else {
    defaultDBName = finalDBName.replace(prefix,"").replace('$' + username, "");
  }
  return defaultDBName;
};
