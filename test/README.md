# SuperLogin tests

## install
1. Run `npm install`
2. Install CouchDB: http://docs.couchdb.org/en/2.0.0/install/index.html
3. Install Redis: http://redis.io
4. Run `npm test` or if you disabled CouchDB's admin party run with environment variables, for example:  
`COUCH_USER=anna COUCH_PASS=secret npm test`

For additional configuration check: [test.config.js](https://github.com/colinskow/superlogin/blob/master/test/test.config.js)
