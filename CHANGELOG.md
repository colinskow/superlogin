## Change Log

#### Misc. Bug Fixes (0.6.1) 2016-04-02
* Misc bugfixes
* Documentation improvements
* Now testing against Node 4.x and 5.x

##### Improved Tests, Enhancements, Bugfixes (0.6.0) 2016-04-02
* Updated dependencies
* Improved unit tests (thanks [@tohagan](https://github.com/tohagan) and [@ybian](https://github.com/ybian))
* CouchDB server can now have a separate URL for public access
* Misc bug fixes


##### Enable Logout of Expired Sessions (0.5.0) 2015-10-08
Previously a user could only logout if the session token was still valid. API keys would be expired, but database credentials could still be used. Now logout will ensure the user is completely logged out, even if the session is already expired. Also fixed a bug that was causing `sessionLife` and `tokenLife` settings not to work.

##### Custom Permissions for Cloudant (0.4.0) 2015-09-21
Default per-DB Cloudant permissions no longer save in the user doc. You can set custom permissions in the user doc, otherwise it will use the settings in your config. Misc bug fixes.

##### Security Roles For CouchDB (0.3.0) 2015-09-18
Created configuration options to setup _security roles when user databases are created. Improved tests and updated PouchDB.

##### Client Access Token Strategies (0.2.0) 2015-09-13
Added client `access_token` strategies to support OAuth2 flows from Cordova, PhoneGap, and native apps.

##### Initial Release (0.1.0) 2015-09-10
The intense power of SuperLogin is unleashed on a world that may not be ready! Tested with Node.js 0.12.7 and 4.0.0.