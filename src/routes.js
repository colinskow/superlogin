import * as util from "./util";

export default function(config, router, passport, user) {
  const env = process.env.NODE_ENV || "development";

  router.post("/login", function(req, res, next) {
    passport.authenticate("local", function(err, user, info) {
      console.log("passport error", err);
      if (err) {
        return next(err);
      }
      if (!user) {
        // Authentication failed
        return res.status(401).json(info);
      }
      // Success
      req.logIn(user, { session: false }, function(err) {
        console.log("Passport logged in", Date.now());
        if (err) {
          return next(err);
        }
      });
      return next();
    })(req, res, next);
  }, async function(req, res, next) {
    // Success handler
    try {
      const mySession = await user.createSession(req.user._id, "local", req, true);
      res.status(200).json(mySession);
    }
    catch (err) {
      return next(err);
    }
  });

  router.post("/refresh", passport.authenticate("bearer", { session: false }),
    async function(req, res, next) {
      try {
        const mySession = await user.refreshSession(req);
        res.status(200).json(mySession);
      }
      catch (err) {
        return next(err);
      }
    }
  );

  router.post("/logout", passport.authenticate("bearer", { session: false }),
    async function(req, res, next) {
      try {
        await user.logoutSession(req.user, req.user.payload.dbUser);
        res.status(200).json({
          ok: true,
          success: "Logged out"
        });
      }
      catch (err) {
        console.error("Logout failed");
        return next(err);
      }
    }
  );

  router.post("/logout-others", passport.authenticate("bearer", { session: false }),
    async function(req, res, next) {
      // console.log(req.user);
      try {
        await user.logoutOthers(req.user, req.user.payload.dbUser);
        res.status(200).json({
          ok: true,
          success: "Other sessions logged out"
        });
      }
      catch (err) {
        console.error("Logout failed");
        return next(err);
      }
    }
  );

  router.post("/logout-all", passport.authenticate("bearer", { session: false }),
    async function(req, res, next) {
      try {
        await user.logoutUser(req.user);
        res.status(200).json({success: "Logged out"});
      }
      catch (err) {
        console.error("Logout-all failed");
        return next(err);
      }
    }
  );

  // Setting up the auth api
  router.post("/register", async function(req, res, next) {
    if (config.getItem("local.disableSignup")) {
      res.status(201).json({
        ok: false,
        error: "Signup is disabled by config."
      });
      return;
    }
    try {
      const newUser = await user.create(req.body, req);
      // console.log(newUser);
      req.user = newUser;
      if (config.getItem("security.loginOnRegistration")) {
        try {
          const mySession = await user.createSession(req.user._id, "local", req, true);
          res.status(200).json(mySession);
        }
        catch (err) {
          return next(err);
        }
      }
      else {
        res.status(201).json({
          ok: true,
          success: "User created."
        });
      }
    }
    catch (err) {
      return next(err);
    }
  });

  router.post("/forgot-password", async function(req, res, next) {
    try {
      await user.forgotPassword(req.body.email, req);
      res.status(200).json({success: "Password recovery email sent."});
    }
    catch (err) {
      return next(err);
    }
  });

  router.post("/password-reset", async function(req, res, next) {
    try {
      await user.resetPassword(req.body, req);
      if (config.getItem("security.loginOnPasswordReset")) {
        try {
          const mySession = await user.createSession(req.user._id, "local", req);
          res.status(200).json(mySession);
        }
        catch (err) {
          return next(err);
        }
      }
      else {
        res.status(200).json({success: "Password successfully reset."});
      }
    }
    catch (err) {
      return next(err);
    }
  });

  router.post("/password-change", passport.authenticate("bearer", { session: false }),
    async function(req, res, next) {
      try {
        await user.changePasswordSecure(req.user._id, req.body, req);
        res.status(200).json({success: "password changed"});
      }
      catch (err) {
        return next(err);
      }
    }
  );

  router.post("/unlink/:provider", passport.authenticate("bearer", { session: false }),
    async function(req, res, next) {
      const provider = req.params.provider;
      try {
        await user.unlink(req.user._id, provider);
        res.status(200).json({
          success: util.capitalizeFirstLetter(provider) + " unlinked"
        });
      }
      catch (err) {
        return next(err);
      }
    }
  );

  router.get("/confirm-email/:token", async function(req, res, next) {
    var redirectURL = config.getItem("local.confirmEmailRedirectURL");
    if (!req.params.token) {
      var err = { error: "Email verification token required" };
      if (redirectURL) {
        return res.status(201).redirect(redirectURL + "?error=" + encodeURIComponent(err.error));
      }
      return res.status(400).send(err);
    }
    try {
      await user.verifyEmail(req.params.token, req);
      if (redirectURL) {
        return res.status(201).redirect(redirectURL + "?success=true");
      }
      res.status(200).send({ok: true, success: "Email verified"});
    }
    catch (err) {
      if (redirectURL) {
        var query = "?error=" + encodeURIComponent(err.error);
        if (err.message) {
          query += "&message=" + encodeURIComponent(err.message);
        }
        return res.status(201).redirect(redirectURL + query);
      }
      return next(err);
    }
  });

  router.get("/validate-username/:username", async function(req, res, next) {
    if (!req.params.username) {
      return next({
        ok: false,
        error: "Username required",
        status: 400
      });
    }
    try {
      const err = await user.validateUsername(req.params.username);
      if (!err) {
        res.status(200).json({ok: true});
      }
      else {
        res.status(409).json({error: "Username already in use"});
      }
    }
    catch (err) {
      return next(err);
    }
  });

  router.get("/validate-email/:email", async function(req, res, next) {
    if (!req.params.email) {
      return next({error: "Email required", status: 400});
    }
    try {
      let err;
      if (config.getItem("local.emailUsername")) {
        err = await user.validateEmailUsername(req.params.email);
      }
      else {
        err = await user.validateEmail(req.params.email);
      }
      if (!err) {
        res.status(200).json({ok: true});
      }
      else {
        res.status(409).json({error: "Email already in use"});
      }
    }
    catch (err) {
      return next(err);
    }
  });

  router.post("/change-email", passport.authenticate("bearer", { session: false }),
    async function(req, res, next) {
      try {
        await user.changeEmail(req.user._id, req.body.newEmail, req);
        res.status(200).json({ok: true, success: "Email changed"});
      }
      catch (err) {
        return next(err);
      }
    }
  );

  // route to test token authentication
  router.get("/session", passport.authenticate("bearer", { session: false }),
    function(req, res) {
      var user = req.user;
      user.user_id = user._id;
      delete user._id;
      // user.token = user.key;
      delete user.key;
      res.status(200).json({
        token: req.get("Authorization").split(" ")[1],
        expires: user.payload.exp * 1000,
        issued: user.payload.iat * 1000,
        ip: req.ip,
        dbUser: user.payload.dbUser,
        dbPass: user.payload.dbPass,
        dbExpires: user.payload.dbExpires,
        user_id: user.user_id,
        roles: user.roles,
        userDBs: user.userDBs
      });
    });

  // Error handling
  router.use(function(err, req, res, next) {
    console.error(err);
    if (err.stack) {
      console.error(err.stack);
    }
    res.status(err.status || 500);
    if (err.stack && env !== "development") {
      delete err.stack;
    }
    res.json(err);
  });
};
