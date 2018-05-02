var express = require("express");
var passport = require("passport");
var router = express.Router();
var u2f = require("u2f");
var https = require("https");
var APP_ID = "https://localhost:4433";
var fs = require("fs");
var Users = {};
var User1 = require("../models/user");
var Car = require("../models/user_car");
var googleMapsClient = require('@google/maps').createClient({
    clientId: '897949743059-29ad8f8jb800tcr6snvp809bj8odglsu.apps.googleusercontent.com',
    clientSecret: 'yjMA6z7XJPDF3gseGEMAeTyT',
});
var tempo_handle;
var User;
var Sessions = {};
router.get("/", function(req, res, next) {
  if (!req.cookies.userid) {
    res.cookie("userid", Math.floor(Math.random() * 100000));
  }
  res.render("index", { title: "Express" });
});

router.get("/login", function(req, res, next) {
  res.render("login.ejs", { message: req.flash("loginMessage") });
});

router.get("/loginu2f", function(req, res, next) {
  console.log(req);
  res.render("loginu2f.ejs", {
    message: req.flash("loginMessage"),
    user: req.user.local.email
  });
});
router.get("/loginbmw", function(req, res, next) {
  res.render("loginbmw.ejs", { message: req.flash("loginMessage") });
});
router.get("/loginu2fcar", function(req, res, next) {
  console.log("fsfdgasfdfdhsgdfhj    " + req.user);
  res.render("loginu2fcar.ejs", {
    message: req.flash("loginMessage"),
    user: req.user
  });
});

router.get("/signup", function(req, res) {
  res.render("signup.ejs", { message: req.flash("signupMessage") });
});

router.get("/profile", isLoggedIn, function(req, res) {
  console.log(req.user);
  res.render("profile.ejs", { user: req.user });
});
router.get("/profile_car", isLoggedIn, function(req, res) {
    console.log(req.user);
    res.render("profile_car.ejs", { user: req.user });
});
router.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

router.post(
  "/loginbmw",
  passport.authenticate("local-bmw", {
    successRedirect: "/loginu2fcar",
    failureRedirect: "/loginbmw",
    failureFlash: true
  })
);

router.post(
  "/loginu2fcar",
  passport.authenticate("local-bmw", {
    successRedirect: "/loginu2fcar",
    failureRedirect: "/loginbmw",
    failureFlash: true
  })
);

router.post(
  "/signup",
  passport.authenticate("local-signup", {
    successRedirect: "/profile",
    failureRedirect: "/signup",
    failureFlash: true
  })
);

router.post(
  "/login",
  passport.authenticate("local-login", {
    successRedirect: "/loginu2f",
    failureRedirect: "/login",
    failureFlash: true
  })
);
router.post(
    "/login",
    passport.authenticate("local-login", {
        successRedirect: "/loginu2f",
        failureRedirect: "/login",
        failureFlash: true
    })
);
router.post(
  "/temp", function(req, res) {
        console.log(JSON.stringify(req.user));
        console.log("dsadfasfdfafadf" + JSON.stringify(req.body));

        process.nextTick(function() {
            User1.findOne({ "local.email": req.user.local.email }, function(err, user) {
                if (err) return done(err);
                if (!user)
                    return done(null, false, req.flash("loginMessage", "No user found."));
                else {
                    console.log("OOOOOOOOOOO" + JSON.stringify("user.local"));
                    user.car.heating.right=req.body.temp2;
                    user.car.heating.left=req.body.temp1;
                    user.car.ventilation.left=req.body.temp3;
                    user.car.ventilation.right=req.body.temp4;


                    console.log(JSON.stringify(user));

                    user.save(function(err) {
                        if (err) throw err;
                        res.send(JSON.stringify({ stat: true}));                    });
                }
            });
        });
    });
router.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope:[ "email","user_birthday","user_location","user_hometown","user_likes","user_tagged_places"] })
);

router.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", {
    successRedirect: "/profile",
    failureRedirect: "/"
  })
);

router.get("/auth/twitter", passport.authenticate("twitter"));

router.get(
  "/auth/twitter/callback",
  passport.authenticate("twitter", {
    successRedirect: "/profile",
    failureRedirect: "/"
  })
);

router.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    successRedirect: "/profile",
    failureRedirect: "/"
  })
);
router.get("/api/register_request", function(req, res) {
  var authRequest = u2f.request(APP_ID);
  console.log(authRequest);
  Sessions[req.cookies.userid] = { authRequest: authRequest };
  res.send(JSON.stringify(authRequest));
});

router.get("/api/sign_request", function(req, res) {
  //var s=JSON.parse(req.user.local);
  console.log("THIS IS HANLD    " + req.user.local.handle.length);
  var authRequest = [];
  for (i = 0; i < req.user.local.handle.length; i++) {
    authRequest[i] = u2f.request(APP_ID, JSON.parse(req.user.local.handle[i]));
    authRequest[i].challenge = authRequest[0].challenge;
  }
  //var authRequest = u2f.request(APP_ID, JSON.parse(req.user.local.handle[0]));

  console.log("THIS IS AUTH    " + JSON.stringify(authRequest));

  Sessions[req.cookies.userid] = { authRequest: authRequest[0] };
  res.send(JSON.stringify(authRequest));
});

router.post("/addkey", function(req, res) {
  console.log(JSON.stringify(req.user));
  console.log("dsadfasfdfafadf" + JSON.stringify(req.body));

  process.nextTick(function() {
    User1.findOne({ "local.email": req.user.local.email }, function(err, user) {
      if (err) return done(err);
      if (!user)
        return done(null, false, req.flash("loginMessage", "No user found."));
      else {
        console.log("OOOOOOOOOOO" + JSON.stringify("user.local"));
        user.local.publickey = user.local.publickey.concat([req.body.pub]);
        user.local.handle = user.local.handle.concat([req.body.han]);
        console.log(JSON.stringify(user));

        user.save(function(err) {
          if (err) throw err;
          return res.redirect(req.get("referer"));
        });
      }
    });
  });
});
// google ---------------------------------

// send to google to do the authentication
router.get('/connect/google', passport.authorize('google', { scope : ['profile', 'email', 'gmail.readonly'] }));

// the callback after google has authorized the user
router.get('/connect/google/callback',
    passport.authorize('google', {
        successRedirect : '/profile',
        failureRedirect : '/'
    }));
router.get('/unlink/google', isLoggedIn, function(req, res) {
    var user          = req.user;
    user.google.token = undefined;
    user.save(function(err) {
        res.redirect('/profile');
    });
});
router.post(
  "/authorize",
  passport.authenticate("local-auth", {
    successRedirect: "/profile_car",
    failureRedirect: "/loginu2fcar",
    failureFlash: true
  })
);
router.post("/api/register", function(req, res) {
  console.log(req.body);
  var checkRes = u2f.checkRegistration(
    Sessions[req.cookies.userid].authRequest,
    req.body
  );
  console.log(checkRes);
  if (checkRes.successful) {
    Users[req.cookies.userid] = {
      publicKey: checkRes.publicKey,
      keyHandle: checkRes.keyHandle
    };
    User = { publicKey: checkRes.publicKey, keyHandle: checkRes.keyHandle };

    res.send(JSON.stringify({ stat: true, usr: User }));
  } else {
    res.send(checkRes.errorMessage);
  }
  console.log(User);
});

router.post("/api/authenticatecar", function(req, res) {
  console.log("MAAAAAAA" + JSON.stringify(req.body));
  tempo_handle = req.body.keyHandle;
  var checkRes;
  var j = req.user.local.handle.indexOf(JSON.stringify(req.body.keyHandle));
  console.log(j);
  checkRes = u2f.checkSignature(
    Sessions[req.cookies.userid].authRequest,
    req.body,
    req.user.local.publickey[j]
  );
  console.log(checkRes);
  if (checkRes.successful) {
    res.send({ success: true, secretData: req.user.local.handle[j] });
  } else {
    res.send({ error: checkRes.errorMessage });
  }
});
router.post("/api/authenticate", function(req, res) {
  console.log("MAAAAAAA" + JSON.stringify(req.body));
  tempo_handle = req.body.keyHandle;
  var checkRes;
  var j = req.user.local.handle.indexOf(JSON.stringify(req.body.keyHandle));
  console.log(j);
  checkRes = u2f.checkSignature(
    Sessions[req.cookies.userid].authRequest,
    req.body,
    req.user.local.publickey[j]
  );
  console.log(checkRes);
  if (checkRes.successful) {
    res.send({ success: true, secretData: "euueueueu" });
  } else {
    res.send({ error: checkRes.errorMessage });
  }
});
router.post(
    "/saveloc", function(req, res) {


        process.nextTick(function() {
            User1.findOne({ "local.email": req.user.local.email }, function(err, user) {
                if (err) return done(err);
                if (!user)
                    return done(null, false, req.flash("loginMessage", "No user found."));
                else {

                    console.log(req.body.locat);
                    var index=user.map.location.indexOf(req.body.locat)
                    if (index > -1) {

                         var nr = Number(user.map.density[index])+1;
                        var t=user.map.density;
                         t[index]=JSON.stringify(nr);
                        user.map.density[index]=JSON.stringify(nr);
                        console.log(JSON.stringify(user.map.density[index]));
                        User1.update({"local.email": req.user.local.email}, {
                            "map.density": t,

                        }, function(err, numberAffected, rawResponse) {
                            console.log(JSON.stringify(user));

                            res.send(JSON.stringify({ stat: true}));
                        });

                    } else {
                        user.map.location =  user.map.location.concat([req.body.locat]);
                        user.map.density =  user.map.density.concat(["1"]);
                        user.save(function(err) {
                            if (err) throw err;
                            console.log(JSON.stringify(user));

                            res.send(JSON.stringify({ stat: true}));                    });
                    }






                }
            });
        });
    });
module.exports = router;

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/");
}
