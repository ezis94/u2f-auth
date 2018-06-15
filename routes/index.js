var express = require("express");
var passport = require("passport");
var router = express.Router();
var u2f = require("u2f");
var https = require("https");
const AccessControl = require('accesscontrol');
var randomstring = require("randomstring");

var request = require('request'); // "Request" library
var GoogleTokenProvider = require('refresh-token').GoogleTokenProvider;
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

//ROLE STUFF-----------------------------------------------------------------------------------------
const ac = new AccessControl();
ac.grant('maintenance')
    .readOwn('car') //access the car version of the application
.grant('non_owner')
    .extend('maintenance')    // inherit role capabilities from maintenance
    .readOwn('web')     //access the web version of the application
    .createOwn('acc_app')             // connect an application
    .deleteOwn('acc_app')           //disconnect an application
    .updateOwn('apps')              //enable/disable applications
    .readOwn('logs')                //read own logs (not implemented)
.grant('owner')
    .extend('non_owner')                 // inherit role capabilities from non owner
    .createAny('non_owner')             //create non owner accounts
    .createAny('maintenance')       //create maintenance accounts
    .deleteAny('maintenance')   //delete maintenance accounts
    .readAny('non_owner_logs')  //read non owner logs(not implemented)
    .readAny('non_owner_permissions')   //view non owner permissions
    .updateAny('non_owner_permissions')  //change non owner permissions
    .deleteAny('non_owner'              )//delete non owner accounts
.grant('admin')
    .createAny('non_owner')              //create non owner accounts
    .createAny('maintenance')            //create maintenance accounts
    .createAny('owner')              //create owner accounts
    .readOwn('web')              //access the web version of the application
    .updateAny('role')              // change account roles
    .deleteAny('non_owner')         //delete non owner accounts
    .deleteAny('maintenance')       //delete maintenance accounts
    .deleteAny('owner');         //create owner accounts

/*const permission = ac.can('user').createOwn('video');
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['*'] (all attributes)

permission = ac.can('admin').updateAny('video');
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['title']*/
//----------------------------------------------------------------------------------------------------

router.get("/", function(req, res, next) {
  if (!req.cookies.userid) {
    res.cookie("userid", Math.floor(Math.random() * 100000));
  }
  res.render("index", { title: "Express" });
});

router.get("/login", function(req, res, next) {
  res.render("login.ejs", { message: req.flash("loginMessage") });
});
router.get("/app_settings", function(req, res, next) {
    var permission = ac.can(req.user.local.ROLE).updateOwn('apps');
    if (permission.granted) {
        res.render("app_settings.ejs", {user: req.user});
    }
    else res.status(403).end();
});
router.get("/acc_settings", function(req, res, next) {
    var permission = ac.can(req.user.local.ROLE).readAny('non_owner_permissions');
    if (permission.granted) {
        process.nextTick(function () {
            User1.find({"local.ROLE": "non_owner","local.name":req.user.local.name}, function (err, users) {
                if (err)        res.send(err);


                else {

                    console.log(JSON.stringify(users));
                    res.render("acc_settings.ejs", {user: req.user,users:users});

                }
            });
        });
    }
    else res.status(403).end();
});
router.get("/admin_settings", function(req, res, next) {
    var permission = ac.can(req.user.local.ROLE).updateAny('role');
    if (permission.granted) {
        process.nextTick(function () {
            User1.find({"local.ROLE": {$ne : "admin"},"local.name":req.user.local.name}, function (err, users) {
                if (err)         res.send(err);


                else {

                    console.log(JSON.stringify(users));
                    res.render("admin_settings.ejs", {user: req.user,users:users});

                }
            });
        });
    }
    else res.status(403).end();
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
  res.render("loginu2fcar.ejs", {
    message: req.flash("loginMessage"),
    user: req.user
  });
});

router.get("/signup", function(req, res) {
  res.render("signup.ejs", { message: req.flash("signupMessage") });
});
router.get("/signupcar", function(req, res) {
    res.render("signupcar.ejs", { message: req.flash("signupMessage") });
});

router.get("/profile", isLoggedIn, function(req, res) {
    var permission = ac.can(req.user.local.ROLE).readOwn('web');
    if (permission.granted) {
        console.log(req.user);
        var date = new Date().getTime();

        var user1 = req.user;
        var permission = ac.can(req.user.local.ROLE).createOwn('acc_app');
        if (permission.granted) {

        if (req.user.spotify.expires <= date) {
            console.log(date);
            var authOptions = {
                url: 'https://accounts.spotify.com/api/token',
                headers: {'Authorization': 'Basic ' + (new Buffer('8b9fff06998742eda4e4c23e1b89e2d0:bb00e746afe14aa2b48d9dae4f0b3923').toString('base64'))},
                form: {
                    grant_type: 'refresh_token',
                    refresh_token: req.user.spotify.refresh
                },
                json: true
            };
            request.post(authOptions, function (error, response, body) {
                if (!error && response.statusCode === 200) {
                    var access_token = body.access_token;
                    var expire_in = body.expires_in;
                    console.log(JSON.stringify(body));
                    process.nextTick(function () {
                        User1.findOne({"local.email": user1.local.email}, function (err, user) {
                            if (err) return done(err);
                            if (!user)
                                return done(null, false, req.flash("loginMessage", "No user found1."));
                            else {

                                user.spotify.access = access_token;
                                var date = new Date().getTime();

                                var t = parseInt(expire_in, 10) * 1000;
                                console.log(t);
                                user.spotify.expires = date + t;
                                user.save(function (err) {
                                    if (err) throw err;
                                });
                            }
                        });
                    });
                }
            });
        }}
        var permission = ac.can(req.user.local.ROLE).createOwn('acc_app');
        if (permission.granted) {
        if (req.user.google.expires <= date) {
            var tokenProvider = new GoogleTokenProvider({
                refresh_token: req.user.google.refresh,
                client_id: '897949743059-1ghfq0eo7eot68goq0hqbjl33eabvicd.apps.googleusercontent.com',
                client_secret: 'ouYHqAuCD-YzGW5d9RRstVE_'
            });
            tokenProvider.getToken(function (err, token) {


                console.log(JSON.stringify(token));
                process.nextTick(function () {
                    User1.findOne({"local.email": user1.local.email}, function (err, user) {
                        if (err) return done(err);
                        if (!user)
                            return done(null, false, req.flash("loginMessage", "No user found2."));
                        else {

                            user.google.access = token;
                            var date = new Date().getTime();

                            user.google.expires = date + 3600000;


                            user.save(function (err) {
                                if (err) throw err;
                            });
                        }
                    });
                });
            });
        }}
        res.render("profile.ejs", {user: req.user});
    }
    else res.status(403).end();
});
router.get("/profile_car", isLoggedIn, function(req, res) {
    var permission = ac.can(req.user.local.ROLE).readOwn('car');
    if (permission.granted) {
    console.log(req.user);
    var  date=new Date().getTime();
console.log(date);
    var user1=req.user;
        var permission1 = ac.can(req.user.local.ROLE).createOwn('acc_app');
        if (permission1.granted) {
    if (req.user.spotify.expires<=date){
        console.log(date);
        var authOptions = {
            url: 'https://accounts.spotify.com/api/token',
            headers: { 'Authorization': 'Basic ' + (new Buffer('8b9fff06998742eda4e4c23e1b89e2d0:bb00e746afe14aa2b48d9dae4f0b3923' ).toString('base64')) },
            form: {
                grant_type: 'refresh_token',
                refresh_token: req.user.spotify.refresh
            },
            json: true
        };

        request.post(authOptions, function(error, response, body) {
            if (!error && response.statusCode === 200) {
                var access_token = body.access_token;
                var expire_in=body.expires_in;
                console.log(JSON.stringify(body));
                process.nextTick(function() {
                    User1.findOne({ "local.email": user1.local.email }, function(err, user) {
                        if (err) return done(err);
                        if (!user)
                            return done(null, false, req.flash("loginMessage", "No user found1."));
                        else {

                            user.spotify.access=access_token;
                            var  date=new Date().getTime();
                            var t=parseInt(expire_in,10)*1000;
                            console.log("this is "+t);

                            user.spotify.expires=date+t;


                            user.save(function(err) {
                                if (err) throw err;
                            });
                        }
                    });
                });
            }
        });
    }}
        var permission2 = ac.can(req.user.local.ROLE).createOwn('acc_app');
        if (permission2.granted) {
     if (req.user.google.expires<=date){
        var tokenProvider = new GoogleTokenProvider({
            refresh_token: req.user.google.refresh,
            client_id:     '897949743059-1ghfq0eo7eot68goq0hqbjl33eabvicd.apps.googleusercontent.com',
            client_secret: 'ouYHqAuCD-YzGW5d9RRstVE_'
        });
        tokenProvider.getToken(function (err, token) {
            if (err) console.log(err);
console.log (JSON.stringify(token));
            process.nextTick(function() {
                User1.findOne({ "local.email": user1.local.email }, function(err, user) {
                    if (err) return done(err);
                    if (!user)
                        return done(null, false, req.flash("loginMessage", "No user found2."));
                    else {

                        user.google.token=token;
                        var  date=new Date().getTime();

                        user.google.expires=date+3600000;


                        user.save(function(err) {
                            if (err) throw err;
                        });
                    }
                });
            });        });
    }}
    res.render("profile_car.ejs", { user: req.user });
    }
    else res.status(403).end();
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
    "/signupcar",
    passport.authenticate("local-signupcar", {
        successRedirect: "/",
        failureRedirect: "/signupcar",
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

    "/deleteuser", function(req, res) {

            process.nextTick(function () {
                User1.findOne({"local.email": req.body.id}, function (err, user) {
                    if (err) return res.send(err);
                    else {

                        var permission = ac.can(req.user.local.ROLE).deleteAny(user.local.ROLE);
                        if (permission.granted){

                            user.local.ROLE=req.body.role;
                            var handle=user.local.handle;
                            console.log(handle);

                            Car.findOne({"local.email": user.local.name}, function (err, user1) {
                                var index = user1.local.handle.indexOf(handle);
                                if (index > -1) {
                                    user1.local.handle.splice(index, 1);
                                    console.log(user1.local.handle);
                                    user1.local.publickey.splice(index, 1);
                                }
                                user1.save(function (err) {
                                    if (err) throw err;
                                    User1.remove({"local.email": req.body.id}, function (err, user){ });
                                    res.send(JSON.stringify({stat: true}));
                                });
                             });


                        }
                    }
                });
            });

    });
router.post(

    "/changerole", function(req, res) {
        var permission = ac.can(req.user.local.ROLE).updateAny('role');
        if (permission.granted){
            process.nextTick(function () {
                User1.findOne({"local.email": req.body.id}, function (err, user) {
                    if (err) return res.send(err);
                    else {
                        user.local.ROLE=req.body.role;
                        user.save(function (err) {
                            if (err) throw err;
                            res.send(JSON.stringify({stat: true}));
                        });
                    }
                });
            });
        }
    });
router.post(

    "/changelimit", function(req, res) {
        var permission = ac.can(req.user.local.ROLE).updateAny('non_owner_permissions');  // explicitly defined attributes

        if (permission.granted){
            process.nextTick(function () {
                User1.findOne({"local.email": req.body.id}, function (err, user) {
                    if (err) return res.send(err);
                    else {
                        user.local.limit=req.body.limit;
                        user.save(function (err) {
                            if (err) throw err;
                            res.send(JSON.stringify({stat: true}));
                        });
                    }
                });
            });
        }
    });
router.post(

    "/changetrunk", function(req, res) {
        var permission = ac.can(req.user.local.ROLE).updateAny('non_owner_permissions');  // explicitly defined attributes

        if (permission.granted){
            process.nextTick(function () {
                User1.findOne({"local.email": req.body.id}, function (err, user) {
                    if (err) return res.send(err);
                    else {
                        user.local.trunk=req.body.trunk;
                        user.save(function (err) {
                            if (err) throw err;
                            res.send(JSON.stringify({stat: true}));
                        });
                    }
                });
            });
        }
    });
router.post(
    "/createuser", function(req, res) {
            process.nextTick(function () {
                Car.findOne({"local.email": req.user.local.name}, function (err, user) {
                    if (err) return res.send(err);
                    else {
                        var key;
                        switch (req.body.role) {
                            case "createOwner":
                                var permission = ac.can(req.user.local.ROLE).createAny('owner');
                                if (permission.granted) {
                                user.local.key_owner = randomstring.generate(32);
                                key = user.local.key_owner;}
                                break;
                            case "createNon_Owner":
                                var permission = ac.can(req.user.local.ROLE).createAny('non_owner');
                                if (permission.granted) {
                                user.local.key_non_owner = randomstring.generate(32);
                                key = user.local.key_non_owner;}
                                break;
                            case "createMaintenance":
                                var permission = ac.can(req.user.local.ROLE).createAny('maintenance');
                                if (permission.granted) {
                                user.local.key_maintenance = randomstring.generate(32);
                                key = user.local.key_maintenance;}
                                break;
                        }
                        console.log(user.local.key_owner);
                        user.save(function (err) {
                            if (err) throw err;
                            res.send(JSON.stringify({key: key, stat: true}));
                        });
                    }
                });
            });

    });
router.post(
  "/temp", function(req, res) {
        console.log(JSON.stringify(req.user));

        process.nextTick(function() {
            User1.findOne({ "local.email": req.user.local.email }, function(err, user) {
                if (err) return done(err);
                if (!user)
                    return done(null, false, req.flash("loginMessage", "No user found."));
                else {
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

router.get('/auth/spotify',
    passport.authenticate('spotify',{ scope: ["user-read-birthdate", "user-read-email", "user-read-private ","user-modify-playback-state", "playlist-read-private","streaming","user-follow-read"] }),
    function(req, res){
        // The request will be redirected to spotify for authentication, so this
        // function will not be called.
    });

router.get('/auth/spotify/callback',
    passport.authenticate('spotify', { failureRedirect: '/login' }),
    function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/profile');
    });

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



// google ---------------------------------

// send to google to do the authentication
router.get('/connect/google', passport.authorize('google', { scope : ['profile', 'email', 'https://www.googleapis.com/auth/calendar.readonly'],accessType: 'offline', approvalPrompt: 'force'  }));

// the callback after google has authorized the user

router.get('/connect/google/callback',
    passport.authorize('google', {
        successRedirect : '/profile',
        failureRedirect : '/'
    }));
router.get('/unlink/google', isLoggedIn, function(req, res) {
    var user          = req.user;
    user.google.token = undefined;
    user.google.refresh = undefined;
    user.google.email = undefined;
    user.google.expires = undefined;
    user.google.id = undefined;
    user.google.name = undefined;

    user.save(function(err) {
        res.redirect('/profile');
    });
});
router.get('/unlink/spotify', isLoggedIn, function(req, res) {
    var user          = req.user;
    user.spotify.access = undefined;
    user.spotify.refresh = undefined;
    user.spotify.expires = undefined;
    user.spotify.spotifyId = undefined;

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
                    var index=user.map.location.indexOf(req.body.locat);
                    console.log("very long string"+index);
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

                            res.send(JSON.stringify({ stat: true,new:false}));
                        });

                    } else {
                        user.map.location =  user.map.location.concat([req.body.locat]);
                        user.map.density =  user.map.density.concat(["1"]);
                        user.save(function(err) {
                            if (err) throw err;
                            console.log(JSON.stringify(user));

                            res.send(JSON.stringify({ stat: true,new:true}));                    });
                    }






                }
            });
        });
    });
router.post("/map_status", function(req, res) {
    process.nextTick(function() {
        User1.findOne({ "local.email": req.user.local.email }, function(err, user) {
            if (err) return done(err);
            if (!user)
                return done(null, false, req.flash("loginMessage", "No user found."));
            else {




                    console.log( req.body.mapon);
                    User1.update({"local.email": req.user.local.email}, {
                        "map.enabled": req.body.mapon,

                    }, function(err, numberAffected, rawResponse) {
                        console.log(JSON.stringify(user));

                        res.send(JSON.stringify({ stat: true}));
                    });








            }
        });
    });
});
router.post("/spotify_status", function(req, res) {
    process.nextTick(function() {
        User1.findOne({ "local.email": req.user.local.email }, function(err, user) {
            if (err) return done(err);
            if (!user)
                return done(null, false, req.flash("loginMessage", "No user found."));
            else {




                console.log( req.body.mapon);
                User1.update({"local.email": req.user.local.email}, {
                    "spotify.enabled": req.body.spoton,

                }, function(err, numberAffected, rawResponse) {
                    console.log(JSON.stringify(user));

                    res.send(JSON.stringify({ stat: true}));
                });








            }
        });
    });
});
router.post("/calendar_status", function(req, res) {
    process.nextTick(function() {
        User1.findOne({ "local.email": req.user.local.email }, function(err, user) {
            if (err) return done(err);
            if (!user)
                return done(null, false, req.flash("loginMessage", "No user found."));
            else {
                console.log( req.body.mapon);
                User1.update({"local.email": req.user.local.email}, {
                    "google.enabled": req.body.calend,

                }, function(err, numberAffected, rawResponse) {
                    console.log(JSON.stringify(user));

                    res.send(JSON.stringify({ stat: true}));
                });
            }
        });
    });
});
module.exports = router;

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/");
}
