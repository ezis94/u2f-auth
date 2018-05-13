var LocalStrategy = require("passport-local").Strategy;
var FacebookStrategy = require("passport-facebook").Strategy;
var TwitterStrategy = require("passport-twitter").Strategy;
var GoogleStrategy = require("passport-google-oauth").OAuth2Strategy;
const SpotifyStrategy = require('passport-spotify').Strategy;
var randomstring = require("randomstring");

var User = require("../models/user");
var Car = require("../models/user_car");
var configAuth = require("./auth");

module.exports = function(passport) {
  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      if (user) done(err, user);
      else
        Car.findById(id, function(err, user) {
          done(err, user);
        });
    });
  });
    passport.use(new SpotifyStrategy({
            clientID: "8b9fff06998742eda4e4c23e1b89e2d0",
            clientSecret: "bb00e746afe14aa2b48d9dae4f0b3923",
            callbackURL: "https://localhost:4433/auth/spotify/callback",
            passReqToCallback : true

        },
        function(req,accessToken, refreshToken, expires_in, profile, done) {
            process.nextTick(function() {
                User.findOne({ "spotify.spotifyId": profile.id }, function (err, user) {
                    if (err) return done(err);
                    if (user) {                        console.log(JSON.stringify(expires_in));
                    }
                    else {
                        var user=req.user;
                        user.spotify.spotifyId=profile.id;
                        user.spotify.refresh=refreshToken;
                        user.spotify.access=accessToken;
                       var  date=new Date().getTime();
                        user.spotify.expires=date+parseInt(expires_in,10);
                        console.log(JSON.stringify(refreshToken));

                        user.save(function(err) {
                            if (err)
                                return done(err);

                            return done(null, user);
                        });

                    }

                    return done(err, user);
                });
            });
        }
    ));
  passport.use(
    "local-signup",
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
        nameField: "tname",
        publickey: "pub",
        handle: "han",
        passReqToCallback: true
      },
      function(req, email, password, tname, publickey, handle, done) {
       var   role="";
       var car_id;
        process.nextTick(function() {
            Car.findOne({ "local.key_admin": tname }, function(err, user1) {
                if (err) return done(err);
                if (user1) {
                    car_id=user1.local.email;
                    role="admin";
                    console.log("admincar");
                    User.findOne({ "local.email": email }, function(err, user) {
                        if (err) return done(err);
                        if (user) {
                            console.log("no user");
                            return done(
                                null,
                                false,
                                req.flash("signupMessage", "That email is already taken.")
                            );
                        } else {

                            console.log("in saving user");
                            var newUser = new User();
                            newUser.local.email = email;
                            newUser.local.password = newUser.generateHash(password);
                            newUser.local.name = car_id;
                            newUser.local.publickey.push(publickey);
                            newUser.local.handle.push(handle);
                            newUser.local.ROLE=role;
                            newUser.car.heating.left = "20";
                            newUser.car.heating.right = "20";
                            newUser.car.ventilation.left = "2";
                            newUser.car.ventilation.right = "2";
                            newUser.map.enabled="false";
                            newUser.spotify.enabled="false";
                            newUser.google.enabled="false";
                            newUser.local.limit="none";
                            newUser.local.trunk="true";

                            newUser.save(function(err) {
                                Car.findOne({ "local.email": car_id }, function(err, user1) {
                                    if (err) return done(err);
                                    if (user1) {
                                        switch (tname) {
                                            case user1.local.key_admin:
                                                user1.local.key_admin="";
                                                break;
                                            case user1.local.key_owner:
                                                user1.local.key_owner="";
                                                break;
                                            case user1.local.key_non_owner:
                                                user1.local.key_non_owner="";
                                                break;
                                            case user1.local.key_maintenance:
                                                user1.local.key_maintenance="";
                                                break;

                                        }

                                        user1.local.publickey = user1.local.publickey.concat([
                                            req.body.pub
                                        ]);
                                        user1.local.handle = user1.local.handle.concat([
                                            req.body.han
                                        ]);

                                        user1.save(function(err) {
                                            if (err) throw err;

                                        });
                                    }
                                });
                                return done(null, newUser);

                            });
                        }
                    });
                }
                 else {
                    Car.findOne({ "local.key_owner": tname }, function(err, user1) {
                        if (err) return done(err);
                        if (user1) {
                              role="owner";
                              car_id=user1.local.email;
                              console.log("ownercar");
                            User.findOne({ "local.email": email }, function(err, user) {
                                if (err) return done(err);
                                if (user) {
                                    console.log("no user");
                                    return done(
                                        null,
                                        false,
                                        req.flash("signupMessage", "That email is already taken.")
                                    );
                                } else {

                                    console.log("in saving user");
                                    var newUser = new User();
                                    newUser.local.email = email;
                                    newUser.local.password = newUser.generateHash(password);
                                    newUser.local.name = car_id;
                                    newUser.local.publickey.push(publickey);
                                    newUser.local.handle.push(handle);
                                    newUser.local.ROLE=role;
                                    newUser.car.heating.left = "20";
                                    newUser.car.heating.right = "20";
                                    newUser.car.ventilation.left = "2";
                                    newUser.car.ventilation.right = "2";
                                    newUser.map.enabled="false";
                                    newUser.spotify.enabled="false";
                                    newUser.google.enabled="false";
                                    newUser.local.limit="none";
                                    newUser.local.trunk="true";
                                    newUser.save(function(err) {
                                        Car.findOne({ "local.email": car_id }, function(err, user1) {
                                            if (err) return done(err);
                                            if (user1) {
                                                switch (tname) {
                                                    case user1.local.key_admin:
                                                        user1.local.key_admin="";
                                                        break;
                                                    case user1.local.key_owner:
                                                        user1.local.key_owner="";
                                                        break;
                                                    case user1.local.key_non_owner:
                                                        user1.local.key_non_owner="";
                                                        break;
                                                    case user1.local.key_maintenance:
                                                        user1.local.key_maintenance="";
                                                        break;

                                                }

                                                user1.local.publickey = user1.local.publickey.concat([
                                                    req.body.pub
                                                ]);
                                                user1.local.handle = user1.local.handle.concat([
                                                    req.body.han
                                                ]);

                                                user1.save(function(err) {
                                                    if (err) throw err;

                                                });
                                            }
                                        });
                                        return done(null, newUser);

                                    });
                                }
                            });
                        } else {
                            Car.findOne({ "local.key_non_owner": tname }, function(err, user1) {
                                  if (err) return done(err);
                                  if (user1) {
                                      role="non_owner";
                                      car_id=user1.local.email;
                                      console.log("nononercar");
                                      User.findOne({ "local.email": email }, function(err, user) {
                                          if (err) return done(err);
                                          if (user) {
                                              console.log("no user");
                                              return done(
                                                  null,
                                                  false,
                                                  req.flash("signupMessage", "That email is already taken.")
                                              );
                                          } else {

                                              console.log("in saving user");
                                              var newUser = new User();
                                              newUser.local.email = email;
                                              newUser.local.password = newUser.generateHash(password);
                                              newUser.local.name = car_id;
                                              newUser.local.publickey.push(publickey);
                                              newUser.local.handle.push(handle);
                                              newUser.local.ROLE=role;
                                              newUser.car.heating.left = "20";
                                              newUser.car.heating.right = "20";
                                              newUser.car.ventilation.left = "2";
                                              newUser.car.ventilation.right = "2";
                                              newUser.map.enabled="false";
                                              newUser.spotify.enabled="false";
                                              newUser.google.enabled="false";
                                              newUser.local.limit="none";
                                              newUser.local.trunk="true";
                                              newUser.save(function(err) {
                                                  Car.findOne({ "local.email": car_id }, function(err, user1) {
                                                      if (err) return done(err);
                                                      if (user1) {
                                                          switch (tname) {
                                                              case user1.local.key_admin:
                                                                  user1.local.key_admin="";
                                                                  break;
                                                              case user1.local.key_owner:
                                                                  user1.local.key_owner="";
                                                                  break;
                                                              case user1.local.key_non_owner:
                                                                  user1.local.key_non_owner="";
                                                                  break;
                                                              case user1.local.key_maintenance:
                                                                  user1.local.key_maintenance="";
                                                                  break;

                                                          }

                                                          user1.local.publickey = user1.local.publickey.concat([
                                                              req.body.pub
                                                          ]);
                                                          user1.local.handle = user1.local.handle.concat([
                                                              req.body.han
                                                          ]);

                                                          user1.save(function(err) {
                                                              if (err) throw err;

                                                          });
                                                      }
                                                  });
                                                  return done(null, newUser);

                                              });
                                          }
                                      });
                                  } else {
                                      Car.findOne({ "local.key_maintenance": tname }, function(err, user1) {
                                          if (err) return done(err);
                                          if (user1) {
                                              role = "maintenance";
                                              car_id = user1.local.email;
                                              console.log("mainntencar");
                                              User.findOne({ "local.email": email }, function(err, user) {
                                                  if (err) return done(err);
                                                  if (user) {
                                                      console.log("no user");
                                                      return done(
                                                          null,
                                                          false,
                                                          req.flash("signupMessage", "That email is already taken.")
                                                      );
                                                  } else {

                                                      console.log("in saving user");
                                                      var newUser = new User();
                                                      newUser.local.email = email;
                                                      newUser.local.password = newUser.generateHash(password);
                                                      newUser.local.name = car_id;
                                                      newUser.local.publickey.push(publickey);
                                                      newUser.local.handle.push(handle);
                                                      newUser.local.ROLE=role;
                                                      newUser.car.heating.left = "20";
                                                      newUser.car.heating.right = "20";
                                                      newUser.car.ventilation.left = "2";
                                                      newUser.car.ventilation.right = "2";
                                                      newUser.map.enabled="false";
                                                      newUser.spotify.enabled="false";
                                                      newUser.google.enabled="false";
                                                      newUser.local.limit="none";
                                                      newUser.local.trunk="true";
                                                      newUser.save(function(err) {
                                                          Car.findOne({ "local.email": car_id }, function(err, user1) {
                                                              if (err) return done(err);
                                                              if (user1) {
                                                                  switch (tname) {
                                                                      case user1.local.key_admin:
                                                                          user1.local.key_admin="";
                                                                          break;
                                                                      case user1.local.key_owner:
                                                                          user1.local.key_owner="";
                                                                          break;
                                                                      case user1.local.key_non_owner:
                                                                          user1.local.key_non_owner="";
                                                                          break;
                                                                      case user1.local.key_maintenance:
                                                                          user1.local.key_maintenance="";
                                                                          break;

                                                                  }

                                                                  user1.local.publickey = user1.local.publickey.concat([
                                                                      req.body.pub
                                                                  ]);
                                                                  user1.local.handle = user1.local.handle.concat([
                                                                      req.body.han
                                                                  ]);

                                                                  user1.save(function(err) {
                                                                      if (err) throw err;

                                                                  });
                                                              }
                                                          });
                                                          return done(null, newUser);

                                                      });
                                                  }
                                              });
                                          }
                                          else  return done(
                                              null,
                                              false,
                                              req.flash("signupMessage", "Not a valid key.")
                                          );
                                      });
                                  }
                            });
                        }
                    });
                }
                console.log("this "+role);


             });




          });
      }
    )
  );



  passport.use(
        "local-signupcar",
        new LocalStrategy(
            {
                usernameField: "email",
                passwordField: "password",
                nameField: "tname",
                publickey: "pub",
                handle: "han",
                passReqToCallback: true
            },
            function(req, email, password, tname, publickey, handle, done) {
                process.nextTick(function() {

                    Car.findOne({ "local.email": tname }, function(err, user) {
                        if (err) return done(err);
                        if (user) {
                            return done(
                                null,
                                false,
                                req.flash("signupMessage", "That car is already made.")
                            );
                        } else {
                            var newCar = new Car();
                            newCar.local.email = email;
                            newCar.local.password = newCar.generateHash(password);
                            newCar.local.name = tname;
                          newCar.local.key_admin = randomstring.generate(32);
                            newCar.local.key_non_owner="";
                            newCar.local.key_owner="";
                            newCar.local.key_maintenance="";

                            newCar.save(function(err) {
                                return done(
                                    null,
                                    false,
                                    req.flash("signupMessage", "Success " +newCar.local.key_admin )
                                );
                            });
                        }
                    });
                });
            }
        )
    );
  passport.use(
    "local-add",
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
        nameField: "tname",
        publickey: "pub",
        handle: "han",
        passReqToCallback: true
      },
      function(req, email, password, tname, publickey, handle, done) {
        process.nextTick(function() {
          User.findOne({ "local.email": email }, function(err, user) {
            if (err) return done(err);
            if (!user)
              return done(
                null,
                false,
                req.flash("loginMessage", "No user found.")
              );
            else {
              console.log("OOOOOOOOOOO" + JSON.stringify("user.local"));
              user.local.publickey.push(publickey);
              user.local.handle.push(handle);

              return done(null, user);
            }
          });
        });
      }
    )
  );

  passport.use(
    "local-login",
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
        publickey: "pub",
        handle: "han",
        passReqToCallback: true
      },
      function(req, email, password, tname, publickey, handle, done) {
        User.findOne({ "local.email": email }, function(err, user) {
          if (err) return done(err);
          if (!user)
            return done(
              null,
              false,
              req.flash("loginMessage", "No user found.")
            );
          if (!user.validPassword(password))
            return done(
              null,
              false,
              req.flash("loginMessage", "Oops! Wrong password.")
            );

          return done(null, user);
        });
      }
    )
  );

  passport.use(
    "local-bmw",
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
        publickey: "pub",
        handle: "han",
        passReqToCallback: true
      },
      function(req, email, password, tname, publickey, handle, done) {
        Car.findOne({ "local.email": email }, function(err, user) {
          if (err) return done(err);
          if (!user)
            return done(
              null,
              false,
              req.flash("loginMessage", "No car found.")
            );
          if (!user.validPassword(password))
            return done(
              null,
              false,
              req.flash("loginMessage", "Oops! Wrong password.")
            );

          return done(null, user);
        });
      }
    )
  );
  passport.use(
    "local-auth",
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
        publickey: "pub",
        handle: "han",
        passReqToCallback: true
      },
      function(req, email, password, tname, publickey, handle, done) {
        console.log("aaaaaaaaassss" + handle);
        User.findOne({ "local.handle": handle }, function(err, user) {
          if (err) return done(err);
          if (!user)
            return done(
              null,
              false,
              req.flash("loginMessage", "No user found.")
            );
          // console.log("kappa");
          return done(null, user);
        });
      }
    )
  );
  passport.use(
    new FacebookStrategy(
      {
        clientID: "200593680707099",
        clientSecret: "ac2aba015116ab04d046d38fa34200c4",
        callbackURL: "https://localhost:4433/auth/facebook/callback",
        profileFields: ["id", "email", "first_name", "last_name","location","birthday","hometown","likes","tagged_places"]
      },
      function(token, refreshToken, profile, done) {
          console.log("locaaaation"+JSON.stringify(JSON.parse(profile._raw).tagged_places.data[0]));
          console.log("locaaaation"+profile._raw);
        process.nextTick(function() {
          User.findOne({ "facebook.id": profile.id }, function(err, user) {
            if (err) return done(err);
            if (user) {
              return done(null, user);
            } else {
              var newUser = new User();
              newUser.facebook.location=JSON.parse(profile._raw).location.name;
              newUser.facebook.birthday=JSON.parse(profile._raw).birthday;
                newUser.facebook.hometown=JSON.parse(profile._raw).hometown.name;

                for(i in JSON.parse(profile._raw).likes.data){
                    newUser.facebook.likes = newUser.facebook.likes.concat([
                        JSON.parse(profile._raw).likes.data[i].name
                    ]);
                }
                for(i in JSON.parse(profile._raw).tagged_places.data){
                    newUser.facebook.taggedlat = newUser.facebook.taggedlat.concat([
                        JSON.parse(profile._raw).tagged_places.data[i].place.location.latitude

                    ]);
                    newUser.facebook.taggedlong = newUser.facebook.taggedlong.concat([
                        JSON.parse(profile._raw).tagged_places.data[i].place.location.longitude

                ]);
                }
                newUser.facebook.id = profile.id;
              newUser.facebook.token = token;
              newUser.facebook.name =
                profile.name.givenName + " " + profile.name.familyName;
              newUser.facebook.email = (
                profile.emails[0].value || ""
              ).toLowerCase();

              newUser.save(function(err) {
                if (err) throw err;
                return done(null, newUser);
              });
            }
          });
        });
      }
    )
  );

  passport.use(
    new TwitterStrategy(
      {
        consumerKey: configAuth.twitterAuth.consumerKey,
        consumerSecret: configAuth.twitterAuth.consumerSecret,
        callbackURL: configAuth.twitterAuth.callbackURL
      },
      function(token, tokenSecret, profile, done) {
        process.nextTick(function() {
          User.findOne({ "twitter.id": profile.id }, function(err, user) {
            if (err) return done(err);
            if (user) {
              return done(null, user);
            } else {
              var newUser = new User();
              newUser.twitter.id = profile.id;
              newUser.twitter.token = token;
              newUser.twitter.username = profile.username;
              newUser.twitter.displayName = profile.displayName;
              newUser.save(function(err) {
                if (err) throw err;
                return done(null, newUser);
              });
            }
          });
        });
      }
    )
  );
    passport.use(new GoogleStrategy({
            clientID: "897949743059-1ghfq0eo7eot68goq0hqbjl33eabvicd.apps.googleusercontent.com",
            clientSecret: "ouYHqAuCD-YzGW5d9RRstVE_",
            callbackURL:"https://localhost:4433/auth/google/callback",
            passReqToCallback : true

        },
        function(req, token, refreshToken, profile, done) {
            // asynchronous
            process.nextTick(function() {
                // check if the user is already logged in
                if (!req.user) {

                    User.findOne({ 'google.id' : profile.id }, function(err, user) {
                        if (err){console.log(err);
                            return done(err);}

                        if (user) {

                            // if there is a user id already but no token (user was linked at one point and then removed)
                            if (!user.google.token) {
                                user.google.token = token;
                                console.log("dsadafaf"+token);
                                user.google.refresh = refreshToken;
                                var  date=new Date().getTime();
                                user.google.expires=date+3600;
                                user.google.name  = profile.displayName;
                                user.google.email = (profile.emails[0].value || '').toLowerCase(); // pull the first email

                                user.save(function(err) {
                                    if (err)
                                        return done(err);

                                    return done(null, user);
                                });
                            }

                            return done(null, user);
                        } else {
                            var newUser          = new User();

                            newUser.google.id    = profile.id;
                            newUser.google.token = token;
                            newUser.google.name  = profile.displayName;
                            newUser.google.email = (profile.emails[0].value || '').toLowerCase(); // pull the first email

                            newUser.save(function(err) {
                                if (err)
                                    return done(err);

                                return done(null, newUser);
                            });
                        }
                    });

                } else {
                    // user already exists and is logged in, we have to link accounts
                    var user               = req.user; // pull the user out of the session

                    user.google.id    = profile.id;
                    user.google.token = token;
                    user.google.refresh = refreshToken;
                    console.log("dsadafaf"+token);
                    console.log("dsadafaf"+refreshToken);

                    var  date=new Date().getTime();
                    user.google.expires=date+3600;
                    user.google.name  = profile.displayName;
                    user.google.email = (profile.emails[0].value || '').toLowerCase(); // pull the first email

                    user.save(function(err) {
                        if (err)
                            return done(err);

                        return done(null, user);
                    });

                }

            });

        }
    ));

};
