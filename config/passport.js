var LocalStrategy = require("passport-local").Strategy;
var FacebookStrategy = require("passport-facebook").Strategy;
var TwitterStrategy = require("passport-twitter").Strategy;
var GoogleStrategy = require("passport-google-oauth").OAuth2Strategy;
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
        process.nextTick(function() {
          User.findOne({ "local.email": email }, function(err, user) {
            if (err) return done(err);
            if (user) {
              return done(
                null,
                false,
                req.flash("signupMessage", "That email is already taken.")
              );
            } else {
              var newUser = new User();
              newUser.local.email = email;
              newUser.local.password = newUser.generateHash(password);
              newUser.local.name = tname;
              newUser.local.publickey.push(publickey);
              newUser.local.handle.push(handle);
              newUser.car.heating.left = "20";
                newUser.car.heating.right = "20";
                newUser.car.ventilation.left = "2";
                newUser.car.ventilation.right = "2";

                newUser.save(function(err) {
                if (err) throw err;
                Car.findOne({ "local.email": tname }, function(err, user) {
                  if (err) return done(err);
                  if (user) {
                    user.local.publickey = user.local.publickey.concat([
                      req.body.pub
                    ]);
                    user.local.handle = user.local.handle.concat([
                      req.body.han
                    ]);

                    user.save(function(err) {
                      if (err) throw err;
                    });
                  } else {
                    var newCar = new Car();
                    newCar.local.email = tname;
                    newCar.local.password = newUser.generateHash(tname);
                    newCar.local.name = tname;
                    newCar.local.publickey.push(publickey);
                    newCar.local.handle.push(handle);
                    newCar.save(function(err) {
                      if (err) throw err;
                    });
                  }
                });
                return done(null, newUser);
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

  passport.use(
    new GoogleStrategy(
      {
        clientID: "897949743059-29ad8f8jb800tcr6snvp809bj8odglsu.apps.googleusercontent.com",
        clientSecret: "yjMA6z7XJPDF3gseGEMAeTyT",
        callbackURL:"https://localhost:4433/connect/google/callback",
          passReqToCallback : true
      },
        function(req, token, refreshToken, profile, done) {

            // asynchronous
            process.nextTick(function() {
                // check if the user is already logged in
                if (!req.user) {

                    User.findOne({ 'google.id' : profile.id }, function(err, user) {
                        if (err)
                            return done(err);

                        if (user) {

                            // if there is a user id already but no token (user was linked at one point and then removed)
                            if (!user.google.token) {
                                user.google.token = token;
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
    )
  );
};
