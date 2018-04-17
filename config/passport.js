var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var User = require('../models/user');
var Car = require('../models/user_car');
var configAuth = require('./auth');

module.exports = function(passport) {

  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      if (user)
        done(err, user);
      else
          Car.findById(id, function(err, user) {
            done(err,user);
          });

      });
  });

  passport.use('local-signup', new LocalStrategy({
            usernameField: 'email',
            passwordField: 'password',
            nameField: 'tname',
            publickey: 'pub',
            handle: 'han',
            passReqToCallback: true,
        },
        function(req, email, password,tname,publickey,handle, done) {
            process.nextTick(function() {
                User.findOne({ 'local.email':  email }, function(err, user) {
                    if (err)
                        return done(err);
                    if (user) {
                        return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
                    } else {
                        var newUser = new User();
                        newUser.local.email = email;
                        newUser.local.password = newUser.generateHash(password);
                        newUser.local.name= tname;
                        newUser.local.publickey.push(publickey);
                        newUser.local.handle.push(handle);

                        newUser.save(function(err) {
                            if (err)
                                throw err;
                            Car.findOne({ 'local.email':  tname }, function(err, user) {
                                if (err)
                                    return done(err);
                                if (user){
                                    user.local.publickey=user.local.publickey.concat([req.body.pub]);
                                    user.local.handle= user.local.handle.concat([req.body.han]);

                                    user.save(function(err) {
                                        if (err)
                                            throw err;

                                    });
                                }

                                else{
                                  var newCar = new Car();
                                    newCar.local.email = tname;
                                    newCar.local.password = newUser.generateHash(tname);
                                    newCar.local.name= tname;
                                    newCar.local.publickey.push(publickey);
                                    newCar.local.handle.push(handle);
                                  newCar.save(function(err) {
                                    if (err)
                                        throw err;});

                                }
                            });
                            return done(null, newUser);
                        });
                    }
                });
            });
        }));
  passport.use('local-add', new LocalStrategy({
            usernameField: 'email',
            passwordField: 'password',
            nameField: 'tname',
            publickey: 'pub',
            handle: 'han',
            passReqToCallback: true,
        },
        function(req, email, password,tname,publickey,handle, done) {
            process.nextTick(function() {
                User.findOne({ 'local.email':  email }, function(err, user) {
                    if (err)
                        return done(err);
                    if (!user)
                        return done(null, false, req.flash('loginMessage', 'No user found.'));
                    else {
                        console.log("OOOOOOOOOOO"+JSON.stringify("user.local"));
                        user.local.publickey.push(publickey);
                        user.local.handle.push(handle);

                        return done(null, user);

                    }
                });
            });
        }));

  passport.use('local-login', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
	publickey: 'pub',
	handle: 'han',
    passReqToCallback: true,
  },
  function(req, email, password,tname,publickey,handle, done) {
    User.findOne({ 'local.email':  email }, function(err, user) {
      if (err)
          return done(err);
      if (!user)
          return done(null, false, req.flash('loginMessage', 'No user found.'));
      if (!user.validPassword(password))
          return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));
	  
      return done(null, user);
    });
  }));

    passport.use('local-bmw', new LocalStrategy({
            usernameField: 'email',
            passwordField: 'password',
            publickey: 'pub',
            handle: 'han',
            passReqToCallback: true,
        },
        function(req, email, password,tname,publickey,handle, done) {
            Car.findOne({ 'local.email':  email }, function(err, user) {
                if (err)
                    return done(err);
                if (!user)
                    return done(null, false, req.flash('loginMessage', 'No car found.'));
                if (!user.validPassword(password))
                    return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));

                return done(null, user);
            });
        }));
    passport.use('local-auth', new LocalStrategy({
            usernameField: 'email',
            passwordField: 'password',
            publickey: 'pub',
            handle: 'han',
            passReqToCallback: true,
        },
        function(req, email, password,tname,publickey,handle, done) {
        console.log("aaaaaaaaassss"+handle);
            User.findOne({ 'local.handle': handle }, function(err, user) {
                if (err)
                    return done(err);
                if (!user)
                    return done(null, false, req.flash('loginMessage', 'No user found.'));
              // console.log("kappa");
                return done(null, user);
            });
        }));
  passport.use(new FacebookStrategy({
    clientID: configAuth.facebookAuth.clientID,
    clientSecret: configAuth.facebookAuth.clientSecret,
    callbackURL: configAuth.facebookAuth.callbackURL,
    profileFields: ['id', 'email', 'first_name', 'last_name'],
  },
  function(token, refreshToken, profile, done) {
    process.nextTick(function() {
      User.findOne({ 'facebook.id': profile.id }, function(err, user) {
        if (err)
          return done(err);
        if (user) {
          return done(null, user);
        } else {
          var newUser = new User();
          newUser.facebook.id = profile.id;
          newUser.facebook.token = token;
          newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
          newUser.facebook.email = (profile.emails[0].value || '').toLowerCase();

          newUser.save(function(err) {
            if (err)
              throw err;
            return done(null, newUser);
          });
        }
      });
    });
  }));

  passport.use(new TwitterStrategy({
    consumerKey: configAuth.twitterAuth.consumerKey,
    consumerSecret: configAuth.twitterAuth.consumerSecret,
    callbackURL: configAuth.twitterAuth.callbackURL,
  },
  function(token, tokenSecret, profile, done) {
    process.nextTick(function() {
      User.findOne({ 'twitter.id': profile.id }, function(err, user) {
        if (err)
          return done(err);
        if (user) {
          return done(null, user);
        } else {
          var newUser = new User();
          newUser.twitter.id          = profile.id;
          newUser.twitter.token       = token;
          newUser.twitter.username    = profile.username;
          newUser.twitter.displayName = profile.displayName;
          newUser.save(function(err) {
            if (err)
             throw err;
            return done(null, newUser);
          });
        }
      });
    });
  }));

  passport.use(new GoogleStrategy({
    clientID: configAuth.googleAuth.clientID,
    clientSecret: configAuth.googleAuth.clientSecret,
    callbackURL: configAuth.googleAuth.callbackURL,
  },
    function(token, refreshToken, profile, done) {
      process.nextTick(function() {
        User.findOne({ 'google.id': profile.id }, function(err, user) {
          if (err)
            return done(err);
          if (user) {
            return done(null, user);
          } else {
            var newUser = new User();
            newUser.google.id = profile.id;
            newUser.google.token = token;
            newUser.google.name = profile.displayName;
            newUser.google.email = profile.emails[0].value;
            newUser.save(function(err) {
              if (err)
                throw err;
              return done(null, newUser);
            });
          }
        });
      });
    }));

};
