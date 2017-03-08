const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JWTStrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

 //Create local strategy
const localOptions = { usernameField: 'email'};
const localLogin = new LocalStrategy(localOptions, function (email, password, done) {
    //verify this username and password, call done with user
    //otherwise call done with false
    User.findOne({email}, (err,user) => {
        if(err) {
            return done(err);
        }
        if(!user) {
            return done(null, false);
        }

        //compare passwords
        user.comparePassword(password, function (err, isMatch) {
            if(err) {
                return done(err);
            }
            if(!isMatch) {
                return done(null, false);
            }

            return done(null, user);
        });
    })
})


//setup options for JWT strategy
const jwtOptions = {
    jwtFromRequest: ExtractJWT.fromHeader('authorization'), //Gettin token
    secretOrKey: config.secrert  //Secret key to be used to decode
};

//Create JWT strategy
const jwtLogin = new JWTStrategy(jwtOptions, function (payload, done) {
    // See if the user ID in the payload exists in our database
    //If it does, call 'done' with that other
    //otherwise, call done without a user object
    User.findById(payload.sub, function (err, user) {
        if(err) {
            return done(err, false);
        }
        if(user) {
            done(null, user);
        } else {
            done(null, false);
        }
    });

});

//Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);