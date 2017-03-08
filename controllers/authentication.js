const jwt = require('jsonwebtoken');
const config = require('../config');

function tokenForUser(user) {
    return jwt.sign({sub: user.id, iat: new Date().getTime()}, config.secrert);
}

const User = require('../models/user');

exports.signin = function (req, res, next) {
    //user has already had their email and password auth
    //we just need to give them token
    res.send({token: tokenForUser(req.user)});
}


exports.signup = function (req, res, next) {
    const email = req.body.email;
    const password = req.body.password;
    if(!email || !password) {
        return res.status(422).send({error: 'You must provide email and password'});
    }
    //See if a user with given email exists
    User.findOne({email}, (err, existingUser) => {
        if(err) {
            return next(err);
        }
        //if a user with email does exist. return an error
        if(existingUser){
            return res.status(422).send({error : 'Email is in use'});
        }
        //if a user with email doesnt exist, create and save user record
        const user = new User({
            email,
            password
        });
        user.save((err) => {
            if(err) {
                return next(err);
            }
            res.json({token: tokenForUser(user)});
        });
    });


    //Respond to request indicating the user was created
}