const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt');
//Define our model
const userSchema = new Schema({
    email: {type: String, unique: true, lowercase: true},
    password: String
});

//on save hook encrypt password
userSchema.pre('save', function(next) {
    const user = this;
    bcrypt.genSalt(10, (err, salt) => {
        if(err) {
            return next(err);
        }
        bcrypt.hash(user.password, salt, (err, hash) => {
           if(err){
               return next(err);
           }
           user.password = hash;
           next();
        });
    });
});

userSchema.methods.comparePassword = function (candidatepassword, callback) {
    bcrypt.compare(candidatepassword, this.password, function (err, isMatch) {
        if(err) {
            return callback(err);
        }
        callback(null, isMatch);
    });
}

//Create the model class
const ModelClass = mongoose.model('user', userSchema);

//Export the model
module.exports = ModelClass;

