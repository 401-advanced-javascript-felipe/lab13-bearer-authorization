'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const usedToken = new Set();

const users = new mongoose.Schema({
  username: {type:String, required:true, unique:true},
  password: {type:String, required:true},
  email: {type: String},
  role: {type: String, default:'user', enum: ['admin','editor','user']},
});

users.pre('save', function(next) {
  bcrypt.hash(this.password, 10)
    .then(hashedPassword => {
      this.password = hashedPassword;
      next();
    })
    .catch(console.error);
});

users.statics.createFromOauth = function(email) {

  if(! email) { return Promise.reject('Validation Error'); }

  return this.findOne( {email} )
    .then(user => {
      if( !user ) { throw new Error('User Not Found'); }
      console.log('Welcome Back', user.username);
      return user;
    })
    .catch( error => {
      console.log('Creating new user');
      let username = email;
      let password = 'none';
      return this.create({username, password, email});
    });

};

users.statics.authenticateBasic = function(auth) {
  let query = {username:auth.username};
  return this.findOne(query)
    .then( user => user && user.comparePassword(auth.password) )
    .catch(error => {throw error;});
};

users.statics.authenticateBearer = function(token){
  if(usedToken.has(token)){
    return Promise.reject('invalid token');
  }
  console.log(token);
  let parsedToken = jwt.verify(token, process.env.SECRET);
  console.log(parsedToken);

  parsedToken.type !== 'key' && usedToken.add(token);

  let query = {_id: parsedToken.id};
  console.log(query);
  return this.findOne(query);

};

users.methods.comparePassword = function(password) {
  return bcrypt.compare( password, this.password )
    .then( valid => valid ? this : null);
};



users.methods.generateToken = function(type) {
  
  let token = {
    id: this._id,
    role: this.role,
    type: type || 'users'
  };

  let options = {};

  if(token.type === 'users'){
    options = {expiresIn: process.env.TIMEOUT};
  }  
  return jwt.sign(token, process.env.SECRET, options);
};


users.methods.generateKeyToken = function(type) {
  
  let token = {
    id: this._id,
    role: this.role,
    type: type || 'users'
  };
 
  return jwt.sign(token, process.env.SECRET);
};

module.exports = mongoose.model('users', users);
