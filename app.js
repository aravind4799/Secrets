//jshint esversion:6

require('dotenv').config()

//using dotenv to keep private data ,such as api keys ,encryption keys etc
//setup a .env file and access these variables from it using process.env
//dont forget to add this to gitignore else all ur work is just a joke,,
//better to copy the default template from github gitignore for node
//touch .env .gitignore
//ls -a reveals this hidden files

const express = require("express")
const BodyParser = require("body-parser")
const mongoose = require("mongoose")
const ejs = require("ejs")

//to perform encryption
//const encrypt = require("mongoose-encryption")

//to perform hashing
//const md5 = require("md5")

//to perform hashing using bcrypt hashing,includes salting
//const bcrypt = require("bcrypt")
//const saltRounds = 10

//using passport , passport-local ,passport-localmongoose ,express-session
//to perform authentication---hashing and salting

const passport = require("passport")
const session = require("express-session")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy
const FacebookStrategy = require('passport-facebook').Strategy
//to implement findOrCreate
const findOrCreate = require('mongoose-findorcreate')

const app = express()
app.use(BodyParser.urlencoded({extended:true}))

app.set('view engine','ejs')
app.use(express.static('public'))

//let app use the package session
app.use(session({
  secret: process.env.SECRET_KEY,
  resave: false,
  saveUninitialized: false
}))

//initialize passport
app.use(passport.initialize())
//and let passport handle session
app.use(passport.session())

mongoose.connect("mongodb://localhost:27017/secretDB",{ useNewUrlParser: true , useUnifiedTopology: true })
mongoose.set('useCreateIndex', true);

const secret_schema = new mongoose.Schema({
  username:String,
  password:String,
  googleId:String,
  facebookId:String,
  secret:String
})

//passportLocalMongoose is the package we are using to hash and salt passwords and store it into database
secret_schema.plugin(passportLocalMongoose);
//in order to use mongoose-findOrCreate
secret_schema.plugin(findOrCreate);

//encryption of database with a secret key, password field is encrypted at the
// time of .save() and automatically decrypted at the time of .find()

//secret_schema.plugin(encrypt, { secret: process.env.SECRET_KEY , encryptedFields: ["password"] });

const secret = mongoose.model("secret",secret_schema)

//  CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
//default local
passport.use(secret.createStrategy());
// use static serialize and deserialize of model for passport session support
//serialize is a process of setting up cookie containing user identification data
//this comes from passportLocalMongoose
//passport.serializeUser(secret.serializeUser());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

//deserialize is a process of breaking the cookie -- and getting the data in it
//this comes from passportLocalMongoose
//passport.deserializeUser(secret.deserializeUser());
passport.deserializeUser(function(id, done) {
  secret.findById(id, function(err, user) {
    done(err, user);
  });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    //to solve the google+ deprication
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    secret.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    secret.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



app.get("/",function(req,res){
  res.render("home")
})


app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] }));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secret');
  });


  app.get('/auth/facebook',
    passport.authenticate('facebook'));

  app.get('/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secret');
    });



app.get("/login",function(req,res){
  res.render("login")
})

app.get("/register",function(req,res){
  res.render("register")
})

app.get("/submit",function(req,res){
  res.render("submit")
})

app.get("/secret",function(req,res){
  //select all the secrets if its not null from collection to display
  secret.find({"secret":{$ne: null}} ,function(err,found_data){
    if(!err){
        res.render("secrets",{user_secrets:found_data})
    }
    else{
      console.log(err);
    }
  })
})

app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit")
  }
  else{
    res.render("/login")
  }
})

app.get("/logout",function(req,res){
  //logout is method from passport
  //it ends the user session
  //when ever he server is restarted the session and cookie is deleted
  req.logout()

  res.redirect("/")
})

app.post("/submit",function(req,res){
  //contains the details of the current user in the session
  //console.log(req.user);
  secret.findById(req.user.id,function(err,found_data){
    if(err){
      console.log(err);
    }
    else{
      if(found_data){
        found_data.secret = req.body.secret
        found_data.save(function(err){
          if(!err){
            res.redirect("/secret")
          }
        })
      }
    }
  })
})
app.post("/register",function(req,res){
console.log(req.body.username);
console.log(req.body.password);
//register is a function from passportLocalMongoose
// adds the username salt and hash into database -for password entered
//username is defaultb key
  secret.register({username:req.body.username},req.body.password,function(err,secret){
    if(err){
      console.log(secret);
      console.log(err);
      res.redirect("/")
    }
    else{
      //if authentication is successful then we established a session which lasts until the user
      //closes the browser and can tap into /secret route in the session with the help on cookie
      //generated

      //creates a local session
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secret")
      })
    }
  })
})

app.post("/login", function(req, res) {

  const new_user = secret({
    username:req.body.username,
    password:req.body.password
  })

  //login is a function from passport package used to check if given user_id is found in DB
  req.login(new_user,function(err){
    if(err){
      console.log(err);
      res.redirect("/")
    }
    else{
      //authenticate the user
      //create a cookie with a local session_id
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secret")
      })
    }
  })

});



app.listen(3000,function(req,res){
  console.log("server up and running at port 3000");
})
