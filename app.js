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
const md5 = require("md5")

const app = express()
app.use(BodyParser.urlencoded({extended:true}))

app.set('view engine','ejs')
app.use(express.static('public'))

mongoose.connect("mongodb://localhost:27017/secretDB",{ useNewUrlParser: true , useUnifiedTopology: true })

const secret_schema = new mongoose.Schema({
  user_id:String,
  password:String
})

//encryption of database with a secret key, password field is encrypted at the
// time of .save() and automatically decrypted at the time of .find()

//secret_schema.plugin(encrypt, { secret: process.env.SECRET_KEY , encryptedFields: ["password"] });

const secret = mongoose.model("secret",secret_schema)


app.get("/",function(req,res){
  res.render("home")
})

app.get("/login",function(req,res){
  res.render("login")
})

app.get("/register",function(req,res){
  res.render("register")
})

app.get("/submit",function(req,res){
  res.render("submit")
})

app.post("/register",function(req,res){

  const user_data = secret({
    user_id:req.body.username,
    password:md5(req.body.password)
  })

user_data.save(function(err){
  if(err){
    res.send(err)
  }
  else{
    res.render("secrets")
  }
})

})

app.post("/login",function(req,res){

  secret.findOne({user_id:req.body.username},function(err,found_data){
    if(err){
      res.send(err)
    }
    else{
      if(found_data){
        if(found_data.password === md5(req.body.password)){
          res.render("secrets")
        }
        else{
          //console.log("handled");
          res.send("password incorrect")
        }
      }
    }
  })
})




app.listen(3000,function(req,res){
  console.log("server up and running at port 3000");
})
