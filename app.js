//jshint esversion:6
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const _ = require("lodash");
const bcrypt = require('bcrypt');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const session = require("express-session");
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const findOrCreate = require('mongoose-findorcreate')


const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
    secret: 'Our Little Secret',
    resave: false,
    saveUninitialized: false

}));
app.use(passport.initialize());
app.use(passport.session());
// mongoose.set('strictQuery', false);
mongoose.connect("mongodb://127.0.0.1:27017/UserDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId:String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = mongoose.model("User", userSchema);
passport.use(User.createStrategy());


passport.serializeUser(function (user, done) { done(null, user) });
passport.deserializeUser(function (user, done) { done(null, user) });
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback: true
},
    function (request, accessToken, refreshToken, profile, done) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return done(err, user);
        });
    }
));
app.get("/", function (req, res) {
    res.render("home");
})
app.get('/auth/google',
    passport.authenticate('google', {
        scope:
            ['email', 'profile']
    }
    ));
app.get("/auth/google/secrets",
    passport.authenticate('google', {
        successRedirect: '/auth/google/secrets',
        failureRedirect: '/auth/google/login'
    }))
app.get("/login", function (req, res) {
    res.render("login");
})
app.get("/register", function (req, res) {
    res.render("register");
})
app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {

        res.render("secrets");
    }
    else {
        res.redirect("/login");
    }
})
app.get("/logout", function (req, res, next) {
    req.logout(function (err) {
        if (err) { return next(err); }
        res.redirect("/");
    });
});
app.post("/register", function (req, res) {
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        }
        else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            })
        }
    })


})
app.post("/login", function (req, res) {
    const user = new User({
        username: req.body.username,
        username: req.body.password,
    })
    req.login(user, function (err) {
        if (err) {
            console.log(err);

        }
        else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            })
        }

    })

})
app.listen(3000, function () {
    console.log("Server is started at port 3000");
});
