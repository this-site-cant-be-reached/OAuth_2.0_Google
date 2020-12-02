//jshint esversion:6
//----------------------  require seccion ------------------- //
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose'); // this will salt and hash the password in the background without needing to apply a code for it 
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
//----------------------  Fin de require seccion ------------------- //

// ---- reference to implement express to our app ----------- //
const app = express();


// ------------- Things to use in our app  interacting with our require packages xD ---------// 
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));


//So ... first we tell our app to use the session package that we required in declaration seccion
// And we set it up with some initial configurations xD 
app.use(session({
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: false,
}));

//Next we tell our app to use passport and initialize the passport package and also use passport to dealing we the sessions xD
app.use(passport.initialize());
app.use(passport.session());

// ----------------------- End of the "use things" for our methods ------------- //


// ----------- connect with our database that is in a specific port for itself -------------
mongoose.connect("mongodb://localhost:27017/userDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true

});
mongoose.set("useCreateIndex", true);

// ----------- The Schema that we will implement in our User model xD ---------
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});


//In order to it to have a plugin we have to declarate our schema in a mongoose schema as above
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Mongoose model
const User = new mongoose.model("User", userSchema);

//We have to use this serialize and deserialize our user
//This is only necessary when we are using sessions 
//What it does is when we tell it to serialize our user it basically creates the cookie and stuffs the messsage namely our user identifications into the cookie
//And then we deserialize basically allows passports to be able to crumble that cookie and discover the message inside which is who this user is and all of the identification xD
//So we this we can authenticate them on our server 
//Normally if are just using passport and passport local  we will have to write a lot more code but because we are using passport-local-mongoose it's gonna take care a lot of that in between code for us   
passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));


app.get("/", function (req, res) {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect to secrets.
        res.redirect("/secrets");
    });

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
    User.find({ "secret": { $ne: null } }, function (err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", { usersWithSecrets: foundUsers });
            }
        }
    });
});

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;

    //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
    // console.log(req.user.id);

    User.findById(req.user.id, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function () {
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/");
});

app.post("/register", function (req, res) {

    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });

});

app.post("/login", function (req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });

});







app.listen(3000, function () {
    console.log("Server started on port 3000.");
});
