var LocalStrategy    = require('passport-local').Strategy,
    GoogleStrategy   = require('passport-google-oauth').OAuth2Strategy,
    User             = require('../models/user'),
    passport         = require('passport')

var configAuth = require('./authConfig'); //google IDs

passport.serializeUser(function(user, done) {
    done(null, user.id);
});
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});
// =========================================================================
// passport session setup ==================================================
// =========================================================================
// required for persistent login sessions
// passport needs ability to serialize and unserialize users out of session

// used to serialize the user for the session
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

// =========================================================================
// LOCAL LOGIN =============================================================
// =========================================================================
passport.use('local-login', new LocalStrategy({
    // by default, local strategy uses username and password, we will override with email
    usernameField : 'email',
    passwordField : 'password',
    passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
},
function(req, email, password, done) {

    // asynchronous
    process.nextTick(function() {
        User.findOne({ 'local.email' :  email }, function(err, user) {
            // if there are any errors, return the error
            if (err)
                return done(err);

            // if no user is found, return the message
            if (!user)
                return done(null, false, req.flash('loginMessage', 'Usuário não encontrado'));

            if (!user.validPassword(password))
                return done(null, false, req.flash('loginMessage', 'Senha incorreta'));

            // all is well, return user
            else
                return done(null, user);
        });
    });

}));

// =========================================================================
// LOCAL SIGNUP ============================================================
// =========================================================================
passport.use('local-signup', new LocalStrategy({
    // by default, local strategy uses username and password, we will override with email
    usernameField : 'email',
    passwordField : 'password',
    passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
},
async (req, email, password, done) =>  {

    //  Whether we're signing up or connecting an account, we'll need
    //  to know if the email address is in use.
    User.findOne({'local.email': email}, async (err, existingUser) => {

        // if there are any errors, return the error
        if (err)
            return done(err);

        // check to see if there's already a user with that email
        if (existingUser) 
            return done(null, false, req.flash('signupMessage', 'Este email já está em uso!'));

        //  If we're logged in, we're connecting a new local account.
            // create the user
            var emailPattern =  /^([a-zA-Z0-9_.+-])+\@(([a-zA-Z0-9-])+\.)+([a-zA-Z0-9]{2,4})+$/;
            var emailTest  = await emailPattern.test(email);
            if(emailTest === true){
                var newUser            = new User();

                newUser.local.email    = email;
                newUser.local.password = newUser.generateHash(password);

                newUser.save(function(err) {
                    if (err)
                        throw err;

                    return done(null, newUser);
                });    
            }else {
                return done(null, false, req.flash('signupMessage', 'Este email está imcompleto ou errado'));
            }
            
        

    });
}));


// =========================================================================
// GOOGLE ==================================================================
// =========================================================================

passport.use(new GoogleStrategy({
    clientID        : configAuth.googleAuth.clientID,
    clientSecret    : configAuth.googleAuth.clientSecret,
    callbackURL     : configAuth.googleAuth.callbackURL,

},
function(accessToken, refreshToken, profile, done) {
    User.findOne({ 'google.id' : profile.id }, function(err, user) {
        if (err)
            return done(err);
        if (user) {
            return done(null, user);
        } else {
            var newUser          = new User();

            newUser.google.id    = profile.id;
            newUser.google.name  = profile.displayName;
            newUser.google.email = profile.emails[0].value; // pull the first email

            newUser.save(function(err) {
                if (err)
                    throw err;
                return done(null, newUser);
            });
        }
    });
}
));