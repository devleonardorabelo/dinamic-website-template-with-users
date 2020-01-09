const express  = require('express'),
	  router   = express.Router(),
	  passport = require('passport');
	  
// AUTH CHECK
function isLoggedIn(req, res, next) {
	if (req.isAuthenticated())
		return next();
	res.redirect('/login');
}

// LOGIN 
router.get('/login', (req, res) => {
	res.render('login', { message: req.flash('loginMessage') });
});

// POST LOGIN
router.post('/login', passport.authenticate('local-login', {
	successRedirect : '/panel',
	failureRedirect : '/auth/login',
	failureFlash : true
}));

//SIGNUP 
router.get('/signup', (req, res) => {
	res.render('signup', { message: req.flash('signupMessage') });
});

// POST SIGNUP
router.post('/signup', passport.authenticate('local-signup', {
	successRedirect : '/panel',
	failureRedirect : '/auth/signup',
	failureFlash : true
}));
//LOGOUT
router.get('/logout', (req, res) => {
	req.logout();
	res.redirect('/auth/login');
});

//GOOGLE
router.get('/google', passport.authenticate('google', { scope : ['profile', 'email'] }));

router.get('/google/callback',
	passport.authenticate('google', {
		successRedirect : '/panel',
		failureRedirect : '/auth/login'
	})
);
module.exports = router