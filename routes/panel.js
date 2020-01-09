const express = require('express'),
      router  = express.Router(),
      local   = require('../config/passport')
      
async function verifyUser(req, res, next) {
    if(req.user){
        next()
    }else{
        return res.redirect('/auth/login')
    }
}
router.get('/', verifyUser, (req, res) => {
    res.render('panel/home', {
        user: req.user
    })
})
module.exports = router