var express = require('express')
var cookieParser = require('cookie-parser')
var auth = require('./auth')

var app = express()
app.use(cookieParser())

// User signs in by clicking link provided by auth.getAuthUrl
// and is redirected to '/' on success, or back to '/login' on failure
// TODO prevent user from being able to go to '/login' if they already
// have a valid token
app.get('/login', function (req, res) {
  res.send('Welcome to Outlook Authentication Test! <br /> <a href="' + auth.getAuthUrl() + '">Sign in with Outlook to see dorms</a>')
})

// '/dorms' and '/' are both protected pages that you need to be authenticated
// to access. This authenticates by using the auth.isAuthenticated middleware. Assume
// user is authenticated if the last function in the middleware chain is called.
// Unauthenticated users will be redirected to '/login'.
app.get('/dorms', auth.isAuthenticated, function (req, res) {
  // user is authenticated at this point
  var timeLeftUntilTokenExpires = Math.floor(Date.now() / 1000) - req.params.expiration
  res.send('<a href="/">home</a><br><a href="/dorms">dorms</a><br>Welcome ' + req.params.email + '<br>dorms here... <br>Number of seconds until token expires: ' + timeLeftUntilTokenExpires)
})

app.get('/', auth.isAuthenticated, function (req, res) {
  // user is authenticated at this point
  var timeLeftUntilTokenExpires = Math.floor(Date.now() / 1000) - req.params.expiration
  res.send('<a href="/">home</a><br><a href="/dorms">dorms</a><br>Welcome ' + req.params.email + '<br>homepage here... <br>Number of seconds until token expires: ' + timeLeftUntilTokenExpires)
})

var port = 8000
app.listen(port, function () {
  console.log('Running on port %s', port)
})
