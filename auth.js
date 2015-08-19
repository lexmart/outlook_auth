var url = require('url')
var jwt = require('jsonwebtoken')

// You can get these credentials at https://apps.dev.microsoft.com/
// TODO should be put in secret file
var oauth2 = require('simple-oauth2')({
  clientID: 'f64af141-67cb-4212-b088-143196fb6121',
  clientSecret: 'Kgqd1YG2SiqFW3TKkJZ5HKi',
  site: 'https://login.microsoftonline.com/common',
  authorizationPath: '/oauth2/v2.0/authorize',
  tokenPath: '/oauth2/v2.0/token'
})

// This is page where user will be redirected upon successful authentication.
// TODO have redirect_uri setup dynamically based on what the last page before
// going to '/login' was
var redirect_uri = 'http://localhost:8000/'

// The OAuth authorization we need from Microsoft. This app doesn't actually use openid, but we need to provide at least one scope.
var scope = 'openid'

// Returns URL to Microsoft for user to login.
// If login successful, redirected to 'redirect_uri' as a GET request
// the request will include a paramater 'code' (this is the authentication code)
// Not sure when the authUrl expires, might be security issue.
exports.getAuthUrl = function () {
  return oauth2.authCode.authorizeURL({
    redirect_uri: redirect_uri,
    scope: scope
  })
}

// Takes authentication code and a callback for once code has been authenticated
// If the authentication code is valid, it will call the callback and pass it
// an OAuth token (we will not use this token for authentcation, we only need it to
// to get the user's email). Otherwise it calls callback with error.
exports.validateAuthCode = function (authCode, callback) {
  oauth2.authCode.getToken({
    code: authCode,
    redirect_uri: redirect_uri,
    scope: scope
  }, function (err, result) {
    if (err) {
      callback(err)
    } else {
      var token = oauth2.accessToken.create(result)
      callback(null, token)
    }
  })
}

// Takes an OAuth token (returned from the function above) and returns the email
// of the token owner.
exports.getEmailFromOauthToken = function (token) {
  var token_parts = token.split('.')
  var encoded_token = new Buffer(token_parts[1].replace('-', '_').replace('+', '/'), 'base64')
  var decoded_token = encoded_token.toString()
  var jwt = JSON.parse(decoded_token)
  return jwt.preferred_username
}

// Secret key used to generate internal JWT
var secretKey = 'grinnell!'

// Generates an internal JWT. We use this JWT for further authentication instead of
// authenticating through Micosoft. User will have to re-authenticate through
// Microsoft to get another internal JWT once this token expires.
exports.generateJWT = function (email) {
  var payload = {
    email: email
  }
  var options = {
    expiresInSeconds: 30
  }
  return jwt.sign(payload, secretKey, options)
}

// Takes a JWT and verifies that the JWT is valid and has not expired.
exports.verifyJWT = function (token, callback) {
  jwt.verify(token, secretKey, function (err, decoded) {
    if (err) {
      callback(err)
    } else if (!decoded) {
      callback(null, false)
    } else {
      callback(null, true)
    }
  })
}

// Middleware that prevent unauthorized attempts to access protected web pages.
exports.isAuthenticated = function (req, res, next) {
  // Tries to get authentication code or token
  var authCode = url.parse(req.url, true).query.code
  var token = req.cookies['jwt']

  // Takes an authentication code and validates it. If the authCode is valid, it creates an internal JWT. Then it sends the JWT as a cookie, as well as the user email and token expiration time.
  function handleAuthCode (authCode) {
    exports.validateAuthCode(authCode, function (err, oauthToken) {
      // If token is not valid, redirect to '/login'
      if (err) res.redirect('/login')
      var email = exports.getEmailFromOauthToken(oauthToken.token.id_token)
      token = exports.generateJWT(email)

      var decoded = jwt.decode(token)
      req.params.email = decoded.email
      req.params.expiration = decoded.exp
      res.cookie('jwt', token)

      // Can assume that user is authentiacted in next handler
      next()
    })
  }

  if (!token) {
    if (!authCode) {
      // There is no JWT cookie, and no authCode is presented in url.
      res.redirect('/login')
    } else {
      // There is no JWT cookie, but an authCode is presented.
      // We need to check if authCode is valid, save a jwt cookie if it is valid, and do appropriate redirects.
      handleAuthCode(authCode)
    }
  } else {
    // A JWT cookie is presented, lets verify that its valid.
    exports.verifyJWT(token, function (err, result) {
      if (err || !result) {
        // JWT is invalid (it might have expired), lets check if an authCode was
        // presented.
        if (!authCode) {
          // Authcode not presented and JWT is invalid, user needs to login
          res.redirect('/login')
        } else {
          // Authcode is presented and JWT is invalid, lets verify the authCode
          handleAuthCode(authCode)
        }
      } else {
        // JWT is valid. Decode the token to get necessary params and go to the next
        // handler.
        var decoded = jwt.decode(token)
        req.params.email = decoded.email
        req.params.expiration = decoded.exp

        // Can assume that user is authentiacted in next handler
        next()
      }
    })
  }
}
