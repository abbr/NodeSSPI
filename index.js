var fs = require('fs'),
  path = require('path');
var binding;

// Look for binary for this platform
var modPath = path.join(__dirname, 'bin', process.platform + '-' + process.arch, 'nodeSSPI');
try {
  fs.statSync(modPath + '.node');
  binding = require(modPath);
} catch (ex) {
  binding = require('bindings')('nodeSSPI');
}

/*
  opts:{
    offerSSPI: true|false,
    offerBasic: true|false,
    authoritative: true|false,
    omitDomain: false|true,
    usernameCase: 'lower'|'upper',
    perRequestAuth: false|true,
    maxLoginAttemptsPerConnection: 3,
    sspiPackagesUsed: ['NTLM'], // SSPI packages used
    domain: <string>, // used by basic authentication
  }
*/
function main(opts) {
  opts = opts || {};
  // defaults
  var defaultOpts = {
    offerSSPI: true,
    offerBasic: true,
    authoritative: true,
    omitDomain: false,
    usernameCase: 'lower',
    perRequestAuth: false,
    maxLoginAttemptsPerConnection: 3,
    sspiPackagesUsed: ['NTLM']
  };
  opts.__proto__ = defaultOpts;
  this.opts = opts;
}

main.prototype.authenticate = function (req, res, next) {
  if (this.opts.perRequestAuth) {
    delete req.connection.user;
  }
  try {
    binding.authenticate(this.opts, req, res);
  } catch (ex) {
    res.statusCode = 500;
    res.end();
  }
  if (!this.opts.authoritative || req.connection.user !== undefined) {
    next();
  } else {
    res.end();
  }
}

module.exports = main;