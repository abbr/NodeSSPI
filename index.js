var fs = require('fs'),
  path = require('path');
var binding;

// Look for binary for this platform
var v8 = 'v8-' + /[0-9]+/.exec(process.versions.v8)[0];
var modPath = path.join(__dirname, 'bin', process.platform + '-' + process.arch + '-' + v8, 'nodeSSPI');
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
    perRequestAuth: false|true,
    retrieveGroups: false|true, // whether to retrieve groups upon successful auth
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
    perRequestAuth: false,
    retrieveGroups: false,
    maxLoginAttemptsPerConnection: 3,
    sspiPackagesUsed: ['NTLM']
  };
  opts.__proto__ = defaultOpts;
  this.opts = opts;
}

main.prototype.authenticate = function (req, res) {
  if (this.opts.perRequestAuth) {
    delete req.connection.user;
  }
  try {
    binding.authenticate(this.opts, req, res);
  } catch (ex) {
    if (this.opts.authoritative) {
      res.end(ex);
      return;
    } else {
      return ex;
    }
  }
  if (this.opts.authoritative && req.connection.user === undefined) {
    res.end();
  }
}

module.exports = main;