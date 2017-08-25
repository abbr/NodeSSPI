var fs = require('fs'),
	path = require('path');
var binding;

// Look for binary for this platform
var nodeV = 'node-' + /[0-9]+\.[0-9]+/.exec(process.versions.node)[0];
var nodeVM = 'node-' + /[0-9]+/.exec(process.versions.node)[0];
var modPath = path.join(__dirname, 'bin', process.platform + '-' + process.arch + '-' + nodeV, 'nodeSSPI');
try {
	try{
		fs.statSync(modPath + '.node');
	}
	catch(ex){
		modPath = path.join(__dirname, 'bin', process.platform + '-' + process.arch + '-' + nodeVM, 'nodeSSPI');
		fs.statSync(modPath + '.node');
	}
	binding = require(modPath);
}
catch (ex) {
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

main.prototype.authenticate = function (req, res, cb) {
  if (typeof cb !== 'function') {
    res.statusCode = 500;
    res.end('missing callback');
  }
  if (this.opts.perRequestAuth) {
    delete req.connection.user;
    delete req.connection.userSid;
    delete req.connection.userGroups;
  }
  binding.authenticate(this.opts, req, res, cb);
}

module.exports = main;