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
    basicPreferred: false|true,
    authoritative: true|false,
    usernameCase: 'lower'|'upper',
    perRequestAuth: true|false,
    domain: <string>, // used by basic authentication
    omitDomain: false|true,
  }
*/
function main(opts) {
  // defaults
  var defaultOpts = {
    offerSSPI: true,
    offerBasic: true,
    basicPreferred: false,
    authoritative: true,
    omitDomain: false,
    usernameCase: 'lower',
    perRequestAuth: true
  };
  opts.__proto__ = defaultOpts;
  this.opts = opts;
}

main.prototype.authenticate = function (req, res, next) {
  if (!this.opts.authoritative || req.user !== undefined) {
    next();
  } else {
    res.end();
  }
}

module.exports = main;