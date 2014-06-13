var fs = require('fs'), path = require('path');
var binding;

// Look for binary for this platform
var modPath = path.join(__dirname, 'bin', process.platform+ '-'+ process.arch, 'nodeSSPI');
try {
	fs.statSync(modPath+ '.node');
	binding = require(modPath);
} catch (ex) {
	binding = require('bindings')('nodeSSPI');
}

function main(opts) {
  this.opts = opts;
}

main.prototype.sayHello = function(){
  console.log(this.opts.name + " " +  binding.hello());
}

module.exports = main;
