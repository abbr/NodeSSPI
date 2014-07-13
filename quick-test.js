var nodeSSPI = require('./index.js');
var next = {};
var req = {
  headers: {},
  connection: {}
};
var res = {
  setHeader: function () {},
  end: function () {}
};
var nodeSSPIObj = new nodeSSPI({});
nodeSSPIObj.authenticate(req, res, function (err) {
  if (res.statusCode == 401) {
    process.stdout.write('pass');
  }
});