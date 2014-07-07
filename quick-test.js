var nodeSSPI = require('./index.js');
var next = {};
var req = {
  headers: {},
  connection: {}
};
var res = {
  setHeader: function () {},
  end: function(){}
};
var nodeSSPIObj = new nodeSSPI({});
nodeSSPIObj.authenticate(req, res, next);
if (res.statusCode == 401) {
  process.stdout.write('pass');
}