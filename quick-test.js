var nodeSSPI = require('./index.js');
var next = {};
var req = {
  headers: {
    'authorization': 'BASIC dGVzdDp0ZXN0'
  },
  connection: {},
  isTesting: true
};
var res = {
  setHeader: function () {},
  end: function () {}
};
var nodeSSPIObj = new nodeSSPI({
  'retrieveGroups': true
});
nodeSSPIObj.authenticate(req, res, function (err) {
  if (req.connection.userGroups.indexOf('\\Everyone') >= 0) {
    process.stdout.write('pass');
  }
});