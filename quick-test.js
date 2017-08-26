var nodeSSPI = require('./index.js');
var next = {};
var req = {
  headers: {
    'authorization': 'BASIC dGVzdDp0ZXN0'
  },
  connection: {},
  isTestingNodeSSPI: true
};
var res = {
  setHeader: function() {},
  end: function() {}
};
var nodeSSPIObj = new nodeSSPI({
  'retrieveGroups': true
});
nodeSSPIObj.authenticate(req, res, function(err) {
  if (req.connection.userGroups && req.connection.userGroups.length > 0 && req.connection.userSid) {
    process.stdout.write('pass');
  }
});