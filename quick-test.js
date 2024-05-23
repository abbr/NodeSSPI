/* eslint-disable */


const nodeSSPI = require('./index.js');
const next = {};
const req = {
  headers: {
    authorization: 'BASIC dGVzdDp0ZXN0'
  },
  connection: {},
  isTestingNodeSSPI: true
};
const res = {
  setHeader() {},
  end() {}
};
const nodeSSPIObj = new nodeSSPI({
  retrieveGroups: true
});
nodeSSPIObj.authenticate(req, res, (err) => {
  if (req.connection.userGroups && req.connection.userGroups.length > 0 && req.connection.userSid) {
    process.stdout.write('pass');
  }
});
