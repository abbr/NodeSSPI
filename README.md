NodeSSPI
========

NodeSSPI to Node.js is what [mod-auth-sspi](https://code.google.com/p/mod-auth-sspi/) to Apache HTTPD. In a nutshell NodeSSPI authenticates incoming HTTP(S) requests through native Windows SSPI, hence **NodeSSPI runs on Windows only**.

## Background
Organizations using Microsoft Active Directory for enterprise-wide identity management often rely on NTLM and Kerberos - collectively known as Windows authentication, as Single-Sign-On (SSO) solution to secure various corporate web sites. Windows authentication also offers the convenience of transparent authentication by default for browsers such as Internet Explorer and Google Chrome when running on corporate Windows computers configured by group policy.

Arguably the most popular web server that supports Windows authentication is IIS. Apache HTTPD with module mod-auth-sspi is also a common choice, especially when used as reverse proxy (r-proxy). For Node.js to be useful in such enterprise environment, it is necessary to put Node.js behind one of these web servers to rely on them handling authentication. But this infrastructural layout defeated the design benefits of Node.js - a high performance non-blocking I/O web server more suitable acting as r-proxy than other servers mentioned in front of it.

This paradox has been impeding adoption of Node.js to the enterprise world, until the advent of NodeSSPI.

## Description

NodeSSPI, written mostly in C++, is modeled after mod-auth-sspi to perform Windows authentication through native Windows SSPI. NodeSSPI also supports Basic authentication against underlying Active Directory (for domain servers only) and local users (for domain and non-domain servers). After successful authentication, NodeSSPI can optionally retrieve a list of groups the user belongs to, facilitating downstream middleware to perform authorization.

Despite of the resemblance, NodeSSPI is not an exact feature-wize like-for-like porting of mod-auth-sspi. This is partially because, unlike Apache, which is customizable mostly through configuration, Node.js is customizable through JavaScript which offers much more flexibility.

## Usages
### Overview
Following code illustrates how to add NodeSSPI to the request processing pipeline. Although the code requires Express.js, NodeSSPI doesn't have to be run under the context of Express.js. In fact, at runtime it has no npm module dependencies.

```javascript
'use strict'

var express = require('express')
var app = express()
var server = require('http').createServer(app)
app.use(function (req, res, next) {
  var nodeSSPI = require('node-sspi')
  var nodeSSPIObj = new nodeSSPI({
    retrieveGroups: true
  })
  nodeSSPIObj.authenticate(req, res, function(err){
    res.finished || next()
  })
})
app.use(function(req, res, next) {
  var out =
    'Hello ' +
    req.connection.user +
    '! Your sid is ' +
    req.connection.userSid +
    ' and you belong to following groups:<br/><ul>'
  if (req.connection.userGroups) {
    for (var i in req.connection.userGroups) {
      out += '<li>' + req.connection.userGroups[i] + '</li><br/>\n'
    }
  }
  out += '</ul>'
  res.send(out)
})
// Start server
var port = process.env.PORT || 3000
server.listen(port, function () {
  console.log('Express server listening on port %d in %s mode', port, app.get('env'))
})
```
If you put above code in a file, say *index.js*, and run following commands from the same directory:
```shell
npm install node-sspi
npm install express
node index.js
```
then open [http://localhost:3000](http://localhost:3000) and login with your Windows account if prompted, you will see something like
```
Hello <mypc>\<me>! Your sid is S-*-*-**-**********-**********-**********-**** and you belong to following groups:
*<mypc>\None
*\Everyone
*<mypc>\HelpLibraryUpdaters
*BUILTIN\Administrators
*BUILTIN\Users
*NT AUTHORITY\NETWORK
*NT AUTHORITY\Authenticated Users
*NT AUTHORITY\This Organization
*NT AUTHORITY\NTLM Authentication
*Mandatory Label\High Mandatory Level

```

### Inputs

The call to `new nodeSSPI(opts)` in above code can take following options:
  * offerSSPI: true|false 
      - default to *true*. Whether to offer SSPI Windows authentication
  * offerBasic: true|false 
      - default to *true*. Whether to offer Basic authentication
  * authoritative: true|false 
      -  default to *true*. Whether authentication performed by NodeSSPI is authoritative. If set to *true*, then requests passed to downstream are guaranteed to be authenticated because non-authenticated requests will be blocked. If set to *false*, there is no such guarantee and downstream middleware have the chance to override outputs from NodeSSPI and impose their own rules.
  * perRequestAuth: false|true 
      - default to *false*. Whether authentication should be performed at per request level or per connection level. Per connection level is preferred to reduce overhead.
  * retrieveGroups: false|true 
      - default to *false* for performance sake. Whether to retrieve groups upon successful authentication. See [caveats](#caveats) below.
  * maxLoginAttemptsPerConnection: &lt;number&gt;
      - default to *3*. How many login attempts are permitted for this connection.
  * sspiPackagesUsed: &lt;array&gt;
      - default to *['NTLM']*. An array of SSPI packages used. To obtain a list of all SSPI packages available on your server, download source code of [mod-auth-sspi](https://code.google.com/p/mod-auth-sspi/source/checkout), then run *bin\sspikgs.exe* from your server's DOS console. 
  * domain: &lt;string&gt;
      - no default value. This is the domain name (a.k.a realm) used by basic authentication if user doesn't prefix their login name with *&lt;domain_name&gt;\\*. 

### Outputs
  * upon successful authentication
    * authenticated user name is populated into field `req.connection.user`
    * authenticated user sid is populated into field `req.connection.userSid` 
    * if option `retrieveGroups` is *true*, group names are populated into field `req.connection.userGroups` as an array.
  * otherwise
    * if option `authoritative` is set to *true*, then the request will be blocked. The reason of blocking (i.e. error message) is written to response body as well as the *err* parameter of the callback function. Some response headers such as *WWW-Authenticate* may get filled out, and one of following HTTP response codes will be populated to field `res.statusCode`:
      * 403 if max login attempts are reached
      * 401 for all in-progress authentications, including protocols that require multiple round trips or if max login attempts has not been reached.
      * 500 when NodeSSPI encountered exception it cannot handle.
    * if option `authoritative` is not set to *true*, then the output is the same as authoritative except NodeSSPI will not write error message to response body, nor block the request, i.e. it will not call `res.end(err)`. This allows the caller and downstream middleware to make decision.

## Platforms
NodeSSPI has been tested working on these Windows platforms:

  * Windows Vista x32
  * Windows 7 x64
  * Windows Server 2008 R2

Platforms older than Windows 2000 are unlikely to work. Other platforms may work but haven't been tested.

## Caveats
  * Microsoft provides a number of SSPI [packages](http://msdn.microsoft.com/en-us/library/windows/desktop/aa380502\(v=vs.85\).aspx). So far only NTLM and Negotiate have been tested working. Kerberos is not working. Contribution is encouraged.
  * Because basic authentication has not standarized on character encoding and browser implementation varies, if your AD supports non-ASCII user name and password, it is advised to turn off basic authentication unless you can assume all client browsers use utf-8 encoding as Chrome does. See this [stackoverflow question](http://stackoverflow.com/questions/702629/utf-8-characters-mangled-in-http-basic-auth-username) for details.
  * It has been [reported](https://github.com/abbr/NodeSSPI/issues/23) that enabling *retrieveGroups* could take a heavy toll on AD domain controller in some circumstances. As an alternative, using a LDAP module that supports group filtering may improve performance.

## Installation
Prerequisites: Except on a few [ platforms + Node version combinations](https://github.com/abbr/NodeSSPI-bin) where binary distribution is included, NodeSSPI uses node-gyp to compile C++ source code so you may need the compilers listed in [node-gyp](https://github.com/TooTallNate/node-gyp). You may also need to [update npm's bundled node gyp](https://github.com/TooTallNate/node-gyp/wiki/Updating-npm's-bundled-node-gyp).

To install, run 
```npm install node-sspi```

## Development
Prerequisites: Visual Studio 2017

Run:

```shell
git clone git@github.com:abbr/NodeSSPITest.git NodeSSPI
cd NodeSSPI
npm install
cd node_modules
git clone git@github.com:abbr/NodeSSPI.git node-sspi
cd node-sspi
npm install --debug
node ..\..\server.js
```

To debug, open NodeSSPI.sln in VS2017 and attach to node.js process. 


## Support
Pull requests and issue reporting are welcome. For issues to be considered by maintainer:
  1. they must be reproducible.
  2. there must be evidence the issue is related to NodeSSPI.

To that end, the issue should contain platform information, error message relevant to NodeSSPI, and preferably code snippet. If code snippet is supplied, it must be self-contained, i.e. independent from your runtime environment or other modules not explictly specified via `require` in the code snippet.

## License

The MIT License (MIT)

Copyright (c) 2014-present, @abbr

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
