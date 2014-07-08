NodeSSPI
========

NodeSSPI to Node.js is what [mod-auth-sspi](https://code.google.com/p/mod-auth-sspi/) to Apache HTTPD. In a nutshell NodeSSPI authenticates incoming HTTP(S) requests through native Windows SSPI, hence **NodeSSPI runs on Windows only**.

## Background
Organizations using Microsoft Active Directory for identity management often rely on NTLM and Kerberos - collectively known as Windows authentiaton, as Single-Sign-On (SSO) solution to secure various corporate web sites. Windows authentication also offers the convinence of transparent authentication by default for browsers such as Internet Explorer and Google Chrome when running on corporate Windows computers configured by group policy.

Arguably the most popular web server that supports Windows authentication is IIS. Apache HTTPD with module mod-auth-sspi is also a common choice, especially when used as reverse proxy (r-proxy). For Node.js to be useful in such enterprise environment, it is necessary to put Node.js behind one of these web servers to rely on the r-proxies handling authentication. But this infrastructural layout defeated the design benefits of Node.js - a high performance non-blocking I/O web server ideally acting as forefront r-proxy by itself.

This paradox has been impeding adoption of Node.js to the enterprise world, until the advent of NodeSSPI.

## Description

NodeSSPI, written mostly in C++, is modeled after mod-auth-sspi to perform Windows authentication through native Windows SSPI. NodeSSPI also supports Basic authentication against underlying Active Directory (for domain servers only) and local users (for domain and non-domain servers). After successful authencation, NodeSSPI can optionally retrieve a list of groups the user belongs to, facilitating downstream middleware to perform authorization.

Despite the resemblance, NodeSSPI is not a like-for-like porting of mod-auth-sspi. This is partially because, unlike Apache, which is customizable mostly through configuration, Node.js is customizable through JavaScript which offers much more flexibility.

## Usages
### Overview
Following code illustrates how to add NodeSSPI to the request processing pipeline. Although the code requires Express.js, NodeSSPI doesn't have to be run under the context of Express.js. In fact, it has virtually no npm module dependencies.

```
'use strict';

var express = require('express');
var app = express();
var server = require('http').createServer(app);
app.configure(function () {
  app.use(function (req, res, next) {
    var nodeSSPI = require('node-sspi');
    var nodeSSPIObj = new nodeSSPI({
      retrieveGroups: true
    });
    nodeSSPIObj.authenticate(req, res);
    res.finished || next();
  });
  app.use(function (req, res, next) {
    var out = 'Hello ' + req.connection.user + '! You belong to following groups:<br/><ul>';
    if (req.connection.userGroups) {
      for (var i in req.connection.userGroups) {
        out += '<li>'+ req.connection.userGroups[i] + '</li><br/>\n';
      }
    }
    out += '</ul>';
    res.send(out);
  });
});
// Start server
var port = process.env.PORT || 3000;
server.listen(port, function () {
  console.log('Express server listening on port %d in %s mode', port, app.get('env'));
});
```

### Inputs

The call to `new nodeSSPI(opts)` in above code can take following options:
  * offerSSPI: true|false 
      - default to *true*. Whether to offer SSPI Windows authentication
  * offerBasic: true|false 
      - default to *true*. Whether to offer Basic authenication
  * authoritative: true|false 
      -  default to *ture*. Whether authentication performed by NodeSSPI is authoritative. If set to *true*, then requests passed to downstream are guaranteed to be authenticated because non-authenticated requests will be blocked. If set to *false*, there is no such guarantee and downstream middleware have the chance to impose their own authentication mechanism.
  * perRequestAuth: false|true 
      - default to *false*. Whether authentication should be performed at per request level or per connection level. Per connection level is preferred to reduce overhead.
  * retrieveGroups: false|true 
      - default to *false*. Whether to retrieve groups upon successful authentication. 
  * maxLoginAttemptsPerConnection: &lt;number&gt;
      - default to *3*. How many login attempts are permitted for this connection.
  * sspiPackagesUsed: &lt;array&gt;
      - default to *['NTLM']*. An array of SSPI packages used.
  * domain: &lt;string&gt;
      - no default value. This is the domain name (a.k.a realm) used by basic authentication if user doesn't prefix their login name with *&lt;domain_name&gt;\\*. 

### Outputs
  * Upon successful authentication, authenticated user name is populated into field `req.connection.user` 
    *   If option `retrieveGroups` is *true*, group names are populated into field `req.connection.userGroups` as an array.
  * Otherwise
    *   If option `authoritative` is set to *ture*, then the request will be blocked. The reason of blocking (i.e. error message) is written to response body. Some response headers such as *WWW-Authenticate* may get filled out, and one of following HTTP response codes will be populated to field `res.statusCode`:
      *   403 if max login attempts are reached
      *   401 for all in-progress authentications, including protocols that require multiple round trips or if max login attempts has not been reached.
      *   500 when NodeSSPI encountered unknown exceptions.
    *  If option `authoritative` is not set to *true*, then response headers and `res.statusCode` will still be populated as described above, but NodeSSPI will not block the request, i.e. it will not call `res.end()`. Also, error message will be returned from calling `nodeSSPIObj.authenticate(req, res);` rather than sending to response. This allows the caller and downstream middleware to make decision.

## Platforms
NodeSSPI has been tested working on these Windows platforms:
  * Windows Vista x32
  * Windows 7 x64
  * Windows Server 2008 R2

Platforms older than Windows 2000 are unlikely to work. Other platforms may work but haven't been tested.

## Caveats
  * NodeSSPI is still early in development. Microsoft provides a number of SSPI [packages](http://msdn.microsoft.com/en-us/library/windows/desktop/aa380502(v=vs.85).aspx). So far only NTLM and Negotiate have been tested.
  * All WinAPI calls including SSPI authentication and group retrievals are performed synchronously, during which Node.js thread is blocked while the server is communicating with the domain controler. Therefore there is potential performance impact.

## Installation
Prerequisites: Except on a few [ platforms + V8 version combinations](https://github.com/abbr/NodeSSPI-bin) where binary distribution is included, NodeSSPI uses node-gyp to compile C++ source code so you may need the compilers listed in [node-gyp](https://github.com/TooTallNate/node-gyp). You may also need to [update npm's bundled node gyp](https://github.com/TooTallNate/node-gyp/wiki/Updating-npm's-bundled-node-gyp).

To install, run 
```npm install node-sspi```

