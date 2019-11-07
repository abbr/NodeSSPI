#pragma once

#define SECURITY_WIN32 1
#include <napi.h>

/* System headers */
#include <string>
#include <iostream>
#include <sstream>
#include <atlenc.h>
#include <atlstr.h>
#include <map>
#include <memory>
#include <vector>

//#include <windows.h>
//#include <winsock2.h>
#include <sspi.h>
#include <sddl.h>
//#include <security.h>

#define WINNT_SECURITY_DLL L"SECURITY.DLL"
#define DEFAULT_SSPI_PACKAGE "NTLM"

typedef struct {
	BOOL supportsSSPI;
	LPSTR defaultPackage;
	HMODULE securityDLL;
	SecurityFunctionTable *functable;
	ULONG numPackages;
	PSecPkgInfo pkgInfo;
} sspi_module_rec;

typedef struct {
	CredHandle credHandl;
	TimeStamp exp;
} credHandleRec;

typedef struct {
    /* Server context */
    CtxtHandle server_context;
    TimeStamp server_ctxtexpiry;
} sspi_connection_rec;

class NodeSSPIException : public std::exception {
public:
	NodeSSPIException(const char * pMsg, const UINT http_code = 500)
		: std::exception(pMsg), http_code(http_code) {
	}
	UINT http_code;
};

class Baton {
public:
	Baton() {
		err = 0;
		pGroups = 0;
		basicDomain = 0;
		pInToken = 0;
		pSCR = 0;
		isTesting = false;
	}
	~Baton() {
		if (!callback.IsEmpty())	callback.Reset();
		if (!req.IsEmpty()) req.Reset();
		if (!res.IsEmpty()) res.Reset();
		if (!conn.IsEmpty()) conn.Reset();
		if (!opts.IsEmpty()) opts.Reset();
		if (pGroups) delete pGroups;
		if (err) delete err;
		if (basicDomain) delete basicDomain;
		if (pInToken) free(pInToken);
	}
	Napi::FunctionReference callback;
	//int error_code;
	//std::string error_message;

	// Custom data
	Napi::ObjectReference req;
    Napi::ObjectReference res;
    Napi::ObjectReference conn;
    Napi::ObjectReference opts;
	std::string sspiPkg;
	ULONG ss;
	std::string user;
	std::string userSid;
	bool retrieveGroups;
	NodeSSPIException * err;
	std::vector<std::string> *pGroups;
	BYTE *pInToken;
	ULONG pInTokenSz;
	sspi_connection_rec *pSCR;
	std::string *basicDomain;
	// are we running module installation testing?
	bool isTesting;
};

class AsyncBasicWorker : public Napi::AsyncWorker {
 public:
  AsyncBasicWorker(Napi::Function& cb, Baton* baton);
  ~AsyncBasicWorker();
  void Execute ();
  void OnOK();
  void OnError();
 private:
  Baton* pBaton;
};

class AsyncSSPIWorker : public Napi::AsyncWorker {
 public:
  AsyncSSPIWorker(Napi::Function& cb, Baton* baton);
  ~AsyncSSPIWorker();
  void Execute ();
  void OnOK();
  void OnError();
 private:
  Baton* pBaton;
};