#pragma once

#define SECURITY_WIN32 1
#include <node.h>
#include <nan.h>
#include <v8.h>

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

