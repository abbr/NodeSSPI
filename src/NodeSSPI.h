#pragma once

#define SECURITY_WIN32 1
#include <node.h>
#include <v8.h>

/* System headers */
#include <string>
#include <iostream>
#include <sstream>
#include <atlenc.h>
#include <memory>
#include <map>
//#include <windows.h>
//#include <winsock2.h>
#include <sspi.h>
//#include <security.h>

#define WINNT_SECURITY_DLL "SECURITY.DLL"
#define DEFAULT_SSPI_PACKAGE "NTLM"
#define UUID_STRING_LEN 64

typedef struct {
	BOOL supportsSSPI;
	LPSTR defaultPackage;
	char userDataKeyString[UUID_STRING_LEN];
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
