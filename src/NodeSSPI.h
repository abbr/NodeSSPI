#pragma once

#define SECURITY_WIN32 1
#include <node.h>
#include <v8.h>

/* System headers */
#include <string>
#include <iostream>
#include <sstream>
//#include <windows.h>
//#include <winsock2.h>
#include <sspi.h>
//#include <security.h>

#define WINNT_SECURITY_DLL "SECURITY.DLL"
#define DEFAULT_SSPI_PACKAGE "NTLM"
#define UUID_STRING_LEN 64

typedef struct sspi_module_struct {
    BOOL supportsSSPI;
    LPSTR defaultPackage;
    LPOSVERSIONINFO lpVersionInformation;
    char userDataKeyString[UUID_STRING_LEN];
    HMODULE securityDLL;
    SecurityFunctionTable *functable;
    ULONG numPackages;
    PSecPkgInfo pkgInfo;
} sspi_module_rec;

