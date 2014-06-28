#include "NodeSSPI.h"

using namespace v8;
using namespace std;

sspi_module_rec sspiModuleInfo = { 0, };


void sspi_module_cleanup()
{
	if (sspiModuleInfo.securityDLL != NULL) {
		if (sspiModuleInfo.functable != NULL) {
			sspiModuleInfo.functable->FreeContextBuffer(sspiModuleInfo.pkgInfo);
		}
		FreeLibrary(sspiModuleInfo.securityDLL);
	}
}

void init_module()
{
	LPSTR lpDllName = WINNT_SECURITY_DLL;
	INIT_SECURITY_INTERFACE pInit;
	SECURITY_STATUS ss = SEC_E_INTERNAL_ERROR;

	sspiModuleInfo.defaultPackage = DEFAULT_SSPI_PACKAGE;
	__try {
		sspiModuleInfo.securityDLL = LoadLibrary(lpDllName);
		pInit = (INIT_SECURITY_INTERFACE)GetProcAddress(sspiModuleInfo.securityDLL, SECURITY_ENTRYPOINT);
		sspiModuleInfo.functable = pInit();
		ss = sspiModuleInfo.functable->EnumerateSecurityPackages(&sspiModuleInfo.numPackages, &sspiModuleInfo.pkgInfo);
		sspiModuleInfo.supportsSSPI = TRUE;
	}
	__finally {
		if (ss != SEC_E_OK) {
			sspi_module_cleanup();
		}
	}
}

Handle<Value> Authenticate(const Arguments& args) {
	HandleScope scope;
	auto aut = std::string(*String::Utf8Value(args[1]->ToObject()->Get(String::New("headers"))->ToObject()->Get(String::New("authorization"))));
	if (sspiModuleInfo.supportsSSPI == FALSE) {
		return scope.Close(Integer::New(500));
	}

	return scope.Close(Undefined());
}

void init(Handle<Object> exports) {
	init_module();
	exports->Set(String::NewSymbol("authenticate"),
		FunctionTemplate::New(Authenticate)->GetFunction());
}

NODE_MODULE(nodeSSPI, init)