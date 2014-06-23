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

	if (sspiModuleInfo.lpVersionInformation == NULL) {
		sspiModuleInfo.supportsSSPI = TRUE;
		sspiModuleInfo.defaultPackage = DEFAULT_SSPI_PACKAGE;
		__try {
			sspiModuleInfo.securityDLL = LoadLibrary(lpDllName);
			pInit = (INIT_SECURITY_INTERFACE)GetProcAddress(sspiModuleInfo.securityDLL, SECURITY_ENTRYPOINT);
			sspiModuleInfo.functable = pInit();
			ss = sspiModuleInfo.functable->EnumerateSecurityPackages(&sspiModuleInfo.numPackages, &sspiModuleInfo.pkgInfo);
		}
		__finally {
			if (ss != SEC_E_OK) {
				sspi_module_cleanup();
				sspiModuleInfo.supportsSSPI = FALSE;
			}
		}
	}

}

Handle<Value> Method(const Arguments& args) {
	HandleScope scope;
	TryCatch trycatch;
	if (args[0]->IsObject()){
		auto req = args[0]->ToObject();
		req->Set(String::New("user"), String::New("Fred"));
	}
	return scope.Close(Undefined());
}

void init(Handle<Object> exports) {
	init_module();
	exports->Set(String::NewSymbol("authenticate"),
		FunctionTemplate::New(Method)->GetFunction());
}

NODE_MODULE(nodeSSPI, init)