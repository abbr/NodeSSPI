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

/*
* args[0]: opts
* args[1]: req
* args[2]: res
*/
Handle<Value> Authenticate(const Arguments& args) {
	HandleScope scope;
	BYTE* pToken ;
	try{
		if (sspiModuleInfo.supportsSSPI == FALSE) {
			throw new std::exception();
		}
		auto req = args[1]->ToObject();
		auto aut = std::string(*String::Utf8Value(req->Get(String::New("headers"))->ToObject()->Get(String::New("authorization"))));
		stringstream ssin(aut);
		std::string schema, strToken;
		ssin >> schema;
		ssin >> strToken;
		// base64 decode strToken
		pToken = static_cast<BYTE*>(malloc(strToken.length()));
		int sz = strToken.length();
		if(!Base64Decode(strToken.c_str(), strToken.length(), pToken, &sz)){
			throw new std::exception();
		};
		// get max token size defined by SSPI package
		int maxTokSz = -1;
		for(ULONG i =0 ;i< sspiModuleInfo.numPackages;i++ ){
			if(!schema.compare(sspiModuleInfo.pkgInfo[i].Name)){
				maxTokSz = sspiModuleInfo.pkgInfo[i].cbMaxToken;
				break;
			}
		}
		req->Set(String::New("user"), String::New("Fred"));
	}
	catch(...){
		args[2]->ToObject()->Set(String::New("statusCode"),Integer::New(500));
	}
	free(pToken);
	return scope.Close(Undefined());
}

void init(Handle<Object> exports) {
	init_module();
	exports->Set(String::NewSymbol("authenticate"),
		FunctionTemplate::New(Authenticate)->GetFunction());
}

NODE_MODULE(nodeSSPI, init)