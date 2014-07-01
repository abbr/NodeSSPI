#include "NodeSSPI.h"

using namespace v8;
using namespace std;

sspi_module_rec sspiModuleInfo = { 0, };

std::map<std::string,credHandleRec> credMap;

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
			throw std::exception("Doesn't suport SSPI.");
		}
		auto req = args[1]->ToObject();
		auto aut = std::string(*String::AsciiValue(req->Get(String::New("headers"))->ToObject()->Get(String::New("authorization"))));
		stringstream ssin(aut);
		std::string schema, strToken;
		ssin >> schema;
		ssin >> strToken;
		// base64 decode strToken
		unique_ptr<BYTE[]> pToken(new BYTE[strToken.length()]);
		int sz = strToken.length();
		if(!Base64Decode(strToken.c_str(), strToken.length(), pToken.get(), &sz)){
			throw std::exception("Cannot decode authorization field.");
		};
		// get max token size defined by SSPI package
		int maxTokSz = -1;
		for(ULONG i =0 ;i< sspiModuleInfo.numPackages;i++ ){
			if(!schema.compare(sspiModuleInfo.pkgInfo[i].Name)){
				maxTokSz = sspiModuleInfo.pkgInfo[i].cbMaxToken;
				break;
			}
		}
		if(maxTokSz < 0){
			throw std::exception(("No " +schema+ " SSPI package.").c_str());
		}
		// acquire server credential
		if(credMap.find(schema.c_str()) == credMap.end()){
			credHandleRec temp = {{0,0},0};
			credMap[schema.c_str()] = temp;
		}
		FILETIME ft;
		SYSTEMTIME st;
		GetSystemTime(&st); // gets current time
		SystemTimeToFileTime(&st, &ft); // converts to file time format
		if(CompareFileTime(&ft,(FILETIME *)(&credMap[schema.c_str()].exp))>0){
			// cred expired, re-generate
			if(sspiModuleInfo.functable->AcquireCredentialsHandle(
				NULL //pszPrincipal
				,(char*)(schema.c_str()) //pszPackage
				,SECPKG_CRED_INBOUND //fCredentialUse
				,NULL // pvLogonID
				,NULL //pAuthData
				,NULL //pGetKeyFn
				,NULL //pvGetKeyArgument
				,&credMap[schema.c_str()].credHandl //phCredential
				,&credMap[schema.c_str()].exp //ptsExpiry
				) != SEC_E_OK){
					throw std::exception("Cannot get server credential");
			}

		}
		req->Set(String::New("user"), String::New("Fred"));
	}
	catch(std::exception& ex){
		args[2]->ToObject()->Set(String::New("statusCode"),Integer::New(500));
		// throw exception to js land
		return v8::ThrowException(v8::String::New(ex.what()));
	}
	return scope.Close(Undefined());
}

void init(Handle<Object> exports) {
	init_module();
	exports->Set(String::NewSymbol("authenticate"),
		FunctionTemplate::New(Authenticate)->GetFunction());
}

NODE_MODULE(nodeSSPI, init)