#include "NodeSSPI.h"

using namespace v8;
using namespace std;

sspi_module_rec sspiModuleInfo = { 0, };

std::map<std::string, credHandleRec> credMap;

class NodeSSPIException : public std::exception{
public:
	NodeSSPIException(const char * pMsg, const UINT http_code = 500) 
		: std::exception(pMsg), http_code(http_code) {
	}
	UINT http_code;
};

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

void note_sspi_auth_failure(const Local<Object> opts,const Local<Object> req,Local<Object> res){
	int nWays = 0;
	int nSSPIPkgs = 0;
	bool offerBasic = false, offerSSPI = false;
	if(opts->Get(String::New("offerBasic"))->BooleanValue()){
		offerBasic = true;
		nWays += 1;
	}
	if(opts->Get(String::New("offerSSPI"))->BooleanValue()){
		offerSSPI = true;
		nSSPIPkgs = opts->Get(String::New("sspiPackagesUsed"))->ToObject()->Get(String::New("length"))->ToInteger()->Uint32Value();
		nWays += nSSPIPkgs;
	}
	auto authHArr = v8::Array::New(nWays);
	int curIdx = 0;
	if(offerBasic){
		std::string basicStr("Basic");
		if(opts->Has(String::New("domain"))){
			basicStr += " realm=\"";
			basicStr += std::string(*String::AsciiValue(opts->Get(String::New("domain"))));
			basicStr += "\"";
		}
		authHArr->Set(curIdx++, String::New(basicStr.c_str()));
	}
	if(offerSSPI){
		for(int i =0;i<nSSPIPkgs;i++){
			authHArr->Set(curIdx++,opts->Get(String::New("sspiPackagesUsed"))->ToObject()->Get(i));
		}
	}
	Handle<Value> argv[] = { String::New("WWW-Authenticate"), authHArr };
	res->Get(String::New("setHeader"))->ToObject()->CallAsFunction(res, 2, argv);
	res->Set(String::New("statusCode"),Integer::New(401));
}

void cleanup_sspi_connection(Local<Object> conn)
{
	sspi_connection_rec *pSCR = 0;
	PCtxtHandle outPch = 0;
	if (conn->HasOwnProperty(String::New("svrCtx"))){
		Local<External> wrap = Local<External>::Cast(conn->Get(String::New("svrCtx"))->ToObject()->GetInternalField(0));
		pSCR = static_cast<sspi_connection_rec *>(wrap->Value());
		outPch = &pSCR->server_context;
		sspiModuleInfo.functable->DeleteSecurityContext(outPch);
		outPch->dwLower = outPch->dwUpper = 0;
		free(pSCR);
		conn->Delete(String::New("svrCtx"));
	}
}

/*
* get max token size defined by SSPI package
*/
ULONG getMaxTokenSz(std::string pkgNm){
	for (ULONG i = 0; i < sspiModuleInfo.numPackages; i++){
		if (!pkgNm.compare(sspiModuleInfo.pkgInfo[i].Name)){
			return sspiModuleInfo.pkgInfo[i].cbMaxToken;
		}
	}
	throw NodeSSPIException(("No " + pkgNm + " SSPI package.").c_str());
}

void basic_authentication(const Local<Object> opts,const Local<Object> req,Local<Object> res, Local<Object> conn, BYTE *pInToken, UINT sz){
	std::string sspiPkg(sspiModuleInfo.defaultPackage);
	if(opts->Has(String::New("sspiPackagesUsed"))){
		auto firstSSPIPackage = opts->Get(String::New("sspiPackagesUsed"))->ToObject()->Get(0);
		sspiPkg = *v8::String::Utf8Value(firstSSPIPackage);
	}
	ULONG maxTokSz = getMaxTokenSz(sspiPkg);
}

void sspi_authentication(const Local<Object> opts,const Local<Object> req,Local<Object> res, std::string schema, Local<Object> conn, BYTE *pInToken, UINT sz){
	ULONG maxTokSz = getMaxTokenSz(schema);
	// acquire server credential
	if (credMap.find(schema) == credMap.end()){
		credHandleRec temp = { 0, 0 };
		credMap[schema] = temp;
	}
	FILETIME ft;
	SYSTEMTIME st;
	GetSystemTime(&st); // gets current time
	SystemTimeToFileTime(&st, &ft); // converts to file time format
	if (CompareFileTime(&ft, (FILETIME *)(&credMap[schema].exp)) > 0){
		sspiModuleInfo.functable->FreeCredentialsHandle(&credMap[schema].credHandl);
		// cred expired, re-generate
		if (sspiModuleInfo.functable->AcquireCredentialsHandle(
			NULL //pszPrincipal
			, (char*)(schema.c_str()) //pszPackage
			, SECPKG_CRED_INBOUND //fCredentialUse
			, NULL // pvLogonID
			, NULL //pAuthData
			, NULL //pGetKeyFn
			, NULL //pvGetKeyArgument
			, &credMap[schema].credHandl //phCredential
			, &credMap[schema].exp //ptsExpiry
			) != SEC_E_OK){
				throw NodeSSPIException("Cannot get server credential");
		}

	}
	// acquire server context from request.connection
	sspi_connection_rec *pSCR = 0;
	PCtxtHandle inPch = 0, outPch = 0;
	PTimeStamp pTS;
	if (conn->HasOwnProperty(String::New("svrCtx"))){
		// this is not initial request
		Local<External> wrap = Local<External>::Cast(conn->Get(String::New("svrCtx"))->ToObject()->GetInternalField(0));
		pSCR = static_cast<sspi_connection_rec *>(wrap->Value());
		inPch = outPch = &pSCR->server_context;
	}
	else{
		pSCR = static_cast<sspi_connection_rec *>(malloc(sizeof(sspi_connection_rec)));
		outPch = &pSCR->server_context;
		Handle<ObjectTemplate> svrCtx_templ = ObjectTemplate::New();
		svrCtx_templ->SetInternalFieldCount(1);
		Local<Object> obj = svrCtx_templ->NewInstance();
		obj->SetInternalField(0, External::New(outPch));
		conn->Set(String::New("svrCtx"), obj);
	}
	pTS = &pSCR->server_ctxtexpiry;
	// call AcceptSecurityContext 
	SecBuffer inbuf, outbuf;
	SecBufferDesc inbufdesc, outbufdesc;
	outbuf.cbBuffer = maxTokSz;
	outbuf.BufferType = SECBUFFER_TOKEN;
	unique_ptr<BYTE[]> pOutBuf(new BYTE[maxTokSz]);
	outbuf.pvBuffer = pOutBuf.get();
	outbufdesc.ulVersion = SECBUFFER_VERSION;
	outbufdesc.cBuffers = 1;
	outbufdesc.pBuffers = &outbuf;

	inbuf.BufferType = SECBUFFER_TOKEN;
	inbuf.cbBuffer = sz;
	inbuf.pvBuffer = pInToken;
	inbufdesc.cBuffers = 1;
	inbufdesc.ulVersion = SECBUFFER_VERSION;
	inbufdesc.pBuffers = &inbuf;
	ULONG ContextAttributes;

	SECURITY_STATUS ss;
	ss = sspiModuleInfo.functable->AcceptSecurityContext(
		&credMap[schema].credHandl	//  _In_opt_     PCredHandle phCredential,
		, inPch //  _Inout_opt_  PCtxtHandle phContext,
		, &inbufdesc //  _In_opt_     PSecBufferDesc pInput,
		, ASC_REQ_DELEGATE //  _In_         ULONG fContextReq,
		, SECURITY_NATIVE_DREP //  _In_         ULONG TargetDataRep,
		, outPch //  _Inout_opt_  PCtxtHandle phNewContext,
		, &outbufdesc //  _Inout_opt_  PSecBufferDesc pOutput,
		, &ContextAttributes //  _Out_        PULONG pfContextAttr,
		, pTS //  _Out_opt_    PTimeStamp ptsTimeStamp
		);
	if (ss == SEC_I_COMPLETE_NEEDED || ss == SEC_I_COMPLETE_AND_CONTINUE) {
		sspiModuleInfo.functable->CompleteAuthToken(outPch, &outbufdesc);
	}

	switch (ss) {
	case SEC_I_COMPLETE_NEEDED:
	case SEC_I_CONTINUE_NEEDED:
	case SEC_I_COMPLETE_AND_CONTINUE: 
		{
			CStringA base64;
			int base64Length = Base64EncodeGetRequiredLength(outbuf.cbBuffer);
			Base64Encode(pOutBuf.get(),
				outbuf.cbBuffer,
				base64.GetBufferSetLength(base64Length),
				&base64Length, ATL_BASE64_FLAG_NOCRLF);
			base64.ReleaseBufferSetLength(base64Length);
			std::string authHStr = schema + " " + std::string(base64.GetString());
			Handle<Value> argv[] = { String::New("WWW-Authenticate"), String::New(authHStr.c_str()) };
			res->Get(String::New("setHeader"))->ToObject()->CallAsFunction(res, 2, argv);
			res->Set(String::New("statusCode"), Integer::New(401));
			break;
		}
	case SEC_E_INVALID_TOKEN:
	case SEC_E_LOGON_DENIED:
		{
			note_sspi_auth_failure(opts,req,res);
			cleanup_sspi_connection(conn);
			if(!conn->HasOwnProperty(String::New("remainingAttempts"))){
				conn->Set(String::New("remainingAttempts")
					,Integer::New(opts->Get(String::New("maxLoginAttemptsPerConnection"))->Int32Value()-1));
			}
			int remainingAttmpts = conn->Get(String::New("remainingAttempts"))->Int32Value(); 
			if(remainingAttmpts<=0){
				throw NodeSSPIException("Max login attempts reached.",403);
			}
			conn->Set(String::New("remainingAttempts")
				,Integer::New(remainingAttmpts-1));
			res->Set(String::New("statusCode"), Integer::New(401));
			break;
		}
	case SEC_E_INVALID_HANDLE:
	case SEC_E_INTERNAL_ERROR:
	case SEC_E_NO_AUTHENTICATING_AUTHORITY:
	case SEC_E_INSUFFICIENT_MEMORY:
		{
			cleanup_sspi_connection(conn);
			res->Set(String::New("statusCode"), Integer::New(500));
			break;
		}
	case SEC_E_OK:
		{
			// get user name
			SecPkgContext_Names names;
			SECURITY_STATUS ss;
			char *retval = NULL;

			if ((ss = sspiModuleInfo.functable->QueryContextAttributes(outPch, 
				SECPKG_ATTR_NAMES, 
				&names)
				) == SEC_E_OK) {
					conn->Set(String::New("user"),String::New(names.sUserName));
					sspiModuleInfo.functable->FreeContextBuffer(names.sUserName);
					cleanup_sspi_connection(conn);
			}
			else{
				throw NodeSSPIException("Cannot obtain user name.");
			}
			break;
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
	Local<Object> conn;
	try{
		if (sspiModuleInfo.supportsSSPI == FALSE) {
			throw NodeSSPIException("Doesn't suport SSPI.");
		}
		auto opts = args[0]->ToObject();
		auto req = args[1]->ToObject();
		auto res = args[2]->ToObject();
		auto headers = req->Get(String::New("headers"))->ToObject(); 
		conn = req->Get(String::New("connection"))->ToObject();
		if(conn->HasOwnProperty(String::New("user"))){
			return scope.Close(Undefined());
		}
		if(!headers->Has(String::New("authorization"))){
			note_sspi_auth_failure(opts,req,res);
			return scope.Close(Undefined());
		}
		auto aut = std::string(*String::AsciiValue(headers->Get(String::New("authorization"))));
		stringstream ssin(aut);
		std::string schema, strToken;
		ssin >> schema;
		ssin >> strToken;
		// base64 decode strToken
		unique_ptr<BYTE[]> pToken(new BYTE[strToken.length()]);
		int sz = strToken.length();
		if (!Base64Decode(strToken.c_str(), strToken.length(), pToken.get(), &sz)){
			throw NodeSSPIException("Cannot decode authorization field.");
		};
		if(_stricmp(schema.c_str(),"basic")==0){
			basic_authentication(opts,req,res,conn, pToken.get(), sz);
		}
		else{
			sspi_authentication(opts,req,res,schema,conn, pToken.get(), sz);
		}
	}
	catch (NodeSSPIException& ex){
		cleanup_sspi_connection(conn);
		args[2]->ToObject()->Set(String::New("statusCode"), Integer::New(ex.http_code));
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