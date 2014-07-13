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

void CleanupAuthenicationResources(Local<Object> conn
	, PCtxtHandle pSvrCtxHdl = NULL)
{
	sspi_connection_rec *pSCR = 0;
	PCtxtHandle outPch = 0;
	if (conn->HasOwnProperty(String::New("svrCtx"))){
		conn->Delete(String::New("svrCtx"));
	}
	pSvrCtxHdl && sspiModuleInfo.functable->DeleteSecurityContext(pSvrCtxHdl);
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
/*
* Acquire sharable server credentials by schema honoring expiry timestamp
*/
void acquireServerCredential(std::string schema){
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
}

static ULONG gen_client_context(CredHandle *pCredentials
	, const char * pkgNm	, BYTE *pInToken, ULONG *pInLen
	, PCtxtHandle outPch, BYTE *out, ULONG * pOutlen, TimeStamp *pTS){
		SecBuffer inbuf, outbuf;
		SecBufferDesc inbufdesc, outbufdesc;
		outbuf.cbBuffer = *pOutlen;
		outbuf.BufferType = SECBUFFER_TOKEN;
		outbuf.pvBuffer = out;
		outbufdesc.ulVersion = SECBUFFER_VERSION;
		outbufdesc.cBuffers = 1;
		outbufdesc.pBuffers = &outbuf;
		BOOL havecontext = (outPch->dwLower || outPch->dwUpper);


		if (pInToken) {
			inbuf.cbBuffer = *pInLen;
			inbuf.BufferType = SECBUFFER_TOKEN;
			inbuf.pvBuffer = pInToken;
			inbufdesc.ulVersion = SECBUFFER_VERSION;
			inbufdesc.cBuffers = 1;
			inbufdesc.pBuffers = &inbuf;
		}
		ULONG ContextAttributes;
		ULONG ss = sspiModuleInfo.functable->InitializeSecurityContext(
			pCredentials //  _In_opt_     PCredHandle phCredential,
			, havecontext ? outPch : NULL //  _In_opt_     PCtxtHandle phContext,
			, (SEC_CHAR *) pkgNm //  _In_opt_     SEC_CHAR *pszTargetName,
			, ISC_REQ_DELEGATE //  _In_         ULONG fContextReq,
			, 0 //  _In_         ULONG Reserved1,
			, SECURITY_NATIVE_DREP //  _In_         ULONG TargetDataRep,
			, pInToken ? &inbufdesc : NULL //  _In_opt_     PSecBufferDesc pInput,
			, 0 //  _In_         ULONG Reserved2,
			, outPch //  _Inout_opt_  PCtxtHandle phNewContext,
			, &outbufdesc //  _Inout_opt_  PSecBufferDesc pOutput,
			, &ContextAttributes //  _Out_        PULONG pfContextAttr,
			, pTS //  _Out_opt_    PTimeStamp ptsExpiry
			);
		if (ss == SEC_I_COMPLETE_NEEDED || ss == SEC_I_COMPLETE_AND_CONTINUE) {
			sspiModuleInfo.functable->CompleteAuthToken(outPch, &outbufdesc);
		}
		*pOutlen = outbufdesc.pBuffers->cbBuffer;
		return ss;
}

static ULONG gen_server_context(CredHandle *pCredentials
	, BYTE *pInToken, ULONG *pInLen
	, PCtxtHandle outPch, BYTE *out, ULONG * pOutlen, TimeStamp *pTS){
		SecBuffer inbuf, outbuf;
		SecBufferDesc inbufdesc, outbufdesc;
		BOOL havecontext = (outPch->dwLower || outPch->dwUpper);
		outbuf.cbBuffer = *pOutlen;
		outbuf.BufferType = SECBUFFER_TOKEN;
		outbuf.pvBuffer = out;
		outbufdesc.ulVersion = SECBUFFER_VERSION;
		outbufdesc.cBuffers = 1;
		outbufdesc.pBuffers = &outbuf;

		inbuf.BufferType = SECBUFFER_TOKEN;
		inbuf.cbBuffer = *pInLen;
		inbuf.pvBuffer = pInToken;
		inbufdesc.cBuffers = 1;
		inbufdesc.ulVersion = SECBUFFER_VERSION;
		inbufdesc.pBuffers = &inbuf;
		ULONG ContextAttributes;

		ULONG ss;
		ss = sspiModuleInfo.functable->AcceptSecurityContext(
			pCredentials	//  _In_opt_     PCredHandle phCredential,
			, havecontext ? outPch : NULL //  _Inout_opt_  PCtxtHandle phContext,
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
		*pOutlen = outbufdesc.pBuffers->cbBuffer;
		return ss;
}

void AddUserGroupsToConnection(HANDLE usertoken, Local<Object> conn)
{
	TOKEN_GROUPS *groupinfo = NULL;
	DWORD groupinfosize = 0;
	SID_NAME_USE sidtype;
	char group_name[_MAX_PATH], domain_name[_MAX_PATH];
	DWORD grouplen, domainlen;
	unsigned int i;

	if ((GetTokenInformation(usertoken, TokenGroups, groupinfo
		, groupinfosize, &groupinfosize))
		|| (GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
			return;
	}
	groupinfo = (TOKEN_GROUPS *)malloc(groupinfosize);
	if (!GetTokenInformation(usertoken, TokenGroups, groupinfo, groupinfosize, &groupinfosize)) {
		return;
	}
	auto groups = v8::Array::New(groupinfo->GroupCount);
	for (i = 0; i < groupinfo->GroupCount; i++) {
		grouplen = _MAX_PATH;
		domainlen = _MAX_PATH;
		if (LookupAccountSid(NULL, groupinfo->Groups[i].Sid, 
			group_name, &grouplen,
			domain_name, &domainlen,
			&sidtype)) {
				std::string grpNm = std::string(domain_name)+std::string("\\")+std::string(group_name);
				groups->Set(i, String::New(grpNm.c_str()));
		}
	}
	free(groupinfo );
	conn->Set(String::New("userGroups"),groups);
}

void RetrieveUserGroups(PCtxtHandle * ppServerCtx, Local<Object> conn, Local<Object> opts){
	// Retrieve user groups if requested, then call CleanupAuthenicationResources
	if(
		opts->Get(String::New("retrieveGroups"))->ToBoolean()->BooleanValue()){
			HANDLE userToken;
			ULONG ss;
			if ((ss = sspiModuleInfo.functable->ImpersonateSecurityContext(*ppServerCtx)) != SEC_E_OK) {
				throw NodeSSPIException("Cannot impersonate user.");
			}

			if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY_SOURCE | TOKEN_READ, TRUE, &userToken)) {
				sspiModuleInfo.functable->RevertSecurityContext(*ppServerCtx);
				throw NodeSSPIException("Cannot obtain user token.");
			}
			if ((ss = sspiModuleInfo.functable->RevertSecurityContext(*ppServerCtx)) != SEC_E_OK) {
				throw NodeSSPIException("Cannot revert security context.");
			}
			AddUserGroupsToConnection(userToken, conn);
	}
	CleanupAuthenicationResources(conn, *ppServerCtx);
}

void basic_authentication(const Local<Object> opts,const Local<Object> req
	,Local<Object> res, Local<Object> conn, BYTE *pInToken
	, ULONG sz, PCtxtHandle pServerCtx){
		std::string sspiPkg(sspiModuleInfo.defaultPackage);
		if(opts->Has(String::New("sspiPackagesUsed"))){
			auto firstSSPIPackage = opts->Get(String::New("sspiPackagesUsed"))->ToObject()->Get(0);
			sspiPkg = *v8::String::Utf8Value(firstSSPIPackage);
		}
		ULONG tokSz = getMaxTokenSz(sspiPkg);
		acquireServerCredential(sspiPkg);
		// get domain, user name, password
		*(pInToken+sz) = '\0';
		std::string domainNnm, domain, nm, pswd, inStr((char*)pInToken);
		if(opts->Has(String::New("domain"))){
			domain = *String::AsciiValue(opts->Get(String::New("domain")));
		}
		domainNnm = inStr.substr(0,inStr.find_first_of(":"));
		if(domainNnm.find("\\") != std::string::npos){
			domain = domainNnm.substr(0,domainNnm.find_first_of("\\"));
			nm = domainNnm.substr(domainNnm.find_first_of("\\")+1);
		}
		else{
			nm = domainNnm;
		}
		pswd = inStr.substr(inStr.find_first_of(":")+1);
		// acquire client credential
		CredHandle clientCred;
		TimeStamp clientCredTs;
		SEC_WINNT_AUTH_IDENTITY authIden;
		authIden.Domain = (unsigned char *)domain.c_str();
		authIden.DomainLength = domain.length();
		authIden.User = (unsigned char *) nm.c_str();
		authIden.UserLength = nm.length();
		authIden.Password = (unsigned char *) pswd.c_str();
		authIden.PasswordLength = pswd.length();
#ifdef UNICODE
		authIden.Flags  = SEC_WINNT_AUTH_IDENTITY_UNICODE;
#else
		authIden.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
#endif
		if(sspiModuleInfo.functable->AcquireCredentialsHandle(                                        
			NULL,
			(char*) sspiPkg.c_str(),
			SECPKG_CRED_OUTBOUND,
			NULL, &authIden, NULL, NULL,
			&clientCred,
			&clientCredTs) != SEC_E_OK){
				throw NodeSSPIException("Cannot acquire client credential.");
		};

		// perform authentication loop
		ULONG cbOut, cbIn;
		BYTE *clientbuf = NULL;
		ULONG ss;
		unique_ptr<BYTE[]> pServerbuf(new BYTE[tokSz]), pClientBuf(new BYTE[tokSz]);
		cbOut = 0;
		CtxtHandle client_context = {0,0};
		TimeStamp client_ctxtexpiry,server_ctxtexpiry;

		do {
			cbIn = cbOut;
			cbOut = tokSz;
			ss = gen_client_context(&clientCred, sspiPkg.c_str()
				, clientbuf, &cbIn, &client_context, pServerbuf.get(), &cbOut, &client_ctxtexpiry);

			if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED || ss == SEC_I_COMPLETE_AND_CONTINUE) {
				if (clientbuf == NULL) {
					clientbuf = pClientBuf.get();
				}
				cbIn = cbOut;
				cbOut = tokSz;
				ss = gen_server_context(&credMap[sspiPkg].credHandl,pServerbuf.get()
					, &cbIn, pServerCtx, clientbuf, &cbOut, &server_ctxtexpiry);
			}
		} while (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_I_COMPLETE_AND_CONTINUE);
		sspiModuleInfo.functable->DeleteSecurityContext(&client_context);
		sspiModuleInfo.functable->FreeCredentialsHandle(&clientCred);
		switch (ss) {
		case SEC_E_OK:
			{
				// get user name
				SecPkgContext_Names names;
				SECURITY_STATUS ss;
				char *retval = NULL;

				if ((ss = sspiModuleInfo.functable->QueryContextAttributes(pServerCtx, 
					SECPKG_ATTR_NAMES, 
					&names)
					) == SEC_E_OK) {
						conn->Set(String::New("user"),String::New(names.sUserName));
						sspiModuleInfo.functable->FreeContextBuffer(names.sUserName);
						RetrieveUserGroups(&pServerCtx,conn,opts);
				}
				else{
					CleanupAuthenicationResources(conn, pServerCtx);
					throw NodeSSPIException("Cannot obtain user name.");
				}
				break;
			}
		case SEC_E_INVALID_HANDLE:
		case SEC_E_INTERNAL_ERROR:
		case SEC_E_NO_AUTHENTICATING_AUTHORITY:
		case SEC_E_INSUFFICIENT_MEMORY:
			{
				CleanupAuthenicationResources(conn, pServerCtx);
				res->Set(String::New("statusCode"), Integer::New(500));
				break;
			}
		case SEC_E_INVALID_TOKEN:
		case SEC_E_LOGON_DENIED:
		default:
			{
				note_sspi_auth_failure(opts,req,res);
				CleanupAuthenicationResources(conn, pServerCtx);
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
				break;
			}
		}
}

void weakSvrCtxCallback(Persistent<Value> object, void *parameter)
{
	sspi_connection_rec *pSCR = static_cast<sspi_connection_rec *> (parameter);
	if(!pSCR) return;
	PCtxtHandle outPch =  &pSCR->server_context;
	SECURITY_STATUS ss = sspiModuleInfo.functable->DeleteSecurityContext(outPch);
	outPch->dwLower = outPch->dwUpper = 0;
	free(pSCR);
}

void sspi_authentication(const Local<Object> opts,const Local<Object> req
	,Local<Object> res, std::string schema, Local<Object> conn, BYTE *pInToken
	, ULONG sz, PCtxtHandle * ppServerCtx){
		ULONG tokSz = getMaxTokenSz(schema);
		acquireServerCredential(schema);
		// acquire server context from request.connection
		sspi_connection_rec *pSCR = 0;
		PCtxtHandle outPch = 0;
		PTimeStamp pTS;
		if (conn->HasOwnProperty(String::New("svrCtx"))){
			// this is not initial request
			Local<External> wrap = Local<External>::Cast(conn->Get(String::New("svrCtx"))->ToObject()->GetInternalField(0));
			pSCR = static_cast<sspi_connection_rec *>(wrap->Value());
		}
		else{
			pSCR = static_cast<sspi_connection_rec *>(malloc(sizeof(sspi_connection_rec)));
			SecureZeroMemory(pSCR,sizeof(sspi_connection_rec));
			Handle<ObjectTemplate> svrCtx_templ = ObjectTemplate::New();
			svrCtx_templ->SetInternalFieldCount(1);
			Persistent<Object> obj = Persistent<Object>::New(svrCtx_templ->NewInstance());
			obj->SetInternalField(0, External::New(pSCR));
			// hook to GC to clean up in-progress authentications
			// necessary to defend against attacks similar to sync flood 
			obj.MakeWeak(pSCR,weakSvrCtxCallback);
			conn->Set(String::New("svrCtx"), obj);
		}
		outPch = &pSCR->server_context;
		pTS = &pSCR->server_ctxtexpiry;
		*ppServerCtx = outPch;
		// call AcceptSecurityContext to generate server context
		unique_ptr<BYTE[]> pOutBuf(new BYTE[tokSz]);
		SECURITY_STATUS ss = gen_server_context(&credMap[schema].credHandl
			, pInToken, &sz, outPch, pOutBuf.get(), &tokSz, pTS);
		switch (ss) {
		case SEC_I_COMPLETE_NEEDED:
		case SEC_I_CONTINUE_NEEDED:
		case SEC_I_COMPLETE_AND_CONTINUE: 
			{
				CStringA base64;
				int base64Length = Base64EncodeGetRequiredLength(tokSz);
				Base64Encode(pOutBuf.get(),
					tokSz,
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
				CleanupAuthenicationResources(conn);
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
				break;
			}
		case SEC_E_INVALID_HANDLE:
		case SEC_E_INTERNAL_ERROR:
		case SEC_E_NO_AUTHENTICATING_AUTHORITY:
		case SEC_E_INSUFFICIENT_MEMORY:
			{
				CleanupAuthenicationResources(conn);
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
						RetrieveUserGroups(ppServerCtx,conn,opts);
				}
				else{
					CleanupAuthenicationResources(conn);
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
	auto opts = args[0]->ToObject();
	auto res = args[2]->ToObject();
	Local<Object> conn;
	Local<Function> cb;
	if(args[3]->IsFunction()) {
		cb = Local<Function>::Cast(args[3]);
	}
	PCtxtHandle pServerCtx = NULL;
	try{
		auto req = args[1]->ToObject();
		conn = req->Get(String::New("connection"))->ToObject();
		if(conn->HasOwnProperty(String::New("user"))){
			if(!cb.IsEmpty()) {
				cb->Call(cb,0,NULL);
			}
			return scope.Close(Undefined());
		}
		if (sspiModuleInfo.supportsSSPI == FALSE) {
			throw NodeSSPIException("Doesn't suport SSPI.");
		}
		auto headers = req->Get(String::New("headers"))->ToObject(); 
		if(!headers->Has(String::New("authorization"))){
			note_sspi_auth_failure(opts,req,res);
			if(opts->Get(String::New("authoritative"))->BooleanValue()
				&& !req->Get(String::New("connection"))->ToObject()->Has(String::New("user"))
				){
					res->Get(String::New("end"))->ToObject()->CallAsFunction(res, 0, NULL);
			}
			if(!cb.IsEmpty())  {
				cb->Call(cb,0, NULL);
			}
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
		CtxtHandle serverCtx = {0,0};
		if(_stricmp(schema.c_str(),"basic")==0){
			pServerCtx = &serverCtx;
			basic_authentication(opts,req,res,conn, pToken.get(), sz, pServerCtx);
		}
		else{
			sspi_authentication(opts,req,res,schema,conn, pToken.get(), sz, &pServerCtx);
		}
	}
	catch (NodeSSPIException& ex){
		CleanupAuthenicationResources(conn, pServerCtx);
		args[2]->ToObject()->Set(String::New("statusCode"), Integer::New(ex.http_code));
		Handle<Value> argv[] = {String::New(ex.what())};
		if(opts->Get(String::New("authoritative"))->BooleanValue()){
			res->Get(String::New("end"))->ToObject()->CallAsFunction(res, 1, argv);
		}
		if(!cb.IsEmpty())  cb->Call(cb,1,argv);
		return scope.Close(Undefined());
	}
	if(!cb.IsEmpty()) {
		cb->Call(cb,0,NULL);
	}
	return scope.Close(Undefined());
}

void init(Handle<Object> exports) {
	init_module();
	exports->Set(String::NewSymbol("authenticate"),
		FunctionTemplate::New(Authenticate)->GetFunction());
}

NODE_MODULE(nodeSSPI, init)