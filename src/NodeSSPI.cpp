#include "NodeSSPI.h"

using namespace v8;
using namespace std;

sspi_module_rec sspiModuleInfo = { 0, };

std::map<std::string, credHandleRec> credMap;

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
	BYTE* pToken;
	try{
		if (sspiModuleInfo.supportsSSPI == FALSE) {
			throw std::exception("Doesn't suport SSPI.");
		}
		auto req = args[1]->ToObject();
		auto res = args[2]->ToObject();
		auto aut = std::string(*String::AsciiValue(req->Get(String::New("headers"))->ToObject()->Get(String::New("authorization"))));
		stringstream ssin(aut);
		std::string schema, strToken;
		ssin >> schema;
		ssin >> strToken;
		// base64 decode strToken
		unique_ptr<BYTE[]> pToken(new BYTE[strToken.length()]);
		int sz = strToken.length();
		if (!Base64Decode(strToken.c_str(), strToken.length(), pToken.get(), &sz)){
			throw std::exception("Cannot decode authorization field.");
		};
		// get max token size defined by SSPI package
		ULONG maxTokSz, i;
		for (i = 0; i < sspiModuleInfo.numPackages; i++){
			if (!schema.compare(sspiModuleInfo.pkgInfo[i].Name)){
				maxTokSz = sspiModuleInfo.pkgInfo[i].cbMaxToken;
				break;
			}
		}
		if (i == sspiModuleInfo.numPackages){
			throw std::exception(("No " + schema + " SSPI package.").c_str());
		}
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
				throw std::exception("Cannot get server credential");
			}

		}
		// acquire server context from request.connection
		sspi_connection_rec *pSCR = 0;
		PCtxtHandle inPch = 0, outPch = 0;
		PTimeStamp pTS;
		auto conn = req->Get(String::New("connection"))->ToObject();
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
		inbuf.pvBuffer = pToken.get();
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
		case SEC_I_COMPLETE_AND_CONTINUE: {
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
			//log_sspi_invalid_token(ctx->r, &ctx->hdr, APR_FROM_OS_ERROR(GetLastError()));
			//ctx->scr->sspi_failing = 1;
			//ctx->scr->package = 0;
			//note_sspi_auth_failure(ctx->r);
			//cleanup_sspi_connection(ctx->scr);
			//return HTTP_UNAUTHORIZED;
			res->Set(String::New("statusCode"), Integer::New(401));
			break;

		case SEC_E_LOGON_DENIED:
			//log_sspi_logon_denied(ctx->r, &ctx->hdr, APR_FROM_OS_ERROR(GetLastError()));
			//ctx->scr->sspi_failing = 1;
			//ctx->scr->package = 0;
			//note_sspi_auth_failure(ctx->r);
			//cleanup_sspi_connection(ctx->scr);
			//return HTTP_UNAUTHORIZED;
			res->Set(String::New("statusCode"), Integer::New(401));
			break;

		case SEC_E_INVALID_HANDLE:
		case SEC_E_INTERNAL_ERROR:
		case SEC_E_NO_AUTHENTICATING_AUTHORITY:
		case SEC_E_INSUFFICIENT_MEMORY:
			//ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_FROM_OS_ERROR(GetLastError()), ctx->r,
			//	"access to %s failed, reason: cannot generate server context", ctx->r->uri);
			//return HTTP_INTERNAL_SERVER_ERROR;
			res->Set(String::New("statusCode"), Integer::New(500));
			break;
		case SEC_E_OK:
			//return OK;
			break;
		}

		req->Set(String::New("user"), String::New("Fred"));
	}
	catch (std::exception& ex){
		args[2]->ToObject()->Set(String::New("statusCode"), Integer::New(500));
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