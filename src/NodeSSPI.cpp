#include "NodeSSPI.h"

using namespace v8;
using namespace std;

sspi_module_rec sspiModuleInfo = { 0, };

std::map<std::string, credHandleRec> credMap;

class NodeSSPIException : public std::exception {
public:
	NodeSSPIException(const char * pMsg, const UINT http_code = 500)
		: std::exception(pMsg), http_code(http_code) {
	}
	UINT http_code;
};

class Baton {
public:
	Baton() {
		err = 0;
		pGroups = 0;
		basicDomain = 0;
		pInToken = 0;
		pSCR = 0;
		isTesting = false;
	}
	~Baton() {
		if (!callback.IsEmpty())	callback.Reset();
		if (!req.IsEmpty()) req.Reset();
		if (!res.IsEmpty()) res.Reset();
		if (!conn.IsEmpty()) conn.Reset();
		if (!opts.IsEmpty()) opts.Reset();
		if (pGroups) delete pGroups;
		if (err) delete err;
		if (basicDomain) delete basicDomain;
		if (pInToken) free(pInToken);
	}
	uv_work_t request;
	Nan::Persistent<v8::Function> callback;
	//int error_code;
	//std::string error_message;

	// Custom data
	Nan::Persistent<v8::Object> req;
	Nan::Persistent<v8::Object> res;
	Nan::Persistent<v8::Object> conn;
	Nan::Persistent<v8::Object> opts;
	std::string sspiPkg;
	ULONG ss;
	std::string user;
	std::string userSid;
	bool retrieveGroups;
	NodeSSPIException * err;
	std::vector<std::string> *pGroups;
	BYTE *pInToken;
	ULONG pInTokenSz;
	sspi_connection_rec *pSCR;
	std::string *basicDomain;
	// are we running module installation testing?
	bool isTesting;
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
	LPCTSTR lpDllName = WINNT_SECURITY_DLL;
	INIT_SECURITY_INTERFACE pInit;
	SECURITY_STATUS ss = SEC_E_INTERNAL_ERROR;

	sspiModuleInfo.defaultPackage = DEFAULT_SSPI_PACKAGE;
	try {
		sspiModuleInfo.securityDLL = LoadLibrary(lpDllName);
		pInit = (INIT_SECURITY_INTERFACE)GetProcAddress(sspiModuleInfo.securityDLL, CW2A(SECURITY_ENTRYPOINT));
		sspiModuleInfo.functable = pInit();
		ss = sspiModuleInfo.functable->EnumerateSecurityPackages(&sspiModuleInfo.numPackages, &sspiModuleInfo.pkgInfo);
		if (ss != SEC_E_OK) {
			throw NodeSSPIException("Error loading SSPI module.");
		}
		sspiModuleInfo.supportsSSPI = TRUE;
	}
	catch (...) {
		sspi_module_cleanup();
		throw;
	}
}

void note_sspi_auth_failure(const Handle<Object> opts, const Handle<Object> req, Handle<Object> res) {
	int nWays = 0;
	int nSSPIPkgs = 0;
	bool offerBasic = false, offerSSPI = false;
	if (opts->Get(Nan::New<String>("offerBasic").ToLocalChecked())->BooleanValue()) {
		offerBasic = true;
		nWays += 1;
	}
	if (opts->Get(Nan::New<String>("offerSSPI").ToLocalChecked())->BooleanValue()) {
		offerSSPI = true;
		nSSPIPkgs = opts->Get(Nan::New<String>("sspiPackagesUsed").ToLocalChecked())->ToObject()->Get(Nan::New<String>("length").ToLocalChecked())->ToInteger()->Uint32Value();
		nWays += nSSPIPkgs;
	}
	auto authHArr = Nan::New<v8::Array>(nWays);
	int curIdx = 0;
	if (offerBasic) {
		std::string basicStr("Basic");
		if (opts->Has(Nan::New<String>("domain").ToLocalChecked())) {
			basicStr += " realm=\"";
			String::Utf8Value dom(opts->Get(Nan::New<String>("domain").ToLocalChecked()));
			basicStr += std::string(*dom);
			basicStr += "\"";
		}
		authHArr->Set(curIdx++, Nan::New<String>(basicStr.c_str()).ToLocalChecked());
	}
	if (offerSSPI) {
		for (int i = 0; i < nSSPIPkgs; i++) {
			authHArr->Set(curIdx++, opts->Get(Nan::New<String>("sspiPackagesUsed").ToLocalChecked())->ToObject()->Get(i));
		}
	}
	Handle<Value> argv[] = { Nan::New<String>("WWW-Authenticate").ToLocalChecked(), authHArr };
	res->Get(Nan::New<String>("setHeader").ToLocalChecked())->ToObject()->CallAsFunction(Isolate::GetCurrent()->GetCurrentContext(), res, 2, argv);
	res->Set(Nan::New<String>("statusCode").ToLocalChecked(), Nan::New<Integer>(401));
}

void CleanupAuthenicationResources(Handle<Object> conn
	, PCtxtHandle pSvrCtxHdl = NULL)
{
	try {
		if (pSvrCtxHdl && pSvrCtxHdl->dwUpper > 0 && pSvrCtxHdl->dwLower > 0) {
			sspiModuleInfo.functable->DeleteSecurityContext(pSvrCtxHdl);
			pSvrCtxHdl->dwUpper = pSvrCtxHdl->dwLower = 0;
		}
		if (conn->HasOwnProperty(Isolate::GetCurrent()->GetCurrentContext(), Nan::New<String>("svrCtx").ToLocalChecked()).FromMaybe(false)) {
			Local<External> wrap = Local<External>::Cast(conn->Get(Nan::New<String>("svrCtx").ToLocalChecked())->ToObject()->GetInternalField(0));
			sspi_connection_rec *pSCR = static_cast<sspi_connection_rec *>(wrap->Value());
			if (pSCR) {
				PCtxtHandle outPch = &pSCR->server_context;
				if (outPch && outPch->dwLower > 0 && outPch->dwUpper > 0) {
					sspiModuleInfo.functable->DeleteSecurityContext(outPch);
					outPch->dwLower = outPch->dwUpper = 0;
				}
				delete pSCR;
			}
			conn->Delete(Nan::New<String>("svrCtx").ToLocalChecked());
		}
	}
	catch (...) {}
}

/*
* get max token size defined by SSPI package
*/
ULONG getMaxTokenSz(std::string pkgNm) {
	for (ULONG i = 0; i < sspiModuleInfo.numPackages; i++) {
		if (!pkgNm.compare(CT2A(sspiModuleInfo.pkgInfo[i].Name, CP_UTF8))) {
			return sspiModuleInfo.pkgInfo[i].cbMaxToken;
		}
	}
	throw new NodeSSPIException(("No " + pkgNm + " SSPI package.").c_str());
}

/*
* Get sid from acct name
*/
void GetSid(
	LPCTSTR wszAccName,
	PSID * ppSid
	)
{
	// Validate the input parameters.
	if (wszAccName == NULL || ppSid == NULL)
	{
		throw new NodeSSPIException("Cannot obtain user account.");
	}
	// Create buffers that may be large enough.
	// If a buffer is too small, the count parameter will be set to the size needed.
	const DWORD INITIAL_SIZE = 32;
	DWORD cbSid = 0;
	DWORD dwSidBufferSize = INITIAL_SIZE;
	DWORD cchDomainName = 0;
	DWORD dwDomainBufferSize = INITIAL_SIZE;
	TCHAR * wszDomainName = NULL;
	SID_NAME_USE eSidType;

	try {
		// Create buffers for the SID and the domain name.
		*ppSid = (PSID) new BYTE[dwSidBufferSize];
		if (*ppSid == NULL)
		{
			throw new NodeSSPIException("Cannot obtain user account.");
		}
		memset(*ppSid, 0, dwSidBufferSize);
		wszDomainName = new TCHAR[dwDomainBufferSize];
		if (wszDomainName == NULL)
		{
			throw new NodeSSPIException("Cannot obtain user account.");
		}
		memset(wszDomainName, 0, dwDomainBufferSize*sizeof(TCHAR));


		// Obtain the SID for the account name passed.
		for (; ; )
		{

			// Set the count variables to the buffer sizes and retrieve the SID.
			cbSid = dwSidBufferSize;
			cchDomainName = dwDomainBufferSize;
			if (LookupAccountName(
				NULL,            // Computer name. NULL for the local computer
				wszAccName,
				*ppSid,          // Pointer to the SID buffer. Use NULL to get the size needed,
				&cbSid,          // Size of the SID buffer needed.
				wszDomainName,   // wszDomainName,
				&cchDomainName,
				&eSidType
				))
			{
				if (IsValidSid(*ppSid) == FALSE)
				{
					throw new NodeSSPIException("Cannot obtain user account.");
				}
				break;
			}

			// Check if one of the buffers was too small.
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				if (cbSid > dwSidBufferSize)
				{

					// Reallocate memory for the SID buffer.
					FreeSid(*ppSid);
					*ppSid = (PSID) new BYTE[cbSid];
					if (*ppSid == NULL)
					{
						throw new NodeSSPIException("Cannot obtain user account.");
					}
					memset(*ppSid, 0, cbSid);
					dwSidBufferSize = cbSid;
				}
				if (cchDomainName > dwDomainBufferSize)
				{
					// Reallocate memory for the domain name buffer.
					delete[] wszDomainName;
					wszDomainName = new TCHAR[cchDomainName];
					if (wszDomainName == NULL)
					{
						throw new NodeSSPIException("Cannot obtain user account.");
					}
					memset(wszDomainName, 0, cchDomainName*sizeof(TCHAR));
					dwDomainBufferSize = cchDomainName;
				}
			}
			else
			{
				throw new NodeSSPIException("Cannot obtain user account.");
				break;
			}
		}
	}
	catch (...) {
		if (*ppSid) delete[] * ppSid;
		if (wszDomainName) delete[] wszDomainName;
		throw;
	}
	delete[] wszDomainName;
}

/*
* Acquire sharable server credentials by schema honoring expiry timestamp
*/
void acquireServerCredential(std::string schema) {
	if (credMap.find(schema) == credMap.end()) {
		credHandleRec temp = { 0, 0 };
		credMap[schema] = temp;
	}
	FILETIME ft;
	SYSTEMTIME st;
	GetSystemTime(&st); // gets current time
	SystemTimeToFileTime(&st, &ft); // converts to file time format
	if (CompareFileTime(&ft, (FILETIME *)(&credMap[schema].exp)) > 0) {
		sspiModuleInfo.functable->FreeCredentialsHandle(&credMap[schema].credHandl);
		// cred expired, re-generate
		if (sspiModuleInfo.functable->AcquireCredentialsHandle(
			NULL //pszPrincipal
			, (LPTSTR)(CA2T(schema.c_str(), CP_UTF8)) //pszPackage
			, SECPKG_CRED_INBOUND //fCredentialUse
			, NULL // pvLogonID
			, NULL //pAuthData
			, NULL //pGetKeyFn
			, NULL //pvGetKeyArgument
			, &credMap[schema].credHandl //phCredential
			, &credMap[schema].exp //ptsExpiry
			) != SEC_E_OK) {
			throw new NodeSSPIException("Cannot get server credential");
		}

	}
}

static ULONG gen_client_context(CredHandle *pCredentials
	, LPCTSTR pkgNm, BYTE *pInToken, ULONG *pInLen
	, PCtxtHandle outPch, BYTE *out, ULONG * pOutlen, TimeStamp *pTS) {
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
		, (LPTSTR)pkgNm //  _In_opt_     SEC_CHAR *pszTargetName,
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
	, PCtxtHandle outPch, BYTE *out, ULONG * pOutlen, TimeStamp *pTS) {
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

void AddUserGroupsToConnection(HANDLE usertoken, vector<std::string> *pGroups)
{
	TOKEN_GROUPS *groupinfo = NULL;
	DWORD groupinfosize = 0;
	SID_NAME_USE sidtype;
	wchar_t group_name[_MAX_PATH], domain_name[_MAX_PATH];
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
	for (i = 0; i < groupinfo->GroupCount; i++) {
		grouplen = _MAX_PATH;
		domainlen = _MAX_PATH;
		if (LookupAccountSidW(NULL, groupinfo->Groups[i].Sid,
			group_name, &grouplen,
			domain_name, &domainlen,
			&sidtype)) {
			std::string grpNm = std::string(CW2A(domain_name, CP_UTF8)) + std::string("\\") + std::string(CW2A(group_name, CP_UTF8));
			pGroups->push_back(grpNm);
		}
	}
	free(groupinfo);
}

void RetrieveUserGroups(PCtxtHandle pServerCtx, vector<std::string> *pGroups) {
	// Retrieve user groups if requested, then call CleanupAuthenicationResources
	HANDLE userToken;
	ULONG ss;
	try {
		if ((ss = sspiModuleInfo.functable->ImpersonateSecurityContext(pServerCtx)) != SEC_E_OK) {
			throw new NodeSSPIException("Cannot impersonate user.");
		}

		if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY_SOURCE | TOKEN_READ, TRUE, &userToken)) {
			sspiModuleInfo.functable->RevertSecurityContext(pServerCtx);
			throw new NodeSSPIException("Cannot obtain user token.");
		}
		if ((ss = sspiModuleInfo.functable->RevertSecurityContext(pServerCtx)) != SEC_E_OK) {
			throw new NodeSSPIException("Cannot revert security context.");
		}
		AddUserGroupsToConnection(userToken, pGroups);
	}
	catch (...) {
		CloseHandle(userToken);
		throw;
	}
}

void WrapUpAsyncAfterAuth(Baton* pBaton) {
	Local<Object> lRes = Nan::New(pBaton->res);
	Local<Object> lOpts = Nan::New(pBaton->opts);
	if (pBaton->err) {
		lRes->Set(Nan::New<String>("statusCode").ToLocalChecked(), Nan::New<Integer>(pBaton->err->http_code));
		pBaton->res.Reset(lRes);
		Handle<Value> argv[] = { Nan::New<String>(pBaton->err->what()).ToLocalChecked() };
		if (lOpts->Get(Nan::New<String>("authoritative").ToLocalChecked())->BooleanValue()) {
			lRes->Get(Nan::New<String>("end").ToLocalChecked())->ToObject()->CallAsFunction(Isolate::GetCurrent()->GetCurrentContext(), lRes, 1, argv);
		}
		if (!pBaton->callback.IsEmpty()) {
			Local<Function> lCb = Nan::New(pBaton->callback);
			lCb->Call(lCb, 1, argv);
		}
	}
	else {
		if (lRes->Get(Nan::New<String>("statusCode").ToLocalChecked())->Int32Value() == 401) {
			Handle<Value> argv[] = { Nan::New<String>("Login aborted.").ToLocalChecked() };
			if (lOpts->Get(Nan::New<String>("authoritative").ToLocalChecked())->BooleanValue()) {
				lRes->Get(Nan::New<String>("end").ToLocalChecked())->ToObject()->CallAsFunction(Isolate::GetCurrent()->GetCurrentContext(), lRes, 1, argv);
			}
		}
		if (!pBaton->callback.IsEmpty()) {
			Local<Function> lCb = Nan::New(pBaton->callback);
			lCb->Call(lCb, 0, NULL);
		}
	}
	delete pBaton;
}

void AsyncBasicAuth(uv_work_t* req) {
	Baton* pBaton = static_cast<Baton*>(req->data);
	try {
		std::string sspiPkg = pBaton->sspiPkg;
		acquireServerCredential(sspiPkg);
		BYTE * pInToken = pBaton->pInToken;
		ULONG sz = pBaton->pInTokenSz;
		// get domain, user name, password
		std::string domainNnm, domain, nm, pswd, inStr((char*)pInToken);
		if (pBaton->basicDomain) domain = *pBaton->basicDomain;
		domainNnm = inStr.substr(0, inStr.find_first_of(":"));
		if (domainNnm.length() == 0) {
			pBaton->ss = SEC_E_LOGON_DENIED;
			return;
		}
		if (domainNnm.find("\\") != std::string::npos) {
			domain = domainNnm.substr(0, domainNnm.find_first_of("\\"));
			nm = domainNnm.substr(domainNnm.find_first_of("\\") + 1);
		}
		else {
			nm = domainNnm;
		}
		pswd = inStr.substr(inStr.find_first_of(":") + 1);
		// acquire client credential
		SEC_WINNT_AUTH_IDENTITY authIden;

		CA2T domaint(domain.c_str(), CP_UTF8);
		authIden.Domain = (unsigned short *)LPTSTR(domaint);
		authIden.DomainLength = static_cast<unsigned long>(_tcslen(domaint));
		CA2T nmt(nm.c_str(), CP_UTF8);
		authIden.User = (unsigned short *)LPTSTR(nmt);
		authIden.UserLength = static_cast<unsigned long>(_tcslen(nmt));
		CA2T pswt(pswd.c_str(), CP_UTF8);
		authIden.Password = (unsigned short *)LPTSTR(pswt);
		authIden.PasswordLength = static_cast<unsigned long>(_tcslen(pswt));
#ifdef UNICODE
		authIden.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
#else
		authIden.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
#endif
		auto pSCR = new sspi_connection_rec();
		auto pServerCtx = &pSCR->server_context;
		pSCR->server_context.dwLower = pSCR->server_context.dwUpper = 0;
		pBaton->pSCR = pSCR;
		ULONG tokSz = getMaxTokenSz(sspiPkg);
		CredHandle clientCred;
		TimeStamp clientCredTs;
		if (sspiModuleInfo.functable->AcquireCredentialsHandle(
			NULL,
			(LPTSTR)CA2T(sspiPkg.c_str(), CP_UTF8),
			SECPKG_CRED_OUTBOUND,
			NULL, ((pBaton->isTesting) ? NULL : &authIden), NULL, NULL,
			&clientCred,
			&clientCredTs) != SEC_E_OK) {
			throw new NodeSSPIException("Cannot acquire client credential.");
		};

		// perform authentication loop
		ULONG cbOut, cbIn;
		BYTE *clientbuf = NULL;
		ULONG ss;
		unique_ptr<BYTE[]> pServerbuf(new BYTE[tokSz]), pClientBuf(new BYTE[tokSz]);
		cbOut = 0;
		CtxtHandle client_context = { 0,0 };
		TimeStamp client_ctxtexpiry;
		do {
			cbIn = cbOut;
			cbOut = tokSz;
			ss = gen_client_context(&clientCred, CA2T(sspiPkg.c_str(), CP_UTF8)
				, clientbuf, &cbIn, &client_context, pServerbuf.get(), &cbOut, &client_ctxtexpiry);

			if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED || ss == SEC_I_COMPLETE_AND_CONTINUE) {
				if (clientbuf == NULL) {
					clientbuf = pClientBuf.get();
				}
				cbIn = cbOut;
				cbOut = tokSz;
				ss = gen_server_context(&credMap[sspiPkg].credHandl, pServerbuf.get()
					, &cbIn, pServerCtx, clientbuf, &cbOut, &pSCR->server_ctxtexpiry);
			}
		} while (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_I_COMPLETE_AND_CONTINUE);
		sspiModuleInfo.functable->DeleteSecurityContext(&client_context);
		sspiModuleInfo.functable->FreeCredentialsHandle(&clientCred);
		pBaton->ss = ss;
		if (ss == SEC_E_OK) {
			// get user name
			SecPkgContext_Names names;
			SECURITY_STATUS ss;
			char *retval = NULL;

			if ((ss = sspiModuleInfo.functable->QueryContextAttributes(pServerCtx,
				SECPKG_ATTR_NAMES,
				&names)
				) == SEC_E_OK) {
				pBaton->user = CT2A(names.sUserName, CP_UTF8);
				PSID pSid = NULL;
				LPTSTR StringSid;
				GetSid(names.sUserName, &pSid);
				ConvertSidToStringSid(pSid, &StringSid);
				delete[] pSid;
				pBaton->userSid = std::string(CT2A(StringSid, CP_UTF8));
				LocalFree(StringSid);
				sspiModuleInfo.functable->FreeContextBuffer(names.sUserName);
				if (pBaton->retrieveGroups) {
					pBaton->pGroups = new vector<std::string>();
					RetrieveUserGroups(pServerCtx, pBaton->pGroups);
				}
			}
			else {
				throw new NodeSSPIException("Cannot obtain user name.");
			}
		}
	}
	catch (NodeSSPIException *ex) {
		pBaton->err = ex;
	}
}

void AsyncAfterBasicAuth(uv_work_t* uvReq, int status) {
	Nan::HandleScope scope;
	Baton* pBaton = static_cast<Baton*>(uvReq->data);
	try {
		ULONG ss = pBaton->ss;
		auto conn = Nan::New(pBaton->conn);
		auto req = Nan::New(pBaton->req);
		auto res = Nan::New(pBaton->res);
		auto opts = Nan::New(pBaton->opts);
		if (pBaton->err) throw pBaton->err;
		auto pServerCtx = &pBaton->pSCR->server_context;
		CleanupAuthenicationResources(conn, pServerCtx);
		switch (ss) {
		case SEC_E_OK:
		{
			if (!pBaton->user.empty()) {
				conn->Set(Nan::New<String>("user").ToLocalChecked(), Nan::New<String>(pBaton->user.c_str()).ToLocalChecked());
				if (pBaton->pGroups) {
					auto groups = Nan::New<v8::Array>(static_cast<uint32_t>(pBaton->pGroups->size()));
					for (ULONG i = 0; i < pBaton->pGroups->size(); i++) {
						groups->Set(i, Nan::New<String>(pBaton->pGroups->at(i).c_str()).ToLocalChecked());
					}
					conn->Set(Nan::New<String>("userGroups").ToLocalChecked(), groups);
				}
			}
			else {
				throw new NodeSSPIException("Cannot obtain user name.");
			}
			if (!pBaton->userSid.empty()) {
				conn->Set(Nan::New<String>("userSid").ToLocalChecked(), Nan::New<String>(pBaton->userSid.c_str()).ToLocalChecked());
			}
			break;
		}
		case SEC_E_INVALID_HANDLE:
		case SEC_E_INTERNAL_ERROR:
		case SEC_E_NO_AUTHENTICATING_AUTHORITY:
		case SEC_E_INSUFFICIENT_MEMORY:
		{
			res->Set(Nan::New<String>("statusCode").ToLocalChecked(), Nan::New<Integer>(500));
			break;
		}
		case SEC_E_INVALID_TOKEN:
		case SEC_E_LOGON_DENIED:
		default:
		{
			note_sspi_auth_failure(opts, req, res);
			if (!conn->HasOwnProperty(Isolate::GetCurrent()->GetCurrentContext(), Nan::New<String>("remainingAttempts").ToLocalChecked()).FromMaybe(false)) {
				conn->Set(Nan::New<String>("remainingAttempts").ToLocalChecked()
					, Nan::New<Integer>(opts->Get(Nan::New<String>("maxLoginAttemptsPerConnection").ToLocalChecked())->Int32Value() - 1));
			}
			int remainingAttmpts = conn->Get(Nan::New<String>("remainingAttempts").ToLocalChecked())->Int32Value();
			if (remainingAttmpts <= 0) {
				throw new NodeSSPIException("Max login attempts reached.", 403);
			}
			conn->Set(Nan::New<String>("remainingAttempts").ToLocalChecked()
				, Nan::New<Integer>(remainingAttmpts - 1));
			break;
		}
		}
	}
	catch (NodeSSPIException *ex) {
		pBaton->err = ex;
	}
	// SCR doesn't span across requests for basic auth
	delete pBaton->pSCR;
	WrapUpAsyncAfterAuth(pBaton);
}

void basic_authentication(const Local<Object> opts, const Local<Object> req
	, Local<Object> res, Local<Object> conn, BYTE *pInToken
	, ULONG sz, Local<Function> cb) {
	std::string sspiPkg(sspiModuleInfo.defaultPackage);
	if (opts->Has(Nan::New<String>("sspiPackagesUsed").ToLocalChecked())) {
		auto firstSSPIPackage = opts->Get(Nan::New<String>("sspiPackagesUsed").ToLocalChecked())->ToObject()->Get(0);
		sspiPkg = *v8::String::Utf8Value(firstSSPIPackage);
	}
	Baton *pBaton = new Baton();
	pBaton->request.data = pBaton;
	pBaton->callback.Reset(cb);
	pBaton->req.Reset(req);
	pBaton->conn.Reset(conn);
	pBaton->res.Reset(res);
	pBaton->opts.Reset(opts);
	pBaton->sspiPkg = sspiPkg;
	pBaton->pInToken = pInToken;
	pBaton->pInTokenSz = sz;
	pBaton->retrieveGroups = opts->Get(Nan::New<String>("retrieveGroups").ToLocalChecked())->BooleanValue();
	if (req->HasOwnProperty(Isolate::GetCurrent()->GetCurrentContext(), Nan::New<String>("isTestingNodeSSPI").ToLocalChecked()).FromMaybe(false)
		&& req->Get(Nan::New<String>("isTestingNodeSSPI").ToLocalChecked())->BooleanValue()) {
		pBaton->isTesting = true;
	}
	if (opts->Has(Nan::New<String>("domain").ToLocalChecked())) {
		pBaton->basicDomain = new std::string(*String::Utf8Value(opts->Get(Nan::New<String>("domain").ToLocalChecked())));
	}
	uv_queue_work(uv_default_loop(), &pBaton->request,
		AsyncBasicAuth, AsyncAfterBasicAuth);
}

NAN_METHOD(onConnectionClose) {
	Local<v8::Object> conn = info.This();
	CleanupAuthenicationResources(conn);
}

void AsyncSSPIAuth(uv_work_t* req) {
	Baton* pBaton = static_cast<Baton*>(req->data);
	try {
		std::string schema = pBaton->sspiPkg;
		acquireServerCredential(schema);
		PCtxtHandle outPch = &pBaton->pSCR->server_context;
		PTimeStamp pTS = &pBaton->pSCR->server_ctxtexpiry;

		BYTE * pInToken = pBaton->pInToken;
		ULONG sz = pBaton->pInTokenSz;
		ULONG tokSz = getMaxTokenSz(schema);
		// call AcceptSecurityContext to generate server context
		BYTE * pOutBuf = new BYTE[tokSz];
		ULONG ss = gen_server_context(&credMap[schema].credHandl
			, pInToken, &sz, outPch, pOutBuf, &tokSz, pTS);
		pBaton->ss = ss;
		if (pBaton->pInToken) free(pBaton->pInToken);
		pBaton->pInToken = pOutBuf;
		pBaton->pInTokenSz = tokSz;
		if (ss == SEC_E_OK)
		{
			// get user name
			SecPkgContext_Names names;
			SECURITY_STATUS ss;
			char *retval = NULL;

			if ((ss = sspiModuleInfo.functable->QueryContextAttributes(outPch,
				SECPKG_ATTR_NAMES,
				&names)
				) == SEC_E_OK) {
				PSID pSid = NULL;
				GetSid(names.sUserName, &pSid);
				if (IsWellKnownSid(pSid, WinAnonymousSid)) {
					pBaton->ss = SEC_E_INVALID_TOKEN;
				}
				else {
					pBaton->user = std::string(CT2A(names.sUserName, CP_UTF8));
					LPTSTR StringSid;
					GetSid(names.sUserName, &pSid);
					ConvertSidToStringSid(pSid, &StringSid);
					pBaton->userSid = std::string(CT2A(StringSid, CP_UTF8));
					LocalFree(StringSid);
					if (pBaton->retrieveGroups) {
						pBaton->pGroups = new vector<std::string>();
						RetrieveUserGroups(outPch, pBaton->pGroups);
					}
				}
				delete[] pSid;
				sspiModuleInfo.functable->FreeContextBuffer(names.sUserName);
			}
			else {
				throw new NodeSSPIException("Cannot obtain user name.");
			}
		}
	}
	catch (NodeSSPIException *ex) {
		pBaton->err = ex;
	}
}

void AsyncAfterSSPIAuth(uv_work_t* uvReq, int status) {
	Nan::HandleScope scope;
	Baton* pBaton = static_cast<Baton*>(uvReq->data);
	BYTE *  pOutBuf = pBaton->pInToken;
	auto opts = Nan::New(pBaton->opts);
	auto res = Nan::New(pBaton->res);
	try {
		ULONG ss = pBaton->ss;
		auto conn = Nan::New(pBaton->conn);
		auto req = Nan::New(pBaton->req);
		if (pBaton->err) throw pBaton->err;
		ULONG tokSz = pBaton->pInTokenSz;
		switch (ss) {
		case SEC_I_COMPLETE_NEEDED:
		case SEC_I_CONTINUE_NEEDED:
		case SEC_I_COMPLETE_AND_CONTINUE:
		{
			CStringA base64;
			int base64Length = Base64EncodeGetRequiredLength(tokSz);
			Base64Encode(pOutBuf,
				tokSz,
				base64.GetBufferSetLength(base64Length),
				&base64Length, ATL_BASE64_FLAG_NOCRLF);
			base64.ReleaseBufferSetLength(base64Length);
			std::string authHStr = pBaton->sspiPkg + " " + std::string(base64.GetString());
			Handle<Value> argv[] = { Nan::New<String>("WWW-Authenticate").ToLocalChecked(), Nan::New<String>(authHStr.c_str()).ToLocalChecked() };
			res->Get(Nan::New<String>("setHeader").ToLocalChecked())->ToObject()->CallAsFunction(Isolate::GetCurrent()->GetCurrentContext(), res, 2, argv);
			res->Set(Nan::New<String>("statusCode").ToLocalChecked(), Nan::New<Integer>(401));
			break;
		}
		case SEC_E_INVALID_TOKEN:
		case SEC_E_LOGON_DENIED:
		{
			note_sspi_auth_failure(opts, req, res);
			CleanupAuthenicationResources(conn, &pBaton->pSCR->server_context);
			if (!conn->HasOwnProperty(Isolate::GetCurrent()->GetCurrentContext(), Nan::New<String>("remainingAttempts").ToLocalChecked()).FromMaybe(false)) {
				conn->Set(Nan::New<String>("remainingAttempts").ToLocalChecked()
					, Nan::New<Integer>(opts->Get(Nan::New<String>("maxLoginAttemptsPerConnection").ToLocalChecked())->Int32Value() - 1));
			}
			int remainingAttmpts = conn->Get(Nan::New<String>("remainingAttempts").ToLocalChecked())->Int32Value();
			if (remainingAttmpts <= 0) {
				throw new NodeSSPIException("Max login attempts reached.", 403);
			}
			conn->Set(Nan::New<String>("remainingAttempts").ToLocalChecked()
				, Nan::New<Integer>(remainingAttmpts - 1));
			break;
		}
		case SEC_E_INVALID_HANDLE:
		case SEC_E_INTERNAL_ERROR:
		case SEC_E_NO_AUTHENTICATING_AUTHORITY:
		case SEC_E_INSUFFICIENT_MEMORY:
		{
			CleanupAuthenicationResources(conn, &pBaton->pSCR->server_context);
			res->Set(Nan::New<String>("statusCode").ToLocalChecked(), Nan::New<Integer>(500));
			break;
		}
		case SEC_E_OK:
		{
			CleanupAuthenicationResources(conn, &pBaton->pSCR->server_context);
			if (!pBaton->user.empty()) {
				conn->Set(Nan::New<String>("user").ToLocalChecked(), Nan::New<String>(pBaton->user.c_str()).ToLocalChecked());
				if (pBaton->pGroups) {
					auto groups = Nan::New<v8::Array>(static_cast<uint32_t>(pBaton->pGroups->size()));
					for (ULONG i = 0; i < pBaton->pGroups->size(); i++) {
						groups->Set(i, Nan::New<String>(pBaton->pGroups->at(i).c_str()).ToLocalChecked());
					}
					conn->Set(Nan::New<String>("userGroups").ToLocalChecked(), groups);
				}

			}
			else {
				throw new NodeSSPIException("Cannot obtain user name.");
			}
			if (!pBaton->userSid.empty()) {
				conn->Set(Nan::New<String>("userSid").ToLocalChecked(), Nan::New<String>(pBaton->userSid.c_str()).ToLocalChecked());
			}

			break;
		}
		}
	}
	catch (NodeSSPIException *ex) {
		pBaton->err = ex;
	}
	WrapUpAsyncAfterAuth(pBaton);
}

void sspi_authentication(const Local<Object> opts, const Local<Object> req
	, Local<Object> res, std::string schema, Local<Object> conn, BYTE *pInToken
	, ULONG sz, Local<Function> cb) {
	// acquire server context from request.connection
	sspi_connection_rec *pSCR = 0;
	if (conn->HasOwnProperty(Isolate::GetCurrent()->GetCurrentContext(), Nan::New<String>("svrCtx").ToLocalChecked()).FromMaybe(false)) {
		// this is not initial request
		Local<External> wrap = Local<External>::Cast(conn->Get(Nan::New<String>("svrCtx").ToLocalChecked())->ToObject()->GetInternalField(0));
		pSCR = static_cast<sspi_connection_rec *>(wrap->Value());
	}
	else {
		pSCR = new sspi_connection_rec();
		pSCR->server_context.dwLower = pSCR->server_context.dwUpper = 0;
		Isolate* isolate = Isolate::GetCurrent();
		Handle<ObjectTemplate> svrCtx_templ = Nan::New<ObjectTemplate>();
		svrCtx_templ->SetInternalFieldCount(1);
		Local<Object> lObj = svrCtx_templ->NewInstance();
		lObj->SetInternalField(0, Nan::New<External>(pSCR));
		// use conn socket to hold pSCR
		conn->Set(Nan::New<String>("svrCtx").ToLocalChecked(), lObj);
		// hook to socket close event to clean up abandoned in-progress authentications
		// necessary to defend against attacks similar to sync flood 
		Handle<Value> argv[] = { Nan::New<String>("close").ToLocalChecked(), Nan::New<FunctionTemplate>(onConnectionClose)->GetFunction() };
		conn->Get(Nan::New<String>("on").ToLocalChecked())->ToObject()->CallAsFunction(Isolate::GetCurrent()->GetCurrentContext(), conn, 2, argv);
	}
	Baton *pBaton = new Baton();
	pBaton->request.data = pBaton;
	pBaton->callback.Reset(cb);
	pBaton->req.Reset(req);
	pBaton->conn.Reset(conn);
	pBaton->res.Reset(res);
	pBaton->opts.Reset(opts);
	pBaton->sspiPkg = schema;
	pBaton->pInToken = pInToken;
	pBaton->pInTokenSz = sz;
	pBaton->pSCR = pSCR;
	pBaton->retrieveGroups = opts->Get(Nan::New<String>("retrieveGroups").ToLocalChecked())->BooleanValue();
	uv_queue_work(uv_default_loop(), &pBaton->request,
		AsyncSSPIAuth, AsyncAfterSSPIAuth);
}

/*
* args[0]: opts
* args[1]: req
* args[2]: res
*/
NAN_METHOD(Authenticate) {
	auto opts = info[0]->ToObject();
	auto res = info[2]->ToObject();
	Local<Object> conn;
	Local<Function> cb;
	if (info[3]->IsFunction()) {
		cb = Local<Function>::Cast(info[3]);
	}
	try {
		auto req = info[1]->ToObject();
		conn = req->Get(Nan::New<String>("connection").ToLocalChecked())->ToObject();
		if (conn->HasOwnProperty(Isolate::GetCurrent()->GetCurrentContext(), Nan::New<String>("user").ToLocalChecked()).FromMaybe(false)) {
			if (!cb.IsEmpty()) {
				cb->Call(cb, 0, NULL);
			}
			return;
		}
		if (sspiModuleInfo.supportsSSPI == FALSE) {
			throw NodeSSPIException("Doesn't suport SSPI.");
		}
		auto headers = req->Get(Nan::New<String>("headers").ToLocalChecked())->ToObject();

		if (conn->HasOwnProperty(Isolate::GetCurrent()->GetCurrentContext(), Nan::New<String>("remainingAttempts").ToLocalChecked()).FromMaybe(false)) {
			int remainingAttmpts = conn->Get(Nan::New<String>("remainingAttempts").ToLocalChecked())->Int32Value();
			if (remainingAttmpts < 0) {
				throw NodeSSPIException("Max login attempts reached.", 403);
			}
		}

		if (!headers->Has(Nan::New<String>("authorization").ToLocalChecked())) {
			note_sspi_auth_failure(opts, req, res);
			if (opts->Get(Nan::New<String>("authoritative").ToLocalChecked())->BooleanValue()
				&& !req->Get(Nan::New<String>("connection").ToLocalChecked())->ToObject()->Has(Nan::New<String>("user").ToLocalChecked())
				) {
				res->Get(Nan::New<String>("end").ToLocalChecked())->ToObject()->CallAsFunction(Isolate::GetCurrent()->GetCurrentContext(), res, 0, NULL);
			}
			if (!cb.IsEmpty()) {
				cb->Call(cb, 0, NULL);
			}
			return;
		}
		auto aut = std::string(*String::Utf8Value(headers->Get(Nan::New<String>("authorization").ToLocalChecked())));
		stringstream ssin(aut);
		std::string schema, strToken;
		ssin >> schema;
		ssin >> strToken;
		// base64 decode strToken
		int sz = static_cast<int>(strToken.length());
		BYTE * pToken = static_cast<BYTE*>(calloc(sz, 1));
		if (!Base64Decode(strToken.c_str(), sz, pToken, &sz)) {
			throw NodeSSPIException("Cannot decode authorization field.");
		};
		if (_stricmp(schema.c_str(), "basic") == 0) {
			basic_authentication(opts, req, res, conn, pToken, sz, cb);
		}
		else {
			sspi_authentication(opts, req, res, schema, conn, pToken, sz, cb);
		}
	}
	catch (NodeSSPIException &ex) {
		CleanupAuthenicationResources(conn);
		info[2]->ToObject()->Set(Nan::New<String>("statusCode").ToLocalChecked(), Nan::New<Integer>(ex.http_code));
		Handle<Value> argv[] = { Nan::New<String>(ex.what()).ToLocalChecked() };
		if (opts->Get(Nan::New<String>("authoritative").ToLocalChecked())->BooleanValue()) {
			res->Get(Nan::New<String>("end").ToLocalChecked())->ToObject()->CallAsFunction(Isolate::GetCurrent()->GetCurrentContext(), res, 1, argv);
		}
		if (!cb.IsEmpty())  cb->Call(cb, 1, argv);
	}
}

void init(Handle<Object> exports) {
	init_module();
	exports->Set(Nan::New<String>("authenticate").ToLocalChecked(),
		Nan::New<FunctionTemplate>(Authenticate)->GetFunction());
}

NODE_MODULE(nodeSSPI, init)
