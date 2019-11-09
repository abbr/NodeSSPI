#include "NodeSSPI.h"

using namespace Napi;
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

void note_sspi_auth_failure(const Napi::Env env, const Napi::Object opts, const Napi::Object req, Napi::Object res) {

	int nWays = 0;
	int nSSPIPkgs = 0;
	bool offerBasic = false, offerSSPI = false;
	if (opts.Get(Napi::String::New(env, "offerBasic")).As<Napi::Boolean>().Value()) {
		offerBasic = true;
		nWays += 1;
	}
	if (opts.Get(Napi::String::New(env, "offerSSPI")).As<Napi::Boolean>().Value()) {
		offerSSPI = true;
		nSSPIPkgs = opts.Get(Napi::String::New(env, "sspiPackagesUsed")).ToObject().Get(Napi::String::New(env, "length")).As<Napi::Number>().Uint32Value();
		nWays += nSSPIPkgs;
	}
	auto authHArr = Napi::Array::New(env, nWays);
	int curIdx = 0;

	if (offerSSPI) {
		for (int i = 0; i < nSSPIPkgs; i++) {
			authHArr.Set(curIdx++, opts.Get(Napi::String::New(env, "sspiPackagesUsed")).ToObject().Get(i));
		}
	}
	if (offerBasic) {
		std::string basicStr("Basic");
		if (opts.Get(Napi::String::New(env, "domain"))) {
			basicStr += " realm=\"";
			basicStr += opts.Get(Napi::String::New(env, "domain")).ToString().Utf8Value();
			basicStr += "\"";
		}
		authHArr.Set(curIdx++, Napi::String::New(env, basicStr.c_str()));
	}
	napi_value argv[] = { Napi::String::New(env, "WWW-Authenticate"), authHArr };
	res.Get(Napi::String::New(env, "setHeader")).As<Napi::Function>().Call(res, 2, argv);
	res.Set(Napi::String::New(env, "statusCode"), Napi::Number::New(env, 401));
}

void CleanupAuthenicationResources(Napi::Env env, Napi::Object conn
, PCtxtHandle pSvrCtxHdl = NULL)
{
	try {
		if (pSvrCtxHdl && pSvrCtxHdl->dwUpper > 0 && pSvrCtxHdl->dwLower > 0) {
			sspiModuleInfo.functable->DeleteSecurityContext(pSvrCtxHdl);
			pSvrCtxHdl->dwUpper = pSvrCtxHdl->dwLower = 0;
		}
		if (conn.HasOwnProperty(Napi::String::New(env, "svrCtx"))) {
			Napi::External<sspi_connection_rec> wrap = conn.Get(Napi::String::New(env, "svrCtx")).As<Napi::External<sspi_connection_rec> >();
			sspi_connection_rec *pSCR = wrap.Data();
			if (pSCR) {
				PCtxtHandle outPch = &pSCR->server_context;
				if (outPch && outPch->dwLower > 0 && outPch->dwUpper > 0) {
					sspiModuleInfo.functable->DeleteSecurityContext(outPch);
					outPch->dwLower = outPch->dwUpper = 0;
				}
				delete pSCR;
			}
			conn.Delete(Napi::String::New(env, "svrCtx"));
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

void WrapUpAsyncAfterAuth(const Env env, Baton* pBaton) {
	Napi::Object lRes = pBaton->res.Value();
	Napi::Object lOpts = pBaton->opts.Value();
	if (pBaton->err) {
		lRes.Set(Napi::String::New(env, "statusCode"), Napi::Number::New(env, pBaton->err->http_code));
		pBaton->res.Reset(lRes);
		napi_value argv[] = { Napi::String::New(env, pBaton->err->what()) };
		if (lOpts.Get(Napi::String::New(env, "authoritative")).As<Napi::Boolean>().Value()) {
			lRes.Get(Napi::String::New(env, "end")).As<Napi::Function>().Call(lRes, 1, argv);
		}
		if (!pBaton->callback.IsEmpty()) {
			Napi::Function lCb = pBaton->callback.Value();
			lCb.Call(lCb, 1, argv);
		}
	}
	else {
		Napi::Value v = lRes.Get(Napi::String::New(env, "statusCode"));
		if (v.IsNumber() &&  v.ToNumber().Int32Value() == 401) {
			napi_value argv[] = { Napi::String::New(env, "Login aborted.") };
			if (lOpts.Get(Napi::String::New(env, "authoritative")).As<Napi::Boolean>().Value()) {
				lRes.Get(Napi::String::New(env, "end")).As<Napi::Function>().Call(lRes, 1, argv);
			}
		}
		if (!pBaton->callback.IsEmpty()) {
			Napi::Function lCb = pBaton->callback.Value();
			lCb.Call(lCb, 0, NULL);
		}
	}
	delete pBaton;
}

void AsyncBasicAuth(Baton* pBaton) {
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

void AsyncAfterBasicAuth(const Env env, Baton* pBaton/*, int status*/) {
	Napi::HandleScope scope(env);
	try {
		ULONG ss = pBaton->ss;
		auto conn = pBaton->conn.Value();
		auto req = pBaton->req.Value();
		auto res = pBaton->res.Value();
		auto opts = pBaton->opts.Value();
		if (pBaton->err) throw pBaton->err;
		auto pServerCtx = &pBaton->pSCR->server_context;
		CleanupAuthenicationResources(env, conn, pServerCtx);
		switch (ss) {
		case SEC_E_OK:
		{
			if (!pBaton->user.empty()) {
				conn.Set(Napi::String::New(env, "user"), Napi::String::New(env, pBaton->user.c_str()));
				if (pBaton->pGroups) {
					auto groups = Napi::Array::New(env, static_cast<uint32_t>(pBaton->pGroups->size()));
					for (ULONG i = 0; i < pBaton->pGroups->size(); i++) {
						groups.Set(i, Napi::String::New(env, pBaton->pGroups->at(i).c_str()));
					}
					conn.Set(Napi::String::New(env, "userGroups"), groups);
				}
			}
			else {
				throw new NodeSSPIException("Cannot obtain user name.");
			}
			if (!pBaton->userSid.empty()) {
				conn.Set(Napi::String::New(env, "userSid"), Napi::String::New(env, pBaton->userSid.c_str()));
			}
			break;
		}
		case SEC_E_INVALID_HANDLE:
		case SEC_E_INTERNAL_ERROR:
		case SEC_E_NO_AUTHENTICATING_AUTHORITY:
		case SEC_E_INSUFFICIENT_MEMORY:
		{
			res.Set(Napi::String::New(env, "statusCode"), Napi::Number::New(env, 500));
			break;
		}
		case SEC_E_INVALID_TOKEN:
		case SEC_E_LOGON_DENIED:
		default:
		{
			note_sspi_auth_failure(env, opts, req, res);
			if (!conn.HasOwnProperty(Napi::String::New(env, "remainingAttempts"))) {
				conn.Set(Napi::String::New(env, "remainingAttempts")
					, Napi::Number::New(env, opts.Get(Napi::String::New(env, "maxLoginAttemptsPerConnection")).As<Napi::Number>().Int32Value() - 1));
			}
			int remainingAttmpts = conn.Get(Napi::String::New(env, "remainingAttempts")).As<Napi::Number>().Int32Value();
			if (remainingAttmpts <= 0) {
				throw new NodeSSPIException("Max login attempts reached.", 403);
			}
			conn.Set(Napi::String::New(env, "remainingAttempts")
				, Napi::Number::New(env, remainingAttmpts - 1));
			break;
		}
		}
	}
	catch (NodeSSPIException *ex) {
		pBaton->err = ex;
	}
	// SCR doesn't span across requests for basic auth
	delete pBaton->pSCR;
	WrapUpAsyncAfterAuth(env, pBaton);
}

void basic_authentication(const Napi::Env env, const Napi::Object opts, const Napi::Object req
	, Napi::Object res, Napi::Object conn, BYTE *pInToken
	, ULONG sz, Napi::Function cb) {
	std::string sspiPkg(sspiModuleInfo.defaultPackage);
	if (opts.Has(Napi::String::New(env, "sspiPackagesUsed"))) {
		auto firstSSPIPackage = opts.Get(Napi::String::New(env, "sspiPackagesUsed")).ToObject().Get((uint32_t)0);
		sspiPkg = firstSSPIPackage.ToString().Utf8Value();
	}
	Baton *pBaton = new Baton();
	pBaton->callback.Reset(cb);
	pBaton->req.Reset(req);
	pBaton->conn.Reset(conn);
	pBaton->res.Reset(res);
	pBaton->opts.Reset(opts);
	pBaton->sspiPkg = sspiPkg;
	pBaton->pInToken = pInToken;
	pBaton->pInTokenSz = sz;
	pBaton->retrieveGroups = opts.Get(Napi::String::New(env, "retrieveGroups")).As<Napi::Boolean>().Value();
	if (req.HasOwnProperty(Napi::String::New(env, "isTestingNodeSSPI"))
		&& req.Get(Napi::String::New(env, "isTestingNodeSSPI")).As<Napi::Boolean>().Value()) {
		pBaton->isTesting = true;
	}
	if (opts.Has(Napi::String::New(env, "domain"))) {
		pBaton->basicDomain = new std::string(opts.Get(Napi::String::New(env, "domain")).ToString().Utf8Value());
	}
	AsyncBasicWorker* basicWorker = new AsyncBasicWorker(cb, pBaton);
    basicWorker->Queue();
}

Napi::Value onConnectionClose(const Napi::CallbackInfo& info) {
	CleanupAuthenicationResources(info.Env(), info.This().ToObject());
	return info.Env().Undefined();
}

void AsyncSSPIAuth(Baton* pBaton) {
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

void AsyncAfterSSPIAuth(Env env, Baton* pBaton) {
	Napi::HandleScope scope(env);
	BYTE *  pOutBuf = pBaton->pInToken;
	auto opts = pBaton->opts.Value();
	auto res = pBaton->res.Value();
	try {
		ULONG ss = pBaton->ss;
		auto conn = pBaton->conn.Value();
		auto req = pBaton->req.Value();
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
			napi_value argv[] = { Napi::String::New(env, "WWW-Authenticate"), Napi::String::New(env, authHStr.c_str()) };
			res.Get(Napi::String::New(env, "setHeader")).As<Napi::Function>().Call(res, 2, argv);
			res.Set(Napi::String::New(env, "statusCode"), Napi::Number::New(env, 401));
			break;
		}
		case SEC_E_INVALID_TOKEN:
		case SEC_E_LOGON_DENIED:
		{
			note_sspi_auth_failure(env, opts, req, res);
			CleanupAuthenicationResources(env, conn, &pBaton->pSCR->server_context);
			if (!conn.HasOwnProperty(Napi::String::New(env, "remainingAttempts"))) {
				conn.Set(Napi::String::New(env, "remainingAttempts")
					, Napi::Number::New(env, opts.Get(Napi::String::New(env, "maxLoginAttemptsPerConnection")).As<Napi::Number>().Int32Value() - 1));
			}
			int remainingAttmpts = conn.Get(Napi::String::New(env, "remainingAttempts")).As<Napi::Number>().Int32Value();
			if (remainingAttmpts <= 0) {
				throw new NodeSSPIException("Max login attempts reached.", 403);
			}
			conn.Set(Napi::String::New(env, "remainingAttempts")
				, Napi::Number::New(env, remainingAttmpts - 1));
			break;
		}
		case SEC_E_INVALID_HANDLE:
		case SEC_E_INTERNAL_ERROR:
		case SEC_E_NO_AUTHENTICATING_AUTHORITY:
		case SEC_E_INSUFFICIENT_MEMORY:
		{
			CleanupAuthenicationResources(env, conn, &pBaton->pSCR->server_context);
			res.Set(Napi::String::New(env, "statusCode"), Napi::Number::New(env, 500));
			break;
		}
		case SEC_E_OK:
		{
			CleanupAuthenicationResources(env, conn, &pBaton->pSCR->server_context);
			if (!pBaton->user.empty()) {
				conn.Set(Napi::String::New(env, "user"), Napi::String::New(env, pBaton->user.c_str()));
				if (pBaton->pGroups) {
					auto groups = Napi::Array::New(env, static_cast<uint32_t>(pBaton->pGroups->size()));
					for (ULONG i = 0; i < pBaton->pGroups->size(); i++) {
						groups.Set(i, Napi::String::New(env, pBaton->pGroups->at(i).c_str()));
					}
					conn.Set(Napi::String::New(env, "userGroups"), groups);
				}

			}
			else {
				throw new NodeSSPIException("Cannot obtain user name.");
			}
			if (!pBaton->userSid.empty()) {
				conn.Set(Napi::String::New(env, "userSid"), Napi::String::New(env, pBaton->userSid.c_str()));
			}

			break;
		}
		}
	}

	catch (NodeSSPIException *ex) {
		pBaton->err = ex;
	}
	WrapUpAsyncAfterAuth(env, pBaton);
}

void sspi_authentication(const Env env, const Napi::Object opts, const Napi::Object req
	, Napi::Object res, std::string schema, Napi::Object conn, BYTE *pInToken
	, ULONG sz, Napi::Function cb) {
	// acquire server context from request.connection
	sspi_connection_rec *pSCR = 0;
	if (conn.HasOwnProperty(Napi::String::New(env, "svrCtx"))) {
		// this is not initial request
		Napi::External<sspi_connection_rec> wrap = conn.Get(Napi::String::New(env, "svrCtx")).As<Napi::External<sspi_connection_rec> >();
		pSCR = wrap.Data();
	}
	else {
		pSCR = new sspi_connection_rec();
		pSCR->server_context.dwLower = pSCR->server_context.dwUpper = 0;
		
		Napi::Value lObj = Napi::External<sspi_connection_rec>::New(env, pSCR);
		// use conn socket to hold pSCR
		conn.Set(Napi::String::New(env, "svrCtx"), lObj);
		// hook to socket close event to clean up abandoned in-progress authentications
		// necessary to defend against attacks similar to sync flood 

		napi_value argv[] = { Napi::String::New(env, "close"), Napi::Function::New(conn.Env(), onConnectionClose) };
		conn.Get(Napi::String::New(env, "on")).As<Napi::Function>().Call(conn, 2, argv);
	}
	Baton *pBaton = new Baton();
	pBaton->callback.Reset(cb);
	pBaton->req.Reset(req);
	pBaton->conn.Reset(conn);
	pBaton->res.Reset(res);
	pBaton->opts.Reset(opts);
	pBaton->sspiPkg = schema;
	pBaton->pInToken = pInToken;
	pBaton->pInTokenSz = sz;
	pBaton->pSCR = pSCR;
	pBaton->retrieveGroups = opts.Get(Napi::String::New(env, "retrieveGroups")).As<Napi::Boolean>().Value();

	AsyncSSPIWorker* basicWorker = new AsyncSSPIWorker(cb, pBaton);
    basicWorker->Queue();
}

// /*
// * args[0]: opts
// * args[1]: req
// * args[2]: res
// */
Napi::Value Authenticate(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	auto opts = info[0].ToObject();
	auto res = info[2].ToObject();
	Napi::Object conn;
	Napi::Function cb;

	if (info[3].IsFunction()) {
		cb = info[3].As<Napi::Function>();
	}
	try {
		auto req = info[1].ToObject();
		conn = req.Get(Napi::String::New(env, "connection")).ToObject();
		if (conn.HasOwnProperty(Napi::String::New(env, "user"))) {
			if (!cb.IsEmpty()) {
				cb.Call(cb, 0, NULL);
			}
			return env.Undefined();
		}
		if (sspiModuleInfo.supportsSSPI == FALSE) {
			throw NodeSSPIException("Doesn't suport SSPI.");
		}
		auto headers = req.Get(Napi::String::New(env, "headers")).ToObject();

		if (conn.HasOwnProperty(Napi::String::New(env, "remainingAttempts"))) {
			int remainingAttmpts = conn.Get(Napi::String::New(env, "remainingAttempts")).As<Napi::Number>().Int32Value();
			if (remainingAttmpts < 0) {
				throw NodeSSPIException("Max login attempts reached.", 403);
			}
		}
		if (!headers.Has(Napi::String::New(env, "authorization"))) {
			note_sspi_auth_failure(env, opts, req, res);
			if (opts.Get(Napi::String::New(env, "authoritative")).As<Napi::Boolean>().Value()
				&& !req.Get(Napi::String::New(env, "connection")).ToObject().Has(Napi::String::New(env, "user"))
				) {
				res.Get(Napi::String::New(env, "end")).As<Napi::Function>().Call(res, 0, NULL);
			}
			if (!cb.IsEmpty()) {
				cb.Call(cb, 0, NULL);
			}
			return env.Undefined();
		}

		auto aut = std::string(headers.Get(Napi::String::New(env, "authorization")).ToString());
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
			basic_authentication(env, opts, req, res, conn, pToken, sz, cb);
		}
		else {
			sspi_authentication(env, opts, req, res, schema, conn, pToken, sz, cb);
		}
	}
	catch (NodeSSPIException &ex) {
		CleanupAuthenicationResources(env, conn);
		info[2].ToObject().Set(Napi::String::New(env, "statusCode"), Napi::Number::New(env, ex.http_code));
		napi_value argv[] = {Napi::String::New(env, ex.what())};
		if (opts.Get(Napi::String::New(env, "authoritative")).As<Napi::Boolean>().Value()) {
			res.Get(Napi::String::New(env, "end")).As<Napi::Function>().Call(res, 1, argv);
		}
		if (!cb.IsEmpty())  cb.Call(cb, 1, argv);
	}

	return env.Undefined();
}


  AsyncBasicWorker::AsyncBasicWorker(Napi::Function& cb, Baton* baton)
    : Napi::AsyncWorker(cb), pBaton(baton) {}
  AsyncBasicWorker::~AsyncBasicWorker() {}

  // Executed inside the worker-thread.
  // It is not safe to access JS engine data structure
  // here, so everything we need for input and output
  // should go on `this`.
  void AsyncBasicWorker::Execute () {
	  AsyncBasicAuth(pBaton);
  }

  // Executed when the async work is complete
  // this function will be run inside the main event loop
  // so it is safe to use JS engine data again
  void AsyncBasicWorker::OnOK() {
    AsyncAfterBasicAuth(Env(), pBaton);
  }

  void AsyncBasicWorker::OnError() {
	  
  }

  AsyncSSPIWorker::AsyncSSPIWorker(Napi::Function& cb, Baton* baton)
    : Napi::AsyncWorker(cb), pBaton(baton) {}
  AsyncSSPIWorker::~AsyncSSPIWorker() {}

  // Executed inside the worker-thread.
  // It is not safe to access JS engine data structure
  // here, so everything we need for input and output
  // should go on `this`.
  void AsyncSSPIWorker::Execute () {
	  AsyncSSPIAuth(pBaton);
  }

  // Executed when the async work is complete
  // this function will be run inside the main event loop
  // so it is safe to use JS engine data again
  void AsyncSSPIWorker::OnOK() {
    AsyncAfterSSPIAuth(Env(), pBaton);
  }

  void AsyncSSPIWorker::OnError() {
	  
  }

Napi::Object init(Napi::Env env, Napi::Object exports) {
	init_module();
	exports.Set(Napi::String::New(env, "authenticate"), 
				Napi::Function::New(env, Authenticate));
	return exports;
}

NODE_API_MODULE(nodeSSPI, init)
