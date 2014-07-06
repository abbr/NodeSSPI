#include "NodeSSPI.h"

using namespace v8;
using namespace std;

HRESULT IsUserInGroup(HANDLE user, const wchar_t* groupNm)
{
    HRESULT result = E_FAIL;
    SID_NAME_USE snu;
    WCHAR szDomain[256];
    DWORD dwSidSize = 0;
    DWORD dwSize = sizeof szDomain / sizeof * szDomain;

    if ((LookupAccountNameW(NULL, groupNm, 0, &dwSidSize, szDomain, &dwSize, &snu) == 0)
            && (ERROR_INSUFFICIENT_BUFFER == GetLastError()))
    {
        SID* pSid = (SID*)malloc(dwSidSize);

        if (LookupAccountNameW(NULL, groupNm, pSid, &dwSidSize, szDomain, &dwSize, &snu))
        {
            BOOL b;

            if (CheckTokenMembership(user, pSid, &b))
            {
                if (b == TRUE)
                {
                    result = S_OK;
                }
            }
            else
            {
                result = S_FALSE;
            }
        }
        free(pSid);
    }

    return result;
}