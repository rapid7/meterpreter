/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globals.h"
#include "kull_m_handle.h"
#include <sddl.h>

typedef BOOL (CALLBACK * PKULL_M_TOKEN_ENUM_CALLBACK) (HANDLE hToken, DWORD ptid, PVOID pvArg);

typedef struct _KULL_M_TOKEN_ENUM_DATA {
	PKULL_M_TOKEN_ENUM_CALLBACK callback;
	PVOID pvArg;
	BOOL mustContinue;
} KULL_M_TOKEN_ENUM_DATA, *PKULL_M_TOKEN_ENUM_DATA;

BOOL kull_m_token_getTokens(PKULL_M_TOKEN_ENUM_CALLBACK callBack, PVOID pvArg);
BOOL CALLBACK kull_m_token_getTokens_process_callback(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
BOOL CALLBACK kull_m_token_getTokens_handles_callback(HANDLE handle, PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);

BOOL kull_m_token_getNameDomainFromToken(HANDLE hToken, PWSTR * pName, PWSTR * pDomain, PWSTR * pSid, PSID_NAME_USE pSidNameUse);
BOOL kull_m_token_getNameDomainFromSID(PSID pSid, PWSTR * pName, PWSTR * pDomain, PSID_NAME_USE pSidNameUse);