/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globals_sekurlsa.h"
#include "kuhl_m_sekurlsa.h"
#include "../modules/kull_m_memory.h"

PLIST_ENTRY LogonSessionList;
PULONG LogonSessionListCount;

PVOID kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(PKULL_M_MEMORY_ADDRESS pSecurityStruct, ULONG LUIDoffset, PLUID luidToFind);
PVOID kuhl_m_sekurlsa_utils_pFromAVLByLuid(PKULL_M_MEMORY_ADDRESS pTable, ULONG LUIDoffset, PLUID luidToFind);
PVOID kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(PKULL_M_MEMORY_ADDRESS pTable, ULONG LUIDoffset, PLUID luidToFind);

BOOL kuhl_m_sekurlsa_utils_search(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib);
BOOL kuhl_m_sekurlsa_utils_search_generic(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib, PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PVOID * genericPtr, PVOID * genericPtr1, PLONG genericOffset1);

void kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(PVOID BaseAddress, PLSA_UNICODE_STRING String, BOOL relative);
BOOL kuhl_m_sekurlsa_utils_getSid(IN PSID * pSid, IN PKULL_M_MEMORY_HANDLE source);

const wchar_t * KUHL_M_SEKURLSA_LOGON_TYPE[];

typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS {
	struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS *next;
	ANSI_STRING Primary;
	LSA_UNICODE_STRING Credentials;
} KIWI_MSV1_0_PRIMARY_CREDENTIALS, *PKIWI_MSV1_0_PRIMARY_CREDENTIALS;

typedef struct _KIWI_MSV1_0_CREDENTIALS {
	struct _KIWI_MSV1_0_CREDENTIALS *next;
	DWORD AuthenticationPackageId;
	PKIWI_MSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
} KIWI_MSV1_0_CREDENTIALS, *PKIWI_MSV1_0_CREDENTIALS;

typedef struct _KIWI_MSV1_0_LIST_5 {
	struct _KIWI_MSV1_0_LIST_5 *Flink;
	struct _KIWI_MSV1_0_LIST_5 *Blink;
	LUID LocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk0;
	PVOID unk1;
	PSID  pSid;
	ULONG LogonType;
    ULONG Session;
    LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
} KIWI_MSV1_0_LIST_5, *PKIWI_MSV1_0_LIST_5;

typedef struct _KIWI_MSV1_0_LIST_6 {
	struct _KIWI_MSV1_0_LIST_6 *Flink;
	struct _KIWI_MSV1_0_LIST_6 *Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	PSID  pSid;
	ULONG LogonType;
    ULONG Session;
    LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
} KIWI_MSV1_0_LIST_6, *PKIWI_MSV1_0_LIST_6;

typedef struct _KIWI_MSV1_0_LIST_62 {
	struct _KIWI_MSV1_0_LIST_62 *Flink;
	struct _KIWI_MSV1_0_LIST_62 *Blink;
	PVOID unk0;
	ULONG unk1;
	PVOID unk2;
	ULONG unk3;
	ULONG unk4;
	ULONG unk5;
	HANDLE hSemaphore6;
	PVOID unk7;
	HANDLE hSemaphore8;
	PVOID unk9;
	PVOID unk10;
	ULONG unk11;
	ULONG unk12;
	PVOID unk13;
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	/*PVOID unk16;
	PVOID unk17;*/LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
    ULONG Session;
    LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
} KIWI_MSV1_0_LIST_62, *PKIWI_MSV1_0_LIST_62;

typedef struct _KIWI_MSV1_0_LIST_63 {
	struct _KIWI_MSV1_0_LIST_63 *Flink;	//off_2C5718
	struct _KIWI_MSV1_0_LIST_63 *Blink; //off_277380
	PVOID unk0; // unk_2C0AC8
	ULONG unk1; // 0FFFFFFFFh
	PVOID unk2; // 0
	ULONG unk3; // 0
	ULONG unk4; // 0
	ULONG unk5; // 0A0007D0h
	HANDLE hSemaphore6; // 0F9Ch
	PVOID unk7; // 0
	HANDLE hSemaphore8; // 0FB8h
	PVOID unk9; // 0
	PVOID unk10; // 0
	ULONG unk11; // 0
	ULONG unk12; // 0 
	PVOID unk13; // unk_2C0A28
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	BYTE waza[12]; /// to do (maybe align)
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	/*PVOID unk16;
	PVOID unk17;*/LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PKIWI_MSV1_0_CREDENTIALS Credentials;
} KIWI_MSV1_0_LIST_63, *PKIWI_MSV1_0_LIST_63;