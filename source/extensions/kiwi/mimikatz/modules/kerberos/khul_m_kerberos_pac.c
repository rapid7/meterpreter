/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "khul_m_kerberos_pac.h"

BOOL kuhl_m_pac_validationInfo_to_PAC(PKERB_VALIDATION_INFO validationInfo, PPACTYPE * pacType, DWORD * pacLength)
{
	BOOL status = FALSE;
	PRPCE_KERB_VALIDATION_INFO pLogonInfo = NULL;
	DWORD szLogonInfo = 0, szLogonInfoAligned = 0;
	PPAC_CLIENT_INFO pClientInfo = NULL;
	DWORD szClientInfo = 0, szClientInfoAligned = 0;
	PAC_SIGNATURE_DATA signature = {KERB_CHECKSUM_HMAC_MD5, {0}, 0, 0};
	DWORD szSignature = sizeof(PAC_SIGNATURE_DATA) - 2 * sizeof(USHORT), szSignatureAligned;
	DWORD modulo, offsetData = sizeof(PACTYPE) + 3 * sizeof(PAC_INFO_BUFFER);

	if(kuhl_m_pac_validationInfo_to_LOGON_INFO(validationInfo, &pLogonInfo, &szLogonInfo))
	{
		szLogonInfoAligned = szLogonInfo;
		if(modulo = szLogonInfo % 8)
			szLogonInfoAligned += 8 - modulo;
	}
	if(kuhl_m_pac_validationInfo_to_CNAME_TINFO(validationInfo, &pClientInfo, &szClientInfo))
	{
		szClientInfoAligned = szClientInfo;
		if(modulo = szClientInfo % 8)
			szClientInfoAligned += (8 - modulo);
	}
	szSignatureAligned = szSignature;
	if(modulo = szSignature % 8)
		szSignatureAligned += 8 - modulo;

	if(pLogonInfo && pClientInfo)
	{
		*pacLength = offsetData + szLogonInfoAligned + szClientInfoAligned + 2 * sizeof(PAC_SIGNATURE_DATA);
		if(*pacType = (PPACTYPE) LocalAlloc(LPTR, *pacLength))
		{
			(*pacType)->cBuffers = 4;
			(*pacType)->Version = 0;

			(*pacType)->Buffers[0].cbBufferSize = szLogonInfo;
			(*pacType)->Buffers[0].ulType = PACINFO_TYPE_LOGON_INFO;
			(*pacType)->Buffers[0].Offset = offsetData;
			RtlCopyMemory((PBYTE) *pacType + (*pacType)->Buffers[0].Offset, pLogonInfo, (*pacType)->Buffers[0].cbBufferSize);

			(*pacType)->Buffers[1].cbBufferSize = szClientInfo;
			(*pacType)->Buffers[1].ulType = PACINFO_TYPE_CNAME_TINFO;
			(*pacType)->Buffers[1].Offset = (*pacType)->Buffers[0].Offset + szLogonInfoAligned;
			RtlCopyMemory((PBYTE) *pacType + (*pacType)->Buffers[1].Offset, pClientInfo, (*pacType)->Buffers[1].cbBufferSize);

			(*pacType)->Buffers[2].cbBufferSize = szSignature;
			(*pacType)->Buffers[2].ulType = PACINFO_TYPE_CHECKSUM_SRV;
			(*pacType)->Buffers[2].Offset = (*pacType)->Buffers[1].Offset + szClientInfoAligned;
			RtlCopyMemory((PBYTE) *pacType + (*pacType)->Buffers[2].Offset, &signature, (*pacType)->Buffers[2].cbBufferSize);

			(*pacType)->Buffers[3].cbBufferSize = szSignature;
			(*pacType)->Buffers[3].ulType = PACINFO_TYPE_CHECKSUM_KDC;
			(*pacType)->Buffers[3].Offset = (*pacType)->Buffers[2].Offset + szSignatureAligned;
			RtlCopyMemory((PBYTE) *pacType + (*pacType)->Buffers[3].Offset, &signature, (*pacType)->Buffers[3].cbBufferSize);

			status = TRUE;
		}
	}

	if(pLogonInfo)
		LocalFree(pLogonInfo);
	if(pClientInfo)
		LocalFree(pClientInfo);

	return status;
}

NTSTATUS kuhl_m_pac_signature(PPACTYPE pacType, DWORD pacLenght, LPCVOID key, DWORD keySize)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	DWORD i;
	PKERB_CHECKSUM pCheckSum;
	PVOID Context;
	PPAC_SIGNATURE_DATA pSignatureData;
	PBYTE checksumSrv = NULL, checksumpKdc = NULL;

	for(i = 0; i < pacType->cBuffers; i++)
	{
		if((pacType->Buffers[i].ulType ==  PACINFO_TYPE_CHECKSUM_SRV) || (pacType->Buffers[i].ulType == PACINFO_TYPE_CHECKSUM_KDC))
		{
			pSignatureData = (PPAC_SIGNATURE_DATA) ((PBYTE) pacType + pacType->Buffers[i].Offset);
			RtlZeroMemory(pSignatureData->Signature, 16); // ok, I deal only with KERB_CHECKSUM_HMAC_MD5, and what ?
			if(pacType->Buffers[i].ulType ==  PACINFO_TYPE_CHECKSUM_SRV)
				checksumSrv = pSignatureData->Signature;
			else
				checksumpKdc = pSignatureData->Signature;
		}
	}

	if(checksumSrv && checksumpKdc)
	{
		status = kullCDLocateCheckSum(KERB_CHECKSUM_HMAC_MD5, &pCheckSum);
		if(NT_SUCCESS(status))
		{
			status = pCheckSum->InitializeEx(key, keySize, KERB_NON_KERB_CKSUM_SALT, &Context);
			if(NT_SUCCESS(status))
			{
				pCheckSum->Sum(Context, pacLenght, pacType);
				pCheckSum->Finalize(Context, checksumSrv);
				pCheckSum->Sum(Context, pCheckSum->Size, checksumSrv);
				pCheckSum->Finalize(Context, checksumpKdc);
				pCheckSum->Finish(&Context);
			}
		}
	}
	return status;
}

BOOL kuhl_m_pac_marshall_unicodestring(PUNICODE_STRING pString, PMARSHALL_UNICODE_STRING pMarshall, RPCEID id, PVOID * current, DWORD * size)
{
	BOOL status = FALSE;
	PVOID newbuffer;
	DWORD modulo, actualsize = sizeof(MARSHALLED_UNICODE_STRING) + pString->Length;

	if(modulo = actualsize % 4)
		actualsize += 4 - modulo;

	if(newbuffer = LocalAlloc(LPTR, *size + actualsize))
	{
		pMarshall->Length = pString->Length;
		pMarshall->MaximumLength = pString->MaximumLength;
		pMarshall->ElementId = id;

		RtlCopyMemory(newbuffer, *current, *size);
		((PMARSHALLED_UNICODE_STRING) ((PBYTE) newbuffer + *size))->ReservedElements = pString->MaximumLength / sizeof(wchar_t);
		((PMARSHALLED_UNICODE_STRING) ((PBYTE) newbuffer + *size))->Elements = pString->Length / sizeof(wchar_t);
		RtlCopyMemory((PBYTE) newbuffer + *size + sizeof(MARSHALLED_UNICODE_STRING), pString->Buffer, pString->Length);

		LocalFree(*current);
		*current = newbuffer;
		*size += actualsize;

		status = TRUE;
	}
	return status;
}

BOOL kuhl_m_pac_marshall_groups(PGROUP_MEMBERSHIP pGroups, DWORD nbGroups, PVOID * current, DWORD * size)
{
	BOOL status = FALSE;
	PVOID newbuffer;
	DWORD i, actualsize = sizeof(ULONG32) + nbGroups * sizeof(GROUP_MEMBERSHIP);

	if(newbuffer = LocalAlloc(LPTR, *size + actualsize))
	{
		RtlCopyMemory(newbuffer, *current, *size);
		(*(PULONG32) ((PBYTE) newbuffer + *size)) = nbGroups;
		for(i = 0 ; i < nbGroups; i++)
			((PGROUP_MEMBERSHIP) ((PBYTE) newbuffer + *size + sizeof(ULONG32)))[i] = pGroups[i];

		LocalFree(*current);
		*current = newbuffer;
		*size += actualsize;

		status = TRUE;
	}
	return status;
}

BOOL kuhl_m_pac_marshall_sid(PISID pSid, PVOID * current, DWORD * size)
{
	BOOL status = FALSE;
	PVOID newbuffer;
	DWORD sidSize, actualsize;

	sidSize = 1 + 1 + 6 + pSid->SubAuthorityCount * sizeof(DWORD);
	actualsize = sizeof(ULONG32) + sidSize;

	if(newbuffer = LocalAlloc(LPTR, *size + actualsize))
	{
		RtlCopyMemory(newbuffer, *current, *size);
		(*(PULONG32) ((PBYTE) newbuffer + *size)) = pSid->SubAuthorityCount;
		RtlCopyMemory((PBYTE) newbuffer + *size + sizeof(ULONG32), pSid, sidSize);

		LocalFree(*current);
		*current = newbuffer;
		*size += actualsize;

		status = TRUE;
	}
	return status;
}

BOOL kuhl_m_pac_validationInfo_to_LOGON_INFO(PKERB_VALIDATION_INFO validationInfo, PRPCE_KERB_VALIDATION_INFO * rpceValidationInfo, DWORD *rpceValidationInfoLength)
{
	BOOL status = FALSE;
	RPCE_KERB_VALIDATION_INFO rpce;
	PVOID buffer = NULL;
	DWORD szBuffer = 0;

	rpce.typeHeader.Version = 0x01;
	rpce.typeHeader.Endianness = 0x10;
	rpce.typeHeader.CommonHeaderLength = 8;
	rpce.typeHeader.Filler = 0xcccccccc;
	rpce.privateHeader.Filler = 0x00000000;

	rpce.RootElementId = PACINFO_ID_KERB_VALINFO;

	rpce.infos.LogonTime = validationInfo->LogonTime;
	rpce.infos.LogoffTime = validationInfo->LogoffTime;
	rpce.infos.KickOffTime = validationInfo->KickOffTime;
	rpce.infos.PasswordLastSet = validationInfo->PasswordLastSet;
	rpce.infos.PasswordCanChange = validationInfo->PasswordCanChange;
	rpce.infos.PasswordMustChange = validationInfo->PasswordMustChange;

	kuhl_m_pac_marshall_unicodestring(&validationInfo->EffectiveName,		&rpce.infos.EffectiveName,		PACINFO_ID_KERB_EFFECTIVENAME,		&buffer, &szBuffer);
	kuhl_m_pac_marshall_unicodestring(&validationInfo->FullName,			&rpce.infos.FullName,			PACINFO_ID_KERB_FULLNAME,			&buffer, &szBuffer);
	kuhl_m_pac_marshall_unicodestring(&validationInfo->LogonScript,			&rpce.infos.LogonScript,		PACINFO_ID_KERB_LOGONSCRIPT,		&buffer, &szBuffer);
	kuhl_m_pac_marshall_unicodestring(&validationInfo->ProfilePath,			&rpce.infos.ProfilePath,		PACINFO_ID_KERB_PROFILEPATH,		&buffer, &szBuffer);
	kuhl_m_pac_marshall_unicodestring(&validationInfo->HomeDirectory,		&rpce.infos.HomeDirectory,		PACINFO_ID_KERB_HOMEDIRECTORY,		&buffer, &szBuffer);
	kuhl_m_pac_marshall_unicodestring(&validationInfo->HomeDirectoryDrive,	&rpce.infos.HomeDirectoryDrive,	PACINFO_ID_KERB_HOMEDIRECTORYDRIVE,	&buffer, &szBuffer);

	rpce.infos.LogonCount = validationInfo->LogonCount;
	rpce.infos.BadPasswordCount = validationInfo->BadPasswordCount;

	rpce.infos.UserId = validationInfo->UserId;
	rpce.infos.PrimaryGroupId = validationInfo->PrimaryGroupId;

	rpce.infos.GroupCount = validationInfo->GroupCount;
	rpce.infos.GroupIds = PACINFO_ID_KERB_GROUPIDS;
	kuhl_m_pac_marshall_groups(validationInfo->GroupIds, validationInfo->GroupCount, &buffer, &szBuffer);

	rpce.infos.UserFlags = validationInfo->UserFlags;
	RtlCopyMemory(rpce.infos.UserSessionKey.data, validationInfo->UserSessionKey.data, 16);

	kuhl_m_pac_marshall_unicodestring(&validationInfo->LogonServer,			&rpce.infos.LogonServer,		PACINFO_ID_KERB_LOGONSERVER,		&buffer, &szBuffer);
	kuhl_m_pac_marshall_unicodestring(&validationInfo->LogonDomainName,		&rpce.infos.LogonDomainName,	PACINFO_ID_KERB_LOGONDOMAINNAME,	&buffer, &szBuffer);

	rpce.infos.LogonDomainId = PACINFO_ID_KERB_LOGONDOMAINID;
	kuhl_m_pac_marshall_sid(validationInfo->LogonDomainId, &buffer, &szBuffer);

	rpce.infos.Reserved1[0] = validationInfo->Reserved1[0];
	rpce.infos.Reserved1[1] = validationInfo->Reserved1[1];

	rpce.infos.UserAccountControl = validationInfo->UserAccountControl;
	rpce.infos.SubAuthStatus = validationInfo->SubAuthStatus;

	rpce.infos.LastSuccessfulILogon = validationInfo->LastSuccessfulILogon;
	rpce.infos.LastFailedILogon = validationInfo->LastFailedILogon;
	rpce.infos.FailedILogonCount = validationInfo->FailedILogonCount;

	rpce.infos.Reserved3 = validationInfo->Reserved3;

	rpce.infos.SidCount = 0; //validationInfo->SidCount;
	rpce.infos.ExtraSids = 0; // lazy;
	rpce.infos.ResourceGroupDomainSid = 0; //lazy
	rpce.infos.ResourceGroupCount = 0; //validationInfo->ResourceGroupCount;
	rpce.infos.ResourceGroupIds = 0; // lazy

	rpce.privateHeader.ObjectBufferLength = sizeof(MARSHALL_KERB_VALIDATION_INFO) + sizeof(ULONG) + szBuffer;
	*rpceValidationInfoLength = sizeof(RPCE_KERB_VALIDATION_INFO) + szBuffer;
	if(*rpceValidationInfo = (PRPCE_KERB_VALIDATION_INFO) LocalAlloc(LPTR, *rpceValidationInfoLength))
	{
		RtlCopyMemory(*rpceValidationInfo, &rpce, sizeof(RPCE_KERB_VALIDATION_INFO));
		RtlCopyMemory((PBYTE) *rpceValidationInfo + sizeof(RPCE_KERB_VALIDATION_INFO), buffer, szBuffer);
		status = TRUE;
	}
	if(buffer)
		LocalFree(buffer);

	return status;
}

BOOL kuhl_m_pac_validationInfo_to_CNAME_TINFO(PKERB_VALIDATION_INFO validationInfo, PPAC_CLIENT_INFO * pacClientInfo, DWORD * pacClientInfoLength)
{
	BOOL status = FALSE;
	*pacClientInfoLength = sizeof(PAC_CLIENT_INFO) + validationInfo->EffectiveName.Length - sizeof(wchar_t);
	if(*pacClientInfo = (PPAC_CLIENT_INFO) LocalAlloc(LPTR, *pacClientInfoLength))
	{
		(*pacClientInfo)->ClientId = validationInfo->LogonTime;
		(*pacClientInfo)->NameLength = validationInfo->EffectiveName.Length;
		RtlCopyMemory((*pacClientInfo)->Name, validationInfo->EffectiveName.Buffer, (*pacClientInfo)->NameLength);
		status = TRUE;
	}
	return status;
}

#ifdef KERBEROS_TOOLS
#ifdef KERBEROS_TOOLS
const RPCE_LAZY_ELEMENT_HEADER kuhl_m_kerberos_pac_headers[] = {
        //{0x00020000, sizeof(KERB_VALIDATION_INFO), 0, FALSE},
        {PACINFO_ID_KERB_EFFECTIVENAME,                 sizeof(WCHAR), 0, TRUE},        // EffectiveName
        {PACINFO_ID_KERB_FULLNAME,                              sizeof(WCHAR), 0, TRUE},        // FullName
        {PACINFO_ID_KERB_LOGONSCRIPT,                   sizeof(WCHAR), 0, TRUE},        // LogonScript
        {PACINFO_ID_KERB_PROFILEPATH,                   sizeof(WCHAR), 0, TRUE},        // ProfilePath
        {PACINFO_ID_KERB_HOMEDIRECTORY,                 sizeof(WCHAR), 0, TRUE},        // HomeDirectory
        {PACINFO_ID_KERB_HOMEDIRECTORYDRIVE,    sizeof(WCHAR), 0, TRUE},        // HomeDirectoryDrive
        {PACINFO_ID_KERB_GROUPIDS,                              sizeof(GROUP_MEMBERSHIP), 0, FALSE}, // GroupIds
        {PACINFO_ID_KERB_LOGONSERVER,                   sizeof(WCHAR), 0, TRUE},        // LogonServer
        {PACINFO_ID_KERB_LOGONDOMAINNAME,               sizeof(WCHAR), 0, TRUE},        // LogonDomainName
        {PACINFO_ID_KERB_LOGONDOMAINID,                 sizeof(DWORD), 8, FALSE},       // LogonDomainId
        // ... Lazy ;)
};

PVOID kuhl_m_kerberos_pac_giveElementById(RPCEID id, LPCVOID base)
{
        DWORD i, modulo;
        PBYTE start = (PBYTE) base;
        ULONG64 dataOffset, nextOffset;
        if(id)
        {
                for(i = 0; i < sizeof(kuhl_m_kerberos_pac_headers) / sizeof(RPCE_LAZY_ELEMENT_HEADER); i++)
                {
                        if(kuhl_m_kerberos_pac_headers[i].isBuffer)
                        {
                                dataOffset = sizeof(ULONG64) + sizeof(ULONG32);
                                nextOffset = *((PULONG32) (start + sizeof(ULONG64))) * kuhl_m_kerberos_pac_headers[i].ElementSize;
                        }
                        else
                        {
                                dataOffset = sizeof(ULONG32);
                                nextOffset = *((PULONG32) start) * kuhl_m_kerberos_pac_headers[i].ElementSize;
                        }

                        if(id == kuhl_m_kerberos_pac_headers[i].ElementId)
                        {
                                kull_m_string_wprintf_hex(start, 12, 1); kprintf(L"\n");
                                if(nextOffset)
                                        return start + dataOffset;
                                else
                                        return NULL;
                        }

                        start += dataOffset + nextOffset + kuhl_m_kerberos_pac_headers[i].FixedBeginSize;
                        if(modulo = ((ULONG_PTR) start % 4))
                                start += 4 - modulo;
                }
        }
        return NULL;
}

void kuhl_m_kerberos_pac_ustring(LPCWCHAR prefix, PMARSHALL_UNICODE_STRING pString, PVOID base)
{
        UNICODE_STRING s = {pString->Length, pString->MaximumLength, (PWSTR) kuhl_m_kerberos_pac_giveElementById(pString->ElementId, base)};
        kprintf(L"%s (%2hu, %2hu, @ %08x) - %wZ\n", prefix, pString->Length, pString->MaximumLength, pString->ElementId, &s);
}

NTSTATUS kuhl_m_kerberos_pac_info(int argc, wchar_t * argv[])
{
        PPACTYPE pacType;
        DWORD pacLenght, i, j;
        BYTE buffer[16] = {0};
        PRPCE_KERB_VALIDATION_INFO pValInfo;
        PPAC_SIGNATURE_DATA pSignatureData;
        PPAC_CLIENT_INFO pClientInfo;
        PGROUP_MEMBERSHIP pGroup;
        PSID pSid;
        PVOID base;

        if(kull_m_file_readData(L"C:\\Users\\gentilkiwi\\Desktop\\out.pac", (PBYTE *) &pacType, &pacLenght))
        {
                kprintf(L"version %u, nbBuffer = %u\n\n", pacType->Version, pacType->cBuffers);
                
                for(i = 0; i < pacType->cBuffers; i++)
                {
                        switch(pacType->Buffers[i].ulType)
                        {
                        case PACINFO_TYPE_LOGON_INFO:
                                pValInfo = (PRPCE_KERB_VALIDATION_INFO) ((PBYTE) pacType + pacType->Buffers[i].Offset);
                                base = (PBYTE) &pValInfo->infos + sizeof(MARSHALL_KERB_VALIDATION_INFO);
                                
                                kprintf(L"*** Validation Informations *** (%u)\n", pacType->Buffers[i].cbBufferSize);
                                kprintf(L"TypeHeader    : version 0x%02x, endianness 0x%02x, length %hu (%u), filer %08x\n", pValInfo->typeHeader.Version, pValInfo->typeHeader.Endianness, pValInfo->typeHeader.CommonHeaderLength, sizeof(MARSHALL_KERB_VALIDATION_INFO), pValInfo->typeHeader.Filler);
                                kprintf(L"PrivateHeader : length %u, filer %08x\n", pValInfo->privateHeader.ObjectBufferLength, pValInfo->privateHeader.Filler);
                                kprintf(L"RootElementId : %08x\n\n", pValInfo->RootElementId);
                                
                                kprintf(L"LogonTime              %016llx - ", pValInfo->infos.LogonTime); kull_m_string_displayLocalFileTime(&pValInfo->infos.LogonTime); kprintf(L"\n");
                                kprintf(L"LogoffTime             %016llx - ", pValInfo->infos.LogoffTime); kull_m_string_displayLocalFileTime(&pValInfo->infos.LogoffTime); kprintf(L"\n");
                                kprintf(L"KickOffTime            %016llx - ", pValInfo->infos.KickOffTime); kull_m_string_displayLocalFileTime(&pValInfo->infos.KickOffTime); kprintf(L"\n");
                                kprintf(L"PasswordLastSet        %016llx - ", pValInfo->infos.PasswordLastSet); kull_m_string_displayLocalFileTime(&pValInfo->infos.PasswordLastSet); kprintf(L"\n");
                                kprintf(L"PasswordCanChange      %016llx - ", pValInfo->infos.PasswordCanChange); kull_m_string_displayLocalFileTime(&pValInfo->infos.PasswordCanChange); kprintf(L"\n");
                                kprintf(L"PasswordMustChange     %016llx - ", pValInfo->infos.PasswordMustChange); kull_m_string_displayLocalFileTime(&pValInfo->infos.PasswordMustChange); kprintf(L"\n");
                                kprintf(L"\n");
                                kuhl_m_kerberos_pac_ustring(L"EffectiveName         ", &pValInfo->infos.EffectiveName, base);
                                kuhl_m_kerberos_pac_ustring(L"FullName              ", &pValInfo->infos.FullName, base);
                                kuhl_m_kerberos_pac_ustring(L"LogonScript           ", &pValInfo->infos.LogonScript, base);
                                kuhl_m_kerberos_pac_ustring(L"ProfilePath           ", &pValInfo->infos.ProfilePath, base);
                                kuhl_m_kerberos_pac_ustring(L"HomeDirectory         ", &pValInfo->infos.HomeDirectory, base);
                                kuhl_m_kerberos_pac_ustring(L"HomeDirectoryDrive    ", &pValInfo->infos.HomeDirectoryDrive, base);
                                kprintf(L"\n");
                                kprintf(L"LogonCount             %hu\n", pValInfo->infos.LogonCount);
                                kprintf(L"BadPasswordCount       %hu\n", pValInfo->infos.BadPasswordCount);
                                kprintf(L"\n");
                                kprintf(L"UserId                 %08x (%u)\n", pValInfo->infos.UserId, pValInfo->infos.UserId);
                                kprintf(L"PrimaryGroupId         %08x (%u)\n", pValInfo->infos.PrimaryGroupId, pValInfo->infos.PrimaryGroupId);
                                kprintf(L"\n");
                                kprintf(L"GroupCount             %u\n", pValInfo->infos.GroupCount);
                                pGroup = (PGROUP_MEMBERSHIP) kuhl_m_kerberos_pac_giveElementById(pValInfo->infos.GroupIds, base);
                                kprintf(L"GroupIds               @ %08x\n * RID : ", pValInfo->infos.GroupIds);
                                for(j = 0; j < pValInfo->infos.GroupCount; j++)
                                        kprintf(L"%u,", pGroup[j].RelativeId); //, pGroup[j].Attributes);
                                kprintf(L"\n\n");
                                kprintf(L"UserFlags              %08x (%u)\n", pValInfo->infos.UserFlags, pValInfo->infos.UserFlags);
                                kprintf(L"UserSessionKey         "); kull_m_string_wprintf_hex(pValInfo->infos.UserSessionKey.data, 16, 0); kprintf(L"\n");
                                kprintf(L"\n");
                                kuhl_m_kerberos_pac_ustring(L"LogonServer           ", &pValInfo->infos.LogonServer, base);
                                kuhl_m_kerberos_pac_ustring(L"LogonDomainName       ", &pValInfo->infos.LogonDomainName, base);
                                kprintf(L"\n");
                                pSid = (PSID) kuhl_m_kerberos_pac_giveElementById(pValInfo->infos.LogonDomainId, base);
                                kprintf(L"LogonDomainId          @ %08x\n * SID : ", pValInfo->infos.LogonDomainId); kull_m_string_displaySID(pSid); kprintf(L"\n");
                                kprintf(L"\n");
                                kprintf(L"UserAccountControl     %08x (%u)\n", pValInfo->infos.UserAccountControl, pValInfo->infos.UserAccountControl);
                                kprintf(L"SubAuthStatus          %08x (%u)\n", pValInfo->infos.SubAuthStatus, pValInfo->infos.SubAuthStatus);
                                kprintf(L"\n");
                                kprintf(L"LastSuccessfulILogon   %016llx\n", pValInfo->infos.LastSuccessfulILogon);
                                kprintf(L"LastFailedILogon       %016llx\n", pValInfo->infos.LastFailedILogon);
                                kprintf(L"\n");
                                kprintf(L"FailedILogonCount      %u\n", pValInfo->infos.FailedILogonCount);
                                kprintf(L"\n");
                                kprintf(L"SidCount               %u\n", pValInfo->infos.SidCount);
                                kprintf(L"ExtraSids              @ %08x\n", pValInfo->infos.ExtraSids);
                                kprintf(L"ResourceGroupDomainSid @ %08x\n", pValInfo->infos.ResourceGroupDomainSid);
                                kprintf(L"ResourceGroupCount     %u\n", pValInfo->infos.ResourceGroupCount);
                                kprintf(L"ResourceGroupIds       @ %08x\n", pValInfo->infos.ResourceGroupIds);
                                break;
                        case PACINFO_TYPE_CHECKSUM_SRV: // Server Signature
                        case PACINFO_TYPE_CHECKSUM_KDC: // KDC Signature
                                pSignatureData = (PPAC_SIGNATURE_DATA) ((PBYTE) pacType + pacType->Buffers[i].Offset);
                                kprintf(L"*** %s Signature ***\n", (pacType->Buffers[i].ulType == 0x00000006) ? L"Server" : L"KDC");
                                kprintf(L"Type %08x - (%hu) : ", pSignatureData->SignatureType, pSignatureData->RODCIdentifier);
                                kull_m_string_wprintf_hex(pSignatureData->Signature, LM_NTLM_HASH_LENGTH, 0);
                                kprintf(L"\n");
                                break;
                        case PACINFO_TYPE_CNAME_TINFO: // Client name and ticket information
                                pClientInfo  = (PPAC_CLIENT_INFO) ((PBYTE) pacType + pacType->Buffers[i].Offset);
                                kprintf(L"*** Client name and ticket information ***\n");
                                kprintf(L"ClientId %016llx - ", pClientInfo->ClientId); kull_m_string_displayLocalFileTime(&pClientInfo->ClientId); kprintf(L"\n");
                                kprintf(L"Client   (%hu, %.*s)\n", pClientInfo->NameLength, pClientInfo->NameLength / sizeof(WCHAR), pClientInfo->Name);
                                break;
                        default:
                                kull_m_string_wprintf_hex(&pacType->Buffers[i], sizeof(PAC_INFO_BUFFER), 1);
                                kprintf(L"\n");
                                kprintf(L"[%02u] %08x @ offset %016llx (%u)\n", i, pacType->Buffers[i].ulType, pacType->Buffers[i].Offset, pacType->Buffers[i].cbBufferSize);
                                kull_m_string_wprintf_hex((PBYTE) pacType + pacType->Buffers[i].Offset, pacType->Buffers[i].cbBufferSize, 1);
                                kprintf(L"\n");
                        }
                        kprintf(L"\n");
                }
                LocalFree(pacType);
        }
        return STATUS_SUCCESS;
}
#endif
#endif
