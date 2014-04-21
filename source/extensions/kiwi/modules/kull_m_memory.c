/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kull_m_memory.h"

BOOL kull_m_memory_open(IN KULL_M_MEMORY_TYPE Type, IN HANDLE hAny, OUT PKULL_M_MEMORY_HANDLE *hMemory)
{
	BOOL status = FALSE;

	*hMemory = (PKULL_M_MEMORY_HANDLE) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE));
	if(*hMemory)
	{
		(*hMemory)->type = Type;
		switch (Type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			status = TRUE;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			if((*hMemory)->pHandleProcess = (PKULL_M_MEMORY_HANDLE_PROCESS) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE_PROCESS)))
			{
				(*hMemory)->pHandleProcess->hProcess = hAny;
				status = TRUE;
			}
			break;
		case KULL_M_MEMORY_TYPE_FILE:
			if((*hMemory)->pHandleFile = (PKULL_M_MEMORY_HANDLE_FILE) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE_FILE)))
			{
				(*hMemory)->pHandleFile->hFile = hAny;
				status = TRUE;
			}
			break;
		case KULL_M_MEMORY_TYPE_PROCESS_DMP:
			if((*hMemory)->pHandleProcessDmp = (PKULL_M_MEMORY_HANDLE_PROCESS_DMP) LocalAlloc(LPTR, sizeof(KULL_M_MEMORY_HANDLE_PROCESS_DMP)))
				status = kull_m_minidump_open(hAny, &(*hMemory)->pHandleProcessDmp->hMinidump);
			break;
		default:
			break;
		}
		if(!status)
			LocalFree(*hMemory);
	}
	return status;
}

PKULL_M_MEMORY_HANDLE kull_m_memory_close(IN PKULL_M_MEMORY_HANDLE hMemory)
{
	if(hMemory)
	{
		switch (hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_PROCESS:
			LocalFree(hMemory->pHandleProcess);
			break;
		case KULL_M_MEMORY_TYPE_FILE:
			LocalFree(hMemory->pHandleFile);
			break;
		case KULL_M_MEMORY_TYPE_PROCESS_DMP:
			if(hMemory->pHandleProcessDmp)
			{
				kull_m_minidump_close(hMemory->pHandleProcessDmp->hMinidump);
				LocalFree(hMemory->pHandleProcessDmp);
			}
		default:
			break;
		}
		return (PKULL_M_MEMORY_HANDLE) LocalFree(hMemory);
	}
	else return NULL;
}

BOOL kull_m_memory_copy(OUT PKULL_M_MEMORY_ADDRESS Destination, IN PKULL_M_MEMORY_ADDRESS Source, IN SIZE_T Length)
{
	BOOL status = FALSE;
	BOOL bufferMeFirst = FALSE;
	KULL_M_MEMORY_HANDLE  hBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aBuffer = {NULL, &hBuffer};
	DWORD nbReadWrite;

	switch(Destination->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		switch(Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			RtlCopyMemory(Destination->address, Source->address, Length);
			status = TRUE;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			status = ReadProcessMemory(Source->hMemory->pHandleProcess->hProcess, Source->address, Destination->address, Length, NULL);
			break;
		case KULL_M_MEMORY_TYPE_PROCESS_DMP:
			status = kull_m_minidump_copy(Source->hMemory->pHandleProcessDmp->hMinidump, Destination->address, Source->address, Length);
			break;
		case KULL_M_MEMORY_TYPE_FILE:
			if(SetFilePointer(Source->hMemory->pHandleFile->hFile, (LONG) Source->address, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
				status = ReadFile(Source->hMemory->pHandleFile->hFile, Destination->address, (DWORD) Length, &nbReadWrite, NULL);
			break;
		default:
			break;
		}
		break;
	case KULL_M_MEMORY_TYPE_PROCESS:
		switch(Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			status = WriteProcessMemory(Destination->hMemory->pHandleProcess->hProcess, Destination->address, Source->address, Length, NULL);
			break;
		default:
			bufferMeFirst = TRUE;
			break;
		}
		break;
	case KULL_M_MEMORY_TYPE_FILE:
		switch(Source->hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			if(!Destination->address || SetFilePointer(Destination->hMemory->pHandleFile->hFile, (LONG) Destination->address, NULL, FILE_BEGIN))
				status = WriteFile(Destination->hMemory->pHandleFile->hFile, Source->address, (DWORD) Length, &nbReadWrite, NULL);
			break;
		default:
			bufferMeFirst = TRUE;
			break;
		}
		break;
	default:
		break;
	}

	if(bufferMeFirst)
	{
		if(aBuffer.address = LocalAlloc(LPTR, Length))
		{
			if(kull_m_memory_copy(&aBuffer, Source, Length))
				status = kull_m_memory_copy(Destination, &aBuffer, Length);
			LocalFree(aBuffer.address);
		}
	}
	return status;
}

BOOL kull_m_memory_search(IN PKULL_M_MEMORY_ADDRESS Pattern, IN SIZE_T Length, IN PKULL_M_MEMORY_SEARCH Search, IN BOOL bufferMeFirst)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_HANDLE  hBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_SEARCH  sBuffer = {{{NULL, &hBuffer}, Search->kull_m_memoryRange.size}, NULL};
	PBYTE CurrentPtr;
	PBYTE limite = (PBYTE) Search->kull_m_memoryRange.kull_m_memoryAdress.address + Search->kull_m_memoryRange.size;

	switch(Pattern->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		switch(Search->kull_m_memoryRange.kull_m_memoryAdress.hMemory->type)
		{
		case KULL_M_MEMORY_TYPE_OWN:
			for(CurrentPtr = (PBYTE) Search->kull_m_memoryRange.kull_m_memoryAdress.address; !status && (CurrentPtr + Length <= limite); CurrentPtr++)
				status = RtlEqualMemory(Pattern->address, CurrentPtr, Length);
			CurrentPtr--;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
		case KULL_M_MEMORY_TYPE_FILE:
			if(sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address = LocalAlloc(LPTR, Search->kull_m_memoryRange.size))
			{
				if(kull_m_memory_copy(&sBuffer.kull_m_memoryRange.kull_m_memoryAdress, &Search->kull_m_memoryRange.kull_m_memoryAdress, Search->kull_m_memoryRange.size))
					if(status = kull_m_memory_search(Pattern, Length, &sBuffer, FALSE))
						CurrentPtr = (PBYTE) Search->kull_m_memoryRange.kull_m_memoryAdress.address + (((PBYTE) sBuffer.result) - (PBYTE) sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address);
				LocalFree(sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address);
			}
			break;
		case KULL_M_MEMORY_TYPE_PROCESS_DMP:
			if(sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address = kull_m_minidump_remapVirtualMemory64(Search->kull_m_memoryRange.kull_m_memoryAdress.hMemory->pHandleProcessDmp->hMinidump, Search->kull_m_memoryRange.kull_m_memoryAdress.address, Search->kull_m_memoryRange.size))
				if(status = kull_m_memory_search(Pattern, Length, &sBuffer, FALSE))
					CurrentPtr = (PBYTE) Search->kull_m_memoryRange.kull_m_memoryAdress.address + (((PBYTE) sBuffer.result) - (PBYTE) sBuffer.kull_m_memoryRange.kull_m_memoryAdress.address);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	Search->result = status ? CurrentPtr : NULL;

	return status;
}

BOOL kull_m_memory_alloc(IN PKULL_M_MEMORY_ADDRESS Address, IN SIZE_T Lenght, IN DWORD Protection)
{
	Address->address = NULL;
	switch(Address->hMemory->type)
	{
		case KULL_M_MEMORY_TYPE_OWN:
			Address->address = VirtualAlloc(NULL, Lenght, MEM_COMMIT, Protection);
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			Address->address = VirtualAllocEx(Address->hMemory->pHandleProcess->hProcess, NULL, Lenght, MEM_COMMIT, Protection);
			break;
		default:
			break;
	}
	return (Address->address) != NULL;
}

BOOL kull_m_memory_free(IN PKULL_M_MEMORY_ADDRESS Address, IN SIZE_T Lenght)
{
	BOOL status = FALSE;

	switch(Address->hMemory->type)
	{
		case KULL_M_MEMORY_TYPE_OWN:
			status = VirtualFree(Address->address, Lenght, MEM_RELEASE);
			break;
		case KULL_M_MEMORY_TYPE_PROCESS:
			status = VirtualFreeEx(Address->hMemory->pHandleProcess->hProcess, Address->address, Lenght, MEM_RELEASE);
			break;
		default:
			break;
	}
	return status;
}


BOOL kull_m_memory_query(IN PKULL_M_MEMORY_ADDRESS Address, OUT PMEMORY_BASIC_INFORMATION MemoryInfo)
{
	BOOL status = FALSE;
	PMINIDUMP_MEMORY_INFO_LIST maListeInfo = NULL;
	PMINIDUMP_MEMORY_INFO mesInfos = NULL;
	ULONG i;

	switch(Address->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		status = VirtualQuery(Address->address, MemoryInfo, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION);
		break;
	case KULL_M_MEMORY_TYPE_PROCESS:
		status = VirtualQueryEx(Address->hMemory->pHandleProcess->hProcess, Address->address, MemoryInfo, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION);
		break;
	case KULL_M_MEMORY_TYPE_PROCESS_DMP:
		if(maListeInfo = (PMINIDUMP_MEMORY_INFO_LIST) kull_m_minidump_stream(Address->hMemory->pHandleProcessDmp->hMinidump, MemoryInfoListStream))
		{
			for(i = 0; (i < maListeInfo->NumberOfEntries) && !status; i++)
			{
				if(status = ((PBYTE) Address->address >= (PBYTE) mesInfos->BaseAddress) && ((PBYTE) Address->address <= (PBYTE) mesInfos->BaseAddress + (SIZE_T) mesInfos->RegionSize))
				{
					MemoryInfo->AllocationBase = (PVOID) mesInfos->AllocationBase;
					MemoryInfo->AllocationProtect = mesInfos->AllocationProtect;
					MemoryInfo->BaseAddress = (PVOID) mesInfos->BaseAddress;
					MemoryInfo->Protect = mesInfos->Protect;
					MemoryInfo->RegionSize = (SIZE_T) mesInfos->RegionSize;
					MemoryInfo->State = mesInfos->State;
					MemoryInfo->Type = mesInfos->Type;
				}
			}
		}
		break;
	default:
		break;
	}

	return status;
}

BOOL kull_m_memory_protect(IN PKULL_M_MEMORY_ADDRESS Address, IN SIZE_T dwSize, IN DWORD flNewProtect, OUT OPTIONAL PDWORD lpflOldProtect)
{
	BOOL status = FALSE;
	DWORD OldProtect;

	switch(Address->hMemory->type)
	{
	case KULL_M_MEMORY_TYPE_OWN:
		status = VirtualProtect(Address->address, dwSize, flNewProtect, &OldProtect);
		break;
	case KULL_M_MEMORY_TYPE_PROCESS:
		status = VirtualProtectEx(Address->hMemory->pHandleProcess->hProcess, Address->address, dwSize, flNewProtect, &OldProtect);
		break;
	default:
		break;
	}

	if(status && lpflOldProtect)
		*lpflOldProtect = OldProtect;

	return status;
}
