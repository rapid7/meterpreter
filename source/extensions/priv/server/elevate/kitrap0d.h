#ifndef _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_ELEVATE_TECHNIQUES_KITRAP0D_H
#define _METERPRETER_SOURCE_EXTENSION_PRIV_PRIV_SERVER_ELEVATE_TECHNIQUES_KITRAP0D_H

#define PAGE_SIZE 0x1000

enum { SystemModuleInformation = 11 };

typedef struct
{
	ULONG   Unknown1;
	ULONG   Unknown2;
	PVOID   Base;
	ULONG   Size;
	ULONG   Flags;
	USHORT  Index;
	USHORT  NameLength;
	USHORT  LoadCount;
	USHORT  PathLength;
	CHAR    ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct
{
	ULONG   Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct CodeSignature
{
	UCHAR Signature[16];
	DWORD Version;
};

DWORD elevate_via_exploit_kitrap0d( Remote * remote, Packet * packet );

#endif
