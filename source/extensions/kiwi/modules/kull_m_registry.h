/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kull_m_registry_structures.h"
#include "kull_m_string.h"

const wchar_t *KULL_M_REGISTRY_TYPE_WSTRING[];

typedef enum _KULL_M_REGISTRY_TYPE
{
	KULL_M_REGISTRY_TYPE_OWN,
	KULL_M_REGISTRY_TYPE_HIVE,
} KULL_M_REGISTRY_TYPE;

typedef struct _KULL_M_REGISTRY_HIVE_HANDLE
{
	HANDLE hFileMapping;
	LPVOID pMapViewOfFile;
	PBYTE pStartOf;
	PKULL_M_REGISTRY_HIVE_KEY_NAMED pRootNamedKey;
} KULL_M_REGISTRY_HIVE_HANDLE, *PKULL_M_REGISTRY_HIVE_HANDLE;

typedef struct _KULL_M_REGISTRY_HANDLE {
	KULL_M_REGISTRY_TYPE type;
	union {
		PKULL_M_REGISTRY_HIVE_HANDLE pHandleHive;
	};
} KULL_M_REGISTRY_HANDLE, *PKULL_M_REGISTRY_HANDLE;

BOOL kull_m_registry_open(IN KULL_M_REGISTRY_TYPE Type, IN HANDLE hAny, OUT PKULL_M_REGISTRY_HANDLE *hRegistry);
PKULL_M_REGISTRY_HANDLE kull_m_registry_close(IN PKULL_M_REGISTRY_HANDLE hRegistry);

BOOL kull_m_registry_RegOpenKeyEx(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpSubKey, IN DWORD ulOptions, IN REGSAM samDesired, OUT PHKEY phkResult);
BOOL kull_m_registry_RegCloseKey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey);
BOOL kull_m_registry_RegQueryValueEx(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpValueName, IN LPDWORD lpReserved, OUT OPTIONAL LPDWORD lpType, OUT OPTIONAL LPBYTE lpData, IN OUT OPTIONAL LPDWORD lpcbData);
BOOL kull_m_registry_RegQueryInfoKey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, OUT OPTIONAL LPWSTR lpClass, IN OUT OPTIONAL LPDWORD lpcClass, IN OPTIONAL LPDWORD lpReserved, OUT OPTIONAL LPDWORD lpcSubKeys, OUT OPTIONAL LPDWORD lpcMaxSubKeyLen, OUT OPTIONAL LPDWORD lpcMaxClassLen, OUT OPTIONAL LPDWORD lpcValues, OUT OPTIONAL LPDWORD lpcMaxValueNameLen, OUT OPTIONAL LPDWORD lpcMaxValueLen, OUT OPTIONAL LPDWORD lpcbSecurityDescriptor, OUT OPTIONAL PFILETIME lpftLastWriteTime);
BOOL kull_m_registry_RegEnumValue(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, IN DWORD dwIndex, OUT LPWSTR lpValueName, IN OUT LPDWORD lpcchValueName, IN LPDWORD lpReserved, OUT OPTIONAL LPDWORD lpType, OUT OPTIONAL LPBYTE lpData, OUT OPTIONAL LPDWORD lpcbData);

BOOL kull_m_registry_RegEnumKeyEx(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hKey, IN DWORD dwIndex, OUT LPWSTR lpName, IN OUT LPDWORD lpcName, IN LPDWORD lpReserved, OUT OPTIONAL LPWSTR lpClass, IN OUT OPTIONAL LPDWORD lpcClass, OUT OPTIONAL PFILETIME lpftLastWriteTime);

PKULL_M_REGISTRY_HIVE_KEY_NAMED kull_m_registry_searchKeyNamedInList(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN PKULL_M_REGISTRY_HIVE_BIN_CELL pHbC, IN LPCWSTR lpSubKey);
