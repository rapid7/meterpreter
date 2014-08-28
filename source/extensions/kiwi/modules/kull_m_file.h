/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globals.h"
#include <shlwapi.h>

extern BOOL isBase64Intercept;

BOOL kull_m_file_getCurrentDirectory(wchar_t ** ppDirName);
BOOL kull_m_file_getAbsolutePathOf(wchar_t *thisData, wchar_t ** reponse);
BOOL kull_m_file_isFileExist(wchar_t *fileName);
BOOL kull_m_file_writeData(PCWCHAR fileName, PBYTE data, DWORD length);
BOOL kull_m_file_readData(PCWCHAR fileName, PBYTE * data, PDWORD length);	// for little files !
void kull_m_file_cleanFilename(wchar_t *fileName);