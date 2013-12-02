#ifndef METERPRETER_SOURCE_EXTENSION_SNIFFER_SERVER_PRECOMP_H
#define METERPRETER_SOURCE_EXTENSION_SNIFFER_SERVER_PRECOMP_H

#define  _WIN32_WINNT 0x0400

#include "sniffer.h"

#ifdef _WIN32

#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
#include "../../ReflectiveDLLInjection/inject/src/GetProcAddressR.h"
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.h"

// declared in ReflectiveLoader.c and set by DllMain also in ReflectiveLoader.c
extern HINSTANCE hAppInstance;

#endif

#define strcasecmp stricmp



#endif
