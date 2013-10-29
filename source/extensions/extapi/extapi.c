/*!
 * @file extapi.h
 * @brief Entry point and intialisation definitions for the extended API extension.
 */
#include "../../common/common.h"

#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"

#include "window.h"
#include "service.h"
#include "clipboard.h"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

Command customCommands[] =
{
	// Window management and enumeration
	{ "extapi_window_enum",
		{ request_window_enum,          { 0 }, 0 },
		{ EMPTY_DISPATCH_HANDLER                 }
	},
	// Service management and enumeration
	{ "extapi_service_enum",
		{ request_service_enum,         { 0 }, 0 },
		{ EMPTY_DISPATCH_HANDLER                 }
	},
	{ "extapi_service_query",
		{ request_service_query,        { 0 }, 0 },
		{ EMPTY_DISPATCH_HANDLER                 }
	},
	// Clipboard interaction
	{ "extapi_clipboard_get_data",
		{ request_clipboard_get_data,   { 0 }, 0 },
		{ EMPTY_DISPATCH_HANDLER                 }
	},
	{ "extapi_clipboard_set_data",
		{ request_clipboard_set_data,   { 0 }, 0 },
		{ EMPTY_DISPATCH_HANDLER                 }
	},
	// Terminator
	{ NULL,
		{ EMPTY_DISPATCH_HANDLER                 },
		{ EMPTY_DISPATCH_HANDLER                 }
	}
};

/*!
 * @brief Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	DWORD index;

	hMetSrv = remote->hMetSrv;

	for (index = 0; customCommands[index].method; index++)
		command_register(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	DWORD index;

	for (index = 0; customCommands[index].method; index++)
		command_deregister(&customCommands[index]);

	return ERROR_SUCCESS;
}
