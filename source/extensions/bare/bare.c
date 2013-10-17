/*!
 * @file bare.c
 * @brief Entry point and intialisation functionality for the bare extention.
 */
#include "../../common/common.h"

#include "../../ReflectiveDLLInjection/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/ReflectiveLoader.c"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

Command customCommands[] =
{
	// custom commands go here
	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
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

