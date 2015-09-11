/*!
 * @file pageantjacker.h
 * @brief Entry point and intialisation declrations for the pageantjacker extention.
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_PAGEANTJACKER_PAGEANTJACKER_H
#define _METERPRETER_SOURCE_EXTENSION_PAGEANTJACKER_PAGEANTJACKER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// TLVs
#define TLV_TYPE_EXTENSION_PAGEANTJACKER 0

#define TLV_TYPE_EXTENSION_PAGEANTJACKER_STATUS		  MAKE_CUSTOM_TLV(TLV_META_TYPE_BOOL, TLV_TYPE_EXTENSION_PAGEANTJACKER, TLV_EXTENSIONS + 1)
#define TLV_TYPE_EXTENSION_PAGEANTJACKER_ERRORMESSAGE MAKE_CUSTOM_TLV(TLV_META_TYPE_UINT, TLV_TYPE_EXTENSION_PAGEANTJACKER, TLV_EXTENSIONS + 2)
#define TLV_TYPE_EXTENSION_PAGEANTJACKER_RETURNEDBLOB MAKE_CUSTOM_TLV(TLV_META_TYPE_RAW, TLV_TYPE_EXTENSION_PAGEANTJACKER, TLV_EXTENSIONS + 3)

// Input
#define TLV_TYPE_EXTENSION_PAGEANTJACKER_SIZE_IN MAKE_CUSTOM_TLV(TLV_META_TYPE_UINT, TLV_TYPE_EXTENSION_PAGEANTJACKER, TLV_EXTENSIONS + 4)
#define TLV_TYPE_EXTENSION_PAGEANTJACKER_BLOB_IN MAKE_CUSTOM_TLV(TLV_META_TYPE_RAW, TLV_TYPE_EXTENSION_PAGEANTJACKER, TLV_EXTENSIONS + 5)

// Results from the pageant query function
typedef struct __PAGEANTQUERYRESULTS {
	BOOL result;
	unsigned int errorMessage;
	byte *blob;
	DWORD bloblength;
} PAGEANTQUERYRESULTS;

// Class and window name
#define PAGEANT_NAME L"Pageant"

//#define PAGEANTJACKER_ERROR_NOERROR "No error."
//#define PAGEANTJACKER_ERROR_SENDMESSAGE "The Pageant request was not processed."
//#define PAGEANTJACKER_ERROR_MAPVIEWOFFILE "Unable to obtain IPC memory address."
//#define PAGEANTJACKER_ERROR_CREATEFILEMAPPING "Unable to allocate memory for Pageant<-->Meterpreter IPC."
//#define PAGEANTJACKER_ERROR_ALLOC "Unable to allocate memory buffer."
//#define PAGEANTJACKER_ERROR_REQSTRINGBUILD "Unable to build Pageant request string."
//#define PAGEANTJACKER_ERROR_NOTFOUND "Pageant not found."
//#define PAGEANTJACKER_ERROR_NOTFORWARDED "Not forwarded."

#define PAGEANTJACKER_ERROR_NOERROR 0
#define PAGEANTJACKER_ERROR_SENDMESSAGE 1
#define PAGEANTJACKER_ERROR_MAPVIEWOFFILE 2
#define PAGEANTJACKER_ERROR_CREATEFILEMAPPING 3
#define PAGEANTJACKER_ERROR_ALLOC 4
#define PAGEANTJACKER_ERROR_REQSTRINGBUILD 5
#define PAGEANTJACKER_ERROR_NOTFOUND 6
#define PAGEANTJACKER_ERROR_NOTFORWARDED 7

#define AGENT_MAX 8192
#define AGENT_COPYDATA_ID 0x804e50ba 
#define PAGENT_REQUEST_LENGTH 23

// Function definitions
void send_query_to_pageant(byte *query, unsigned int querylength, PAGEANTQUERYRESULTS *ret);
DWORD request_pageant_send_query(Remote *remote, Packet *packet);
DWORD get_length_response(byte *b);

#endif


