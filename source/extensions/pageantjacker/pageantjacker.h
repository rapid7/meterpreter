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
// Output
#define TLV_TYPE_EXTENSION_PAGEANTJACKER_STATUS		  1
#define TLV_TYPE_EXTENSION_PAGEANTJACKER_ERRORMESSAGE 1<<1
#define TLV_TYPE_EXTENSION_PAGEANTJACKER_RETURNEDBLOB 1<<2

// Input
#define TLV_TYPE_EXTENSION_PAGEANTJACKER_SIZE_IN 1<<3
#define TLV_TYPE_EXTENSION_PAGEANTJACKER_BLOB_IN 1<<4

// Results from the pageant query function
typedef struct __PAGEANTQUERYRESULTS {
	byte result;
	unsigned char *error_message;
	byte *blob;
} PAGEANTQUERYRESULTS;

// Class and window name
#define PAGEANT_NAME L"Pageant"

#define PAGEANTJACKER_ERROR_SENDMESSAGE "The Pageant request was not processed."
#define PAGEANTJACKER_ERROR_MAPVIEWOFFILE "Unable to obtain IPC memory address."
#define PAGEANTJACKER_ERROR_CREATEFILEMAPPING "Unable to allocate memory for Pageant<-->Meterpreter IPC."
#define PAGEANTJACKER_ERROR_ALLOC "Unable to allocate memory buffer."
#define PAGEANTJACKER_ERROR_REQSTRINGBUILD "Unable to build Pageant request string."
#define PAGEANTJACKER_ERROR_NOERROR "No error."
#define PAGEANTJACKER_ERROR_NOTFOUND "Pageant not found."

#define AGENT_MAX 8192
#define AGENT_COPYDATA_ID 0x804e50ba 

// Function definitions
PAGEANTQUERYRESULTS send_query_to_pageant(byte *query, unsigned int querylength);
DWORD request_pageant_send_query(Remote *remote, Packet *packet);

#endif
