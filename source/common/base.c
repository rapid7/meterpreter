/*!
 * @file base.c
 * @brief Definitions that apply to almost any Meterpreter component.
 */
#include "common.h"

// Local remote request implementors
extern DWORD remote_request_core_console_write(Remote *remote, Packet *packet);

extern DWORD remote_request_core_channel_open(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_write(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_read(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_close(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_seek(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_eof(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_tell(Remote *remote, Packet *packet);
extern DWORD remote_request_core_channel_interact(Remote *remote, Packet *packet);

extern DWORD remote_request_core_crypto_negotiate(Remote *remote, Packet *packet);

extern DWORD remote_request_core_shutdown(Remote *remote, Packet *packet);

extern DWORD remote_request_core_migrate(Remote *remote, Packet *packet);

// Local remote response implementors
extern DWORD remote_response_core_console_write(Remote *remote, Packet *packet);

extern DWORD remote_response_core_channel_open(Remote *remote, Packet *packet);
extern DWORD remote_response_core_channel_close(Remote *remote, Packet *packet);

DWORD remote_request_core_console_write(Remote *remote, Packet *packet)
{
	return ERROR_SUCCESS;
}

DWORD remote_response_core_console_write(Remote *remote, Packet *packet)
{
	return ERROR_SUCCESS;
}


/*!
 * @brief Base RPC dispatch table.
 */
Command commands[] =
{
	/*
	* Core commands
	*/

	// Console commands
	{  "core_console_write",  
		{ remote_request_core_console_write,     { TLV_META_TYPE_STRING }, 1 | ARGUMENT_FLAG_REPEAT },
		{ remote_response_core_console_write,    EMPTY_TLV },
	},

	// Native Channel commands
	COMMAND_REQ_REP( "core_channel_open", remote_request_core_channel_open, remote_response_core_channel_open ),
	COMMAND_REQ( "core_channel_write", remote_request_core_channel_write ),
	COMMAND_REQ_REP( "core_channel_close", remote_request_core_channel_close, remote_response_core_channel_close ),
	// Buffered/Pool channel commands
	COMMAND_REQ( "core_channel_read", remote_request_core_channel_read ),
	// Pool channel commands
	COMMAND_REQ( "core_channel_seek", remote_request_core_channel_seek ),
	COMMAND_REQ( "core_channel_eof", remote_request_core_channel_eof ),
	COMMAND_REQ( "core_channel_tell", remote_request_core_channel_tell ),
	// Soon to be deprecated
	COMMAND_REQ( "core_channel_interact", remote_request_core_channel_interact ),
	// Crypto
	COMMAND_REQ( "core_crypto_negotiate", remote_request_core_crypto_negotiate ),
	// Migration
	COMMAND_REQ( "core_migrate", remote_request_core_migrate ),
	// Shutdown
	COMMAND_REQ( "core_shutdown", remote_request_core_shutdown ),
	// Terminator
	COMMAND_TERMINATOR
};

// Dynamically registered command extensions
Command *extension_commands = NULL;

/*!
 * @brief Register a full list of commands with meterpreter.
 * @param commands The array of commands that are to be registered for the module/extension.
 */
void command_register_all(Command commands[])
{
	DWORD index;

	for (index = 0; commands[index].method; index++)
		command_register(&commands[index]);
}

/*!
 * @brief Dynamically register a custom command handler
 * @param command Pointer to the command that should be registered.
 * @return `ERROR_SUCCESS` when command registers successfully, otherwise returns the error.
 */
DWORD command_register(Command *command)
{
	Command *newCommand;

	dprintf("Registering a new command (%s)...", command->method);
	if (!(newCommand = (Command *)malloc(sizeof(Command))))
		return ERROR_NOT_ENOUGH_MEMORY;

	dprintf("Allocated memory...");
	memcpy(newCommand, command, sizeof(Command));

	dprintf("Setting new command...");
	if (extension_commands)
		extension_commands->prev = newCommand;

	dprintf("Fixing next/prev...");
	newCommand->next    = extension_commands;
	newCommand->prev    = NULL;
	extension_commands  = newCommand;

	dprintf("Done...");
	return ERROR_SUCCESS;
}

/*!
 * @brief Deregister a full list of commands from meterpreter.
 * @param commands The array of commands that are to be deregistered from the module/extension.
 */
void command_deregister_all(Command commands[])
{
	DWORD index;

	for (index = 0; commands[index].method; index++)
		command_deregister(&commands[index]);
}

/*!
 * @brief Dynamically deregister a custom command handler
 * @param command Pointer to the command that should be deregistered.
 * @return `ERROR_SUCCESS` when command deregisters successfully, otherwise returns the error.
 */
DWORD command_deregister(Command *command)
{
	Command *current, *prev;
	DWORD res = ERROR_NOT_FOUND;

	// Search the extension list for the command
	for (current = extension_commands, prev = NULL;
		current;
		prev = current, current = current->next)
	{
		if (strcmp(command->method, current->method))
			continue;

		if (prev)
			prev->next = current->next;
		else
			extension_commands = current->next;

		if (current->next)
			current->next->prev = prev;

		// Deallocate it
		free(current);

		res = ERROR_SUCCESS;

		break;
	}

	return res;
}

/*! * @brief A list of all command threads currenlty executing. */
LIST * commandThreadList = NULL;

/*!
 * @brief Block untill all running command threads have finished.
 */
VOID command_join_threads( VOID )
{
	while( list_count( commandThreadList ) > 0 )
	{
		THREAD * thread = (THREAD *)list_get( commandThreadList, 0 );
		if( thread )
			thread_join( thread );
	}
}

#ifndef _WIN32
/*!
 * @brief Reap child zombie threads on linux 2.4 (before NPTL).
 * @detail Each thread appears as a process and pthread_join don't necessarily reap it
 * threads are created using the clone syscall, so use special __WCLONE flag in waitpid.
 */
VOID reap_zombie_thread(void * param)
{
	while(1) {
		waitpid(-1, NULL, __WCLONE);
		// on 2.6 kernels, don't chew 100% CPU
		usleep(500000);
	}
}
#endif

/*!
 * @brief Process a single command in a seperate thread of execution.
 * @param thread Pointer to the thread to execute.
 * @return Result of processing.
 */
DWORD THREADCALL command_process_thread( THREAD * thread )
{
	DWORD index       = 0;
	DWORD result      = ERROR_SUCCESS;
	Tlv methodTlv     = {0};
	Tlv requestIdTlv  = {0};
	PCHAR method      = NULL;
	PCHAR requestId   = NULL;
	Command * current = NULL;
	Remote * remote   = NULL;
	Packet * packet   = NULL;

	if( thread == NULL )
		return ERROR_INVALID_HANDLE;

	remote = (Remote *)thread->parameter1;
	if( remote == NULL )
		return ERROR_INVALID_HANDLE;

	packet = (Packet *)thread->parameter2;
	if( packet == NULL )
		return ERROR_INVALID_DATA;

	if( commandThreadList == NULL )
	{
		commandThreadList = list_create();
		if( commandThreadList == NULL )
			return ERROR_INVALID_HANDLE;
#ifndef _WIN32
		pthread_t tid;
		pthread_create(&tid, NULL, reap_zombie_thread, NULL);
		dprintf("reap_zombie_thread created, thread_id : 0x%x",tid);
#endif
	}

	list_add( commandThreadList, thread );

	__try
	{
		do
		{

			// Extract the method
			result = packet_get_tlv_string( packet, TLV_TYPE_METHOD, &methodTlv );
			if( result != ERROR_SUCCESS )
				break;

			dprintf( "[COMMAND] Processing method %s", methodTlv.buffer );

#ifdef _WIN32
			// Impersonate the thread token if needed (only on Windows)
			if(remote->hServerToken != remote->hThreadToken) {
				if(! ImpersonateLoggedOnUser(remote->hThreadToken)) {
					dprintf( "[COMMAND] Failed to impersonate thread token (%s) (%u)", methodTlv.buffer, GetLastError());
				}
			}
#endif

			// Get the request identifier if the packet has one.
			result = packet_get_tlv_string( packet, TLV_TYPE_REQUEST_ID, &requestIdTlv );
			if( result == ERROR_SUCCESS )
				requestId = (PCHAR)requestIdTlv.buffer;

			method = (PCHAR)methodTlv.buffer;

			result = ERROR_NOT_FOUND;

			// Try to find a match in the dispatch type
			for( index = 0, result = ERROR_NOT_FOUND ; result == ERROR_NOT_FOUND && commands[index].method ; index++ )
			{
				if( strcmp( commands[index].method, method ) )
					continue;

				// Call the base handler
				result = command_call_dispatch( &commands[index], remote, packet );
			}

			// Regardless of error code, try to see if someone has overriden a base handler
			for( current = extension_commands, result = ERROR_NOT_FOUND ; 
				result == ERROR_NOT_FOUND && current && current->method ; current = current->next )
			{
				if( strcmp( current->method, method ) )
					continue;

				// Call the custom handler
				result = command_call_dispatch( current, remote, packet );
			}

			dprintf("[COMMAND] Calling completion handlers...");
			// Finally, call completion routines for the provided identifier
			if( ((packet_get_type(packet) == PACKET_TLV_TYPE_RESPONSE) || (packet_get_type(packet) == PACKET_TLV_TYPE_PLAIN_RESPONSE)) && (requestId))
				packet_call_completion_handlers( remote, packet, requestId );

			// If we get here, we're successful.
			result = ERROR_SUCCESS;

		} while( 0 );
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		dprintf("[COMMAND] Exception hit in command thread 0x%08X!", thread );
	}

	packet_destroy( packet );

	if( list_remove( commandThreadList, thread ) )
		thread_destroy( thread );

	return ERROR_SUCCESS;
}

/*
 * Process a single command
 */
/*
DWORD command_process_remote(Remote *remote, Packet *inPacket)
{
	DWORD res = ERROR_SUCCESS, index;
	Tlv methodTlv, requestIdTlv;
	Packet *localPacket = NULL;
	PCHAR method, requestId = NULL;
	Command *current;

	do
	{
		// If no packet was providied, try to receive one.
		if (!inPacket)
		{
			if ((res = packet_receive(remote, &localPacket)) != ERROR_SUCCESS)
				break;
			else
				inPacket = localPacket;
		}

		// Extract the method
		if ((packet_get_tlv_string(inPacket, TLV_TYPE_METHOD, &methodTlv)
				!= ERROR_SUCCESS))
			break;
		dprintf("Processing method %s", methodTlv.buffer);

		// Get the request identifier if the packet has one.
		if (packet_get_tlv_string(inPacket, TLV_TYPE_REQUEST_ID, 
				&requestIdTlv) == ERROR_SUCCESS)
			requestId = (PCHAR)requestIdTlv.buffer;

		method = (PCHAR)methodTlv.buffer;

		res = ERROR_NOT_FOUND;

		// Try to find a match in the dispatch type
		for (index = 0, res = ERROR_NOT_FOUND; 
			  res = ERROR_NOT_FOUND && commands[index].method; 
			  index++)
		{
			if (strcmp(commands[index].method, method))
				continue;

			// Call the base handler
			res = command_call_dispatch(&commands[index], remote, inPacket);
		}

		// Regardless of error code, try to see if someone has overriden
		// a base handler
		for (current = extension_commands, res = ERROR_NOT_FOUND; 
			  res == ERROR_NOT_FOUND && current && current->method; 
			  current = current->next)
		{
			if (strcmp(current->method, method))
				continue;
		
			// Call the custom handler
			res = command_call_dispatch(current, remote, inPacket);
		}

		dprintf("Calling completion handlers...");
		// Finally, call completion routines for the provided identifier
		if (((packet_get_type(inPacket) == PACKET_TLV_TYPE_RESPONSE) ||
		     (packet_get_type(inPacket) == PACKET_TLV_TYPE_PLAIN_RESPONSE)) &&
		    (requestId))
			packet_call_completion_handlers(remote, inPacket, requestId);

		// If we get here, we're successful.
		res = ERROR_SUCCESS;
		
	} while (0);

	if (localPacket)
		packet_destroy(localPacket);

	return res;
}*/

/*
 * Process incoming commands, calling dispatch tables appropriately
 */ 
/*
DWORD command_process_remote_loop(Remote *remote)
{
	DWORD res = ERROR_SUCCESS;
	Packet *packet;

	while ((res = packet_receive(remote, &packet)) == ERROR_SUCCESS)
	{
		res = command_process_remote(remote, packet);

		// Destroy the packet
		packet_destroy(packet);
	
		// If a command returned exit, we shall return.
		if (res == ERROR_INSTALL_USEREXIT)
			break;
	}

	return res;
}
*/

/*!
 * @brief Call the dispatch routine for a given command.
 * @param command The command to call the dispatch routine on.
 * @param remote Pointer to the remote connection.
 * @param packet Pointer to the current packet.
 * @return Result of the command dispatch handler call.
 */
 DWORD command_call_dispatch(Command *command, Remote *remote, Packet *packet)
{
	DWORD res;

	// Validate the arguments, if requested.  Always make sure argument 
	// lengths are sane.
	if ((res = command_validate_arguments(command, packet)) != ERROR_SUCCESS)
		return res;

	switch (packet_get_type(packet))
	{
	case PACKET_TLV_TYPE_REQUEST:
	case PACKET_TLV_TYPE_PLAIN_REQUEST:
		if (command->request.handler)
			res = command->request.handler(remote, packet);
		break;
	case PACKET_TLV_TYPE_RESPONSE:
	case PACKET_TLV_TYPE_PLAIN_RESPONSE:
		if (command->response.handler)
			res = command->response.handler(remote, packet);
		break;
	default:
		res = ERROR_NOT_FOUND;
		break;
	}

	return res;
}

/*!
 * @brief Validate command arguments
 * @return Indication of whether the commands are valid or not.
 * @retval ERROR_SUCCESS All arguments are valid.
 * @retval ERROR_INVALID_PARAMETER An invalid parameter exists.
 */
DWORD command_validate_arguments(Command *command, Packet *packet)
{
	PacketDispatcher *dispatcher = NULL;
	PacketTlvType type = packet_get_type(packet);
	DWORD res = ERROR_SUCCESS, 
		packetIndex, commandIndex;
	Tlv current;

	// Select the dispatcher table
	if ((type == PACKET_TLV_TYPE_RESPONSE) ||
		(type == PACKET_TLV_TYPE_PLAIN_RESPONSE))
		dispatcher = &command->response;
	else
		dispatcher = &command->request;

	// Enumerate the arguments, validating the meta types of each
	for (commandIndex = 0, packetIndex = 0;
		((packet_enum_tlv(packet, packetIndex, TLV_TYPE_ANY, &current) == ERROR_SUCCESS)
		&& (res == ERROR_SUCCESS));
		commandIndex++, packetIndex++)
	{
		TlvMetaType tlvMetaType;

		// Check to see if we've reached the end of the command arguments
		if ((dispatcher->numArgumentTypes) &&
			(commandIndex == (dispatcher->numArgumentTypes & ARGUMENT_FLAG_MASK)))
		{
			// If the repeat flag is set, reset the index
			if (commandIndex & ARGUMENT_FLAG_REPEAT)
				commandIndex = 0;
			else
				break;
		}

		// Make sure the argument is at least one of the meta types
		tlvMetaType = packet_get_tlv_meta(packet, &current);

		// Validate argument meta types
		switch (tlvMetaType)
		{
		case TLV_META_TYPE_STRING:
			if (packet_is_tlv_null_terminated(&current) != ERROR_SUCCESS)
				res = ERROR_INVALID_PARAMETER;
			break;
		default:
			break;
		}

		if ((res != ERROR_SUCCESS) && 
			(commandIndex < dispatcher->numArgumentTypes))
			break;
	}

	return res;
}
