/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mimidrv.h"
UNICODE_STRING
	uStrDriverName = {30, 32, L"\\Device\\" MIMIDRV},
	uStrDosDeviceName = {38, 40, L"\\DosDevices\\" MIMIDRV};

NTSTATUS UnSupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	return STATUS_NOT_SUPPORTED;
}

void DriverUnload(IN PDRIVER_OBJECT theDriverObject)
{
	IoDeleteSymbolicLink(&uStrDosDeviceName);
	IoDeleteDevice(theDriverObject->DeviceObject);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;
	PDEVICE_OBJECT pDeviceObject;
	ULONG i;
	
	if(KiwiOsIndex = getWindowsIndex())
	{
		status = IoCreateDevice(theDriverObject, 0, &uStrDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
		if(NT_SUCCESS(status))
		{
			for(i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
				theDriverObject->MajorFunction[i] = UnSupported;

			theDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MimiDispatchDeviceControl;
			theDriverObject->DriverUnload = DriverUnload;
		
			pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
			IoCreateSymbolicLink(&uStrDosDeviceName, &uStrDriverName);
			status = AuxKlibInitialize();
		}
	}
	return status;
}

NTSTATUS MimiDispatchDeviceControl(IN OUT DEVICE_OBJECT *DeviceObject, IN OUT IRP *Irp)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;
	PIO_STACK_LOCATION pIoStackIrp = NULL;
	SIZE_T szBufferIn, szBufferOut, szReallyOut = 0;
	PVOID bufferIn, bufferOut;
	KIWI_BUFFER kOutputBuffer = {&szBufferOut, &bufferOut};
	ULONG i;
	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);    
	if(pIoStackIrp)
	{
		szBufferIn	= pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
		szBufferOut	= pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
		bufferIn	= pIoStackIrp->Parameters.DeviceIoControl.Type3InputBuffer;
		bufferOut	= Irp->UserBuffer;
		
		switch(pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
		{
			case IOCTL_MIMIDRV_RAW:
				status = kprintf(&kOutputBuffer, L"Raw command (not implemented yet) : %s\n", bufferIn);
				break;
			case IOCTL_MIMIDRV_PING:
				status = kprintf(&kOutputBuffer, L"Input  : %s\nOutput : %s\n", bufferIn, L"pong");
				break;
			case IOCTL_MIMIDRV_BSOD:
				KeBugCheck(MANUALLY_INITIATED_CRASH);
				break;

			case IOCTL_MIMIDRV_PROCESS_LIST:
				status = kkll_m_process_enum(szBufferIn, bufferIn, &kOutputBuffer, kkll_m_process_list_callback, NULL); // input needed ?
				break;
			case IOCTL_MIMIDRV_PROCESS_TOKEN:
				status = kkll_m_process_token(szBufferIn, bufferIn, &kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_PROCESS_PROTECT:
				status = kkll_m_process_protect(szBufferIn, bufferIn, &kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_PROCESS_FULLPRIV:
				status = kkll_m_process_fullprivileges(szBufferIn, bufferIn, &kOutputBuffer);
				break;

			case IOCTL_MIMIDRV_MODULE_LIST:
				status = kkll_m_modules_enum(szBufferIn, bufferIn, &kOutputBuffer, kkll_m_modules_list_callback, NULL); // input needed ?
				break;

			case IOCTL_MIMIDRV_SSDT_LIST:
				status = kkll_m_ssdt_list(&kOutputBuffer);
				break;

			case IOCTL_MIMIDRV_NOTIFY_PROCESS_LIST:
				status = kkll_m_notify_list_process(&kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_NOTIFY_THREAD_LIST:
				status = kkll_m_notify_list_thread(&kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_NOTIFY_IMAGE_LIST:
				status = kkll_m_notify_list_image(&kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_NOTIFY_REG_LIST:
				status = kkll_m_notify_list_reg(&kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_NOTIFY_OBJECT_LIST:
				status = kkll_m_notify_list_object(&kOutputBuffer);
				break;

			case IOCTL_MIMIDRV_FILTER_LIST:
				status = kkll_m_filters_list(&kOutputBuffer);
				break;
			case IOCTL_MIMIDRV_MINIFILTER_LIST:
				status = kkll_m_minifilters_list(&kOutputBuffer);
				break;
		}

		if(NT_SUCCESS(status))
			szReallyOut = pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength - szBufferOut;
	}
	
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = szReallyOut;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

KIWI_OS_INDEX getWindowsIndex()
{
	switch(*NtBuildNumber)
	{
		case 2600:
			return KiwiOsIndex_XP;
			break;
		case 3790:	
			return KiwiOsIndex_2K3;
			break;
		case 6000:
		case 6001:
		case 6002:
			return KiwiOsIndex_VISTA;
			break;
		case 7600:
		case 7601:
			return KiwiOsIndex_7;
			break;
		case 8102:
		case 8250:
		case 9200:
			return KiwiOsIndex_8;
		case 9431:
		case 9600:
			return KiwiOsIndex_BLUE;
			break;
		default:
			return KiwiOsIndex_UNK;
	}
}