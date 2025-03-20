#include "../Includes.h"
#define DEVICE_MODULE E(L"{a1f3b2c4-8d9e-4f7a-bc23-6e5d1a89f012}")


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	NTSTATUS StatusResult = { };
	PDEVICE_OBJECT deviceObj = { };

	DeviceN = Utility::ConcatenateStrings(E(L"\\Device\\"), DEVICE_MODULE);
	DosL = Utility::ConcatenateStrings(E(L"\\DosDevices\\"), DEVICE_MODULE);

	StatusResult = Agents(IoCreateDevice)(DriverObject, 0, &DeviceN, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObj);

	if (!NT_SUCCESS(StatusResult))
		return StatusResult;

	StatusResult = Agents(IoCreateSymbolicLink)(&DosL, &DeviceN);
	if (!NT_SUCCESS(StatusResult))
		return StatusResult;

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = &DriverInit::UnsupportedDispatch;

	deviceObj->Flags |= DO_BUFFERED_IO;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = &DriverInit::DispatchHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = &DriverInit::DispatchHandler;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &IoControl::Dispatch;
	DriverObject->DriverUnload = &DriverInit::DriverUnloading;
	deviceObj->Flags &= ~DO_DEVICE_INITIALIZING;

	return StatusResult;
}