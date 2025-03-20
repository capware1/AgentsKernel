#include "Driverinit.h"

namespace DriverInit
{
	NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT DriverObject, PIRP irp)
	{
		UNREFERENCED_PARAMETER(DriverObject);
		irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
		//IofCompleteRequest(irpRequest, IO_NO_INCREMENT);
		Agents(IofCompleteRequest)(irp, IO_NO_INCREMENT);
		return irp->IoStatus.Status;
	}
	NTSTATUS DispatchHandler(PDEVICE_OBJECT DriverObject, PIRP irp)
	{
		UNREFERENCED_PARAMETER(DriverObject);
		PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(irp);
		switch (stackLocation->MajorFunction) {
		case IRP_MJ_CREATE:
			break;
		case IRP_MJ_CLOSE:
			break;
		default:
			break;
		}
		Agents(IofCompleteRequest)(irp, IO_NO_INCREMENT);
		return irp->IoStatus.Status;
	}
	void DriverUnloading(PDRIVER_OBJECT DriverObject)
	{
		NTSTATUS unlinkStatus = { 0 };
		unlinkStatus = Agents(IoDeleteSymbolicLink)(&DosL);
		if (!NT_SUCCESS(unlinkStatus))
			return;
		Agents(IoDeleteDevice)(DriverObject->DeviceObject);
	}
}