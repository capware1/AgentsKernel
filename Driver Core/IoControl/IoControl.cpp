#include "IoControl.h"

namespace IoControl
{
	auto Dispatch(PDEVICE_OBJECT deviceObject, PIRP irp) -> NTSTATUS
	{
		UNREFERENCED_PARAMETER(deviceObject);
		NTSTATUS ioStatus = { 0 };
		ULONG bytesHandled = { 0 };
		PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(irp);
		ULONG ioCode = stackLocation->Parameters.DeviceIoControl.IoControlCode;
		ULONG inputSize = stackLocation->Parameters.DeviceIoControl.InputBufferLength;





		irp->IoStatus.Status = ioStatus;
		irp->IoStatus.Information = bytesHandled;
		Agents(IofCompleteRequest)(irp, IO_NO_INCREMENT);
		return ioStatus;
	}
}