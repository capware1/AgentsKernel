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
		if (ioCode == Base_code)
		{
			if (inputSize == sizeof(base)) {
				pbase req = (pbase)(irp->AssociatedIrp.SystemBuffer);
				ioStatus = BaseAddy::BaseAddress(req);
				bytesHandled = sizeof(base);
			}
			else {
				ioStatus = STATUS_INFO_LENGTH_MISMATCH;
				bytesHandled = 0;
			}
		}
		else if (ioCode == Read_code)
		{
			if (inputSize == sizeof(read)) {
				pread req = (pread)(irp->AssociatedIrp.SystemBuffer);
				ioStatus = PML4::ReadHandler(req);
				bytesHandled = sizeof(read);
			}
			else {
				ioStatus = STATUS_INFO_LENGTH_MISMATCH;
				bytesHandled = 0;
			}
		}
		irp->IoStatus.Status = ioStatus;
		irp->IoStatus.Information = bytesHandled;
		Agents(IofCompleteRequest)(irp, IO_NO_INCREMENT);
		return ioStatus;
	}
}