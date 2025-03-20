#include "IoControl.h"

namespace IoControl
{
	auto HookedIoctl(PDEVICE_OBJECT deviceObject, PIRP irp) -> NTSTATUS
	{ }
}