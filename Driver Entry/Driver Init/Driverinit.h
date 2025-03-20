#pragma once

#include "../../Includes.h"

namespace DriverInit
{
	NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT DriverObject, PIRP irp);
	NTSTATUS DispatchHandler(PDEVICE_OBJECT DriverObject, PIRP irp);
	void DriverUnloading(PDRIVER_OBJECT DriverObject);
}