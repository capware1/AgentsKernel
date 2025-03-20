#pragma once

#include "../../Includes.h"


typedef struct _base {
	INT32 process_id;
	ULONGLONG* address;
} base, * pbase;

namespace BaseAddy
{
	NTSTATUS BaseAddress(pbase request);
}