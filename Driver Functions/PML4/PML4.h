#pragma once

#include "../../Includes.h"



typedef struct _dtb {
	INT32 ProcessID;
	bool* operation;
} dtb, * pdtb;

typedef struct _read {
	INT32 ProcessID;
	ULONGLONG address;
	ULONGLONG buffer;
	ULONGLONG size;
} read, * pread;

namespace PML4
{
	auto ReadMemory(PVOID destination, PVOID src, SIZE_T size, SIZE_T* copiedSize) -> NTSTATUS;
	UINT64 Cr3Cahce(UINT64 address, cache* cached_entry, SIZE_T* readsize);
	auto TranslateLinear(UINT64 dtbase, UINT64 vtaddy) -> uint64_t;
	PVOID fpim(const void* startAddress, size_t memorySize, const void* pattern, size_t patternSize);
	NTSTATUS initDb();
	static auto DirbaseFromBaseAddress(void* processBase) -> uint64_t;
	NTSTATUS DecryptCR3(pdtb request);
	auto ReadHandler(pread request) -> NTSTATUS;
}
