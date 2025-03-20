#include "pml4.h"

namespace PML4
{
    static cache cached_pml4e[512];
    void* KDb = nullptr;
    ULONGLONG suDB = 0;
	auto ReadMemory(PVOID destination, PVOID src, SIZE_T size, SIZE_T* copiedSize) -> NTSTATUS {
		MM_COPY_ADDRESS srcAddr;
		srcAddr.PhysicalAddress.QuadPart = (LONGLONG)destination;
		return Agents(MmCopyMemory)(src, srcAddr, size, MM_COPY_MEMORY_PHYSICAL, copiedSize);
	}
	UINT64 Cr3Cahce(UINT64 address, cache* cached_entry, SIZE_T* readsize) {
		if (cached_entry->Address == address) {
			return cached_entry->Value;
		}
		ReadMemory(PVOID(address), &cached_entry->Value, sizeof(cached_entry->Value), readsize);
		cached_entry->Address = address;
		return cached_entry->Value;
	}
    auto TranslateLinear(UINT64 dtbase, UINT64 vtaddy) -> uint64_t {
        dtbase &= ~0xf;
        UINT64 pageOffset = vtaddy & ((1ULL << 12) - 1);
        UINT64 pte = (vtaddy >> 12) & 0x1ff;
        UINT64 pt = (vtaddy >> 21) & 0x1ff;
        UINT64 pd = (vtaddy >> 30) & 0x1ff;
        UINT64 pdp = (vtaddy >> 39) & 0x1ff;
        SIZE_T readsize = 0;
        UINT64 pdpe = 0;
        pdpe = Cr3Cahce(dtbase + 8 * pdp, &cached_pml4e[pdp], &readsize);
        if ((pdpe & 1) == 0)
            return 0;
        UINT64 pde = 0;
        ReadMemory(PVOID((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
        if ((pde & 1) == 0)
            return 0;
        if (pde & 0x80) {
            return (pde & PMASK) + (vtaddy & ((1ULL << 30) - 1));
        }
        UINT64 pteAddr = 0;
        ReadMemory(PVOID((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
        if ((pteAddr & 1) == 0)
            return 0;
        if (pteAddr & 0x80) {
            return (pteAddr & PMASK) + (vtaddy & ((1ULL << 21) - 1));
        }
        UINT64 finalAddr = 0;
        ReadMemory(PVOID((pteAddr & PMASK) + 8 * pte), &finalAddr, sizeof(finalAddr), &readsize);
        finalAddr &= PMASK;
        if (finalAddr == 0)
            return 0;
        return finalAddr + pageOffset;
    }

    PVOID fpim(const void* startAddress, size_t memorySize, const void* pattern, size_t patternSize) {
        const auto* memoryStart = static_cast<const uint8_t*>(startAddress);
        const auto* memoryPattern = static_cast<const uint8_t*>(pattern);

        for (size_t offset = 0; offset <= memorySize - patternSize; ++offset) {
            size_t patternIndex = 0;
            while (patternIndex < patternSize && memoryStart[offset + patternIndex] == memoryPattern[patternIndex]) {
                ++patternIndex;
            }
            if (patternIndex == patternSize) {
                return const_cast<uint8_t*>(&memoryStart[offset]);
            }
        }
        return nullptr;
    }
    NTSTATUS initDb() {
        struct PfnDatabasePattern {
            const uint8_t* bytePattern;
            size_t byteSize;
            bool isHardcoded;
        };

        static const uint8_t win10X64Pattern[] = { 0x48, 0x8B, 0xC1, 0x48, 0xC1, 0xE8, 0x0C, 0x48, 0x8D, 0x14, 0x40, 0x48, 0x03, 0xD2, 0x48, 0xB8 };

        PfnDatabasePattern searchConfig{
            win10X64Pattern,
            sizeof(win10X64Pattern),
            true
        };

        auto* virtualFunctionAddress = reinterpret_cast<uint8_t*>(Agents(MmGetVirtualForPhysical));
        if (!virtualFunctionAddress) {
            return STATUS_PROCEDURE_NOT_FOUND;
        }

        auto* resultAddress = reinterpret_cast<uint8_t*>(fpim(virtualFunctionAddress, 0x20, searchConfig.bytePattern, searchConfig.byteSize));
        if (!resultAddress) {
            return STATUS_UNSUCCESSFUL;
        }

        resultAddress += searchConfig.byteSize;

        if (searchConfig.isHardcoded) {
            KDb = *reinterpret_cast<void**>(resultAddress);
        }
        else {
            auto pfnAddress = *reinterpret_cast<uintptr_t*>(resultAddress);
            KDb = *reinterpret_cast<void**>(pfnAddress);
        }

        KDb = PAGE_ALIGN(KDb);
        return STATUS_SUCCESS;
    }
    static auto DirbaseFromBaseAddress(void* processBase) -> uint64_t {
        if (!NT_SUCCESS(initDb())) {
            return 0;
        }

        virt_addr_t virtualBase{};
        virtualBase.value = processBase;
        size_t bytesRead = 0;
        auto physicalMemory = Agents(MmGetPhysicalMemoryRanges)();

        for (int i = 0; physicalMemory[i].BaseAddress.QuadPart; ++i) {
            auto& currentRange = physicalMemory[i];
            uint64_t physicalAddr = currentRange.BaseAddress.QuadPart;

            for (uint64_t offset = 0; offset < currentRange.NumberOfBytes.QuadPart; offset += 0x1000, physicalAddr += 0x1000) {
                auto pfn = reinterpret_cast<_MMPFN*>((uintptr_t)KDb + ((physicalAddr >> 12) * sizeof(_MMPFN)));

                if (pfn->u4.PteFrame == (physicalAddr >> 12)) {
                    MMPTE pml4Entry{};
                    if (!NT_SUCCESS(ReadMemory(reinterpret_cast<void*>(physicalAddr + 8 * virtualBase.pml4_index), &pml4Entry, 8, &bytesRead))) {
                        continue;
                    }
                    if (!pml4Entry.u.Hard.Valid) {
                        continue;
                    }
                    MMPTE pdptEntry{};
                    if (!NT_SUCCESS(ReadMemory(reinterpret_cast<void*>((pml4Entry.u.Hard.PageFrameNumber << 12) + 8 * virtualBase.pdpt_index), &pdptEntry, 8, &bytesRead))) {
                        continue;
                    }
                    if (!pdptEntry.u.Hard.Valid) {
                        continue;
                    }
                    MMPTE pdeEntry{};
                    if (!NT_SUCCESS(ReadMemory(reinterpret_cast<void*>((pdptEntry.u.Hard.PageFrameNumber << 12) + 8 * virtualBase.pd_index), &pdeEntry, 8, &bytesRead))) {
                        continue;
                    }
                    if (!pdeEntry.u.Hard.Valid) {
                        continue;
                    }
                    MMPTE pteEntry{};
                    if (!NT_SUCCESS(ReadMemory(reinterpret_cast<void*>((pdeEntry.u.Hard.PageFrameNumber << 12) + 8 * virtualBase.pt_index), &pteEntry, 8, &bytesRead))) {
                        continue;
                    }
                    if (!pteEntry.u.Hard.Valid) {
                        continue;
                    }
                    return physicalAddr;
                }
            }
        }
        return 0;
    }
    auto ReadHandler(pread request) -> NTSTATUS
    {
        if (!request->ProcessID) {
            return STATUS_UNSUCCESSFUL;
        }

        PEPROCESS TargetProcess = nullptr;
        Agents(PsLookupProcessByProcessId)(reinterpret_cast<HANDLE>(request->ProcessID), &TargetProcess);
        if (!TargetProcess) {
            return STATUS_UNSUCCESSFUL;
        }
        size_t Size = request->size;
        int64_t physicalAddress = TranslateLinear(suDB, (uint64_t)(request->address));
        if (!physicalAddress) {
            if (refreshcache_r) {
                suDB = DirbaseFromBaseAddress(reinterpret_cast<void*>(Agents(PsGetProcessSectionBaseAddress)(TargetProcess)));
                refreshcache_r = false;
                physicalAddress = TranslateLinear(suDB, (uint64_t)(request->address));
                if (!physicalAddress) {
                    return STATUS_UNSUCCESSFUL;
                }
            }
            else {
                return STATUS_UNSUCCESSFUL;
            }
        }
        uint64_t FinalSize = FIND_MIN(PAGE_SIZE - (physicalAddress & 0xFFF), Size);
        size_t BytesProcessed = 0;

        ReadMemory(reinterpret_cast<void*>(physicalAddress), reinterpret_cast<void*>((uint64_t)(request->buffer)), FinalSize, &BytesProcessed);
        return STATUS_SUCCESS;
    }
}