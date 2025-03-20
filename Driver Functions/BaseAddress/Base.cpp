#include "Base.h"


namespace BaseAddy
{
    NTSTATUS BaseAddress(pbase request)
    {
        if (request == NULL || request->address == NULL || request->process_id == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        PEPROCESS Process = NULL;
        if (!NT_SUCCESS(Agents(PsLookupProcessByProcessId)((HANDLE)request->process_id, &Process))) {
            return STATUS_UNSUCCESSFUL;
        }
        ULONGLONG ProcessBase = (ULONGLONG)Agents(PsGetProcessSectionBaseAddress)(Process);
        if (!ProcessBase)
            return STATUS_INVALID_PARAMETER;
        Agents(memcpy)(request->address, &ProcessBase, sizeof(ProcessBase));
        Agents(ObfDereferenceObject)(Process);
        refreshcache_r = true;
        return STATUS_SUCCESS;
    }
}