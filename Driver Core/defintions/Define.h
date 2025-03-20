#pragma once
#include <ntifs.h>
#include <windef.h>
#include <cstdint>
#include <intrin.h>
#include "../../Includes.h"
#ifndef HEADER_FILE_NAME_H
#define HEADER_FILE_NAME_H

#pragma warning(disable: 4201)

#ifdef _MSC_VER
#define _KLI_FORCEINLINE __forceinline
#else
#define _KLI_FORCEINLINE __attribute__((always_inline))
#endif

#ifndef KLI_DONT_INLINE
#define KLI_FORCEINLINE _KLI_FORCEINLINE
#else
#define KLI_FORCEINLINE inline
#endif

namespace kli {

    namespace type_traits
    {
        template <class Type>
        struct remove_reference {
            using type = Type;
        };

        template <class Type>
        struct remove_reference<Type&> {
            using type = Type;
        };

        template <class Type>
        struct remove_reference<Type&&> {
            using type = Type;
        };

        template <class Type>
        using remove_reference_t = typename remove_reference<Type>::type;

        template <class Type>
        struct remove_const {
            using type = Type;
        };

        template <class Type>
        struct remove_const<const Type> {
            using type = Type;
        };

        template <class Type>
        using remove_const_t = typename remove_const<Type>::type;
    }

    namespace cache {
        inline uintptr_t kernel_base;
    }

    namespace literals {
        KLI_FORCEINLINE constexpr size_t operator ""_KiB(size_t num) { return num << 10; }
        KLI_FORCEINLINE constexpr size_t operator ""_MiB(size_t num) { return num << 20; }
        KLI_FORCEINLINE constexpr size_t operator ""_GiB(size_t num) { return num << 30; }
        KLI_FORCEINLINE constexpr size_t operator ""_TiB(size_t num) { return num << 40; }
    }
    using namespace literals;

    namespace hash {
        namespace detail {
            template <typename Size>
            struct fnv_constants;

            template <>
            struct fnv_constants<uint32_t>
            {
                constexpr static uint32_t default_offset_basis = 0x811C9DC5UL;
                constexpr static uint32_t prime = 0x01000193UL;
            };

            template <>
            struct fnv_constants<uint64_t>
            {
                constexpr static uint64_t default_offset_basis = 0xCBF29CE484222325ULL;
                constexpr static uint64_t prime = 0x100000001B3ULL;
            };

            template <typename Char>
            struct char_traits;

            template <>
            struct char_traits<char>
            {
                KLI_FORCEINLINE static constexpr char to_lower(char c) { return c | ' '; };
                KLI_FORCEINLINE static constexpr char to_upper(char c) { return c & '_'; };
                KLI_FORCEINLINE static constexpr char flip_case(char c) { return c ^ ' '; };
                KLI_FORCEINLINE static constexpr bool is_caps(char c) { return (c & ' ') == ' '; }
            };

            template <>
            struct char_traits<wchar_t>
            {
                KLI_FORCEINLINE static constexpr wchar_t to_lower(wchar_t c) { return c | L' '; };
                KLI_FORCEINLINE static constexpr wchar_t to_upper(wchar_t c) { return c & L'_'; };
                KLI_FORCEINLINE static constexpr wchar_t flip_case(wchar_t c) { return c ^ L' '; };
                KLI_FORCEINLINE static constexpr bool is_caps(wchar_t c) { return (c & L' ') == L' '; }
            };
        }

        template <typename Char> KLI_FORCEINLINE constexpr Char to_lower(Char c) { return detail::char_traits<Char>::to_lower(c); }
        template <typename Char> KLI_FORCEINLINE constexpr Char to_upper(Char c) { return detail::char_traits<Char>::to_upper(c); }
        template <typename Char> KLI_FORCEINLINE constexpr Char flip_case(Char c) { return detail::char_traits<Char>::flip_case(c); }

        template <typename Type, typename Char, bool ToLower = false>
        KLI_FORCEINLINE constexpr Type hash_fnv1a(const Char* str)
        {
            Type val = detail::fnv_constants<Type>::default_offset_basis;

            for (; *str != static_cast<Char>(0); ++str) {
                Char c = *str;

                if constexpr (ToLower)
                    c = to_lower<Char>(c);

                val ^= static_cast<Type>(c);
                val *= static_cast<Type>(detail::fnv_constants<Type>::prime);
            }

            return val;
        }

        template <typename Type, Type Value>
        struct force_cx
        {
            constexpr static auto value = Value;
        };

#define _KLI_HASH_RTS(str) (::kli::hash::hash_fnv1a<uint64_t, ::kli::type_traits::remove_const_t<::kli::type_traits::remove_reference_t<decltype(*(str))>>, false>((str)))
#define _KLI_HASH_RTS_TOLOWER(str) (::kli::hash::hash_fnv1a<uint64_t, ::kli::type_traits::remove_const_t<::kli::type_traits::remove_reference_t<decltype(*(str))>>, true>((str)))

#define _KLI_HASH_STR(str) (::kli::hash::force_cx<uint64_t, ::kli::hash::hash_fnv1a<uint64_t, ::kli::type_traits::remove_const_t<::kli::type_traits::remove_reference_t<decltype(*(str))>>, false>((str))>::value)
#define _KLI_HASH_STR_TOLOWER(str) (::kli::hash::force_cx<uint64_t, ::kli::hash::hash_fnv1a<uint64_t, ::kli::type_traits::remove_const_t<::kli::type_traits::remove_reference_t<decltype(*(str))>>, true>((str))>::value)

#ifndef KLI_USE_TOLOWER

#define FIND_MIN(val1, val2) (static_cast<ULONG64>((val1) < (val2) ? (val1) : (val2)))
#define KLI_HASH_RTS(str) _KLI_HASH_RTS(str)
#define KLI_HASH_STR(str) _KLI_HASH_STR(str)
#else

#define KLI_HASH_RTS(str) _KLI_HASH_RTS_TOLOWER(str)
#define KLI_HASH_STR(str) _KLI_HASH_STR_TOLOWER(str)
#endif
    }

    namespace detail {
#pragma pack(push, 1)
        enum exception_vector
        {
            VECTOR_DIVIDE_ERROR_EXCEPTION = 0,
            VECTOR_DEBUG_EXCEPTION = 1,
            VECTOR_NMI_INTERRUPT = 2,
            VECTOR_BREAKPOINT_EXCEPTION = 3,
            VECTOR_OVERFLOW_EXCEPTION = 4,
            VECTOR_BOUND_EXCEPTION = 5,
            VECTOR_UNDEFINED_OPCODE_EXCEPTION = 6,
            VECTOR_DEVICE_NOT_AVAILABLE_EXCEPTION = 7,
            VECTOR_DOUBLE_FAULT_EXCEPTION = 8,
            VECTOR_COPROCESSOR_SEGMENT_OVERRUN = 9,
            VECTOR_INVALID_TSS_EXCEPTION = 10,
            VECTOR_SEGMENT_NOT_PRESENT = 11,
            VECTOR_STACK_FAULT_EXCEPTION = 12,
            VECTOR_GENERAL_PROTECTION_EXCEPTION = 13,
            VECTOR_PAGE_FAULT_EXCEPTION = 14,
            VECTOR_X87_FLOATING_POINT_ERROR = 16,
            VECTOR_ALIGNMENT_CHECK_EXCEPTION = 17,
            VECTOR_MACHINE_CHECK_EXCEPTION = 18,
            VECTOR_SIMD_FLOATING_POINT_EXCEPTION = 19,
            VECTOR_VIRTUALIZATION_EXCEPTION = 20,
            VECTOR_SECURITY_EXCEPTION = 30
        };

        union idt_entry
        {
            struct
            {
                uint64_t low64;
                uint64_t high64;
            } split;

            struct
            {
                uint16_t offset_low;

                union
                {
                    uint16_t flags;

                    struct
                    {
                        uint16_t rpl : 2;
                        uint16_t table : 1;
                        uint16_t index : 13;
                    };
                } segment_selector;
                uint8_t reserved0;
                union
                {
                    uint8_t flags;

                    struct
                    {
                        uint8_t gate_type : 4;
                        uint8_t storage_segment : 1;
                        uint8_t dpl : 2;
                        uint8_t present : 1;
                    };
                } type_attr;

                uint16_t offset_mid;
                uint32_t offset_high;
                uint32_t reserved1;
            };
        };

        struct idtr
        {
            uint16_t idt_limit;
            uint64_t idt_base;

            KLI_FORCEINLINE idt_entry* operator [](size_t index) {
                return &((idt_entry*)idt_base)[index];
            }
        };
#pragma pack(pop)

        typedef struct _IMAGE_DOS_HEADER {
            uint16_t   e_magic;
            uint16_t   e_cblp;
            uint16_t   e_cp;
            uint16_t   e_crlc;
            uint16_t   e_cparhdr;
            uint16_t   e_minalloc;
            uint16_t   e_maxalloc;
            uint16_t   e_ss;
            uint16_t   e_sp;
            uint16_t   e_csum;
            uint16_t   e_ip;
            uint16_t   e_cs;
            uint16_t   e_lfarlc;
            uint16_t   e_ovno;
            uint16_t   e_res[4];
            uint16_t   e_oemid;
            uint16_t   e_oeminfo;
            uint16_t   e_res2[10];
            int32_t    e_lfanew;
        } IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

        typedef struct _IMAGE_FILE_HEADER {
            uint16_t    Machine;
            uint16_t    NumberOfSections;
            uint32_t   TimeDateStamp;
            uint32_t   PointerToSymbolTable;
            uint32_t   NumberOfSymbols;
            uint16_t    SizeOfOptionalHeader;
            uint16_t    Characteristics;
        } IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

        typedef struct _IMAGE_DATA_DIRECTORY {
            uint32_t   VirtualAddress;
            uint32_t   Size;
        } IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

        typedef struct _IMAGE_OPTIONAL_HEADER64 {
            uint16_t        Magic;
            uint8_t        MajorLinkerVersion;
            uint8_t        MinorLinkerVersion;
            uint32_t       SizeOfCode;
            uint32_t       SizeOfInitializedData;
            uint32_t       SizeOfUninitializedData;
            uint32_t       AddressOfEntryPoint;
            uint32_t       BaseOfCode;
            uint64_t   ImageBase;
            uint32_t       SectionAlignment;
            uint32_t       FileAlignment;
            uint16_t        MajorOperatingSystemVersion;
            uint16_t        MinorOperatingSystemVersion;
            uint16_t        MajorImageVersion;
            uint16_t        MinorImageVersion;
            uint16_t        MajorSubsystemVersion;
            uint16_t        MinorSubsystemVersion;
            uint32_t       Win32VersionValue;
            uint32_t       SizeOfImage;
            uint32_t       SizeOfHeaders;
            uint32_t       CheckSum;
            uint16_t        Subsystem;
            uint16_t        DllCharacteristics;
            uint64_t   SizeOfStackReserve;
            uint64_t   SizeOfStackCommit;
            uint64_t   SizeOfHeapReserve;
            uint64_t   SizeOfHeapCommit;
            uint32_t       LoaderFlags;
            uint32_t       NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY DataDirectory[16];
        } IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

        typedef struct _IMAGE_NT_HEADERS64 {
            uint32_t Signature;
            IMAGE_FILE_HEADER FileHeader;
            IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        } IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

        typedef struct _IMAGE_EXPORT_DIRECTORY {
            uint32_t   Characteristics;
            uint32_t   TimeDateStamp;
            uint16_t   MajorVersion;
            uint16_t   MinorVersion;
            uint32_t   Name;
            uint32_t   Base;
            uint32_t   NumberOfFunctions;
            uint32_t   NumberOfNames;
            uint32_t   AddressOfFunctions;
            uint32_t   AddressOfNames;
            uint32_t   AddressOfNameOrdinals;
        } IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

        constexpr uint16_t IMAGE_DOS_SIGNATUREg = 0x5A4D;
        constexpr uint32_t IMAGE_NT_SIGNATUREg = 0x00004550;
        constexpr uint16_t IMAGE_FILE_MACHINE_AMD64g = 0x8664;
        constexpr auto IMAGE_DIRECTORY_ENTRY_EXPORTg = 0;

        KLI_FORCEINLINE bool is_kernel_base(uintptr_t addr)
        {
            const auto dos_header = (PIMAGE_DOS_HEADER)addr;

            if (dos_header->e_magic != IMAGE_DOS_SIGNATUREg)
                return false;

            const auto nt_headers = (PIMAGE_NT_HEADERS64)(addr + dos_header->e_lfanew);

            if (nt_headers->Signature != IMAGE_NT_SIGNATUREg)
                return false;

            if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64g)
                return false;

            const auto export_directory = (PIMAGE_EXPORT_DIRECTORY)(addr + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORTg].VirtualAddress);
            const auto dll_name = (const char*)(addr + export_directory->Name);
            const auto dll_name_hash = KLI_HASH_RTS(dll_name);

            if (dll_name_hash != KLI_HASH_STR("ntoskrnl.exe"))
                return false;

            return true;
        }

        KLI_FORCEINLINE uintptr_t find_kernel_base()
        {
            idtr k_idtr;
            __sidt((void*)&k_idtr);

            if (!k_idtr.idt_base)
                __debugbreak();

            const auto isr_divide_error = k_idtr[VECTOR_DIVIDE_ERROR_EXCEPTION];
            const auto pfn_KiDivideErrorFault = ((uintptr_t)isr_divide_error->offset_low) |
                (((uintptr_t)isr_divide_error->offset_mid) << 16) |
                (((uintptr_t)isr_divide_error->offset_high) << 32);

            const auto aligned_isr = pfn_KiDivideErrorFault & ~(2_MiB - 1);
            uintptr_t address = aligned_isr;

            while (!is_kernel_base(address)) {
                address -= 2_MiB;
            }

            return address;
        }
    }

    template <uint64_t ExportHash>
    KLI_FORCEINLINE uintptr_t find_kernel_export()
    {
        if (!cache::kernel_base)
            cache::kernel_base = detail::find_kernel_base();

        const auto dos_header = (detail::PIMAGE_DOS_HEADER)cache::kernel_base;
        const auto nt_headers = (detail::PIMAGE_NT_HEADERS64)(cache::kernel_base + dos_header->e_lfanew);
        const auto export_directory = (detail::PIMAGE_EXPORT_DIRECTORY)(cache::kernel_base +
            nt_headers->OptionalHeader.DataDirectory[detail::IMAGE_DIRECTORY_ENTRY_EXPORTg].VirtualAddress);

        const auto address_of_functions = (uint32_t*)(cache::kernel_base + export_directory->AddressOfFunctions);
        const auto address_of_names = (uint32_t*)(cache::kernel_base + export_directory->AddressOfNames);
        const auto address_of_name_ordinals = (uint16_t*)(cache::kernel_base + export_directory->AddressOfNameOrdinals);

        for (uint32_t i = 0; i < export_directory->NumberOfNames; ++i)
        {
            const auto export_entry_name = (char*)(cache::kernel_base + address_of_names[i]);
            const auto export_entry_hash = KLI_HASH_RTS(export_entry_name);

            if (export_entry_hash == ExportHash)
                return cache::kernel_base + address_of_functions[address_of_name_ordinals[i]];
        }

        __debugbreak();
        return { };
    }

    template <uint64_t ExportHash>
    KLI_FORCEINLINE uintptr_t find_kernel_export_cached()
    {
        static uintptr_t address = 0;
        if (!address)
            address = find_kernel_export<ExportHash>();

        return address;
    }
}
#ifdef KLI_DISABLE_CACHE
#define _(name) ((decltype(&##name))(::kli::find_kernel_export<KLI_HASH_STR(#name)>()))
#else
#define Agents(name) ((decltype(&##name))(::kli::find_kernel_export_cached<KLI_HASH_STR(#name)>()))
#endif
#endif
typedef union _virt_addr_t
{
    void* value;
    struct
    {
        uintptr_t offset : 12;
        uintptr_t pt_index : 9;
        uintptr_t pd_index : 9;
        uintptr_t pdpt_index : 9;
        uintptr_t pml4_index : 9;
        uintptr_t reserved : 16;
    };
} virt_addr_t, * pvirt_addr_t;
typedef struct _MI_ACTIVE_PFN
{
    union
    {
        struct
        {
            struct
            {
                unsigned __int64 Tradable : 1;
                unsigned __int64 NonPagedBuddy : 43;
            };
        }  Leaf;
        struct
        {
            struct
            {
                unsigned __int64 Tradable : 1;
                unsigned __int64 WsleAge : 3;
                unsigned __int64 OldestWsleLeafEntries : 10;
                unsigned __int64 OldestWsleLeafAge : 3;
                unsigned __int64 NonPagedBuddy : 43;
            };
        }  PageTable;
        unsigned __int64 EntireActiveField;
    };
} MI_ACTIVE_PFN, * PMI_ACTIVE_PFN;
typedef struct _MMPTE_HARDWARE
{
    struct
    {
        unsigned __int64 Valid : 1;
        unsigned __int64 Dirty1 : 1;
        unsigned __int64 Owner : 1;
        unsigned __int64 WriteThrough : 1;
        unsigned __int64 CacheDisable : 1;
        unsigned __int64 Accessed : 1;
        unsigned __int64 Dirty : 1;
        unsigned __int64 LargePage : 1;
        unsigned __int64 Global : 1;
        unsigned __int64 CopyOnWrite : 1;
        unsigned __int64 Unused : 1;
        unsigned __int64 Write : 1;
        unsigned __int64 PageFrameNumber : 40;
        unsigned __int64 ReservedForSoftware : 4;
        unsigned __int64 WsleAge : 4;
        unsigned __int64 WsleProtection : 3;
        unsigned __int64 NoExecute : 1;
    };
} MMPTE_HARDWARE, * PMMPTE_HARDWARE;
#define rva(addr, size)((PBYTE)(addr + *(DWORD*)(addr + ((size) - 4)) + size))
typedef struct _TAG_WND
{
    char padding_0[0x10];
    struct _TAG_INFO* tag_info;
    char padding_0x0[0x40];
    struct _TAG_WND* next; // 0x58
    struct _TAG_WND* prev; // 0x60
    struct _TAG_WND* parent; // 0x68
    struct _TAG_WND* child; // 0x70
}TAG_WND, * PTAG_WND;
struct comms_t {
    std::uint32_t key;

    struct {
        void* handle;
    } window;
};
typedef struct _MMPTE_PROTOTYPE
{
    struct
    {
        unsigned __int64 Valid : 1;
        unsigned __int64 DemandFillProto : 1;
        unsigned __int64 HiberVerifyConverted : 1;
        unsigned __int64 ReadOnly : 1;
        unsigned __int64 SwizzleBit : 1;
        unsigned __int64 Protection : 5;
        unsigned __int64 Prototype : 1;
        unsigned __int64 Combined : 1;
        unsigned __int64 Unused1 : 4;
        __int64 ProtoAddress : 48;
    };
} MMPTE_PROTOTYPE, * PMMPTE_PROTOTYPE;
typedef struct _MMPTE_SOFTWARE
{
    struct
    {
        unsigned __int64 Valid : 1;
        unsigned __int64 PageFileReserved : 1;
        unsigned __int64 PageFileAllocated : 1;
        unsigned __int64 ColdPage : 1;
        unsigned __int64 SwizzleBit : 1;
        unsigned __int64 Protection : 5;
        unsigned __int64 Prototype : 1;
        unsigned __int64 Transition : 1;
        unsigned __int64 PageFileLow : 4;
        unsigned __int64 UsedPageTableEntries : 10;
        unsigned __int64 ShadowStack : 1;
        unsigned __int64 Unused : 5;
        unsigned __int64 PageFileHigh : 32;
    };
} MMPTE_SOFTWARE, * PMMPTE_SOFTWARE;
typedef struct _MMPTE_TIMESTAMP
{
    struct
    {
        unsigned __int64 MustBeZero : 1;
        unsigned __int64 Unused : 3;
        unsigned __int64 SwizzleBit : 1;
        unsigned __int64 Protection : 5;
        unsigned __int64 Prototype : 1;
        unsigned __int64 Transition : 1;
        unsigned __int64 PageFileLow : 4;
        unsigned __int64 Reserved : 16;
        unsigned __int64 GlobalTimeStamp : 32;
    };
} MMPTE_TIMESTAMP, * PMMPTE_TIMESTAMP;
typedef struct _MMPTE_TRANSITION
{
    struct
    {
        unsigned __int64 Valid : 1;
        unsigned __int64 Write : 1;
        unsigned __int64 Spare : 1;
        unsigned __int64 IoTracker : 1;
        unsigned __int64 SwizzleBit : 1;
        unsigned __int64 Protection : 5;
        unsigned __int64 Prototype : 1;
        unsigned __int64 Transition : 1;
        unsigned __int64 PageFrameNumber : 40;
        unsigned __int64 Unused : 12;
    };
} MMPTE_TRANSITION, * PMMPTE_TRANSITION;
typedef struct _MMPTE_SUBSECTION
{
    struct
    {
        unsigned __int64 Valid : 1;
        unsigned __int64 Unused0 : 3;
        unsigned __int64 SwizzleBit : 1;
        unsigned __int64 Protection : 5;
        unsigned __int64 Prototype : 1;
        unsigned __int64 ColdPage : 1;
        unsigned __int64 Unused1 : 3;
        unsigned __int64 ExecutePrivilege : 1;
        __int64 SubsectionAddress : 48;
    };
} MMPTE_SUBSECTION, * PMMPTE_SUBSECTION;
typedef struct _MMPTE_LIST
{
    struct
    {
        unsigned __int64 Valid : 1;
        unsigned __int64 OneEntry : 1;
        unsigned __int64 filler0 : 2;
        unsigned __int64 SwizzleBit : 1;
        unsigned __int64 Protection : 5;
        unsigned __int64 Prototype : 1;
        unsigned __int64 Transition : 1;
        unsigned __int64 filler1 : 16;
        unsigned __int64 NextEntry : 36;
    };
} MMPTE_LIST, * PMMPTE_LIST;
typedef struct _MMPTE
{
    union
    {
        union
        {
            unsigned __int64 Long;
            volatile unsigned __int64 VolatileLong;
            struct _MMPTE_HARDWARE Hard;
            struct _MMPTE_PROTOTYPE Proto;
            struct _MMPTE_SOFTWARE Soft;
            struct _MMPTE_TIMESTAMP TimeStamp;
            struct _MMPTE_TRANSITION Trans;
            struct _MMPTE_SUBSECTION Subsect;
            struct _MMPTE_LIST List;
        };
    }  u;
} MMPTE, * PMMPTE;
typedef struct _MIPFNBLINK
{
    union
    {
        struct /* bitfield */
        {
            /* 0x0000 */ unsigned __int64 Blink : 40; /* bit position: 0 */
            /* 0x0000 */ unsigned __int64 NodeBlinkLow : 19; /* bit position: 40 */
            /* 0x0000 */ unsigned __int64 TbFlushStamp : 3; /* bit position: 59 */
            /* 0x0000 */ unsigned __int64 PageBlinkDeleteBit : 1; /* bit position: 62 */
            /* 0x0000 */ unsigned __int64 PageBlinkLockBit : 1; /* bit position: 63 */
        }; /* bitfield */
        struct /* bitfield */
        {
            /* 0x0000 */ unsigned __int64 ShareCount : 62; /* bit position: 0 */
            /* 0x0000 */ unsigned __int64 PageShareCountDeleteBit : 1; /* bit position: 62 */
            /* 0x0000 */ unsigned __int64 PageShareCountLockBit : 1; /* bit position: 63 */
        }; /* bitfield */
        /* 0x0000 */ unsigned __int64 EntireField;
        /* 0x0000 */ volatile __int64 Lock;
        struct /* bitfield */
        {
            /* 0x0000 */ unsigned __int64 LockNotUsed : 62; /* bit position: 0 */
            /* 0x0000 */ unsigned __int64 DeleteBit : 1; /* bit position: 62 */
            /* 0x0000 */ unsigned __int64 LockBit : 1; /* bit position: 63 */
        }; /* bitfield */
    }; /* size: 0x0008 */
} MIPFNBLINK, * PMIPFNBLINK; /* size: 0x0008 */
typedef struct _MMPFNENTRY1
{
    struct /* bitfield */
    {
        /* 0x0000 */ unsigned char PageLocation : 3; /* bit position: 0 */
        /* 0x0000 */ unsigned char WriteInProgress : 1; /* bit position: 3 */
        /* 0x0000 */ unsigned char Modified : 1; /* bit position: 4 */
        /* 0x0000 */ unsigned char ReadInProgress : 1; /* bit position: 5 */
        /* 0x0000 */ unsigned char CacheAttribute : 2; /* bit position: 6 */
    }; /* bitfield */
} MMPFNENTRY1, * PMMPFNENTRY1; /* size: 0x0001 */
typedef struct _MMPFNENTRY3
{
    struct /* bitfield */
    {
        /* 0x0000 */ unsigned char Priority : 3; /* bit position: 0 */
        /* 0x0000 */ unsigned char OnProtectedStandby : 1; /* bit position: 3 */
        /* 0x0000 */ unsigned char InPageError : 1; /* bit position: 4 */
        /* 0x0000 */ unsigned char SystemChargedPage : 1; /* bit position: 5 */
        /* 0x0000 */ unsigned char RemovalRequested : 1; /* bit position: 6 */
        /* 0x0000 */ unsigned char ParityError : 1; /* bit position: 7 */
    }; /* bitfield */
} MMPFNENTRY3, * PMMPFNENTRY3; /* size: 0x0001 */
typedef struct _MI_PFN_ULONG5
{
    union
    {
        /* 0x0000 */ unsigned long EntireField;
        struct
        {
            struct /* bitfield */
            {
                /* 0x0000 */ unsigned long NodeBlinkHigh : 21; /* bit position: 0 */
                /* 0x0000 */ unsigned long NodeFlinkMiddle : 11; /* bit position: 21 */
            }; /* bitfield */
        } /* size: 0x0004 */ StandbyList;
        struct
        {
            /* 0x0000 */ unsigned char ModifiedListBucketIndex : 4; /* bit position: 0 */
        } /* size: 0x0001 */ MappedPageList;
        struct
        {
            struct /* bitfield */
            {
                /* 0x0000 */ unsigned char AnchorLargePageSize : 2; /* bit position: 0 */
                /* 0x0000 */ unsigned char Spare1 : 6; /* bit position: 2 */
            }; /* bitfield */
            /* 0x0001 */ unsigned char ViewCount;
            /* 0x0002 */ unsigned short Spare2;
        } /* size: 0x0004 */ Active;
    }; /* size: 0x0004 */
} MI_PFN_ULONG5, * PMI_PFN_ULONG5; /* size: 0x0004 */
typedef struct _MMPFN
{
    union
    {
        /* 0x0000 */ struct _LIST_ENTRY ListEntry;
        /* 0x0000 */ struct _RTL_BALANCED_NODE TreeNode;
        struct
        {
            union
            {
                union
                {
                    /* 0x0000 */ struct _SINGLE_LIST_ENTRY NextSlistPfn;
                    /* 0x0000 */ void* Next;
                    struct /* bitfield */
                    {
                        /* 0x0000 */ unsigned __int64 Flink : 40; /* bit position: 0 */
                        /* 0x0000 */ unsigned __int64 NodeFlinkLow : 24; /* bit position: 40 */
                    }; /* bitfield */
                    /* 0x0000 */ struct _MI_ACTIVE_PFN Active;
                }; /* size: 0x0008 */
            } /* size: 0x0008 */ u1;
            union
            {
                /* 0x0008 */ struct _MMPTE* PteAddress;
                /* 0x0008 */ unsigned __int64 PteLong;
            }; /* size: 0x0008 */
            /* 0x0010 */ struct _MMPTE OriginalPte;
        }; /* size: 0x0018 */
    }; /* size: 0x0018 */
    /* 0x0018 */ struct _MIPFNBLINK u2;
    union
    {
        union
        {
            struct
            {
                /* 0x0020 */ unsigned short ReferenceCount;
                /* 0x0022 */ struct _MMPFNENTRY1 e1;
                /* 0x0023 */ struct _MMPFNENTRY3 e3;
            }; /* size: 0x0004 */
            struct
            {
                /* 0x0020 */ unsigned short ReferenceCount;
            } /* size: 0x0002 */ e2;
            struct
            {
                /* 0x0020 */ unsigned long EntireField;
            } /* size: 0x0004 */ e4;
        }; /* size: 0x0004 */
    } /* size: 0x0004 */ u3;
    /* 0x0024 */ struct _MI_PFN_ULONG5 u5;
    union
    {
        union
        {
            struct /* bitfield */
            {
                /* 0x0028 */ unsigned __int64 PteFrame : 40; /* bit position: 0 */
                /* 0x0028 */ unsigned __int64 ResidentPage : 1; /* bit position: 40 */
                /* 0x0028 */ unsigned __int64 Unused1 : 1; /* bit position: 41 */
                /* 0x0028 */ unsigned __int64 Unused2 : 1; /* bit position: 42 */
                /* 0x0028 */ unsigned __int64 Partition : 10; /* bit position: 43 */
                /* 0x0028 */ unsigned __int64 FileOnly : 1; /* bit position: 53 */
                /* 0x0028 */ unsigned __int64 PfnExists : 1; /* bit position: 54 */
                /* 0x0028 */ unsigned __int64 NodeFlinkHigh : 5; /* bit position: 55 */
                /* 0x0028 */ unsigned __int64 PageIdentity : 3; /* bit position: 60 */
                /* 0x0028 */ unsigned __int64 PrototypePte : 1; /* bit position: 63 */
            }; /* bitfield */
            /* 0x0028 */ unsigned __int64 EntireField;
        }; /* size: 0x0008 */
    } /* size: 0x0008 */ u4;
} MMPFN, * PMMPFN; /* size: 0x0030 */
struct cache {
    uintptr_t Address;
    UINT64 Value;
};
typedef enum SYSTEM_INFORMATION_CLASS
{
    SystemInformationClassMin = 0,
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemNotImplemented1 = 4,
    SystemProcessInformation = 5,
    SystemProcessesAndThreadsInformation = 5,
    SystemCallCountInfoInformation = 6,
    SystemCallCounts = 6,
    SystemDeviceInformation = 7,
    SystemConfigurationInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemProcessorTimes = 8,
    SystemFlagsInformation = 9,
    SystemGlobalFlag = 9,
    SystemCallTimeInformation = 10,
    SystemNotImplemented2 = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemLockInformation = 12,
    SystemStackTraceInformation = 13,
    SystemNotImplemented3 = 13,
    SystemPagedPoolInformation = 14,
    SystemNotImplemented4 = 14,
    SystemNonPagedPoolInformation = 15,
    SystemNotImplemented5 = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemPagefileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemInstructionEmulationCounts = 19,
    SystemVdmBopInformation = 20,
    SystemInvalidInfoClass1 = 20,
    SystemFileCacheInformation = 21,
    SystemCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemProcessorStatistics = 23,
    SystemDpcBehaviourInformation = 24,
    SystemDpcInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemNotImplemented6 = 25,
    SystemLoadImage = 26,
    SystemUnloadImage = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemTimeAdjustment = 28,
    SystemSummaryMemoryInformation = 29,
    SystemNotImplemented7 = 29,
    SystemNextEventIdInformation = 30,
    SystemNotImplemented8 = 30,
    SystemEventIdsInformation = 31,
    SystemNotImplemented9 = 31,
    SystemCrashDumpInformation = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemLoadAndCallImage = 38,
    SystemPrioritySeparation = 39,
    SystemPlugPlayBusInformation = 40,
    SystemNotImplemented10 = 40,
    SystemDockInformation = 41,
    SystemNotImplemented11 = 41,
    SystemInvalidInfoClass2 = 42,
    SystemProcessorSpeedInformation = 43,
    SystemInvalidInfoClass3 = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemSetTimeSlipEvent = 46,
    SystemCreateSession = 47,
    SystemDeleteSession = 48,
    SystemInvalidInfoClass4 = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemAddVerifier = 52,
    SystemSessionProcessesInformation = 53,
    SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;
static const UINT64 PMASK = (~0xfull << 8) & 0xfffffffffull;

inline bool refreshcache_r = false;

extern "C"
{
    PVOID
        NTAPI
        PsGetProcessSectionBaseAddress(
            PEPROCESS Process
        );
}