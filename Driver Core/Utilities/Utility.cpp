#include "Utility.h"


namespace Utility
{
	static inline void CustomMemcpy(const void* dstp, const void* srcp, UINT len)
	{
		ULONG* dst = (ULONG*)dstp;
		ULONG* src = (ULONG*)srcp;
		UINT i, tail;

		for (i = 0; i < (len / sizeof(ULONG)); i++)
			*dst++ = *src++;

		tail = len & (sizeof(ULONG) - 1);
		if (tail) {

			UCHAR* dstb = (UCHAR*)dstp;
			UCHAR* srcb = (UCHAR*)srcp;

			for (i = len - tail; i < len; i++)
				dstb[i] = srcb[i];
		}
	}

	UNICODE_STRING ConcatenateStrings(const wchar_t* str1, const wchar_t* str2)
	{
		UNICODE_STRING result;
		Agents(RtlInitUnicodeString)(&result, nullptr);

		size_t length1 = wcslen(str1);
		size_t length2 = wcslen(str2);
		size_t totalLength = length1 + length2;

		result.Buffer = (wchar_t*)Agents(ExAllocatePool)(NonPagedPool, (totalLength + 1) * sizeof(wchar_t));

		if (result.Buffer)
		{
			result.Length = (USHORT)(totalLength * sizeof(wchar_t));
			result.MaximumLength = (USHORT)((totalLength + 1) * sizeof(wchar_t));

			CustomMemcpy(result.Buffer, str1, length1 * sizeof(wchar_t));

			CustomMemcpy(result.Buffer + length1, str2, (length2 + 1) * sizeof(wchar_t));
		}

		return result;
	}
}