#pragma once
#include "../../includes.h"

namespace Utility
{
	static inline void CustomMemcpy(const void* dstp, const void* srcp, UINT len);
	UNICODE_STRING ConcatenateStrings(const wchar_t* str1, const wchar_t* str2);
}