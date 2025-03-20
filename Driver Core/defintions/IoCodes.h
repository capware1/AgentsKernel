#pragma once

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
) 
#define Read_code  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2A2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define Base_code  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2A3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define Mouse_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2A4, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
