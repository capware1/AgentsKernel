#pragma once
//Driver Mains
#include <ntifs.h>
#include <ntddmou.h>
#include <cstdint>
#include <ntimage.h>

inline UNICODE_STRING DeviceN, DosL;

//Driver Cores
#include "Driver Core/defintions/Define.h"
#include "Driver Core/defintions/IoCodes.h"
#include "Driver Core/Utilities/Utility.h"

//Driver Functions
#include "Driver Functions/BaseAddress/Base.h"
#include "Driver Functions/PML4/PML4.h"
#include "Driver Functions/Protect/Protect.h"


//Driver IoControl
#include "Driver Core/IoControl/IoControl.h"

//Driver Init
#include "Driver Entry/Driver Init/Driverinit.h"