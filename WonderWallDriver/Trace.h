#pragma once
 
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
	((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) )

#define CTL_GETPROCESSIMAGNAMEBYID \
	CTL_CODE(FILE_DEVICE_UNKNOWN,0x830,METHOD_NEITHER,FILE_ANY_ACCESS)


#define CTL_INJECTPROCESS \
	CTL_CODE(FILE_DEVICE_UNKNOWN,0x831,METHOD_NEITHER,FILE_ANY_ACCESS)