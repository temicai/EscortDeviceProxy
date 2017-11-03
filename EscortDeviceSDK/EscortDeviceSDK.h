#ifndef ESCORT_DEVICE_SDK_10B394C544F94A9AB0F4412F69A5989B_H
#define ESCORT_DEVICE_SDK_10B394C544F94A9AB0F4412F69A5989B_H

#include "EscortDeviceCommon.h"

#ifdef __cplusplus
extern "C"
{
#endif
	int __stdcall EDS_Init();
	unsigned long long __stdcall EDS_Start(const char * pHost, unsigned short usPort1, unsigned short usPort2, 
		ccrfid_device::fMessageCallback fMsgCb, void * pUserData);
	int __stdcall EDS_SendCommand(unsigned long long inst, ccrfid_device::DeviceCommandInfo command);
	int __stdcall EDS_SetMessageCallback(unsigned long long inst, ccrfid_device::fMessageCallback fMsgCb, void * pUserData);
	int __stdcall EDS_AddDeviceListener(unsigned long long inst, const char * pFactoryId, const char * pDeviceId);
	int __stdcall EDS_RemoveDeviceListener(unsigned long long inst, const char * pFactoryId, const char * pDeviceId);
	int __stdcall EDS_Stop(unsigned long long inst);
	int __stdcall EDS_Release();
#ifdef __cplusplus
}
#endif



#endif
