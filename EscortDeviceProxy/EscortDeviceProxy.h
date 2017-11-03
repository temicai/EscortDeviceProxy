#ifndef ESCORT_DEVICE_PROXY_6C5E3F02B0C24AB9985A96F03636215C_H
#define ESCORT_DEVICE_PROXY_6C5E3F02B0C24AB9985A96F03636215C_H

#define MAX_INSTANCE_NUM 64

#ifdef __cplusplus
extern "C"
{
#endif

#define EDP_API __declspec(dllexport)

	int __stdcall EDP_Init();
	unsigned long long __stdcall EDP_Start(unsigned short, unsigned short, unsigned short, unsigned short flag=0);
	int __stdcall EDP_SetLbsQueryParameter(unsigned long long, int, const char *);
	int __stdcall EDP_Stop(unsigned long long);
	int __stdcall EDP_Release();
	int __stdcall EDP_GetLastError(unsigned long long);

#ifdef __cplusplus
}
#endif


#endif 
