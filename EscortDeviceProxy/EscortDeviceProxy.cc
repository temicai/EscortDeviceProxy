#include "EscortDeviceProxy.h"
#include "DeviceProxyConcrete.h"
#include <stdio.h>
#include <Windows.h>
#include <map>

static char g_szDllDir[256] = { 0 };
static pthread_mutex_t g_mutex4ProxyInstList;
static std::map<unsigned long long, ccrfid_proxy::DeviceProxy *> g_proxyInstList;

BOOL APIENTRY DllMain(void * hInst_, DWORD dwReason_, void * pReversed_)
{
	switch (dwReason_) {
		case DLL_PROCESS_ATTACH: {
			pthread_mutex_init(&g_mutex4ProxyInstList, NULL);
			char szPath[256] = { 0 };
			GetModuleFileNameA((HMODULE)hInst_, szPath, 256);
			char szDrive[16] = { 0 };
			char szDir[256] = { 0 };
			_splitpath_s(szPath, szDrive, 16, szDir, 256, NULL, 0, NULL, 0);
			sprintf_s(g_szDllDir, sizeof(g_szDllDir), "%s%s", szDrive, szDir);
			break;
		}
		case DLL_PROCESS_DETACH: {
			pthread_mutex_lock(&g_mutex4ProxyInstList);
			if (!g_proxyInstList.empty()) {
				std::map<unsigned long long, ccrfid_proxy::DeviceProxy *>::iterator iter = g_proxyInstList.begin();
				while (iter != g_proxyInstList.end()) {
					ccrfid_proxy::DeviceProxy * pDevProxy = iter->second;
					iter = g_proxyInstList.erase(iter);
					if (pDevProxy) {
						pDevProxy->Stop();
						Sleep(10);
						delete pDevProxy;
						pDevProxy = NULL;
					}
				}
			}
			pthread_mutex_unlock(&g_mutex4ProxyInstList);
			pthread_mutex_destroy(&g_mutex4ProxyInstList);
			break;
		}
		case DLL_THREAD_ATTACH: {
			break;
		}
		case DLL_THREAD_DETACH: {
			break;
		}
	}
	return TRUE;
}

int __stdcall EDP_Init()
{
	return 0;
}

unsigned long long __stdcall EDP_Start(unsigned short usProxyPort_, unsigned short usPublishPort_, 
	unsigned short usInteractPort_, unsigned short usLogType_)
{
	unsigned long long result = 0;
	pthread_mutex_lock(&g_mutex4ProxyInstList);
	size_t nInstCount = g_proxyInstList.size();
	if (nInstCount < MAX_INSTANCE_NUM) {
		ccrfid_proxy::DeviceProxy * pDeviceProxy = new ccrfid_proxy::DeviceProxy(g_szDllDir);
		if (pDeviceProxy) {
			if (pDeviceProxy->Start(usProxyPort_, usPublishPort_, usInteractPort_, usLogType_) == 0) {
				unsigned long long instVal = (unsigned long long)pDeviceProxy;
				g_proxyInstList.emplace(instVal, pDeviceProxy);
				result = instVal;
			}
			else {
				delete pDeviceProxy;
				pDeviceProxy = NULL;
			}
		}
	}
	pthread_mutex_unlock(&g_mutex4ProxyInstList);
	return result;
}

int __stdcall EDP_SetLbsQueryParameter(unsigned long long instVal_, int nLbsQry_, const char * szQryKey_)
{
	int result = -1;
	pthread_mutex_unlock(&g_mutex4ProxyInstList);
	if (!g_proxyInstList.empty()) {
		std::map<unsigned long long, ccrfid_proxy::DeviceProxy *>::iterator iter = g_proxyInstList.find(instVal_);
		if (iter != g_proxyInstList.end()) {
			ccrfid_proxy::DeviceProxy * pDeviceProxy = iter->second;
			if (pDeviceProxy) {
				pDeviceProxy->SetLbsQueryParameter(nLbsQry_, szQryKey_);
				result = 0;
			}
		}
	}
	pthread_mutex_unlock(&g_mutex4ProxyInstList);
	return result;
}

int __stdcall EDP_Stop(unsigned long long instVal_)
{
	int result = -1;
	pthread_mutex_unlock(&g_mutex4ProxyInstList);
	if (!g_proxyInstList.empty()) {
		std::map<unsigned long long, ccrfid_proxy::DeviceProxy *>::iterator iter = g_proxyInstList.find(instVal_);
		if (iter != g_proxyInstList.end()) {
			ccrfid_proxy::DeviceProxy * pDeviceProxy = iter->second;
			if (pDeviceProxy) {
				if (pDeviceProxy->Stop() == 0) {
					result = 0;
					delete pDeviceProxy;
					pDeviceProxy = NULL;
					g_proxyInstList.erase(iter);
				}
			}
		}
	}
	pthread_mutex_unlock(&g_mutex4ProxyInstList);
	return result;
}

int __stdcall EDP_Release()
{
	return 0;
}

int __stdcall EDP_GetLastError(unsigned long long instVal_)
{
	int result = -1;
	pthread_mutex_lock(&g_mutex4ProxyInstList);
	if (!g_proxyInstList.empty()) {
		std::map<unsigned long long, ccrfid_proxy::DeviceProxy *>::iterator iter = g_proxyInstList.find(instVal_);
		if (iter != g_proxyInstList.end()) {
			ccrfid_proxy::DeviceProxy * pProxy = iter->second;
			if (pProxy) {
				result = pProxy->GetLastError();
			}
		}
	}
	pthread_mutex_unlock(&g_mutex4ProxyInstList);
	return result;
}