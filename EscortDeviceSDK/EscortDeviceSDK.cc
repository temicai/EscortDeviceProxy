#include "EscortDeviceSDK.h"
#include "DeviceSDKConcrete.h"

#include <Windows.h>
#include <map>

#define MAX_INSTANCE_NUM 128

static char g_szDllPath[256] = { 0 };
typedef std::map<unsigned long long, DeviceManager *> DeviceMangerList;
static DeviceMangerList g_deviceMgList;
static pthread_mutex_t g_mutex4DeviceMgList;
static int g_nRefCount = 0;

BOOL APIENTRY DllMain(void * hInst, unsigned long ulReason, void * pReserved)
{
	switch (ulReason) {
		case DLL_PROCESS_ATTACH: {
			g_nRefCount = 0;
			pthread_mutex_init(&g_mutex4DeviceMgList, NULL);
			char szDllPath[256] = { 0 };
			GetModuleFileNameA((HMODULE)hInst, szDllPath, 256);
			char szDriver[32] = { 0 };
			char szDir[256] = { 0 };
			_splitpath_s(szDllPath, szDriver, 32, szDir, 256, NULL, 0, NULL, 0);
			sprintf_s(g_szDllPath, sizeof(g_szDllPath), "%s%s", szDriver, szDir);
			break;
		}
		case DLL_PROCESS_DETACH: {
			pthread_mutex_lock(&g_mutex4DeviceMgList);
			if (!g_deviceMgList.empty()) {
				DeviceMangerList::iterator iter = g_deviceMgList.begin();
				while (iter != g_deviceMgList.end()) {
					DeviceManager * pManager = iter->second;
					if (pManager) {
						pManager->Stop();
						Sleep(10);
						delete pManager;
						pManager = NULL;
					}
					iter = g_deviceMgList.erase(iter);
				}
			}
			pthread_mutex_unlock(&g_mutex4DeviceMgList);
			pthread_mutex_destroy(&g_mutex4DeviceMgList);
			break;
		}
	}
	return TRUE;
}

int __stdcall EDS_Init()
{
	if (g_nRefCount == 0) {
		g_deviceMgList.clear();
	}
	g_nRefCount++;
	return 0;
}

unsigned long long __stdcall EDS_Start(const char * pHost_, unsigned short usPort1_, unsigned short usPort2_,
	ccrfid_device::fMessageCallback fMsgCb_, void * pUserData_)
{
	unsigned long long result = 0;
	pthread_mutex_lock(&g_mutex4DeviceMgList);
	unsigned int uiManagerInstanceCount = (unsigned int)g_deviceMgList.size();
	if (uiManagerInstanceCount < MAX_INSTANCE_NUM) {
		DeviceManager * pManager = new DeviceManager(g_szDllPath);
		if (pManager) {
			if (pManager->Start(pHost_, usPort1_, usPort2_) == 0) {
				pManager->SetMessageCallback(fMsgCb_, pUserData_);
				unsigned long long instVal = (unsigned long long)pManager;
				g_deviceMgList.insert(std::make_pair(instVal, pManager));	
				result = instVal;
			} else {
				delete pManager;
				pManager = NULL;
			}
		}
	}
	pthread_mutex_unlock(&g_mutex4DeviceMgList);
	return result;
}

int __stdcall EDS_SendCommand(unsigned long long inst_, ccrfid_device::DeviceCommandInfo cmdInfo_)
{
	int result = -1;
	pthread_mutex_lock(&g_mutex4DeviceMgList);
	if (!g_deviceMgList.empty()) {
		DeviceMangerList::iterator iter = g_deviceMgList.find(inst_);
		if (iter != g_deviceMgList.end()) {
			DeviceManager * pManager = iter->second;
			if (pManager) {
				result = pManager->SendCommand(cmdInfo_);
			}
		}
	}
	pthread_mutex_unlock(&g_mutex4DeviceMgList);
	return result;
}

int __stdcall EDS_SetMessageCallback(unsigned long long inst_, ccrfid_device::fMessageCallback fMsgCb_, void * pUserData_)
{
	int result = -1;
	pthread_mutex_lock(&g_mutex4DeviceMgList);
	if (!g_deviceMgList.empty()) {
		DeviceMangerList::iterator iter = g_deviceMgList.find(inst_);
		if (iter != g_deviceMgList.end()) {
			DeviceManager * pManager = iter->second;
			if (pManager) {
				pManager->SetMessageCallback(fMsgCb_, pUserData_);
				result = 0;
			}
		}
	}
	pthread_mutex_unlock(&g_mutex4DeviceMgList);
	return result;
}

int __stdcall EDS_AddDeviceListener(unsigned long long inst_, const char * pFactoryId_, const char * pDeviceId_)
{
	int result = -1;
	pthread_mutex_lock(&g_mutex4DeviceMgList);
	if (!g_deviceMgList.empty()) {
		DeviceMangerList::iterator iter = g_deviceMgList.find(inst_);
		if (iter != g_deviceMgList.end()) {
			DeviceManager * pManager = iter->second;
			if (pManager) {
				result = pManager->AddDeviceListen(pFactoryId_, pDeviceId_);
			}
		}
	}
	pthread_mutex_unlock(&g_mutex4DeviceMgList);
	return result;
}

int __stdcall EDS_RemoveDeviceListener(unsigned long long inst_, const char * pFactoryId_, const char * pDeviceId_)
{
	int result = -1;
	pthread_mutex_lock(&g_mutex4DeviceMgList);
	if (!g_deviceMgList.empty()) {
		DeviceMangerList::iterator iter = g_deviceMgList.find(inst_);
		if (iter != g_deviceMgList.end()) {
			DeviceManager * pManager = iter->second;
			if (pManager) {
				result = pManager->RemoveDeviceListen(pFactoryId_, pDeviceId_);
			}
		}
	}
	pthread_mutex_unlock(&g_mutex4DeviceMgList);
	return result;
}

int __stdcall EDS_Stop(unsigned long long inst_)
{
	int result = -1;
	pthread_mutex_lock(&g_mutex4DeviceMgList);
	if (!g_deviceMgList.empty()) {
		DeviceMangerList::iterator iter = g_deviceMgList.find(inst_);
		if (iter != g_deviceMgList.end()) {
			DeviceManager * pManager = iter->second;
			if (pManager) {
				if (pManager->Stop() == 0) {
					Sleep(100);
					delete pManager;
					pManager = NULL;
					result = 0;	
					g_deviceMgList.erase(iter);
				}
			}
		}
	}
	pthread_mutex_unlock(&g_mutex4DeviceMgList);
	return result;
}

int __stdcall EDS_Release()
{
	g_nRefCount--;
	if (g_nRefCount <= 0) {
		pthread_mutex_lock(&g_mutex4DeviceMgList);
		if (!g_deviceMgList.empty()) {
			DeviceMangerList::iterator iter = g_deviceMgList.begin();
			while (iter != g_deviceMgList.end()) {
				DeviceManager * pManager = iter->second;
				if (pManager) {
					pManager->Stop();
					Sleep(10);
					delete pManager;
					pManager = NULL;
				}
				iter = g_deviceMgList.erase(iter);
			}
		}
		pthread_mutex_unlock(&g_mutex4DeviceMgList);
	}
	return 0;
}



