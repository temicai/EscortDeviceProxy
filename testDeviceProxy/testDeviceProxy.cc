#include <stdio.h>
#include <stdlib.h>
#include "EscortDeviceProxy.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <process.h>

#pragma comment(lib, "EscortDeviceProxy.lib")

void openDeamon(char * szExePath)
{
	do {
		PROCESSENTRY32 processEntry32;
		processEntry32.dwSize = sizeof(processEntry32);
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE) {
			break;
		}
		bool bFindDeamon = false;
		BOOL bFlag = Process32First(hProcessSnap, &processEntry32);
		while (bFlag) {
			if (strcmp(processEntry32.szExeFile, "EscortProxyDeamon.exe") == 0) {
				printf("find EscortProxyDeamon.exe, pid=%lu\n", processEntry32.th32ProcessID);
				bFindDeamon = true;
				break;
			}
			bFlag = Process32Next(hProcessSnap, &processEntry32);
		}
		if (!bFindDeamon) {
			STARTUPINFOA startUpInfo;
			PROCESS_INFORMATION processInfo;
			memset(&startUpInfo, 0, sizeof(startUpInfo));
			memset(&processInfo, 0, sizeof(processInfo));
			char szDeamonName[256] = { 0 };
			sprintf_s(szDeamonName, sizeof(szDeamonName), "%sEscortProxyDeamon.exe", szExePath);
			if (CreateProcessA(szDeamonName, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &startUpInfo,
				&processInfo)) {
				printf("open %s, pid=%lu\n", szDeamonName, processInfo.dwProcessId);
			}
			else {
				printf("open %s failed, error=%lu\n", szDeamonName, GetLastError());
			}
		}
	} while (0);
}

//#define USE_SERVICE

#if USE_SERVICE

#define SVRNAME TEXT("EDP_SS")
SERVICE_STATUS gSvrStatus;
SERVICE_STATUS_HANDLE gSvrStatusHandle;
HANDLE ghSvrStopEvent = NULL;
HANDLE ghWork = NULL;
bool gbRun = false;
int gnInst = 0;

VOID WINAPI SrvMain(DWORD dwNumServicesArgs, LPSTR * lpServiceArgVectors);
void WINAPI SrvCtrlHandle(DWORD dwCtrl);
unsigned int __stdcall startWorkThread(void *);
bool IsInstalled();
bool Uninstall();
bool Install();
void LogEvent(const char * pszFormat, ...);




VOID WINAPI SrvMain(DWORD dwNumServicesArgs, LPSTR * lpServiceArgVectors)
{
	gSvrStatus.dwCurrentState = SERVICE_START_PENDING;
	gSvrStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	gSvrStatusHandle = RegisterServiceCtrlHandlerA(SVRNAME, SrvCtrlHandle);
	if (!gSvrStatusHandle) {
		printf("");
		return;
	}
	SetServiceStatus(gSvrStatusHandle, &gSvrStatus);
	gSvrStatus.dwCurrentState = SERVICE_RUNNING;
	gSvrStatus.dwCheckPoint = 0;
	gSvrStatus.dwWaitHint = 3000;
	if (!SetServiceStatus(gSvrStatusHandle, &gSvrStatus)) {

	}
	gbRun = true;
	ghWork = (HANDLE)_beginthreadex(NULL, 0, startWorkThread, NULL, 0, NULL);
}

void WINAPI SrvCtrlHandle(DWORD dwCtrl_)
{
	switch (dwCtrl_) {
		case SERVICE_CONTROL_STOP: {
			gSvrStatus.dwWin32ExitCode = 0;
			gSvrStatus.dwCurrentState = SERVICE_STOPPED;
			gSvrStatus.dwCheckPoint = 0;
			gSvrStatus.dwWaitHint = 0;
			SetServiceStatus(gSvrStatusHandle, &gSvrStatus);
			gbRun = false;
			if (ghWork) {
				CloseHandle(ghWork);
				ghWork = NULL;
			}
			if (gnInst) {
				EDP_Stop(gnInst);
				gnInst = 0;
			}
			EDP_Release();
			break;
		}	
	}
}

void main(int argc_, TCHAR * argv_[])
{
	if (lstrcmpi(argv_[1], TEXT("/install")) == 0) {
		Install();
		return;
	}
	else if (lstrcmpi(argv_[1], TEXT("/uninstall")) == 0) {
		Uninstall();
		return;
	}
	gSvrStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;// | SERVICE_INTERACTIVE_PROCESS;
	gSvrStatus.dwCurrentState = SERVICE_START_PENDING;
	gSvrStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	gSvrStatus.dwWin32ExitCode = NO_ERROR;
	gSvrStatus.dwServiceSpecificExitCode = 0;
	gSvrStatus.dwCheckPoint = 0;
	gSvrStatus.dwWaitHint = 0;
	SERVICE_TABLE_ENTRY dispatchTable[] = 
	{
		{SVRNAME, (LPSERVICE_MAIN_FUNCTION)SrvMain}, {NULL, NULL}
	};
	if (!StartServiceCtrlDispatcher(dispatchTable)) {

	}
}

unsigned int __stdcall startWorkThread(void * param_)
{
	char szPath[256] = { 0 };
	GetModuleFileNameA(NULL, szPath, 256);
	char szCfgPath[256] = { 0 };
	char szAppPath[256] = { 0 };
	char szDir[256] = { 0 };
	char szDrive[32] = { 0 };
	_splitpath_s(szPath, szDrive, 32, szDir, 256, NULL, 0, NULL, 0);
	sprintf_s(szAppPath, sizeof(szAppPath), "%s%s", szDrive, szDir);
	sprintf_s(szCfgPath, 256, "%s%sEscortDeviceProxy.ini", szDrive, szDir);
	unsigned short usDevicePort = 28222;
	unsigned short usMsgPort = 28240;
	unsigned short usCtrlPort = 28241;
	unsigned short usLogType = 1;
	unsigned short usDeamon = 0;
	char szFindStr[256] = { 0 };

	GetPrivateProfileStringA("parameter", "device_port", "28222", szFindStr, sizeof(szFindStr), szCfgPath);
	if (strlen(szFindStr)) {
		usDevicePort = (unsigned short)atoi(szFindStr);
		memset(szFindStr, 0, sizeof(szFindStr));
	}
	GetPrivateProfileStringA("parameter", "message_port", "28240", szFindStr, sizeof(szFindStr), szCfgPath);
	if (strlen(szFindStr)) {
		usMsgPort = (unsigned short)atoi(szFindStr);
		memset(szFindStr, 0, sizeof(szFindStr));
	}
	GetPrivateProfileStringA("parameter", "control_port", "28241", szFindStr, sizeof(szFindStr), szCfgPath);
	if (strlen(szFindStr)) {
		usCtrlPort = (unsigned short)atoi(szFindStr);
		memset(szFindStr, 0, sizeof(szFindStr));
	}
	GetPrivateProfileStringA("parameter", "log", "1", szFindStr, sizeof(szFindStr), szCfgPath);
	if (strlen(szFindStr)) {
		usLogType = (unsigned short)atoi(szFindStr);
		memset(szFindStr, 0, sizeof(szFindStr));
	}
	GetPrivateProfileStringA("parameter", "deamon", "0", szFindStr, sizeof(szFindStr), szCfgPath);
	if (strlen(szFindStr)) {
		usDeamon = (unsigned short)atoi(szFindStr);
		memset(szFindStr, 0, sizeof(szFindStr));
	}
	printf("device proxy ready\n");
	EDP_Init();
	int nVal = EDP_Start(usDevicePort, usMsgPort, usCtrlPort, usLogType);
	if (nVal > 0) {
		printf("device proxy at %hu\n", usDevicePort);
		if (usDeamon) {
		//	openDeamon(szAppPath);
		}
	}
	return 0;
}

bool IsInstalled()
{
	bool result = false;
	SC_HANDLE hSCManger = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCManger) {
		SC_HANDLE hService = OpenServiceA(hSCManger, SVRNAME, SERVICE_QUERY_CONFIG);
		if (hService) {
			result = true;
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hSCManger);
	}
	return result;
}

bool Install()
{
	if (IsInstalled()) {
		return true;
	}
	bool result = false;
	SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCManager) {
		char szPath[256] = { 0 };
		GetModuleFileNameA(NULL, szPath, 256);
		SC_HANDLE hService = CreateService(hSCManager, SVRNAME, SVRNAME, SERVICE_ALL_ACCESS,
			SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS, SERVICE_AUTO_START,
			SERVICE_ERROR_NORMAL, szPath, NULL, NULL, NULL, NULL, NULL);
		if (hService) {
			result = true;
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hSCManager);
	}
	return result;
}

bool Uninstall()
{
	if (!IsInstalled()) {
		return true;
	}
	bool result = false;
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCManager) {
		SC_HANDLE hService = OpenService(hSCManager, SVRNAME, SERVER_ALL_ACCESS);
		if (hService) {
			SERVICE_STATUS status;
			ControlService(hService, SERVICE_CONTROL_STOP, &status);
			if (DeleteService(hService)) {
				result = true;
			}
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hSCManager);
	}
	return result;
}

void LogEvent(const char * pFormat_, ...)
{
	const char * szMsg;
	HANDLE hEventSource;
	va_list pVaList;
	va_start(pVaList, pFormat_);
	szMsg = va_arg(pVaList, const char *);
	va_end(pVaList);
	hEventSource = RegisterEventSource(NULL, SVRNAME);
	if (hEventSource) {
		ReportEvent(hEventSource, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, (LPCSTR *)szMsg, NULL);
		DeregisterEventSource(hEventSource);
	}
}

#else

int main()
{
	char szPath[256] = { 0 };
	GetModuleFileNameA(NULL, szPath, 256);
	char szCfgPath[256] = { 0 };
	char szAppPath[256] = { 0 };
	char szDir[256] = { 0 };
	char szDrive[32] = { 0 };
	_splitpath_s(szPath, szDrive, 32, szDir, 256, NULL, 0, NULL, 0);
	sprintf_s(szAppPath, sizeof(szAppPath), "%s%s", szDrive, szDir);
	sprintf_s(szCfgPath, 256, "%s%sEscortDeviceProxy.ini", szDrive, szDir);
	unsigned short usDevicePort = 28222;
	unsigned short usMsgPort = 28240;
	unsigned short usCtrlPort = 28241;
	unsigned short usLogType = 1;
	unsigned short usDeamon = 0;
	int nQryType = 0;
	char szKey[64] = { 0 };
	char szFindStr[256] = { 0 };

	GetPrivateProfileStringA("parameter", "device_port", "28222", szFindStr, sizeof(szFindStr), szCfgPath);
	if (strlen(szFindStr)) {
		usDevicePort = (unsigned short)atoi(szFindStr);
		memset(szFindStr, 0, sizeof(szFindStr));
	}
	GetPrivateProfileStringA("parameter", "message_port", "28240", szFindStr, sizeof(szFindStr), szCfgPath);
	if (strlen(szFindStr)) {
		usMsgPort = (unsigned short)atoi(szFindStr);
		memset(szFindStr, 0, sizeof(szFindStr));
	}
	GetPrivateProfileStringA("parameter", "control_port", "28241", szFindStr, sizeof(szFindStr), szCfgPath);
	if (strlen(szFindStr)) {
		usCtrlPort = (unsigned short)atoi(szFindStr);
		memset(szFindStr, 0, sizeof(szFindStr));
	}
	GetPrivateProfileStringA("parameter", "log", "1", szFindStr, sizeof(szFindStr), szCfgPath);
	if (strlen(szFindStr)) {
		usLogType = (unsigned short)atoi(szFindStr);
		memset(szFindStr, 0, sizeof(szFindStr));
	}
	GetPrivateProfileStringA("parameter", "deamon", "0", szFindStr, sizeof(szFindStr), szCfgPath);
	if (strlen(szFindStr)) {
		usDeamon = (unsigned short)atoi(szFindStr);
		memset(szFindStr, 0, sizeof(szFindStr));
	}
	GetPrivateProfileStringA("parameter", "key", "", szFindStr, sizeof(szFindStr), szCfgPath);
	if (strlen(szFindStr)) {
		strncpy_s(szKey, sizeof(szKey), szFindStr, strlen(szFindStr));
	}
	GetPrivateProfileStringA("parameter", "qryLbs", "0", szFindStr, sizeof(szFindStr), szCfgPath);
	if (strlen(szFindStr)) {
		nQryType = atoi(szFindStr);
	}
	//printf("device proxy ready\n");
	EDP_Init();
	unsigned long long instVal = EDP_Start(usDevicePort, usMsgPort, usCtrlPort, usLogType);
	if (instVal > 0) {
		EDP_SetLbsQueryParameter(instVal, nQryType, szKey);
		//printf("device proxy at %hu\n", usDevicePort);
		if (usDeamon) {
			openDeamon(szAppPath);
		}
		
#ifdef _DEBUG
		getchar();
#else
		while (1) {
			Sleep(100);
		}
#endif
		EDP_Stop(instVal);
	}
	EDP_Release();
	//printf("device proxy stop\n");
	return 0;
}

#endif