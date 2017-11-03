#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <process.h>

#include "pfLog.hh"

#define USE_SERVICE

#ifdef USE_SERVICE

#define SERVICE_NAME TEXT("EDPDS")
#define DISPLAY_NAME TEXT("EscortDeviceProxyDeamonService")

SERVICE_STATUS gSvrStatus;
SERVICE_STATUS_HANDLE ghSvrStatus;
HANDLE ghDeamon = NULL;
bool gbRun = false;

void WINAPI SrvMain(DWORD dwNumServiceArgs, LPSTR * lpServiceArgVectors);
void WINAPI SrvCtrlHandler(DWORD ddwCtrl);
unsigned int __stdcall startDeamonThread(void *);
bool IsInstalled();
bool Uninstall();
bool Install();

VOID WINAPI SrvMain(DWORD dwNumServicesArgs, LPSTR * lpServiceArgVectors)
{
	gSvrStatus.dwCurrentState = SERVICE_START_PENDING;
	gSvrStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	ghSvrStatus = RegisterServiceCtrlHandlerA(SERVICE_NAME, SrvCtrlHandler);
	if (!ghSvrStatus) {
		return;
	}
	SetServiceStatus(ghSvrStatus, &gSvrStatus);
	gSvrStatus.dwCurrentState = SERVICE_RUNNING;
	gSvrStatus.dwCheckPoint = 0;
	gSvrStatus.dwWaitHint = 3000;
	if (!SetServiceStatus(ghSvrStatus, &gSvrStatus)) {

	}
	gbRun = true;
	ghDeamon = (HANDLE)_beginthreadex(NULL, 0, startDeamonThread, NULL, 0, NULL);
}

void WINAPI SrvCtrlHandler(DWORD dwCtrl_)
{
	switch (dwCtrl_) {
		case SERVICE_CONTROL_STOP: {
			gSvrStatus.dwWin32ExitCode = 0;
			gSvrStatus.dwCurrentState = SERVICE_STOPPED;
			gSvrStatus.dwCheckPoint = 0;
			gSvrStatus.dwWaitHint = 0;
			SetServiceStatus(ghSvrStatus, &gSvrStatus);
			gbRun = false;
			if (ghDeamon) {
				CloseHandle(ghDeamon);
				ghDeamon = NULL;
			}
			break;
		}
	}
}

bool IsInstalled()
{
	bool result = false;
	SC_HANDLE hSCManger = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCManger) {
		SC_HANDLE hService = OpenServiceA(hSCManger, SERVICE_NAME, SERVICE_QUERY_CONFIG);
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
		SC_HANDLE hService = CreateServiceA(hSCManager, SERVICE_NAME, SERVICE_NAME, SERVICE_ALL_ACCESS,
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
		SC_HANDLE hService = OpenService(hSCManager, SERVICE_NAME, SERVER_ALL_ACCESS);
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

void main(int argc_, char ** argv_)
{
	if (lstrcmpi(argv_[1], TEXT("install")) == 0) {
		Install();
		return;
	}
	if (lstrcmpi(argv_[1], TEXT("uninstall")) == 0) {
		Uninstall();
		return;
	}
	gSvrStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
	gSvrStatus.dwCurrentState = SERVICE_START_PENDING;
	gSvrStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	gSvrStatus.dwWin32ExitCode = NO_ERROR;
	gSvrStatus.dwServiceSpecificExitCode = 0;
	gSvrStatus.dwCheckPoint = 0;
	gSvrStatus.dwWaitHint = 0;
	SERVICE_TABLE_ENTRY dispatchTable[] =
	{
		{ SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)SrvMain },{ NULL, NULL }
	};
	if (!StartServiceCtrlDispatcher(dispatchTable)) {

	}
}

unsigned int __stdcall startDeamonThread(void * param_)
{
	HMODULE hModule = GetModuleHandleA(NULL);
	char szExePath[256] = { 0 };
	char szProxyExeName[256] = { 0 };
	char szPath[256] = { 0 };
	GetModuleFileNameA(NULL, szPath, 256);
	char szDrive[32] = { 0 };
	char szDir[256] = { 0 };
	_splitpath_s(szPath, szDrive, 32, szDir, 256, NULL, 0, NULL, 0);
	sprintf_s(szExePath, sizeof(szExePath), "%s%s", szDrive, szDir);

	unsigned long long ullInst = LOG_Init();
	pf_logger::LogConfig logConf;
	logConf.usLogPriority = pf_logger::eLOGPRIO_ALL;
	logConf.usLogType = pf_logger::eLOGTYPE_FILE;
	char szLogPath[256] = { 0 };
	sprintf_s(szLogPath, sizeof(szLogPath), "%slog\\", szExePath);
	CreateDirectoryExA(".\\", szLogPath, NULL);
	strcat_s(szLogPath, sizeof(szLogPath), "\\EscortProxyDeamon\\");
	CreateDirectoryExA(".\\", szLogPath, NULL);
	strcpy_s(logConf.szLogPath, sizeof(logConf.szLogPath), szLogPath);
	LOG_SetConfig(ullInst, logConf);
	char szLog[256] = { 0 };
	do {
		PROCESSENTRY32 processEntry32;
		processEntry32.dwSize = sizeof(processEntry32);
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE) {
			break;
		}
		bool bFindProxy = false;
		BOOL bFlag = Process32First(hProcessSnap, &processEntry32);
		while (bFlag) {
			if (strcmp(processEntry32.szExeFile, "EscortDeviceProxySimple.exe") == 0) {
				bFindProxy = true;
				printf("find EscortDeviceProxySimple.exe, pid=%lu\n", processEntry32.th32ProcessID);
				break;
			}
			bFlag = Process32Next(hProcessSnap, &processEntry32);
		}
		if (!bFindProxy) {
			STARTUPINFOA startUpInfo;
			PROCESS_INFORMATION processInfo;
			memset(&startUpInfo, 0, sizeof(startUpInfo));
			memset(&processInfo, 0, sizeof(processInfo));
			sprintf_s(szProxyExeName, sizeof(szProxyExeName), "%sEscortDeviceProxySimple.exe", szExePath);
			if (CreateProcessA(szProxyExeName, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &startUpInfo,
				&processInfo)) {
				sprintf_s(szLog, sizeof(szLog), "[ProxyDeamon]create %s, pid=%lu\r\n", szProxyExeName, processInfo.dwProcessId);
				LOG_Log(ullInst, szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
			}
			else {
				sprintf_s(szLog, sizeof(szLog), "[ProxyDeamon]create process %s failed, error=%lu\r\n", szProxyExeName, GetLastError());
				LOG_Log(ullInst, szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
			}
		}
		Sleep(10 * 1000);
	} while (gbRun);
	LOG_Release(ullInst);
	return 0;
}

#else

int main(int argc, char ** argv)
{
	printf("EscortProxyDeamon start\n");
	HMODULE hModule = GetModuleHandleA(NULL);
	char szExePath[256] = { 0 };
	char szProxyExeName[256] = { 0 };
	//if (hModule) {
		char szPath[256] = { 0 };
		GetModuleFileNameA(NULL, szPath, 256);
		char szDrive[32] = { 0 };
		char szDir[256] = { 0 };
		_splitpath_s(szPath, szDrive, 32, szDir, 256, NULL, 0, NULL, 0);
		sprintf_s(szExePath, sizeof(szExePath), "%s%s", szDrive, szDir);
		do {
			PROCESSENTRY32 processEntry32;
			processEntry32.dwSize = sizeof(processEntry32);
			HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (hProcessSnap == INVALID_HANDLE_VALUE) {
				break;
			}
			bool bFindProxy = false;
			BOOL bFlag = Process32First(hProcessSnap, &processEntry32);
			while (bFlag) {
				if (strcmp(processEntry32.szExeFile, "EscortDeviceProxySimple.exe") == 0) {
					bFindProxy = true;
					printf("find EscortDeviceProxySimple.exe, pid=%lu\n", processEntry32.th32ProcessID);
					break;
				}
				bFlag = Process32Next(hProcessSnap, &processEntry32);
			}
			if (!bFindProxy) {
				STARTUPINFOA startUpInfo;
				PROCESS_INFORMATION processInfo;
				memset(&startUpInfo, 0, sizeof(startUpInfo));
				memset(&processInfo, 0, sizeof(processInfo));
				sprintf_s(szProxyExeName, sizeof(szProxyExeName), "%sEscortDeviceProxySimple.exe", szExePath);
				if (CreateProcessA(szProxyExeName, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &startUpInfo,
					&processInfo)) {
					printf("create %s, pid=%lu\n", szProxyExeName, processInfo.dwProcessId);
				}
				else {
					printf("create %s failed, error=%lu\n", szProxyExeName, GetLastError());
				}
			}
			Sleep(10 * 1000);
		} while (1);
	//}
	printf("EscortProxyDeamon quit\n");
	return 0;
}

#endif