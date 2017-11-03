#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <thread>
#include <string>
#include <Windows.h>

#include "EscortDeviceSDK.h"

#pragma comment(lib, "EscortDeviceSDK.lib")

bool g_bRun;
unsigned long long g_nVal = 0;

const char * gDeviceId = "5602036901";

void formatDatetime(unsigned long long ulTime, char * pDatetime_, unsigned int uiLen_)
{
	struct tm tm_time;
	time_t nTime = ulTime;
	localtime_s(&tm_time, &nTime);
	if (uiLen_ >= 16 && pDatetime_) {
		sprintf_s(pDatetime_, uiLen_, "%04d%02d%02d%02d%02d%02d", tm_time.tm_year + 1900, tm_time.tm_mon + 1,
			tm_time.tm_mday, tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec);
	}
}

void __stdcall MsgCb(unsigned int uiMsgType, unsigned int uiMsgSeq, unsigned long long ulMsgTime, void * pMsg,
	void * pUserData)
{
	switch (uiMsgType) {
		case ccrfid_device::MT_ONLINE: {
			char szOnlineMsgTime[20] = { 0 };
			ccrfid_device::DeviceMessage * pOnlineMsg = (ccrfid_device::DeviceMessage *)pMsg;
			if (pOnlineMsg) {
				formatDatetime(pOnlineMsg->ulMessageTime, szOnlineMsgTime, sizeof(szOnlineMsgTime));
				printf("[%u, %llu]ONLINE, factoryId=%s, deviceId=%s, battery=%hu, onlineTime=%s\n,", uiMsgSeq, ulMsgTime,  
					pOnlineMsg->szFactoryId, pOnlineMsg->szDeviceId, pOnlineMsg->usDeviceBattery, szOnlineMsgTime);
			}
			break;
		}
		case ccrfid_device::MT_OFFLINE: {
			char szOfflineMsgTime[20] = { 0 };
			ccrfid_device::DeviceMessage * pOfflineMsg = (ccrfid_device::DeviceMessage *)pMsg;
			if (pOfflineMsg) {
				formatDatetime(pOfflineMsg->ulMessageTime, szOfflineMsgTime, sizeof(szOfflineMsgTime));
				printf("[%u, %llu]OFFLINE, factoryId=%s, deviceId=%s, offlineTime=%s\n", uiMsgSeq, ulMsgTime,
					pOfflineMsg->szFactoryId, pOfflineMsg->szDeviceId, szOfflineMsgTime);
			}
			break;
		}
		case ccrfid_device::MT_ALIVE: {
			char szAliveDatetime [20] = { 0 };
			ccrfid_device::DeviceMessage * pAliveMsg = (ccrfid_device::DeviceMessage *)pMsg;
			if (pAliveMsg) {
				formatDatetime(pAliveMsg->ulMessageTime, szAliveDatetime, sizeof(szAliveDatetime));
				printf("[%u, %llu]ALIVE, factoryId=%s, deviceId=%s, battery=%hu, aliveTime=%s\n", uiMsgSeq, ulMsgTime,
					pAliveMsg->szFactoryId, pAliveMsg->szDeviceId, pAliveMsg->usDeviceBattery, szAliveDatetime);
			}
			break;
		}
		case ccrfid_device::MT_ALARM_LOOSE: {
			char szLooseAlarmTime[20] = { 0 };
			ccrfid_device::DeviceMessage * pLooseAlarmMsg = (ccrfid_device::DeviceMessage *)pMsg;
			if (pLooseAlarmMsg) {
				formatDatetime(pLooseAlarmMsg->ulMessageTime, szLooseAlarmTime, sizeof(szLooseAlarmTime));
				printf("[%u, %llu]LOOSE_ALARM, factoryId=%s, deviceId=%s, battery=%hu, mode=%hu, looseAlarmTime=%s\n",
					uiMsgSeq, ulMsgTime, pLooseAlarmMsg->szFactoryId, pLooseAlarmMsg->szDeviceId,
					pLooseAlarmMsg->usDeviceBattery, pLooseAlarmMsg->usMessageTypeExtra, szLooseAlarmTime);
			}
			break;
		}
		case ccrfid_device::MT_ALARM_LOWPOWER: {
			char szLowpowerAlarmTime[20] = { 0 };
			ccrfid_device::DeviceMessage * pLowpowerAlarmMsg = (ccrfid_device::DeviceMessage *)pMsg;
			if (pLowpowerAlarmMsg) {
				formatDatetime(pLowpowerAlarmMsg->ulMessageTime, szLowpowerAlarmTime, sizeof(szLowpowerAlarmTime));
				printf("[%u, %llu]LOWPOWER_ALARM, factoryId=%s, deviceId=%s, battery=%hu, mode=%hu, lowpowerAlarmTime=%s\n",
					uiMsgSeq, ulMsgTime, pLowpowerAlarmMsg->szFactoryId, pLowpowerAlarmMsg->szDeviceId,
					pLowpowerAlarmMsg->usDeviceBattery, pLowpowerAlarmMsg->usMessageTypeExtra, szLowpowerAlarmTime);
			}
			break;
		}
		case ccrfid_device::MT_LOCATE_GPS: {
			ccrfid_device::DeviceLocateGpsMessage * pGpsMsg = (ccrfid_device::DeviceLocateGpsMessage *)pMsg;
			if (pGpsMsg) {
				char szLocateDatetime[20];
				formatDatetime(pGpsMsg->ulLocateTime, szLocateDatetime, sizeof(szLocateDatetime));
				printf("[%u, %llu]GPS_LOCATE, factoryId=%s, deviceId=%s, battery=%hu, latitude=%f, lngitude=%f, coordinate=%d, "
					"locateTime=%s\n", uiMsgSeq, ulMsgTime, pGpsMsg->szFactoryId, pGpsMsg->szDeviceId, 
					pGpsMsg->usDeviceBattery, pGpsMsg->dLatitude, pGpsMsg->dLngitude, pGpsMsg->nCoordinate, 
					szLocateDatetime);
			}
			break;
		}
		case ccrfid_device::MT_LOCATE_LBS: {
			ccrfid_device::DeviceLocateLbsMessage * pLbsMsg = (ccrfid_device::DeviceLocateLbsMessage *)pMsg;
			if (pLbsMsg) {
				char szLocateDatetime[20] = { 0 };
				formatDatetime(pLbsMsg->ulLocateTime, szLocateDatetime, sizeof(szLocateDatetime));
				printf("[%u, %llu]LBS_LOCATE, factoryId=%s, deviceId=%s, battery=%hu, latitude=%f, lngitude=%f, coordinate=%d, "
					"locateTime=%s\n", uiMsgSeq, ulMsgTime, pLbsMsg->szFactoryId, pLbsMsg->szDeviceId, 
					pLbsMsg->usDeviceBattery, pLbsMsg->dRefLatitude, pLbsMsg->dRefLngitude, pLbsMsg->nCoordinate,
					szLocateDatetime);
			}
			break;
		}
		case ccrfid_device::MT_COMMAND: {
			ccrfid_device::DeviceCommandInfo * pCmdInfo = (ccrfid_device::DeviceCommandInfo *)pMsg;
			if (pCmdInfo) {
				printf("[%u, %llu]COMMAND, factoryId=%s, deviceId=%s, cmdType=%d, param=%d, retcode=%d\n", uiMsgSeq, ulMsgTime,
					pCmdInfo->szFactoryId, pCmdInfo->szDeviceId, pCmdInfo->nCommand, pCmdInfo->nParam1, pCmdInfo->nParam2);
			}
			break;
		}
		case ccrfid_device::MT_SERVER_CONNECT: {
			ccrfid_device::ProxyInfo * pProxInfo = (ccrfid_device::ProxyInfo *)pMsg;
			if (pProxInfo) {
				printf("[%u,%llu]%s:%hu|%hu connect\r\n", uiMsgSeq, ulMsgTime, pProxInfo->szProxyIp, pProxInfo->usPort1,
					pProxInfo->usPort2);
				EDS_AddDeviceListener(g_nVal, NULL, NULL);
			}
			break;
		}
		case ccrfid_device::MT_SERVER_DISCONNECT: {
			ccrfid_device::ProxyInfo * pProxInfo = (ccrfid_device::ProxyInfo *)pMsg;
			if (pProxInfo) {
				printf("[%u,%llu]%s:%hu|%hu disconnect\r\n", uiMsgSeq, ulMsgTime, pProxInfo->szProxyIp, pProxInfo->usPort1, 
					pProxInfo->usPort2);
			}
			break;
		}
	}
}

void control()
{
	while (1) {
		char c = '0';
		scanf_s("%c", &c, 1);
		if (c == 'q' || c == 'Q') {
			g_bRun = false;
			break;
		}
		else if (c == 'a' || c == 'A') {
			int nVal = EDS_AddDeviceListener(g_nVal, "01", gDeviceId);
			printf("add device listener ret=%d\n", nVal);
		}
		else if (c == 'r' || c == 'R') {
			int nVal = EDS_RemoveDeviceListener(g_nVal, "01", gDeviceId);
			printf("remove device listener ret=%d\n", nVal);
		}
		else if (c == 'b' || c == 'B') {
			ccrfid_device::DeviceCommandInfo command;
			strcpy_s(command.szDeviceId, sizeof(command.szDeviceId), gDeviceId);
			strcpy_s(command.szFactoryId, sizeof(command.szFactoryId), "01");
			command.nCommand = ccrfid_device::CMD_BIND;
			command.nParam1 = 0;
			command.nParam2 = 0;
			command.nParam3 = 0;
			int nVal = EDS_SendCommand(g_nVal, command);
			printf("send command bind ret=%d\n", nVal);
		}
		else if (c == 'i') {
			ccrfid_device::DeviceCommandInfo command;
			strcpy_s(command.szDeviceId, sizeof(command.szDeviceId), gDeviceId);
			strcpy_s(command.szFactoryId, sizeof(command.szFactoryId), "01");
			command.nCommand = ccrfid_device::CMD_SET_INTERVAL;
			command.nParam1 = 50;
			command.nParam2 = 0;
			command.nParam3 = 0;
			int nVal = EDS_SendCommand(g_nVal, command);
			printf("send command interval 50s ret=%d\n", nVal);
		}
		else if (c == 'I') {
			ccrfid_device::DeviceCommandInfo command;
			strcpy_s(command.szDeviceId, sizeof(command.szDeviceId), gDeviceId);
			strcpy_s(command.szFactoryId, sizeof(command.szFactoryId), "01");
			command.nCommand = ccrfid_device::CMD_SET_INTERVAL;
			command.nParam1 = 20;
			command.nParam2 = 0;
			command.nParam3 = 0;
			int nVal = EDS_SendCommand(g_nVal, command);
			printf("send command interval 20s ret=%d\n", nVal);
		}
		else if (c == 't') {
			ccrfid_device::DeviceCommandInfo command;
			strcpy_s(command.szDeviceId, sizeof(command.szDeviceId), gDeviceId);
			strcpy_s(command.szFactoryId, sizeof(command.szFactoryId), "01");
			command.nCommand = ccrfid_device::CMD_TASK;
			command.nParam1 = 1;
			command.nParam2 = 0;
			command.nParam3 = 0;
			int nVal = EDS_SendCommand(g_nVal, command);
			printf("send command task ret=%d\n", nVal);
		} 
		else if (c == 'T') {
			ccrfid_device::DeviceCommandInfo command;
			strcpy_s(command.szDeviceId, sizeof(command.szDeviceId), gDeviceId);
			strcpy_s(command.szFactoryId, sizeof(command.szFactoryId), "01");
			command.nCommand = ccrfid_device::CMD_TASK;
			command.nParam1 = 0;
			command.nParam2 = 0;
			command.nParam3 = 0;
			int nVal = EDS_SendCommand(g_nVal, command);
			printf("send command task close ret=%d\n", nVal);
		}
		else if (c == 'f') {
			ccrfid_device::DeviceCommandInfo command;
			strcpy_s(command.szDeviceId, sizeof(command.szDeviceId), gDeviceId);
			strcpy_s(command.szFactoryId, sizeof(command.szFactoryId), "01");
			command.nCommand = ccrfid_device::CMD_FLEE;
			command.nParam1 = 1;
			command.nParam2 = 0;
			command.nParam3 = 0;
			int nVal = EDS_SendCommand(g_nVal, command);
			printf("send command flee ret=%d\n", nVal);
		} 
		else if (c == 'F') {
			ccrfid_device::DeviceCommandInfo command;
			strcpy_s(command.szDeviceId, sizeof(command.szDeviceId), gDeviceId);
			strcpy_s(command.szFactoryId, sizeof(command.szFactoryId), "01");
			command.nCommand = ccrfid_device::CMD_FLEE;
			command.nParam1 = 0;
			command.nParam2 = 0;
			command.nParam3 = 0;
			int nVal = EDS_SendCommand(g_nVal, command);
			printf("send command flee close ret=%d\n", nVal);
		}
		else if (c == '&') {
			ccrfid_device::DeviceCommandInfo command;
			strcpy_s(command.szDeviceId, sizeof(command.szDeviceId), gDeviceId);
			strcpy_s(command.szFactoryId, sizeof(command.szFactoryId), "01");
			command.nCommand = ccrfid_device::CMD_RESET;
			command.nParam1 = 0;
			command.nParam2 = 0;
			command.nParam3 = 0;
			int nVal = EDS_SendCommand(g_nVal, command);
			printf("send command reboot ret=%d\n", nVal);
		}
	}
}

void control_extra()
{
	while (1) {
		char szLine[256] = { 0 };
		int nLen = sizeof(szLine);
		fgets(szLine, nLen, stdin);
		_strlwr_s(szLine, strlen(szLine) + 1);
		if ((strncmp("q", szLine, 1) == 0 && strlen(szLine) == 2) 
			|| (strncmp("quit", szLine, 4) == 0 && strlen(szLine) == 5)) {
			g_bRun = false;
			break;
		}
		else if (strncmp("&", szLine, 1) == 0 && strlen(szLine) > 2) {
			printf("\nreboot command format: & [deviceId]\n");
			std::string strSrc = szLine;
			size_t nLen = strSrc.size();
			size_t nIdx = strSrc.find_first_of(" ", 0);
			std::string strDevId = "";
			if (nIdx != std::string::npos) {
				strDevId = strSrc.substr(nIdx + 1, nLen - nIdx - 2);
			}
			if (!strDevId.empty()) {
				printf("\nreboot: %s\n", strDevId.c_str());
				ccrfid_device::DeviceCommandInfo devCmdInfo;
				strcpy_s(devCmdInfo.szDeviceId, sizeof(devCmdInfo.szDeviceId), strDevId.c_str());
				strcpy_s(devCmdInfo.szFactoryId, sizeof(devCmdInfo.szFactoryId), "01");
				devCmdInfo.nCommand = ccrfid_device::CMD_RESET;
				devCmdInfo.nParam1 = 0;
				devCmdInfo.nParam2 = 0;
				devCmdInfo.nParam3 = 0;
				int nVal = EDS_SendCommand(g_nVal, devCmdInfo);
				printf("send command device=%s reboot ret=%d\n", strDevId.c_str(), nVal);
			}
		}
		else if ((strncmp("a", szLine, 1) == 0 && strlen(szLine) > 2)
			|| (strncmp("add", szLine, 3) == 0 && strlen(szLine) > 4)) {
			printf("\nadd listener command format: a [deviceId] OR add [deviceId]\n");
			std::string strSrc = szLine;
			size_t nLen = strSrc.size();
			size_t nIdx = strSrc.find_first_of(" ", 0);
			std::string strDevId = "";
			if (nIdx != std::string::npos) {
				strDevId = strSrc.substr(nIdx + 1, nLen - nIdx - 2);
			}
			if (!strDevId.empty()) {
				printf("add device listener: %s\n", strDevId.c_str());
				int nVal = EDS_AddDeviceListener(g_nVal, "01", strDevId.c_str());
				printf("add device=%s listener ret=%d\n", strDevId.c_str(), nVal);
			}
		}
		else if ((strncmp("r", szLine, 1) == 0 && strlen(szLine) > 2)
			|| (strncmp("remove", szLine, 6) == 0 && strlen(szLine) > 7)) {
			printf("\nremove listener command format: r [deviceId] OR remove [deviceId]\n");
			std::string strSrc = szLine;
			size_t nLen = strSrc.size();
			size_t nIdx = strSrc.find_first_of(" ", 0);
			std::string strDevId = "";
			if (nIdx != std::string::npos) {
				strDevId = strSrc.substr(nIdx + 1, nLen - nIdx - 2);
			}
			if (!strDevId.empty()) {
				printf("remove device listener: %s\n", strDevId.c_str());
				int nVal = EDS_RemoveDeviceListener(g_nVal, "01", strDevId.c_str());
				printf("remove device=%s listener ret=%d\n", strDevId.c_str(), nVal);
			}
		}
		else if ((strncmp("b", szLine, 1) == 0 && strlen(szLine) > 2)
			|| (strncmp("bind", szLine, 4) == 0 && strlen(szLine) > 5)) { //bind
			printf("\nbind command format: b [deviceId] OR bind [deviceId]\n");
			std::string strSrc = szLine;
			size_t nLen = strSrc.size();
			size_t nIdx = strSrc.find_first_of(" ", 0);
			std::string strDevId = "";
			if (nIdx != std::string::npos) {
				strDevId = strSrc.substr(nIdx + 1, nLen - nIdx - 2);
			}
			if (!strDevId.empty()) {
				printf("bind: %s\n", strDevId.c_str());
				ccrfid_device::DeviceCommandInfo devCmdInfo;
				strcpy_s(devCmdInfo.szDeviceId, sizeof(devCmdInfo.szDeviceId), strDevId.c_str());
				strcpy_s(devCmdInfo.szFactoryId, sizeof(devCmdInfo.szFactoryId), "01");
				devCmdInfo.nCommand = ccrfid_device::CMD_BIND;
				devCmdInfo.nParam1 = 0;
				devCmdInfo.nParam2 = 0;
				devCmdInfo.nParam3 = 0;
				int nVal = EDS_SendCommand(g_nVal, devCmdInfo);
				printf("send bind command device=%s ret=%d\n", strDevId.c_str(), nVal);
			}
		}
		else if ((strncmp("st", szLine, 2) == 0 && strlen(szLine) > 3)
			|| (strncmp("submittask", szLine, 10) == 0 && strlen(szLine) > 11)) { //submit task
			printf("\nsubmit task command format: st [deviceId] OR submittask [deviceId]\n");
			std::string strSrc = szLine;
			size_t nLen = strSrc.size();
			size_t nIdx = strSrc.find_first_of(" ", 0);
			std::string strDevId = "";
			if (nIdx != std::string::npos) {
				strDevId = strSrc.substr(nIdx + 1, nLen - nIdx - 2);
			}
			if (!strDevId.empty()) {
				printf("submit task: %s\n", strDevId.c_str());
				ccrfid_device::DeviceCommandInfo devCmdInfo;
				strcpy_s(devCmdInfo.szDeviceId, sizeof(devCmdInfo.szDeviceId), strDevId.c_str());
				strcpy_s(devCmdInfo.szFactoryId, sizeof(devCmdInfo.szFactoryId), "01");
				devCmdInfo.nCommand = ccrfid_device::CMD_TASK;
				devCmdInfo.nParam1 = 1;
				devCmdInfo.nParam2 = 0;
				devCmdInfo.nParam3 = 0;
				int nVal = EDS_SendCommand(g_nVal, devCmdInfo);
				printf("send submit task command device=%s ret=%d\n", strDevId.c_str(), nVal);
			}
		}
		else if ((strncmp("ct", szLine, 2) == 0 && strlen(szLine) > 3)
			|| (strncmp("closetask", szLine, 9) == 0 && strlen(szLine) > 10)) { //close task
			printf("\nclose task command format: ct [deviceId] OR closetask [deviceId]\n");
			std::string strSrc = szLine;
			size_t nLen = strSrc.size();
			size_t nIdx = strSrc.find_first_of(" ", 0);
			std::string strDevId = "";
			if (nIdx != std::string::npos) {
				strDevId = strSrc.substr(nIdx + 1, nLen - nIdx - 2);
			}
			if (!strDevId.empty()) {
				printf("close task: %s\n", strDevId.c_str());
				ccrfid_device::DeviceCommandInfo devCmdInfo;
				strcpy_s(devCmdInfo.szDeviceId, sizeof(devCmdInfo.szDeviceId), strDevId.c_str());
				strcpy_s(devCmdInfo.szFactoryId, sizeof(devCmdInfo.szFactoryId), "01");
				devCmdInfo.nCommand = ccrfid_device::CMD_TASK;
				devCmdInfo.nParam1 = 0;
				devCmdInfo.nParam2 = 0;
				devCmdInfo.nParam3 = 0;
				int nVal = EDS_SendCommand(g_nVal, devCmdInfo);
				printf("send close task command device=%s ret=%d\n", strDevId.c_str(), nVal);
			}
		}
		else if ((strncmp("fon", szLine, 3) == 0 && strlen(szLine) > 4)
			|| (strncmp("fleeon", szLine, 6) == 0 && strlen(szLine) > 7)) { //flee on
			printf("\nflee on command format: fon [deviceId] OR fleeon [deviceId]\n");
			std::string strSrc = szLine;
			size_t nLen = strSrc.size();
			size_t nIdx = strSrc.find_first_of(" ", 0);
			std::string strDevId = "";
			if (nIdx != std::string::npos) {
				strDevId = strSrc.substr(nIdx + 1, nLen - nIdx - 2);
			}
			if (!strDevId.empty()) {
				printf("flee on: %s\n", strDevId.c_str());
				ccrfid_device::DeviceCommandInfo devCmdInfo;
				strcpy_s(devCmdInfo.szDeviceId, sizeof(devCmdInfo.szDeviceId), strDevId.c_str());
				strcpy_s(devCmdInfo.szFactoryId, sizeof(devCmdInfo.szFactoryId), "01");
				devCmdInfo.nCommand = ccrfid_device::CMD_FLEE;
				devCmdInfo.nParam1 = 1;
				devCmdInfo.nParam2 = 0;
				devCmdInfo.nParam3 = 0;
				int nVal = EDS_SendCommand(g_nVal, devCmdInfo);
				printf("send flee on command device=%s ret=%d\n", strDevId.c_str(), nVal);
			}
		}
		else if ((strncmp("foff", szLine, 4) == 0 && strlen(szLine) > 5)
			|| (strncmp("fleeoff", szLine, 7) == 0 && strlen(szLine) > 8)) { //flee off
			printf("\nflee off command format: foff [deviceId] OR fleeoff [deviceId]\n");
			std::string strSrc = szLine;
			size_t nLen = strSrc.size();
			size_t nIdx = strSrc.find_first_of(" ", 0);
			std::string strDevId = "";
			if (nIdx != std::string::npos) {
				strDevId = strSrc.substr(nIdx + 1, nLen - nIdx - 2);
			}
			if (!strDevId.empty()) {
				printf("flee off: %s\n", strDevId.c_str());
				ccrfid_device::DeviceCommandInfo devCmdInfo;
				strcpy_s(devCmdInfo.szDeviceId, sizeof(devCmdInfo.szDeviceId), strDevId.c_str());
				strcpy_s(devCmdInfo.szFactoryId, sizeof(devCmdInfo.szFactoryId), "01");
				devCmdInfo.nCommand = ccrfid_device::CMD_FLEE;
				devCmdInfo.nParam1 = 0;
				devCmdInfo.nParam2 = 0;
				devCmdInfo.nParam3 = 0;
				int nVal = EDS_SendCommand(g_nVal, devCmdInfo);
				printf("send flee off command device=%s ret=%d\n", strDevId.c_str(), nVal);
			}
		}
		else if ((strncmp("si", szLine, 2) == 0 && strlen(szLine) > 3) 
			|| (strncmp("setinterval", szLine, 11) == 0 && strlen(szLine) > 12)) { //interval
			printf("\nset interval command format: si [deviceId] [interval] OR setinterval [deviceId] [interval]\n");
			std::string strDevId = "";
			std::string strParam = "";
			std::string strSrc = szLine;
			size_t nLen = strSrc.size();
			size_t nIdx = strSrc.find_first_of(" ", 0);
			if (nIdx != std::string::npos) {
				strSrc = strSrc.substr(nIdx + 1, nLen - nIdx - 2);
				nLen = strSrc.size();
				nIdx = strSrc.find_first_of(" ", 0);
				if (nIdx != std::string::npos) {
					strDevId = strSrc.substr(0, nIdx);
					strParam = strSrc.substr(nIdx + 1, nLen - nIdx - 1);
				}
			}
			if (!strParam.empty() && !strDevId.empty()) {
				ccrfid_device::DeviceCommandInfo devCmdInfo;
				devCmdInfo.nCommand = ccrfid_device::CMD_SET_INTERVAL;
				devCmdInfo.nParam1 = atoi(strParam.c_str());
				devCmdInfo.nParam2 = 0;
				devCmdInfo.nParam3 = 0;
				strcpy_s(devCmdInfo.szDeviceId, sizeof(devCmdInfo.szDeviceId), strDevId.c_str());
				strcpy_s(devCmdInfo.szFactoryId, sizeof(devCmdInfo.szFactoryId), "01");
				int nVal = EDS_SendCommand(g_nVal, devCmdInfo);
				printf("set interval command device=%s, interval=%s, ret=%d\n", 
					strDevId.c_str(), strParam.c_str(), nVal);
			}
		}
		else if (strncmp("?", szLine, 1) == 0 || strncmp("h", szLine, 1) == 0 
			|| strncmp("help", szLine, 4) == 0) {
			printf("\n------------------help---------------\n");
			printf("add device listener: a [deviceId] OR add [deviceID]\n");
			printf("remove device listener: r [deviceId] OR remove [deviceId]\n");
			printf("bind device: b [deviceId] OR bind [deviceId]\n");
			printf("submit task: st [deviceId] OR submittask [deviceId]\n");
			printf("close task: ct [deviceId] OR closetask [deviceId]\n");
			printf("flee on: fon [deviceId] OR fleeon [deviceId]\n");
			printf("flee off: foff [deviceId] OR fleeoff [deviceId]\n");
			printf("set interval: si [deviceId] [interval OR setinterval [deviceId] [interval]\n");
			printf("help: h OR ? OR help\n");
			printf("\n");
		}
	}
}

int main(int argc, char ** argv)
{
	printf("[ip][port1][port2][flag]\n");
	char szHost[16] = { 0 };
	unsigned short usPort1 = 0, usPort2 = 0;
	bool bFlag = false;
	sprintf_s(szHost, 16, "127.0.0.1");
	usPort1 = 28240;
	usPort2 = 28241;
	if (argc > 1) {
		strcpy_s(szHost, sizeof(szHost), argv[1]);
		if (argc > 2) {
			usPort1 = (unsigned short)atoi(argv[2]);
			if (argc > 3) {
				usPort2 = (unsigned short)atoi(argv[3]);
				if (argc > 4) {
					if (atoi(argv[4]) != 0) {
						bFlag = true;
					}
				}
			}
		}
	}
	EDS_Init();
	
	unsigned long long nInst = EDS_Start(szHost, usPort1, usPort2, MsgCb, NULL);
	if (nInst != -1) {
		printf("start sdk, connect %s:%hu|%hu\n", szHost, usPort1, usPort2);
		g_bRun = true;
		g_nVal = nInst;
		//int nRet = EDS_AddDeviceListener(nInst, NULL, NULL);
		//printf("add device listener ret=%d\n", nRet);
		std::thread t1(control_extra);
		if (bFlag) {
			while (g_bRun) {
				int n = rand() % 5;
				ccrfid_device::DeviceCommandInfo cmdInfo;
				if (n == 0) {
					cmdInfo.nCommand = ccrfid_device::CMD_SET_INTERVAL;
					cmdInfo.nParam1 = 10;
					strcpy_s(cmdInfo.szDeviceId, 16, gDeviceId);
					strcpy_s(cmdInfo.szFactoryId, 4, "01");
					cmdInfo.nParam2 = 0;
					cmdInfo.nParam3 = 0;
				}
				else if (n == 1) {
					cmdInfo.nCommand = ccrfid_device::CMD_FLEE;
					cmdInfo.nParam1 = 1;
					strcpy_s(cmdInfo.szDeviceId, 16, gDeviceId);
					strcpy_s(cmdInfo.szFactoryId, 4, "01");
					cmdInfo.nParam2 = 0;
					cmdInfo.nParam3 = 0;
				}
				else if (n == 2) {
					cmdInfo.nCommand = ccrfid_device::CMD_FLEE;
					cmdInfo.nParam1 = 0;
					strcpy_s(cmdInfo.szDeviceId, 16, gDeviceId);
					strcpy_s(cmdInfo.szFactoryId, 4, "01");
					cmdInfo.nParam2 = 0;
					cmdInfo.nParam3 = 0;
				}
				else if (n == 3) {
					cmdInfo.nCommand = ccrfid_device::CMD_TASK;
					cmdInfo.nParam1 = 1;
					strcpy_s(cmdInfo.szDeviceId, 16, gDeviceId);
					strcpy_s(cmdInfo.szFactoryId, 4, "01");
					cmdInfo.nParam2 = 0;
					cmdInfo.nParam3 = 0;
				}
				else if (n == 4) {
					cmdInfo.nCommand = ccrfid_device::CMD_TASK;
					cmdInfo.nParam1 = 0;
					strcpy_s(cmdInfo.szDeviceId, 16, gDeviceId);
					strcpy_s(cmdInfo.szFactoryId, 4, "01");
					cmdInfo.nParam2 = 0;
					cmdInfo.nParam3 = 0;
				}
				int nCmdSeq = EDS_SendCommand(nInst, cmdInfo);
				printf("cmdseq=%d\n", nCmdSeq);
				Sleep(500);
			}
		}
		while (g_bRun) {
			Sleep(500);
		}
		t1.join();
		EDS_RemoveDeviceListener(nInst, NULL, NULL);
		EDS_Stop(nInst);
	}
	EDS_Release();
	return 0;
}