#ifndef ESCORT_DEVICE_COMMON_C60BBF055724462598C8E07F542C8FD5_H
#define ESCORT_DEVICE_COMMON_C60BBF055724462598C8E07F542C8FD5_H

#include <sys/types.h>

namespace ccrfid_device
{
	enum eCommandType 
	{
		CMD_RESET = 0,				//reboot device¸
		CMD_BIND = 1,					//
		CMD_TASK = 2,					//
		CMD_FLEE = 3,					//contining warn
		CMD_SET_INTERVAL = 4,	//locate interval
	};

	// command            param1
	// CMD_RESET          /
	// CMD_BIND           /
	// CMD_TASK           1:on,0:off
	// CMD_FLEE           1:on,0:off
	// CMD_SET_INTERVAL   //min: 10
	typedef struct tagDeviceCommnadInfo
	{
		char szDeviceId[20];
		char szFactoryId[4];
		int nCommand;//enum eCommandType
		int nParam1;//in
		int nParam2;//out, cmd retcode
		int nParam3;
	} DeviceCommandInfo;

	enum eMessageType
	{
		MT_ONLINE = 1,
		MT_ALIVE = 2,
		MT_OFFLINE = 3,
		MT_ALARM_LOOSE = 4,
		MT_ALARM_LOWPOWER = 5,
		MT_LOCATE_GPS = 6,
		MT_LOCATE_LBS = 7,
		MT_COMMAND = 8,
		MT_SERVER_CONNECT = 0x0e,
		MT_SERVER_DISCONNECT = 0x0f,
	};

	enum eCoordinateType
	{
		COORDINATE_WGS84 = 0,
		COORDINATE_BD09 = 1,
		COORDINATE_GCJ02 = 2,
	};

	typedef struct tagDeviceMessage
	{
		char szDeviceId[20];
		char szFactoryId[4];
		unsigned short usMessageType;
		unsigned short usMessageTypeExtra;
		unsigned short usDeviceBattery;
		unsigned short usReserved;
		unsigned long long ulMessageTime;
	} DeviceMessage;

	typedef struct tagDeviceLocateGpsMessage
	{
		char szDeviceId[20];
		char szFactoryId[4];
		unsigned long long ulLocateTime;
		unsigned short usSatelliteCount;
		unsigned short usSignalIntensity;
		unsigned short nCoordinate;//0:wgs84,1:bd09,2:gcj02
		unsigned short usDeviceBattery;
		double dLatitude;
		double dLngitude;
		double dSpeed;
		double dDirection;
	} DeviceLocateGpsMessage;

	typedef struct tagBaseStation
	{
		int nLocateAreaCode;	//LAC
		int nCellId;					//CI
		int nSignalIntensity; 
	} BaseStation;

	typedef struct tagWifiInformation
	{
		char szWifiTagName[32];
		char szWifiMacAddress[32];
		int nWifiSignalIntensity;
	} WifiInformation;

	typedef struct tagDeviceLocateLbsMessage
	{
		char szDeviceId[20];
		char szFactoryId[4];
		unsigned long long ulLocateTime;
		double dRefLatitude;
		double dRefLngitude;
		unsigned short nCoordinate;
		unsigned short usDeviceBattery;
		unsigned short nNationCode;
		unsigned short nNetCode;
		int nBaseStationCount;
		int nDetectedWifiCount;
		BaseStation * pBaseStationList;
		WifiInformation * pDetectedWifiList;
	} DeviceLocateLbsMessage;

	typedef struct tagProxyInfo
	{
		char szProxyIp[20];
		unsigned short usPort1; //message port
		unsigned short usPort2; //control port
	} ProxyInfo;

	//	nMsgType                    pMsg
	//	MT_ONLINE								DeviceMessage
	//	MT_ALIVE								DeviceMessage
	//	MT_OFFLINE							DeviceMessage
	//	MT_ALARM_LOOSE					DeviceMessage
	//	MT_ALARM_LOWPOWER				DeviceMessage
	//	MT_LOCATE_GPS						DeviceLocateGpsMessage
	//	MT_LOCATE_LBS						DeviceLocateLbsMessage
	//	MT_COMMNAD							DeviceCommandInfo
	//	MT_SERVER_CONNECT				ProxyInfo
	//	MT_SEVER_DISCONNECT			ProxyInfo
	typedef void(__stdcall *fMessageCallback)(unsigned int usMsgType, unsigned int uiMsgSequence,
		unsigned long long ulMsgTime, void * pMsg, void * pUserData);
}

#endif
