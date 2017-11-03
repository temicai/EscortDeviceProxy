#ifndef DEVICE_PROXY_CONCRETE_AA37A4148FD5404DA7EB94870A6BF2ED_H
#define DEVICE_PROXY_CONCRETE_AA37A4148FD5404DA7EB94870A6BF2ED_H

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <queue>
#include <string>
#include <vector>
#include <map>

#include "zmq.h"
#include "czmq.h"
#include "pfLog.hh"
#define _TIMESPEC_DEFINED
#include "pthread.h"
#include "iocp_tcp_server.h"

#include "EscortDeviceCommon.h"
#include "DeviceProxyError.h"
#include "HttpQuery.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iocp_tcp_server.lib")
#pragma comment(lib, "pthreadVC2.lib")
#pragma comment(lib, "pfLog.lib")
#pragma comment(lib, "libzmq.lib")
#pragma comment(lib, "czmq.lib")

//01 factory command
#define BEGIN_TOKEN 0x5b
#define END_TOKEN 0x5d
#define DEFAULT_DATA_PORT 28222
#define SECRET_KEY '8'
#define DEFAULT_BATTERY_THRESHOLD 20

//iteract message type
#define INTERACTOR_KEEPALIVE 0
#define INTERACTOR_SNAPSHOT 1
#define INTERACTOR_CONTROL 2


namespace ccrfid_proxy
{
	typedef struct tagLogContext
	{
		char * pLogData;
		unsigned int uiDataLen;
		unsigned short usLogCategory;
		unsigned short usLogType;
		tagLogContext()
		{
			pLogData = NULL;
			uiDataLen = 0;
			usLogCategory = 0;
			usLogType = 0;
		}
	} LogContext;

	typedef struct tagDeviceMessage
	{
		char szEndpoint[32];
		unsigned char * pMsgData;
		unsigned int uiMsgDataLen;
		unsigned int reserved;
		unsigned long long ulMsgTime;
		tagDeviceMessage()
		{
			szEndpoint[0] = '\0';
			pMsgData = NULL;
			uiMsgDataLen = 0;
			reserved = 0;
			ulMsgTime = 0;
		}
	} DeviceMessage;

	typedef struct tagPublishMessage
	{
		char szMsgTopic[32];
		unsigned int uiMsgSeq;
		unsigned int uiMsgType;
		unsigned char * pMsgData;
		unsigned int uiMsgDataLen;
		unsigned long long ulMsgTime;
	} PublishMessage;

	typedef struct tagInteractMessage
	{
		char szMsgIdentity[40];
		unsigned int uiMsgType; 
		unsigned int uiMsgSeq;
		unsigned long long ulMsgTime;
		unsigned int uiMsgDataLen;
		unsigned char * pMsgData;
		tagInteractMessage()
		{
			szMsgIdentity[0] = '\0';
			uiMsgType = 0;
			uiMsgSeq = 0;
			ulMsgTime = 0;
			uiMsgDataLen = 0;
			pMsgData = NULL;
		}
	} InteractMessage;

	typedef struct tagDeviceInfo
	{
		char szFactoryId[4];
		char szDeviceId[20];
		char szLink[32];
		unsigned short usOnline;						//0:offline, 1:online
		unsigned short usLoose;							//0:false, 1:true
		unsigned short usLowpower;					//0:false, 1:true
		unsigned short usBattery;						//0-100
		unsigned long long ulLastActiveTime;			//
		double dLatitude;										//
		double dLngitude;										//
		unsigned long long ulLastLocateTime;			
	} DeviceInfo;

	typedef struct tagLingerData
	{
		unsigned char * pData;
		unsigned int uiDataLen;
		tagLingerData()
		{
			pData = NULL;
			uiDataLen = 0;
		}
	} LingerData;

	typedef struct tagDeviceAlive
	{
		char szFactoryId[4];
		char szDeviceId[20];
		unsigned short usBattery;
	} DeviceAlive;

	typedef struct tagLocateInfo
	{
		unsigned long long ulLocateTime;
		double dLatitude;
		double dLngitude;
		int nLocateFlag;
		unsigned short usLatType;
		unsigned short usLngType;
		double dMoveSpeed;
		double dMoveDirection;
		int nElevation;
		int nGpsStatelliteCount;
		int nSignalIntensity;
		int nBattery;
		int nStatus;
		int nBaseStationCount;
		int nGsmDelay;
		int nNationCode;
		int nNetCode;
		int nDetectedWifiCount;
		ccrfid_device::BaseStation * pBaseStationList;
		ccrfid_device::WifiInformation * pDetectedWifiList;
		tagLocateInfo()
		{
			nLocateFlag = 0;
			dLatitude = dLngitude = 0.000000;
			dMoveSpeed = 0.0000;
			dMoveDirection = 0.0000;
			nElevation = nGpsStatelliteCount = 0;
			nSignalIntensity = nBattery = nStatus = nBaseStationCount = 0;
			nGsmDelay = nDetectedWifiCount = 0;
			usLatType = usLngType = 1;
			nNationCode = 460;
			nNetCode = 0;
			pBaseStationList = NULL;
			pDetectedWifiList = NULL;
		}
	} LocateInfo;

	typedef struct tagDeviceLocate
	{
		char szFactoryId[4];
		char szDeviceId[20];
		LocateInfo locateInfo;
	} DeviceLocate;

	class DeviceProxy
	{
	public:
		DeviceProxy(const char * pRoot);
		~DeviceProxy();
		int Start(unsigned short, unsigned short, unsigned short, unsigned short usLogType=0);
		int Stop();
		void SetLbsQueryParameter(int, const char *);
		int GetLastError();

		friend void __stdcall fMsgCb(int, void *, void *);
		friend void * dealLogThread(void *);
		friend void * dealNetworkThread(void *);
		friend void * dealPublishThread(void *);
		friend void * dealInteractThread(void *);
		friend void * dealDeviceThread(void *);
		friend void freeLingerData(void *);
	protected:
		
		bool addLog(LogContext *);
		void handleLog();
		void writeLog(const char *, unsigned short, unsigned short);
		bool addDeviceMessage(DeviceMessage *);
		void handleDeviceMessage();
		void parseDeviceMessage(DeviceMessage *);
		int getWholeMessage(const unsigned char *, unsigned int, unsigned int, unsigned int &, unsigned int &);
		void splitString(std::string, std::string, std::vector<std::string> &);
		void updateDeviceLink(const char *, const char *);
		void handleDisconnectLink(const char *);
		void handleDeviceAlive(DeviceAlive *, unsigned long long);
		void handleDeviceLocate(DeviceLocate *, unsigned long long);
		void handleDeviceAlarm(DeviceLocate *, unsigned long long);
		void analyzeDeviceStatus(int nStatus , unsigned short & usLooseAlarm, unsigned short & usLooseStatus);
		void handleNetWork();
		bool addPublishMessage(const char *, unsigned int, unsigned char *, size_t);
		void handlePublishMessage();
		bool addInteractMessage(InteractMessage *);
		void handleInteractMessage();

		unsigned int getPublishMessageSequence();
		void encryptMessage(unsigned char *, unsigned int, unsigned int);
		void decryptMessage(unsigned char *, unsigned int, unsigned int);
		void formatDatetime(unsigned long long, char *, size_t);
		void makeDatetime(const char *, unsigned long long *);

	private:
		unsigned long long m_ullSrvInst;
		unsigned long long m_ullLogInst;
		unsigned short m_usLogType;
		unsigned short m_usDataPort;
		unsigned short m_usPublishPort;
		unsigned short m_usInteractPort;
		int m_nRun;
		bool m_bInit;
		int m_nErrCode;
		char m_szKey[64];
		int m_nQryLbs;

		zctx_t * m_ctx;
		void * m_publisher;
		void * m_interactor;

		std::queue<LogContext *> m_logQue;
		pthread_mutex_t m_mutex4LogQue;
		pthread_cond_t m_cond4LogQue;

		std::queue<DeviceMessage *> m_deviceMsgQue;
		pthread_mutex_t m_mutex4DeviceMsgQue;
		pthread_cond_t m_cond4DeviceMsgQue;

		std::queue<PublishMessage *> m_publishMsgQue;
		pthread_mutex_t m_mutex4PublishMsgQue;
		pthread_cond_t m_cond4PublishMsgQue;

		std::queue<InteractMessage *> m_interactMsgQue;
		pthread_mutex_t m_mutex4InteractMsgQue;
		pthread_cond_t m_cond4InteractMsgQue;

		zhash_t * m_endpointLingerDataList;
		pthread_mutex_t m_mutex4EndpointLingerDataList;
		//zhash_t * m_deviceList;//
		std::map<std::string, ccrfid_proxy::DeviceInfo *> m_deviceList2;
		pthread_mutex_t m_mutex4DeviceList;
		zhash_t * m_linkDeviceList;
		pthread_mutex_t m_mutex4LinkDeviceList;//endpoint-deviceId

		pthread_t m_pthdLog;
		pthread_t m_pthdNetwork;
		pthread_t m_pthdInteractor;
		pthread_t m_pthdPublisher;
		pthread_t m_pthdDevice;

		static unsigned int g_uiPubSequence;
		static pthread_mutex_t g_mutex4PubSequence;
		static int g_nRefCount;
	};

}

#endif

