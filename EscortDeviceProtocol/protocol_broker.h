#ifndef PROTOCOL_BROKER_B4CBCC036C674AFBA39C22D05F649AAE_H
#define PROTOCOL_BROKER_B4CBCC036C674AFBA39C22D05F649AAE_H

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <queue>
#include <string>
#include <map>
#include <vector>
#include <set>
#include <algorithm>
#include <sys/timeb.h>
#include <time.h>
#include <fstream>

#include "sqlite3.h"
#include "document.h"
#include "pfLog.hh"
//#include "iocp_tcp_server.h"
#include "EscortDeviceSDK.h"
#include "tcp_server.h"
#include "sodium.h"


#define _TIMESPEC_DEFINED
#include "pthread.h"

#include "escort_protocol.h"


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "pthreadVC2.lib")
#pragma comment(lib, "pfLog.lib")
#pragma comment(lib, "tcp_server.lib")
//#pragma comment(lib, "iocp_tcp_server.lib")
#pragma comment(lib, "EscortDeviceSDK.lib")
#pragma comment(lib, "sqlite3.lib")
#pragma comment(lib, "libsodium.lib")

namespace broker
{
	typedef struct tagLogContext
	{
		unsigned short usLogCategory;
		unsigned short usLogType;
		unsigned int uiContentLength;
		char * pLogContent;
		tagLogContext()
		{
			usLogCategory = 0;
			usLogType = 0;
			uiContentLength = 0;
			pLogContent = NULL;
		}
	} LogContext;

	typedef struct tagEndpoint
	{
		char szIp[20];
		unsigned short usPort;
	} Endpoint;

	typedef struct tagEescortDevice
	{
		char szDeviceId[20]; //
		char szFactoryId[4]; //"01"
		int nBattery : 8;    //0-100
		int nFleeState : 8;  //0:off,1:on
		int nLooseState : 8; //0:off,1:on
		int nFenceState : 8; //0:off,1:on
		int nOnline : 8;     //0:off,1:on
		int nFencePolicy : 8;//0:out alarm,1:in alarm
		int nCoordinate : 8; //
		int nLocateType : 8; //
		unsigned long ulLastActiveTime;
		unsigned long ulLocateTime;
		double lastLatitude;
		double lastLongitude;
		unsigned int uiLastMsgSeq;
		char szDeviceEndpoint[32];
		//std::set<std::pair<std::string, std::string>> fenceList; //fenceId, fenceContent
		std::set<std::string> fenceList; //fenceId
	} EscortDevice;

	typedef struct tagLinkData
	{
		char szLinkId[32];
		int nLinkState;
		unsigned int uiTotalDataLen;
		unsigned int uiLingeDataLen;
		unsigned int uiLackDataLen;
		unsigned char * pLingeData;
		std::set<std::pair<std::string, std::string>> userPair;//user,session
		tagLinkData()
		{
			szLinkId[0] = '\0';
			nLinkState = 0;
			uiTotalDataLen = uiLackDataLen = uiLackDataLen = 0;
			pLingeData = NULL;
			userPair.clear();
		}
	} LinkData;

	typedef struct tagEscortUser
	{
		char szUserId[32];
		char szPassword[64];
		int nLimitWaterLine;
		int nCurrentWaterLine;
	} EscortUser;

	typedef struct tagEscortFence
	{
		char szFenceId[20];
		char szFenceContent[256];
		char szDeviceId[20];
		unsigned long ulStartTime;
		unsigned long ulStopTime;
		int nFenceType: 8;
		int nFenceState : 8;
		int nFencePolicy: 8;
		int nCoordinate : 8;
		std::string describeFence()
		{
			char szOut[512] = { 0 };
			sprintf_s(szOut, sizeof(szOut), "%d|%d|%d|%s|%lu|%lu", nFenceType, nCoordinate, nFencePolicy,
				szFenceContent, ulStartTime, ulStopTime);
			return (std::string)(szOut);
		}
	} EscortFence;

	typedef std::map<std::string, EscortDevice *> EscortDeviceList;

	typedef std::map<std::string, EscortUser *> EscortUserList;

	typedef std::map<std::string, EscortFence *> EscortFenceList;

	typedef struct tagProxyDeviceMessage
	{
		unsigned short usMsgType;
		unsigned int uiMsgSeq;
		unsigned long ulMsgTime;
		unsigned char * pMsgData;
		unsigned int uiMsgDataLen;
	} ProxyDeviceMessage;

	typedef struct tagLinkInfo
	{
		char szSession[20];
		char szAccount[32];
		char szEndpoint[30];
		unsigned long ulLastActiveTime;//local time
		unsigned long ulLastRequestTime;//link request time
		unsigned int uiLastRequestSeq;//link request seq
		unsigned int uiLastNotifySeq; //notify seq
		unsigned int nActiveFlag:8; //0:false, 1:true
		unsigned int nReplyWaitTimeout:8;//default 10, [3-60] sec
		unsigned int nResendCount:8;//default 0,[0-5]
		unsigned int nAliveMissToleranceCount:8;//default 1, [1-5]
		unsigned int nKeepAliveInterval:16;//default-30, [10-600] sec
		unsigned int nProtocolType:8;//default 0, [0-private, 1-mqtt]
		unsigned int nSecurityPolicy:8;//default 1, [0-no, 1-simple, 2-rsa]
		unsigned int nSecurityExtra:16;//default 0, when securityPolicy=1, default 8
	} LinkInfo;

	typedef std::map<std::string, LinkInfo *> LinkInfoList;

}

class ProtocolBroker
{
public:
	ProtocolBroker(const char * pDllDir);
	~ProtocolBroker();
	int StartBroker(const char * pMsgHost, unsigned short usMsgPort, unsigned short usCtrlPort, 
		unsigned short usBrokerPort);
	int StopBroker();

private:
	int m_nSdkInst;
	unsigned int m_uiSrvInst;
	bool m_bInit;
	bool m_bRun;
	unsigned int m_uiLogInst;
	unsigned short m_usLogType;
	unsigned short m_usBrokerPort;
	
	std::queue<MessageContent *> m_srvMsgDataQue;
	pthread_mutex_t m_mutex4SrvMsgDataQue;
	pthread_cond_t m_cond4SrvMsgDataQue;
	pthread_t m_pthdDealSrvMsgData;

	std::queue<broker::LogContext *> m_logQue;
	pthread_mutex_t m_mutex4LogQue;
	pthread_cond_t m_cond4LogQue;
	pthread_t m_pthdDealLog;

	pthread_mutex_t m_mutex4LinkDataList;
	typedef std::map <std::string, broker::LinkData *> LinkDataList;
	LinkDataList m_linkDataList;

	sqlite3 * m_pDb;
	char m_szDbFile[256];
	bool m_bConnectProxy;

	broker::EscortDeviceList m_devList;
	broker::EscortUserList m_userList;
	broker::EscortFenceList m_fenceList;
	pthread_mutex_t m_mutex4DevList;
	pthread_mutex_t m_mutex4UserList;
	pthread_mutex_t m_mutex4FenceList;

	pthread_mutex_t m_mutex4ProxyConnect;

	typedef std::queue<broker::ProxyDeviceMessage *> ProxyDeviceMessageQueue;
	ProxyDeviceMessageQueue m_proxyDevMsgQue;
	pthread_mutex_t m_mutex4ProxyDevMsgQue;
	pthread_cond_t m_cond4ProxyDevMsgQue;
	pthread_t m_pthdDealProxyDevMsg;

	pthread_mutex_t m_mutex4LinkList;
	broker::LinkInfoList m_linkList;

	pthread_mutex_t m_mutex4DeviceSubscribers;
	typedef std::set<std::string> SubscriberSessions;
	typedef std::map<std::string, SubscriberSessions> DeviceSubscribers;
	DeviceSubscribers	m_deviceSubscribers;//deviceId,set<session>

	typedef std::map<std::string, device_protocol::LinkDeviceControlReply *> DeviceControlPair;
	DeviceControlPair m_devCtrlPair;
	pthread_mutex_t m_mutex4DevCtrlPair;

	pthread_mutex_t m_mutex4FenceId;

protected:
	bool addLog(broker::LogContext *);
	void writeLog(const char * pLogContent, unsigned short usLogCategory, unsigned short usLogType);
	void handleLog();

	bool addMsg(MessageContent *);
	void handleMsg();

	void parseMsg(const MessageContent *);
	int getWholeMsg(const unsigned char * pInputData, unsigned int uiDataLen, unsigned int uiIndex, 
		unsigned int & uiHeadIndex, unsigned int & uiTailIndex, device_protocol::ProtocolMessageHead *);
	void descryptMessageViaPrivateSimple(unsigned char *, unsigned int, unsigned int, short);
	void encryptMessageViaPrivateSimple(unsigned char *, unsigned int, unsigned int, short);
	int registerEndpoint(const char *);
	int unregisterEndpoint(const char *);
	int sendDataViaEndpoint(const char * pData, unsigned int uiDataLen, const char * pEndpoint , 
		int, int, int);
	void clearLinkDataList();

	bool addProxyDevMsg(broker::ProxyDeviceMessage *);
	void handleProxyDevMsg();

	void initDB(const char * pDbFile);
	bool isFileExists(const char * pFileName);
	void loadUserList();
	void loadDeviceList();
	void loadFenceList();
	void addDeviceFence(const char * pDeviceId, const char * pFenceId);
	void clearUserList();
	void clearDeviceList();
	void clearFenceList();

	void handleDeviceOnlineMessage(ccrfid_device::DeviceMessage * pDevOnlineMsg, unsigned int uiSeq, 
		unsigned long ulTime);
	void handleDeviceAliveMessage(ccrfid_device::DeviceMessage * pDevAliveMsg, unsigned int uiSeq, 
		unsigned long ulTime);
	void handleDeviceOfflineMessage(ccrfid_device::DeviceMessage * pDevOfflineMsg, unsigned int uiSeq,
		unsigned long ulTime);
	void handleDeviceLowpowerMessage(ccrfid_device::DeviceMessage * pDevLowpoerMsg, unsigned int uiSeq,
		unsigned long ulTime);
	void handleDeviceLooseMessage(ccrfid_device::DeviceMessage * pDevLooseMsg, unsigned int uiSeq,
		unsigned long ulTime);
	void handleDeviceGpsMessage(ccrfid_device::DeviceLocateGpsMessage * pDevGpsMsg, unsigned int uiSeq,
		unsigned long ulTime);
	void handleDeviceLbsMessage(ccrfid_device::DeviceLocateLbsMessage * pDevLbsMsg, unsigned int uiSeq,
		unsigned long ulTime);
	void handleDeviceCommandMessage(ccrfid_device::DeviceCommandInfo * pDevCmdMsg, unsigned int uiSeq,
		unsigned long ulTime);
	void setDeviceProxyConnect(bool bFlag);
	bool getDeviceProxyConnect();
	
	void dispatchMessage(const char * key, const char * value, const char * pEndpoint, int, int);

	//to client link
	void handleLinkInitialize(device_protocol::LinkInitializeRequest *, const char * pEndpoint, 
		int nProtocolType, int nSecurityType);
	int replyLinkInitialize(device_protocol::LinkInitializeReply *, const char * pEndpoint, 
		int nProtocolType, int nSecurityType, int nSecurityExtra);
	void handleLinkUninitialize(device_protocol::LinkUninitializeRequest *, const char * , 
		int nProtocolType, int nSecurityType);
	int replyLinkUninitialize(device_protocol::LinkUnitializeReply *, const char * pEndpoint, 
		int nProtocolType, int nSecurityType, int nSecurityExtra);
	void handleLinkSubscribeDevice(device_protocol::LinkSubscribeDeviceRequest *, 
		const char * pEndpoint, int nProtocolType, int nSecurityType);
	int replyLinkSubscribeDevice(device_protocol::LinkSubscribeDeviceReply *, const char * pEndpoint,
		int nProtocolType, int nSecurityType, int nSecurityExtra);
	void handleLinkSetDeviceFence(device_protocol::LinkSetFenceRequest *, const char * pEndpoint, 
		int nProtocolType, int nSecurityType);
	int replyLinkSetDeviceFence(device_protocol::LinkSetFenceReply *, const char * pEndpoint, 
		int nProtocolType, int nSecurityType, int nSecurityExtra);
	void handleLinkGetDeviceFence(device_protocol::LinkGetFenceRequest *, const char * pEndpoint, 
		int nProtocolType, int nSecurityType);
	int replyLinkGetDeviceFence(device_protocol::LinkGetFenceReply *, const char * pEndpoint, 
		int nProtocolType, int nSecurityType, int nSecurityExtra);
	void handleLinkRemoveDeviceFence(device_protocol::LinkRemoveFenceRequest *, const char *,
		int, int);
	int replyLinkRemoveDeviceFence(device_protocol::LinkRemoveFenceReply *, const char *, int, int, int);
	void handleLinkControlDevice(device_protocol::LinkDeviceControlRequest *, const char *, int, int);
	int replyLinkControlDevice(device_protocol::LinkDeviceControlReply *, const char *, int, int, int);
	void handleLinkKeepAlive(device_protocol::LinkHeartBeatRequest *, const char *, int, int);
	int replyLinkKeepAlive(device_protocol::LinkHeartBeatReply *, const char *, int, int, int);
	void handleLinkSetParameter(device_protocol::LinkSetParameterRequest *, const char *, int, int);
	int replyLinkSetParameter(device_protocol::LinkSetParameterReply *, const char *, int, int, int);
	void handleLinkGetParameter(device_protocol::LinkGetParameterRequest *, const char *, int, int);
	int replyLinkGetParameter(device_protocol::LinkGetParameterReply *, const char *, int, int, int);

	int generateSession(char * pSession, size_t nSize);
	int generateFenceId(char * pFenceId, size_t nSize);
	bool increateUserInstance(const char * pUserId);

	friend void __stdcall sdkMsgCb(unsigned short usMsgType, unsigned int uiMsgSequence, 
		unsigned long ulMsgTime, void * pMsg, void * pUserData);
	friend void __stdcall srvMsgCb(int, void *, void *);
	friend void * startDealLogThread(void *);
	friend void * startDealMsgThread(void *);
	friend void * startDealProxyDevMsgThread(void *);
};






#endif
