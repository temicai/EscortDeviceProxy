#ifndef ESCORT_DEVICE_SDK_CONCRETE_H_
#define ESCORT_DEVICE_SDK_CONCRETE_H_

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <queue>
#include <string>
#include <vector>

#include "zmq.h"
#include "czmq.h"
#include "pfLog.hh"
#define _TIMESPEC_DEFINED
#include "pthread.h"

#define SECRET_KEY '8'

#define INTERACTOR_KEEPALIVE 0
#define INTERACTOR_SNAPSHOT 1
#define INTERACTOR_CONTROL 2

#include "EscortDeviceCommon.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "pthreadVC2.lib")
#pragma comment(lib, "pfLog.lib")
#pragma comment(lib, "libzmq.lib")
#pragma comment(lib, "czmq.lib")

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
	unsigned int uiMsgType;
	unsigned int uiMsgSeq;
	unsigned long long ulMsgTime;
	unsigned int uiMsgDataLen;
	unsigned char * pMsgData;
	tagInteractMessage()
	{
		uiMsgType = 0;
		uiMsgSeq = 0;
		ulMsgTime = 0;
		uiMsgDataLen = 0;
		pMsgData = NULL;
	}
} InteractMessage;

typedef struct tagRemoteLink
{
	unsigned short nActiveFlag; //0:false, 1:true
	unsigned short nFirstSend; //0:fasle, 1:true
	unsigned long long ulLastActiveTime;
	unsigned long long ulLastSendTime;
	tagRemoteLink()
	{
		nActiveFlag = 0;
		nFirstSend = 0;
		ulLastActiveTime = 0;
		ulLastSendTime = 0;
	}
} RemoteLink;

class DeviceManager
{
public:
	DeviceManager(const char *);
	~DeviceManager();
	int Start(const char *, unsigned short, unsigned short);
	int Stop();
	void SetMessageCallback(ccrfid_device::fMessageCallback, void *);
	int SendCommand(ccrfid_device::DeviceCommandInfo);
	int AddDeviceListen(const char *, const char *);
	int RemoveDeviceListen(const char *, const char *);
private:
	unsigned long long m_ullLogInst;
	unsigned short m_usLogType;

	int m_nRun;
	bool m_bInit;

	zctx_t * m_ctx;
	void * m_subscriber;
	void * m_interactor;
	zloop_t * m_loop;
	int m_nTimer4Supervisor;
	int m_nTimerTickCount;

	pthread_t m_pthdLog;
	std::queue<LogContext *> m_logQue;
	pthread_mutex_t m_mutex4LogQue;
	pthread_cond_t m_cond4LogQue;

	pthread_t m_pthdPublishMsg;
	std::queue<PublishMessage *> m_publishMsgQue;
	pthread_mutex_t m_mutex4PublishMsgQue;
	pthread_cond_t m_cond4PublishMsgQue;

	//pthread_t m_pthdInteractMsg;
	//std::queue<InteractMessage *> m_interactMsgQue;
	//pthread_mutex_t m_mutex4InteractMsgQue;
	//pthread_cond_t m_cond4InteractMsgQue;

	pthread_t m_pthdNetwork;

	pthread_t m_pthdSupervise;

	std::vector<std::string> m_filterDeviceList;
	pthread_mutex_t m_mutex4FilterDeviceList;

	ccrfid_device::fMessageCallback m_fMsgCb;
	void * m_pUserData;

	//unsigned long m_ulRemoteLastActiveTime;
	RemoteLink m_serverLink;
	pthread_mutex_t m_mutex4RemoteActiveTime;
	bool m_bConnected;


	ccrfid_device::ProxyInfo m_proxyInfo;

	pthread_mutex_t m_mutex4Interact;

	static unsigned int g_uiInteractSequence;
	static pthread_mutex_t g_mutex4InteractSequence;
	static int g_nRefCount;

protected:
	bool addLog(LogContext *);
	void handleLog();
	void writeLog(const char *, unsigned short, unsigned short);
	void handleNetwork();
	bool addPublishMessage(PublishMessage *);
	void handlePublishMessage();
	//bool addInteractMessage(InteractMessage *);
	//void handleInteractMessage();
	unsigned int getNextInteractSequence();
	void encryptMessage(unsigned char *, unsigned int, unsigned int);
	void decryptMessage(unsigned char *, unsigned int, unsigned int);
	unsigned long long makeDatetime(const char *);
	void formatDatetime(unsigned long long, char *, unsigned int);
	bool verifyMessage(const char *);
	void keepAlive();

	friend void * dealLogThread(void *);
	friend void * dealPublishMessageThread(void *);
	//friend void * dealInteractMessageThread(void *);
	friend void * dealNetworkThread(void *);
	friend void * superviseThread(void *);
	friend int supervise(zloop_t *, int, void *);

};

#endif