#include "protocol_broker.h"

static std::string utf8_to_ansi(LPCSTR utf8)
{
	int WLen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, NULL);
	LPWSTR pszW = (LPWSTR)_alloca((WLen + 1) * sizeof(WCHAR));
	MultiByteToWideChar(CP_UTF8, 0, utf8, -1, pszW, WLen);
	pszW[WLen] = '\0';
	int ALen = WideCharToMultiByte(CP_ACP, 0, pszW, -1, NULL, 0, NULL, NULL);
	LPSTR pszA = (LPSTR)_alloca((ALen + 1) * sizeof(char));
	WideCharToMultiByte(CP_ACP, 0, pszW, -1, pszA, ALen, NULL, NULL);
	pszA[ALen] = '\0';
	std::string retStr = pszA;
	return retStr;
}

static std::string ansi_to_utf8(LPCSTR ansi)
{
	int WLen = MultiByteToWideChar(CP_ACP, 0, ansi, -1, NULL, 0);
	LPWSTR pszW = (LPWSTR)_alloca((WLen + 1) * sizeof(WCHAR));
	MultiByteToWideChar(CP_ACP, 0, ansi, -1, pszW, WLen);
	int ALen = WideCharToMultiByte(CP_UTF8, 0, pszW, -1, NULL, 0, NULL, NULL);
	LPSTR pszA = (LPSTR)_alloca(ALen + 1);
	WideCharToMultiByte(CP_UTF8, 0, pszW, -1, pszA, ALen, NULL, NULL);
	pszA[ALen] = '\0';
	std::string retStr = pszA;
	return retStr;
}

static unsigned long make_datetime(const char * strDatetime)
{
	struct tm tm_time;
	sscanf_s(strDatetime, "%04d%02d%02d%02d%02d%02d", &tm_time.tm_year, &tm_time.tm_mon, &tm_time.tm_mday, 
		&tm_time.tm_hour, &tm_time.tm_min, &tm_time.tm_sec);
	tm_time.tm_year -= 1900;
	tm_time.tm_mon -= 1;
	return (unsigned long)mktime(&tm_time);
}

static void format_datetime(unsigned long ulTime, char * pStrDatetime, size_t nStrLen)
{
	struct tm tm_time;
	time_t srcTime = ulTime;
	localtime_s(&tm_time, &srcTime);
	char szDatetime[20] = { 0 };
	sprintf_s(szDatetime, sizeof(szDatetime), "%04d%02d%02d%02d%02d%02d", tm_time.tm_year + 1900, tm_time.tm_mon + 1,
		tm_time.tm_mday, tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec);
	size_t nLen = strlen(szDatetime);
	if (pStrDatetime && nStrLen >= nLen) {
		strcpy_s(pStrDatetime, nStrLen, szDatetime);
	}
}

static unsigned long make_datetime2(const char * strDatetime)
{
	struct tm tm_time;
	sscanf_s(strDatetime, "%04d-%02d-%02d %02d:%02d:%02d", &tm_time.tm_year, &tm_time.tm_mon, &tm_time.tm_mday,
		&tm_time.tm_hour, &tm_time.tm_min, &tm_time.tm_sec);
	tm_time.tm_year -= 1900;
	tm_time.tm_mon -= 1;
	return (unsigned long)mktime(&tm_time);
}

static void format_datetime2(unsigned long ulTime, char * pStrDatetime, size_t nStrLen)
{
	struct tm tm_time;
	time_t srcTime = ulTime;
	localtime_s(&tm_time, &srcTime);
	char szDatetime[32] = { 0 };
	sprintf_s(szDatetime, sizeof(szDatetime), "%04d-%02d-%02d %02d:%02d:%02d", tm_time.tm_year + 1900,
		tm_time.tm_mon + 1, tm_time.tm_mday, tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec);
	size_t nLen = strlen(szDatetime);
	if (pStrDatetime && nStrLen >= nLen) {
		strcpy_s(pStrDatetime, nStrLen, szDatetime);
	}
}

void __stdcall sdkMsgCb(unsigned short usMsgType_, unsigned int uiMsgSequence_, 
	unsigned long ulMsgTime_, void * pMsg_, void * pUserData_)
{
	ProtocolBroker * pBroker = (ProtocolBroker *)pUserData_;
	switch (usMsgType_) {
		case ccrfid_device::MT_ONLINE:
		case ccrfid_device::MT_ALIVE:
		case ccrfid_device::MT_OFFLINE: 
		case ccrfid_device::MT_ALARM_LOWPOWER: 
		case ccrfid_device::MT_ALARM_LOOSE: {
			if (pBroker) {
				size_t nMsgLen = sizeof(ccrfid_device::DeviceMessage);
				broker::ProxyDeviceMessage * pProxyDevMsg = new broker::ProxyDeviceMessage();
				pProxyDevMsg->ulMsgTime = ulMsgTime_;
				pProxyDevMsg->uiMsgSeq = uiMsgSequence_;
				pProxyDevMsg->usMsgType = usMsgType_;
				pProxyDevMsg->uiMsgDataLen = nMsgLen;
				pProxyDevMsg->pMsgData = new unsigned char[nMsgLen + 1];
				memcpy_s(pProxyDevMsg->pMsgData, nMsgLen + 1, pMsg_, nMsgLen);
				pProxyDevMsg->pMsgData[nMsgLen] = '\0';
				if (!pBroker->addProxyDevMsg(pProxyDevMsg)) {
					delete[] pProxyDevMsg->pMsgData;
					pProxyDevMsg->pMsgData = NULL;
					delete pProxyDevMsg;
					pProxyDevMsg->pMsgData = NULL;
				}
			}
			break;
		}
		case ccrfid_device::MT_LOCATE_GPS: {
			if (pBroker) {
				size_t nMsgLen = sizeof(ccrfid_device::DeviceLocateGpsMessage);
				broker::ProxyDeviceMessage * pProxyDevMsg = new broker::ProxyDeviceMessage();
				pProxyDevMsg->ulMsgTime = ulMsgTime_;
				pProxyDevMsg->uiMsgSeq = uiMsgSequence_;
				pProxyDevMsg->usMsgType = usMsgType_;
				pProxyDevMsg->uiMsgDataLen = nMsgLen;
				pProxyDevMsg->pMsgData = new unsigned char[nMsgLen + 1];
				memcpy_s(pProxyDevMsg->pMsgData, nMsgLen + 1, pMsg_, nMsgLen);
				pProxyDevMsg->pMsgData[nMsgLen] = '\0';
				if (!pBroker->addProxyDevMsg(pProxyDevMsg)) {
					delete[] pProxyDevMsg->pMsgData;
					pProxyDevMsg->pMsgData = NULL;
					delete pProxyDevMsg;
					pProxyDevMsg->pMsgData = NULL;
				}
			}
			break;
		}
		case ccrfid_device::MT_LOCATE_LBS: {
			if (pBroker) {
				size_t nMsgLen = sizeof(ccrfid_device::DeviceLocateLbsMessage), nMsgLen1 = 0, nMsgLen2 = 0;
				ccrfid_device::DeviceLocateLbsMessage * pLocateLbsMsg = 
					(ccrfid_device::DeviceLocateLbsMessage *)pMsg_;
				if (pLocateLbsMsg->nBaseStationCount) {
					nMsgLen1 = sizeof(ccrfid_device::BaseStation) * pLocateLbsMsg->nBaseStationCount;
				}
				if (pLocateLbsMsg->nDetectedWifiCount) {
					size_t nLen = sizeof(ccrfid_device::WifiInformation) * pLocateLbsMsg->nDetectedWifiCount;
				}
				broker::ProxyDeviceMessage * pProxyDevMsg = new broker::ProxyDeviceMessage();
				pProxyDevMsg->uiMsgDataLen = nMsgLen + nMsgLen1 + nMsgLen2;
				pProxyDevMsg->pMsgData = new unsigned char[pProxyDevMsg->uiMsgDataLen + 1];
				memcpy_s(pProxyDevMsg->pMsgData, nMsgLen, pLocateLbsMsg, nMsgLen);
				if (nMsgLen1) {
					memcpy_s(pProxyDevMsg->pMsgData + nMsgLen, nMsgLen1 + 1, 
						pLocateLbsMsg->pBaseStationList, nMsgLen1);
				}
				if (nMsgLen2) {
					memcpy_s(pProxyDevMsg->pMsgData + nMsgLen + nMsgLen1, nMsgLen2 + 1, 
						pLocateLbsMsg->pDetectedWifiList, nMsgLen2);
				}
				pProxyDevMsg->pMsgData[pProxyDevMsg->uiMsgDataLen] = '\0';
				pProxyDevMsg->ulMsgTime = ulMsgTime_;
				pProxyDevMsg->uiMsgSeq = uiMsgSequence_;
				pProxyDevMsg->usMsgType = usMsgType_;
				if (!pBroker->addProxyDevMsg(pProxyDevMsg)) {
					delete[] pProxyDevMsg->pMsgData;
					pProxyDevMsg->pMsgData = NULL;
					delete pProxyDevMsg;
					pProxyDevMsg = NULL;
				}
			}
			break;
		}
		case ccrfid_device::MT_COMMAND: {
			if (pBroker) {
				size_t nMsgLen = sizeof(ccrfid_device::DeviceCommandInfo);
				broker::ProxyDeviceMessage * pProxyDevMsg = new broker::ProxyDeviceMessage();
				pProxyDevMsg->uiMsgDataLen = nMsgLen;
				pProxyDevMsg->pMsgData = new unsigned char[pProxyDevMsg->uiMsgDataLen + 1];
				memcpy_s(pProxyDevMsg->pMsgData, nMsgLen + 1, pMsg_, nMsgLen);
				pProxyDevMsg->pMsgData[pProxyDevMsg->uiMsgDataLen] = '\0';
				pProxyDevMsg->ulMsgTime = ulMsgTime_;
				pProxyDevMsg->uiMsgSeq = uiMsgSequence_;
				pProxyDevMsg->usMsgType = usMsgType_;
				if (!pBroker->addProxyDevMsg(pProxyDevMsg)) {
					delete pProxyDevMsg->pMsgData;
					pProxyDevMsg->pMsgData = NULL;
					delete pProxyDevMsg;
					pProxyDevMsg = NULL;
				}
			}
			break;
		}
		case ccrfid_device::MT_SERVER_CONNECT: {
			if (pBroker) {
				pBroker->setDeviceProxyConnect(true);
				if (pBroker->m_uiSrvInst) {
					EDS_AddDeviceListener(pBroker->m_uiSrvInst, NULL, NULL);
				}
			}
			break;
		}
		case ccrfid_device::MT_SERVER_DISCONNECT: {
			if (pBroker) {
				if (pBroker->m_uiSrvInst) {
					EDS_RemoveDeviceListener(pBroker->m_uiSrvInst, NULL, NULL);
				}
				pBroker->setDeviceProxyConnect(false);
			}
			break;
		}
	}
}

void __stdcall srvMsgCb(int nMsgType_, void * pMsg_, void * pUserData_)
{
	ProtocolBroker * pBroker = (ProtocolBroker *)pUserData_;
	switch (nMsgType_) {
		case MSG_LINK_CONNECT: {
			if (pBroker) {
				const char * pLink = (char *)pMsg_;
				if (pBroker) {
					pBroker->registerEndpoint(pLink);
				}
			}
			break;
		}
		case MSG_LINK_DISCONNECT: {
			if (pBroker) {
				const char * pLink = (char *)pMsg_;
				if (pBroker) {
					pBroker->unregisterEndpoint(pLink);
				}
			}
			break;
		}
		case MSG_DATA: {
			MessageContent * pSrcMsgContent = (MessageContent *)pMsg_;
			if (pSrcMsgContent) {
				if (pBroker) {
					size_t nSize = sizeof(MessageContent);
					MessageContent * pDstMsgContent = new MessageContent();
					memcpy_s(pDstMsgContent, nSize, pSrcMsgContent, nSize);
					if (pDstMsgContent->ulMsgDataLen > 0) {
						pDstMsgContent->pMsgData = (unsigned char *)malloc(pDstMsgContent->ulMsgDataLen + 1);
						memcpy_s(pDstMsgContent->pMsgData, pDstMsgContent->ulMsgDataLen, pSrcMsgContent->pMsgData,
							pSrcMsgContent->ulMsgDataLen);
						pDstMsgContent->pMsgData[pDstMsgContent->ulMsgDataLen] = '\0';
					}
					if (!pBroker->addMsg(pDstMsgContent)) {
						delete pDstMsgContent;
						pDstMsgContent = NULL;
					}
				}
			}
			break;
		}
	}
}

ProtocolBroker::ProtocolBroker(const char * pDllDir_)
{
	srand((unsigned int)time(NULL));
	m_bInit = true;
	m_pthdDealLog.p = NULL;
	m_pthdDealSrvMsgData.p = NULL;
	m_usLogType = pf_logger::eLOGTYPE_FILE;
	m_bRun = false;
	m_nSdkInst = 0;
	m_usBrokerPort = 0;
	m_bConnectProxy = false;

	m_pthdDealProxyDevMsg.p = NULL;
	m_linkList.clear();
	m_deviceSubscribers.clear();

	m_uiLogInst = LOG_Init();
	if (m_uiLogInst > 0) {
		char szLogPath[256] = { 0 };
		if (pDllDir_ && strlen(pDllDir_)) {
			sprintf_s(szLogPath, sizeof(szLogPath), "%slog\\", pDllDir_);
		}
		else {
			sprintf_s(szLogPath, sizeof(szLogPath), ".\\log\\");
		}
		CreateDirectoryExA(".\\", szLogPath, NULL);
		strcat_s(szLogPath, sizeof(szLogPath), "escort_protocol\\");
		CreateDirectoryExA(".\\", szLogPath, NULL);
		pf_logger::LogConfig logConf;
		logConf.usLogType = pf_logger::eLOGTYPE_FILE;
		logConf.usLogPriority = pf_logger::eLOGPRIO_ALL;
		strncpy_s(logConf.szLogPath, sizeof(logConf.szLogPath), szLogPath, strlen(szLogPath));
		LOG_SetConfig(m_uiLogInst, logConf);
	}

	pthread_mutex_init(&m_mutex4LogQue, NULL);
	pthread_mutex_init(&m_mutex4SrvMsgDataQue, NULL);
	pthread_mutex_init(&m_mutex4LinkDataList, NULL);
	pthread_mutex_init(&m_mutex4UserList, NULL);
	pthread_mutex_init(&m_mutex4DevList, NULL);
	pthread_mutex_init(&m_mutex4FenceList, NULL);
	pthread_mutex_init(&m_mutex4ProxyConnect, NULL);
	pthread_mutex_init(&m_mutex4ProxyDevMsgQue, NULL);
	pthread_mutex_init(&m_mutex4DeviceSubscribers, NULL);
	pthread_mutex_init(&m_mutex4LinkList, NULL);
	pthread_mutex_init(&m_mutex4DevCtrlPair, NULL);
	pthread_mutex_init(&m_mutex4FenceId, NULL);

	pthread_cond_init(&m_cond4LogQue, NULL);
	pthread_cond_init(&m_cond4SrvMsgDataQue, NULL);
	pthread_cond_init(&m_cond4ProxyDevMsgQue, NULL);

	pthread_create(&m_pthdDealLog, NULL, startDealLogThread, this);
	m_linkDataList.clear();

	m_pDb = NULL;
	sprintf_s(m_szDbFile, sizeof(m_szDbFile), "%sescort.db", pDllDir_);
	if (!isFileExists(m_szDbFile)) {
		sqlite3_open(m_szDbFile, &m_pDb);
	}
	else {
		initDB(m_szDbFile);
	}
	loadUserList();
	loadDeviceList();
	loadFenceList();
}

ProtocolBroker::~ProtocolBroker()
{
	m_bInit = false;
	if (m_bRun) {
		StopBroker();
	}
	if (m_pDb) {
		sqlite3_close(m_pDb);
		m_pDb = NULL;
	}

	if (m_uiLogInst > 0) {
		LOG_Release(m_uiLogInst);
		m_uiLogInst = 0;
	}
	if (m_pthdDealLog.p) {
		pthread_cond_broadcast(&m_cond4LogQue);
		pthread_join(m_pthdDealLog, NULL);
		m_pthdDealLog.p = NULL;
	}
	pthread_mutex_destroy(&m_mutex4LogQue);
	pthread_mutex_destroy(&m_mutex4SrvMsgDataQue);
	pthread_mutex_destroy(&m_mutex4LinkDataList);
	pthread_mutex_destroy(&m_mutex4UserList);
	pthread_mutex_destroy(&m_mutex4DevList);
	pthread_mutex_destroy(&m_mutex4FenceList);
	pthread_mutex_destroy(&m_mutex4ProxyConnect);
	pthread_mutex_destroy(&m_mutex4ProxyDevMsgQue);
	pthread_mutex_destroy(&m_mutex4LinkList);
	pthread_mutex_destroy(&m_mutex4DeviceSubscribers);
	pthread_mutex_destroy(&m_mutex4DevCtrlPair);
	pthread_mutex_destroy(&m_mutex4FenceId);

	pthread_cond_destroy(&m_cond4LogQue);
	pthread_cond_destroy(&m_cond4SrvMsgDataQue);
	pthread_cond_destroy(&m_cond4ProxyDevMsgQue);
}

int ProtocolBroker::StartBroker(const char * pMsgHost_, unsigned short usMsgPort_, 
	unsigned short usCtrlPort_, unsigned short usBrokerPort_)
{
	char szLog[256] = { 0 };
	if (m_bRun) {
		sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]broker is running, port=%hu, %hu, %hu\r\n", 
			__FUNCTION__, __LINE__, usMsgPort_, usCtrlPort_, usMsgPort_);
		writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		return device_protocol::ERROR_BROKER_IS_RUNNING;
	}
	int result = device_protocol::ERROR_NO;
	do {
		int nVal = EDS_Start(pMsgHost_, usMsgPort_, usCtrlPort_, sdkMsgCb, this);
		if (nVal > 0) {
			unsigned int uiVal = TS_StartServer((unsigned int)usBrokerPort_, m_usLogType, srvMsgCb, 
				this, 60);
			if (uiVal > 0) {
				m_bRun = true;
				pthread_create(&m_pthdDealSrvMsgData, NULL, startDealMsgThread, this);
				pthread_create(&m_pthdDealProxyDevMsg, NULL, startDealProxyDevMsgThread, this);
				m_uiSrvInst = uiVal;
				m_usBrokerPort = usBrokerPort_;
				m_nSdkInst = nVal;
				sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]connect device proxy=%s:%hu|%hu, "
					"start broker at %hu\r\n", __FUNCTION__, __LINE__, pMsgHost_, usMsgPort_, usCtrlPort_, 
					usBrokerPort_);
				writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
			}
			else {
				result = device_protocol::ERROR_BROKER_PORT_IS_USED;
				EDS_Stop(nVal);
				sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]broker port=%hu is used\r\n", 
					__FUNCTION__, __LINE__, usBrokerPort_);
				writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
			}
		}
		else {
			result = device_protocol::ERROR_BROKER_CONNECT_PROXY_FAILED;
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]connect proxy=%s:%hu|%hu failed\r\n", __FUNCTION__,
				__LINE__, pMsgHost_, usMsgPort_, usCtrlPort_);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
	} while (0);
	return result;
}

int ProtocolBroker::StopBroker()
{
	if (!m_bRun) {
		return device_protocol::ERROR_NO;
	}
	if (m_pthdDealSrvMsgData.p) {
		pthread_cond_broadcast(&m_cond4SrvMsgDataQue);
		pthread_join(m_pthdDealSrvMsgData, NULL);
		m_pthdDealSrvMsgData.p = NULL;
	}
	if (m_pthdDealProxyDevMsg.p) {
		pthread_cond_broadcast(&m_cond4ProxyDevMsgQue);
		pthread_join(m_pthdDealProxyDevMsg, NULL);
		m_pthdDealProxyDevMsg.p = NULL;
	}

}

bool ProtocolBroker::addLog(broker::LogContext * pLogCtx_)
{
	bool result = false;
	if (pLogCtx_ && pLogCtx_->pLogContent && pLogCtx_->uiContentLength) {
		pthread_mutex_lock(&m_mutex4LogQue);
		m_logQue.push(pLogCtx_);
		if (m_logQue.size() == 1) {
			pthread_cond_signal(&m_cond4LogQue);
		}
		pthread_mutex_unlock(&m_mutex4LogQue);
		result = true;
	}
	return result;
}

void ProtocolBroker::writeLog(const char * pLogContent_, unsigned short usLogCategory_, 
	unsigned short usLogType_)
{
	if (pLogContent_ && strlen(pLogContent_)) {
		if (m_uiLogInst > 0) {
			broker::LogContext * pLog = new broker::LogContext();
			size_t nLen = strlen(pLogContent_);
			pLog->uiContentLength = nLen;
			pLog->pLogContent = new char[nLen + 1];
			memcpy_s(pLog->pLogContent, nLen + 1, pLogContent_, nLen);
			pLog->pLogContent[nLen] = '\0';
			pLog->usLogCategory = usLogCategory_;
			pLog->usLogType = usLogType_;
			if (!addLog(pLog)) {
				if (pLog->pLogContent) {
					delete[] pLog->pLogContent;
					pLog->pLogContent = NULL;
				}
				delete pLog;
				pLog = NULL;
			}
		}
	}
}

void ProtocolBroker::handleLog()
{
	do {
		pthread_mutex_lock(&m_mutex4LogQue);
		while (m_bInit && m_logQue.empty()) {
			pthread_cond_wait(&m_cond4LogQue, &m_mutex4LogQue);
		}
		if (!m_bInit && m_logQue.empty()) {
			pthread_mutex_unlock(&m_mutex4LogQue);
			break;
		}
		broker::LogContext * pLog = m_logQue.front();
		m_logQue.pop();
		pthread_mutex_unlock(&m_mutex4LogQue);
		if (pLog) {
			if (pLog->pLogContent && pLog->uiContentLength) {
				if (m_uiLogInst > 0) {
					LOG_Log(m_uiLogInst, pLog->pLogContent, pLog->usLogCategory, pLog->usLogType);
				}
				delete[] pLog->pLogContent;
				pLog->pLogContent = NULL;
			}
			delete pLog;
			pLog = NULL;
		}
	} while (1);
}

bool ProtocolBroker::addMsg(MessageContent * pMsg_)
{
	bool result = false;
	if (pMsg_ && pMsg_->pMsgData && pMsg_->ulMsgDataLen) {
		pthread_mutex_lock(&m_mutex4SrvMsgDataQue);
		m_srvMsgDataQue.push(pMsg_);
		if (m_srvMsgDataQue.size() == 1) {
			pthread_cond_signal(&m_cond4SrvMsgDataQue);
		}
		pthread_mutex_unlock(&m_mutex4SrvMsgDataQue);
		result = true;
	}
	return result;
}

void ProtocolBroker::handleMsg()
{
	do {
		pthread_mutex_lock(&m_mutex4SrvMsgDataQue);
		while (m_bRun && m_srvMsgDataQue.empty()) {
			pthread_cond_wait(&m_cond4SrvMsgDataQue, &m_mutex4SrvMsgDataQue);
		}
		if (!m_bRun && m_srvMsgDataQue.empty()) {
			pthread_mutex_unlock(&m_mutex4SrvMsgDataQue);
			break;
		}
		MessageContent * pMsg = m_srvMsgDataQue.front();
		m_srvMsgDataQue.pop();
		pthread_mutex_unlock(&m_mutex4SrvMsgDataQue);
		if (pMsg) {
			parseMsg(pMsg);
			delete pMsg;
			pMsg = NULL;
		}
	} while (1);
}

void ProtocolBroker::parseMsg(const MessageContent * pMsg_)
{
	if (pMsg_) {
		char szLog[1024] = { 0 };
		if (pMsg_->pMsgData && pMsg_->ulMsgDataLen > 0) {
			std::string strEndpoint = pMsg_->szEndPoint;
			unsigned char * pBuf = NULL;
			unsigned int uiBufLen = 0;
			std::string strEndpoint = pMsg_->szEndPoint;
			pthread_mutex_lock(&m_mutex4LinkDataList);
			LinkDataList::iterator iter = m_linkDataList.find(strEndpoint);
			if (iter != m_linkDataList.end()) {
				broker::LinkData * pLinkData = iter->second;
				if (pLinkData) {
					if (pLinkData->uiLackDataLen == 0) {
						pBuf = new unsigned char[pMsg_->ulMsgDataLen + 1];
						uiBufLen = (unsigned int)pMsg_->ulMsgDataLen;
						memcpy_s(pBuf, uiBufLen, pMsg_->pMsgData, uiBufLen);
						pBuf[uiBufLen] = '\0';
					}
					else {
						if (pLinkData->uiLackDataLen <= (unsigned int)pMsg_->ulMsgDataLen) { //full
							uiBufLen = pLinkData->uiLingeDataLen + (unsigned int)pMsg_->ulMsgDataLen;
							pBuf = new unsigned char[uiBufLen + 1];
							memcpy_s(pBuf, uiBufLen, pLinkData->pLingeData, pLinkData->uiLingeDataLen);
							memcpy_s(pBuf + pLinkData->uiLingeDataLen, uiBufLen - pLinkData->uiLingeDataLen, 
								pMsg_->pMsgData, pMsg_->ulMsgDataLen);
							pBuf[uiBufLen] = '\0';
							delete [] pLinkData->pLingeData;
							pLinkData->pLingeData = NULL;
							pLinkData->uiLackDataLen = 0;
							pLinkData->uiTotalDataLen = 0;
							pLinkData->uiLingeDataLen = 0;
						}
						else if (pLinkData->uiLackDataLen > pMsg_->ulMsgDataLen) { //still lack
							memcpy_s(pLinkData->pLingeData + pLinkData->uiLingeDataLen, pLinkData->uiLackDataLen, 
								pMsg_->pMsgData, pMsg_->ulMsgDataLen);
							pLinkData->uiLingeDataLen += (unsigned int)pMsg_->ulMsgDataLen;
							pLinkData->uiLackDataLen -= (unsigned int)pMsg_->ulMsgDataLen;
						}
					}
				}
			}
			else {
				//not find strEndpoint
				sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]link=%s not find in the LinkDataList\r\n",
					__FUNCTION__, __LINE__, strEndpoint.c_str());
				writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
			}
			pthread_mutex_unlock(&m_mutex4LinkDataList);
			if (pBuf && uiBufLen) {
				unsigned int uiIndex = 0;
				unsigned int uiHeadIndex = 0;
				unsigned int uiTailIndex = 0;
				device_protocol::ProtocolMessageHead protocolMsgHead;
				do {
					memset(&protocolMsgHead, 0, sizeof(device_protocol::ProtocolMessageHead));
					int n = getWholeMsg(pBuf, uiBufLen, uiIndex, uiHeadIndex, uiTailIndex, &protocolMsgHead);
					if (n == 0) {
						break;
					}
					else if (n == 1) {
						pthread_mutex_lock(&m_mutex4LinkDataList);
						iter = m_linkDataList.find(strEndpoint);
						if (iter != m_linkDataList.end()) {
							broker::LinkData * pLinkData = iter->second;
							if (pLinkData) {
								pLinkData->uiTotalDataLen = protocolMsgHead.payload_length;
								pLinkData->uiLingeDataLen = uiBufLen - uiHeadIndex;
								pLinkData->uiLackDataLen = pLinkData->uiTotalDataLen - pLinkData->uiLingeDataLen;
								pLinkData->pLingeData = new unsigned char[pLinkData->uiTotalDataLen];
								memcpy_s(pLinkData->pLingeData, pLinkData->uiTotalDataLen, pBuf + uiHeadIndex, 
									pLinkData->uiLingeDataLen);
							}
						}
						pthread_mutex_unlock(&m_mutex4LinkDataList);
						break;
					}
					else if (n == 2) {
						uiIndex = uiTailIndex;
						if (protocolMsgHead.protocol_type == device_protocol::PROTOCOL_PRIVATE) {
							switch (protocolMsgHead.security_policy) {
								case device_protocol::POLICY_SIMPLE_PRIVATE: {
									descryptMessageViaPrivateSimple(pBuf, uiHeadIndex, uiTailIndex, 
										(short)protocolMsgHead.security_extra);
									break;
								}
								case device_protocol::POLICY_EMPTY: {
									break;
								}
								case device_protocol::POLICY_RSA: {
									break;
								}
							}
							char * pContent = new char[protocolMsgHead.payload_length + 1];
							memcpy_s(pContent, protocolMsgHead.payload_length + 1, pBuf + uiHeadIndex, 
								protocolMsgHead.payload_length);
							pContent[protocolMsgHead.payload_length] = '\0';
							std::string ansiStr = utf8_to_ansi(pContent);
							sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]receive form %s, data=%s\r\n", 
								__FUNCTION__, __LINE__, strEndpoint.c_str(), ansiStr.c_str());
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
							rapidjson::Document doc;
							if (!doc.Parse(ansiStr.c_str()).HasParseError()) {
								device_protocol::eCommandType cmdType;
								if (doc.HasMember("cmd")) {
									if (doc["cmd"].IsInt()) {
										cmdType = (device_protocol::eCommandType)doc["cmd"].GetInt();
									}
								}
								switch (cmdType) {
									case device_protocol::CMD_CONNECTION_INITIALIZE_REQUEST: {
										//accout, passwd, seq, datetime, session
										device_protocol::LinkInitializeRequest initRequest;
										memset(&initRequest, 0, sizeof(initRequest));
										char szDatetime[20] = { 0 };
										if (doc.HasMember("account")) {
											if (doc["account"].IsString()) {
												size_t nSize = doc["account"].GetStringLength();
												if (nSize) {
													strcpy_s(initRequest.szAccount, sizeof(initRequest.szAccount), doc["account"].GetString());
												}
											}
										}
										if (doc.HasMember("passwd")) {
											if (doc["passwd"].IsString()) {
												size_t nSize = doc["passwd"].GetStringLength();
												if (nSize) {
													strcpy_s(initRequest.szPasswd, sizeof(initRequest.szPasswd), doc["passwd"].GetString());
												}
											}
										}
										if (doc.HasMember("seq")) {
											if (doc["seq"].IsInt()) {
												initRequest.uiReqSeq = (unsigned int)doc["seq"].GetInt();
											}
										}
										if (doc.HasMember("datetime")) {
											if (doc["datetime"].IsString()) {
												size_t nSize = doc["datetime"].GetStringLength();
												if (nSize) {
													strcpy_s(szDatetime, sizeof(szDatetime), doc["datetime"].GetString());
													initRequest.ulReqTime = make_datetime(szDatetime);
												}
											}
										}
										if (doc.HasMember("session")) {
											if (doc["session"].IsString()) {
												size_t nSize = doc["session"].GetStringLength();
												if (nSize) {
													strcpy_s(initRequest.szSession, sizeof(initRequest.szSession), doc["session"].GetString());
												}
											}
										}
										if (strlen(initRequest.szAccount) && strlen(initRequest.szPasswd) 
											&& strlen(szDatetime)) {
											handleLinkInitialize(&initRequest, pMsg_->szEndPoint, 
												protocolMsgHead.protocol_type, protocolMsgHead.security_policy);
										}
										else {
											sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]initialize request from %s"
												" miss parameter account=%s, passwd=%s, session=%s, reqDatetime=%s, reqSeq=%u, "
												"securityPolicy=%d, key=%hu\r\n", __FUNCTION__, __LINE__, pMsg_->szEndPoint, 
												initRequest.szAccount, initRequest.szPasswd, initRequest.szSession, szDatetime, 
												initRequest.uiReqSeq, protocolMsgHead.security_policy, 
												protocolMsgHead.security_extra);
											writeLog(szLog, pf_logger::eLOGCATEGORY_FAULT, m_usLogType);
										}
										break;
									}
									case device_protocol::CMD_CONNECTION_KEEP_ALIVE_REQUEST: {
										//session,seq,datetime
										device_protocol::LinkHeartBeatRequest hbRequest;
										memset(&hbRequest, 0, sizeof(hbRequest));
										char szDatetime[20] = { 0 };
										if (doc.HasMember("session")) {
											if (doc["session"].IsString()) {
												size_t nSize = doc["session"].GetStringLength();
												if (nSize) {
													strcpy_s(hbRequest.szSession, sizeof(hbRequest.szSession), doc["session"].GetString());
												}
											}
										}
										if (doc.HasMember("seq")) {
											if (doc["seq"].IsInt()) {
												hbRequest.uiHeartBeatSeq = (unsigned int)doc["seq"].GetInt();
											}
										}
										if (doc.HasMember("datetime")) {
											if (doc["datetime"].IsString()) {
												size_t nSize = doc["datetime"].GetStringLength();
												if (nSize) {
													strcpy_s(szDatetime, sizeof(szDatetime), doc["datetime"].GetString());
													hbRequest.ulHeartBeatTime = make_datetime(szDatetime);
												}
											}
										}
										if (strlen(hbRequest.szSession) && strlen(szDatetime)) {
											handleLinkKeepAlive(&hbRequest, pMsg_->szEndPoint, protocolMsgHead.protocol_type,
												protocolMsgHead.security_policy);
										}
										else {
											sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]keep alive request from %s"
												" miss parameter, session=%s, reqDatatime=%s, reqSeq=%u, securityPolicy=%d, "
												"key=%hu\r\n", __FUNCTION__, __LINE__, pMsg_->szEndPoint, hbRequest.szSession,
												szDatetime, protocolMsgHead.security_policy, protocolMsgHead.security_extra);
											writeLog(szLog, pf_logger::eLOGCATEGORY_FAULT, m_usLogType);
										}
										break;
									}
									case device_protocol::CMD_CONNECTION_SET_PARAMETER_REQUEST: {
										//session,parameterKey,parameterValue,seq,datetime
										device_protocol::LinkSetParameterRequest setParamRequest;
										memset(&setParamRequest, 0, sizeof(setParamRequest));
										char szDatetime[20] = { 0 };
										if (doc.HasMember("session")) {
											if (doc["session"].IsString()) {
												size_t nSize = doc["session"].GetStringLength();
												if (nSize) {
													strcpy_s(setParamRequest.szSession, sizeof(setParamRequest.szSession), doc["session"].GetString());
												}
											}
										}
										if (doc.HasMember("parameterKey")) {
											if (doc["parameterKey"].IsInt()) {
												setParamRequest.nParameterKey = doc["parameterKey"].GetInt();
											}
										}
										if (doc.HasMember("parameterValue")) {
											if (doc["parameterValue"].IsString()) {
												size_t nSize = doc["parameterValue"].GetStringLength();
												if (nSize) {
													strcpy_s(setParamRequest.szParameterValue, sizeof(setParamRequest.szParameterValue),
														doc["parameterValue"].GetString());
												}
											}
										}
										if (doc.HasMember("seq")) {
											if (doc["seq"].IsInt()) {
												setParamRequest.uiReqSeq = (unsigned int)doc["seq"].GetInt();
											}
										}
										if (doc.HasMember("datetime")) {
											if (doc["datetime"].IsString()) {
												size_t nSize = doc["datetime"].GetStringLength();
												if (nSize) {
													strcpy_s(szDatetime, sizeof(szDatetime), doc["datetime"].GetString());
													setParamRequest.ulReqTime = make_datetime(szDatetime);
												}
											}
										}
										if (strlen(setParamRequest.szSession) && strlen(szDatetime)) {
											handleLinkSetParameter(&setParamRequest, pMsg_->szEndPoint, 
												protocolMsgHead.protocol_type, protocolMsgHead.security_policy);
										}
										else {
											sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]set parameter from %s "
												"miss parameter, session=%s, parameterKey=%d, parameterValue=%s, seq=%u, "
												"datetime=%s, securityPolicy=%d, securityKey=%hu\r\n", __FUNCTION__, __LINE__,
												pMsg_->szEndPoint, setParamRequest.szSession, setParamRequest.nParameterKey,
												setParamRequest.szParameterValue, setParamRequest.uiReqSeq, szDatetime, 
												protocolMsgHead.security_policy, protocolMsgHead.security_extra);
											writeLog(szLog, pf_logger::eLOGCATEGORY_FAULT, m_usLogType);
										}
										break;
									}
									case device_protocol::CMD_CONNECTION_GET_PARAMETER_REQUEST: {
										//session,parameterKey,seq,datetime
										device_protocol::LinkGetParameterRequest getParamRequest;
										memset(&getParamRequest, 0, sizeof(getParamRequest));
										char szDatetime[20] = { 0 };
										if (doc.HasMember("session")) {
											if (doc["session"].IsString()) {
												size_t nSize = doc["session"].GetStringLength();
												if (nSize) {
													strcpy_s(getParamRequest.szSession, sizeof(getParamRequest.szSession), 
														doc["session"].GetString());
												}
											}
										}
										if (doc.HasMember("parameterKey")) {
											if (doc["parameterKey"].IsInt()) {
												getParamRequest.nParameterKey = doc["parameterKey"].GetInt();
											}
										}
										if (doc.HasMember("seq")) {
											if (doc["seq"].IsInt()) {
												getParamRequest.uiReqSeq = (unsigned int)doc["seq"].GetInt();
											}
										}
										if (doc.HasMember("datetime")) {
											if (doc["datetime"].IsString()) {
												size_t nSize = doc["datetime"].GetStringLength();
												if (nSize) {
													strcpy_s(szDatetime, sizeof(szDatetime), doc["datetime"].GetString());
													getParamRequest.ulReqTime = make_datetime(szDatetime);
												}
											}
										}
										if (strlen(getParamRequest.szSession) && strlen(szDatetime)) {
											handleLinkGetParameter(&getParamRequest, pMsg_->szEndPoint, 
												protocolMsgHead.protocol_type, protocolMsgHead.security_policy);
										}
										else {
											sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]get parameter from %s"
												" miss parameter, session=%s, reqSeq=%u, reqTime=%s, parameterKey=%d, "
												"securityPolicy=%d, securityKey=%hu\r\n", __FUNCTION__, __LINE__, 
												pMsg_->szEndPoint, getParamRequest.szSession, getParamRequest.uiReqSeq, 
												szDatetime, getParamRequest.nParameterKey, protocolMsgHead.security_policy,
												protocolMsgHead.security_extra);
											writeLog(szLog, pf_logger::eLOGCATEGORY_FAULT, m_usLogType);
										}
										break;
									}
									case device_protocol::CMD_CONNECTION_DEVICE_CONTROL_REQUEST: {
										//session,deviceId,subType,parameter,seq,datetime
										device_protocol::LinkDeviceControlRequest devCtrlRequest;
										memset(&devCtrlRequest, 0, sizeof(devCtrlRequest));
										char szDatetime[20] = { 0 };
										if (doc.HasMember("session")) {
											if (doc["session"].IsString()) {
												size_t nSize = doc["session"].GetStringLength();
												if (nSize) {
													strcpy_s(devCtrlRequest.szSession, sizeof(devCtrlRequest.szSession),
														doc["session"].GetString());
												}
											}
										}
										if (doc.HasMember("deviceId")) {
											if (doc["deviceId"].IsString()) {
												size_t nSize = doc["deviceId"].GetStringLength();
												if (nSize) {
													strcpy_s(devCtrlRequest.szDeviceId, sizeof(devCtrlRequest.szDeviceId),
														doc["deviceId"].GetString());
												}
											}
										}
										if (doc.HasMember("subType")) {
											if (doc["subType"].IsString()) {
												devCtrlRequest.nSubType = doc["subType"].GetInt();
											}
										}
										if (doc.HasMember("parameter")) {
											if (doc["parameter"].IsInt()) {
												devCtrlRequest.nParameter = doc["parameter"].GetInt();
											}
										}
										if (doc.HasMember("seq")) {
											if (doc["seq"].IsInt()) {
												devCtrlRequest.uiReqSeq = (unsigned int)doc["seq"].GetInt();
											}
										}
										if (doc.HasMember("datetime")) {
											if (doc["datetime"].IsString()) {
												size_t nSize = doc["datetime"].GetStringLength();
												if (nSize) {
													strcpy_s(szDatetime, sizeof(szDatetime), doc["datetime"].GetString());
													devCtrlRequest.ulReqDatetime = make_datetime(szDatetime);
												}
											}
										}
										if (strlen(szDatetime) && strlen(devCtrlRequest.szSession) 
											&& strlen(devCtrlRequest.szDeviceId)) {
											handleLinkControlDevice(&devCtrlRequest, pMsg_->szEndPoint, 
												protocolMsgHead.protocol_type, protocolMsgHead.security_policy);
										}
										else {
											sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]device control from %s"
												" miss parameter, session=%s, deviceId=%s, reqSeq=%u, reqDatetime=%s, "
												"subType=%d, parameter=%d, securityPolicy=%d, securityKey=%hu\r\n", 
												__FUNCTION__, __LINE__, pMsg_->szEndPoint, devCtrlRequest.szSession, 
												devCtrlRequest.szDeviceId, devCtrlRequest.uiReqSeq, szDatetime, 
												devCtrlRequest.nSubType, devCtrlRequest.nParameter, 
												protocolMsgHead.security_policy, protocolMsgHead.security_extra);
											writeLog(szLog, pf_logger::eLOGCATEGORY_FAULT, m_usLogType);
										}
										break;
									}
									case device_protocol::CMD_CONNECTION_DEVICE_SET_FENCE_REQUEST: {
										//session,deviceId,seq,datetime,fenceId,fenceType,coordinate,fenceContent,
										//startTime,stopTime
										device_protocol::LinkSetFenceRequest setFenceRequest;
										memset(&setFenceRequest, 0, sizeof(setFenceRequest));
										char szDatetime[20] = { 0 };
										char szFenceStartTime[20] = { 0 };
										char szFenceStopTime[20] = { 0 };
										if (doc.HasMember("session")) {
											if (doc["session"].IsString()) {
												size_t nSize = doc["session"].GetStringLength();
												if (nSize) {
													strcpy_s(setFenceRequest.szSession, sizeof(setFenceRequest.szSession),
														doc["session"].GetString());
												}
											}
										}
										if (doc.HasMember("deviceId")) {
											if (doc["deviceId"].IsString()) {
												size_t nSize = doc["deviceId"].GetStringLength();
												if (nSize) {
													strcpy_s(setFenceRequest.szDeviceId, sizeof(setFenceRequest.szDeviceId),
														doc["deviceId"].GetString());
												}
											}
										}
										if (doc.HasMember("seq")) {
											if (doc["seq"].IsInt()) {
												setFenceRequest.uiReqSeq = (unsigned int)doc["seq"].GetInt();
											}
										}
										if (doc.HasMember("datetime")) {
											if (doc["datetime"].IsString()) {
												size_t nSize = doc["datetime"].GetStringLength();
												if (nSize) {
													strcpy_s(szDatetime, sizeof(szDatetime), doc["datetime"].GetString());
													setFenceRequest.ulReqTime = make_datetime(szDatetime);
												}
											}
										}
										/*if (doc.HasMember("fenceId")) {
											if (doc["fenceId"].IsString()) {
												size_t nSize = doc["fenceId"].GetStringLength();
												if (nSize) {
													strcpy_s(setFenceRequest.fenceInfo.szFenceId, 
														sizeof(setFenceRequest.fenceInfo.szFenceId),
														doc["fenceId"].GetString());
												}
											}
										}*/
										if (doc.HasMember("fenceType")) {
											if (doc["fenceType"].IsInt()) {
												setFenceRequest.fenceInfo.nFenceType = doc["fenceType"].GetInt();
											}
										}
										if (doc.HasMember("coordinate")) {
											if (doc["coordinate"].IsInt()) {
												setFenceRequest.fenceInfo.nCoordinate = doc["coordinate"].GetInt();
											}
										}
										if (doc.HasMember("policy")) {
											if (doc["policy"].IsInt()) {
												setFenceRequest.fenceInfo.nPolicy = doc["policy"].GetInt();
											}
										}
										if (doc.HasMember("fenceContent")) {
											if (doc["fenceContent"].IsString()) {
												size_t nSize = doc["fenceContent"].GetStringLength();
												if (nSize) {
													strcpy_s(setFenceRequest.fenceInfo.szFenceContent,
														sizeof(setFenceRequest.fenceInfo.szFenceContent),
														doc["fenceContent"].GetString());
												}
											}
										}
										if (doc.HasMember("startTime")) {
											if (doc["startTime"].IsString()) {
												size_t nSize = doc["startTime"].GetStringLength();
												if (nSize) {
													strcpy_s(szFenceStartTime, sizeof(szFenceStartTime),
														doc["startTime"].GetString());
													setFenceRequest.fenceInfo.ulStartTime = make_datetime(szFenceStartTime);
												}
											}
										}
										if (doc.HasMember("stopTime")) {
											if (doc["stopTime"].IsString()) {
												size_t nSize = doc["stopTime"].GetStringLength();
												if (nSize) {
													strcpy_s(szFenceStopTime, sizeof(szFenceStopTime),
														doc["stopTime"].GetString());
													setFenceRequest.fenceInfo.ulStopTime = make_datetime(szFenceStopTime);
												}
											}
										}
										if (strlen(setFenceRequest.szSession) && strlen(setFenceRequest.szDeviceId)
											&& strlen(setFenceRequest.fenceInfo.szFenceContent) && strlen(szDatetime)
											&& strlen(szFenceStartTime) && strlen(szFenceStopTime)) {
											handleLinkSetDeviceFence(&setFenceRequest, pMsg_->szEndPoint,
												protocolMsgHead.protocol_type, protocolMsgHead.security_policy);
										}
										else {
											sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]set fence from %s, session=%s"
												" deviceId=%s, fenceType=%d, coordinate=%d, fenceContent=%s, fencePolicy=%d, "
												"startTime=%s, stopTime=%s, reqSeq=%u, reqDatetime=%s, securityPolicy=%d, "
												"securityKey=%hu\r\n", __FUNCTION__, __LINE__, pMsg_->szEndPoint, 
												setFenceRequest.szSession, setFenceRequest.szDeviceId, 
												setFenceRequest.fenceInfo.nFenceType, setFenceRequest.fenceInfo.nCoordinate,
												setFenceRequest.fenceInfo.szFenceContent, setFenceRequest.fenceInfo.nPolicy,
												szFenceStartTime, szFenceStopTime, setFenceRequest.uiReqSeq, szDatetime, 
												protocolMsgHead.security_policy, protocolMsgHead.security_extra);
											writeLog(szLog, pf_logger::eLOGCATEGORY_FAULT, m_usLogType);
										}
										break;
									}
									case device_protocol::CMD_CONNECTION_DEVICE_GET_FENCE_REQUEST: {
										//session,deviceId,req,datetime
										device_protocol::LinkGetFenceRequest getFenceRequest;
										memset(&getFenceRequest, 0, sizeof(getFenceRequest));
										char szDatetime[20] = { 0 };
										if (doc.HasMember("session")) {
											if (doc["session"].IsString()) {
												size_t nSize = doc["session"].GetStringLength();
												if (nSize) {
													strcpy_s(getFenceRequest.szSession, sizeof(getFenceRequest.szSession),
														doc["session"].GetString());
												}
											}
										}
										if (doc.HasMember("deviceId")) {
											if (doc["deviceId"].IsString()) {
												size_t nSize = doc["deviceId"].GetStringLength();
												if (nSize) {
													strcpy_s(getFenceRequest.szDeviceId, sizeof(getFenceRequest.szDeviceId),
														doc["deviceId"].GetString());
												}
											}
										}
										if (doc.HasMember("seq")) {
											if (doc["seq"].IsString()) {
												getFenceRequest.uiReqSeq = (unsigned int)doc["seq"].GetInt();
											}
										}
										if (doc.HasMember("datetime")) {
											if (doc["datetime"].IsString()) {
												size_t nSize = doc["datetime"].GetStringLength();
												if (nSize) {
													strcpy_s(szDatetime, sizeof(szDatetime), doc["datetime"].GetString());
													getFenceRequest.ulReqTime = make_datetime(szDatetime);
												}
											}
										}
										if (strlen(getFenceRequest.szSession) && strlen(getFenceRequest.szSession)
											&& strlen(szDatetime)) {
											handleLinkGetDeviceFence(&getFenceRequest, pMsg_->szEndPoint,
												protocolMsgHead.protocol_type, protocolMsgHead.security_policy);
										}
										else {
											sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]get fence from %s "
												"miss parameter, session=%s, deviceId=%s, reqSeq=%u, reqDatetime=%s, "
												"securitypolicy=%d, securityKey=%hu\r\n", __FUNCTION__, __LINE__, 
												pMsg_->szEndPoint, getFenceRequest.szSession, getFenceRequest.szDeviceId,
												getFenceRequest.uiReqSeq, szDatetime, protocolMsgHead.security_policy,
												protocolMsgHead.security_extra);
											writeLog(szLog, pf_logger::eLOGCATEGORY_FAULT, m_usLogType);
										}
										break;
									}
									case device_protocol::CMD_CONNECTION_DEVICE_REMOVE_FENCE_REQUEST: {
										device_protocol::LinkRemoveFenceRequest removeFenceRequest;
										memset(&removeFenceRequest, 0, sizeof(removeFenceRequest));
										char szDatetime[20] = { 0 };
										if (doc.HasMember("session")) {
											if (doc["session"].IsString()) {
												size_t nSize = doc["session"].GetStringLength();
												if (nSize) {
													strcpy_s(removeFenceRequest.szSession, sizeof(removeFenceRequest.szSession),
														doc["session"].GetString());
												}
											}
										}
										if (doc.HasMember("deviceId")) {
											if (doc["deviceId"].IsString()) {
												size_t nSize = doc["deviceId"].GetStringLength();
												if (nSize) {
													strcpy_s(removeFenceRequest.szDeviceId, sizeof(removeFenceRequest.szDeviceId),
														doc["deviceId"].GetString());
												}
											}
										}
										if (doc.HasMember("fenceId")) {
											if (doc["fenceId"].IsString()) {
												size_t nSize = doc["fenceId"].GetStringLength();
												if (nSize) {
													strcpy_s(removeFenceRequest.szFenceId, sizeof(removeFenceRequest.szFenceId),
														doc["fenceId"].GetString());
												}
											}
										}
										if (doc.HasMember("seq")) {
											if (doc["seq"].IsInt()) {
												removeFenceRequest.uiReqSeq = (unsigned int)doc["seq"].GetInt();
											}
										}
										if (doc.HasMember("datetime")) {
											if (doc["datetime"].IsString()) {
												size_t nSize = doc["datetime"].GetStringLength();
												if (nSize) {
													strcpy_s(szDatetime, sizeof(szDatetime), doc["datetime"].GetString());
													removeFenceRequest.ulReqTime = make_datetime(szDatetime);
												}
											}
										}
										if (strlen(removeFenceRequest.szDeviceId) && strlen(removeFenceRequest.szFenceId)
											&& strlen(removeFenceRequest.szSession) && strlen(szDatetime)) {
											handleLinkRemoveDeviceFence(&removeFenceRequest, pMsg_->szEndPoint,
												protocolMsgHead.protocol_type, protocolMsgHead.security_policy);
										}
										else {
											sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]remove fence from %s data "
												"miss parameter, session=%s, deviceId=%s, fenceId=%s, reqSeq=%u, reqTime=%s, "
												"protocolType=%d, securityPolicy=%d, securityExtra=%d\r\n", __FUNCTION__, __LINE__,
												pMsg_->szEndPoint, removeFenceRequest.szSession, removeFenceRequest.szDeviceId,
												removeFenceRequest.szFenceId, removeFenceRequest.uiReqSeq, szDatetime,
												protocolMsgHead.protocol_type, protocolMsgHead.security_policy, 
												protocolMsgHead.security_extra);
											writeLog(szLog, pf_logger::eLOGCATEGORY_FAULT, m_usLogType);
										}
										break;
									}
									case device_protocol::CMD_CONNECTION_SUBSCRIBE_DEVICE_REQUEST: {
										//session,deviceId,act,seq,datetime
										device_protocol::LinkSubscribeDeviceRequest subDevRequest;
										sizeof(&subDevRequest, 0, sizeof(subDevRequest));
										char szDatetime[20] = { 0 };
										if (doc.HasMember("session")) {
											if (doc["session"].IsString()) {
												size_t nSize = doc["session"].GetStringLength();
												if (nSize) {
													strcpy_s(subDevRequest.szSession, sizeof(subDevRequest.szSession),
														doc["session"].GetString());
												}
											}
										}
										if (doc.HasMember("deviceId")) {
											if (doc["deviceId"].IsString()) {
												size_t nSize = doc["deviceId"].GetStringLength();
												if (nSize) {
													strcpy_s(subDevRequest.szDeviceId, sizeof(subDevRequest.szDeviceId),
														doc["deviceId"].GetString());
												}
											}
										}
										if (doc.HasMember("act")) {
											if (doc["act"].IsInt()) {
												subDevRequest.nAct = doc["act"].GetInt();
											}
										}
										if (doc.HasMember("seq")) {
											if (doc["seq"].IsInt()) {
												subDevRequest.uiReqSeq = (unsigned int)doc["seq"].GetInt();
											}
										}
										if (doc.HasMember("datetime")) {
											if (doc["datetime"].IsString()) {
												size_t nSize = doc["datetime"].GetStringLength();
												if (nSize) {
													strcpy_s(szDatetime, sizeof(szDatetime), doc["datetime"].GetString());
													subDevRequest.ulReqTime = make_datetime(szDatetime);
												}
											}
										}
										if (strlen(subDevRequest.szSession) && strlen(subDevRequest.szDeviceId)
											&& strlen(szDatetime)) {

										} 
										else {
											sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]subscribe device from %s"
												" miss parameter, session=%s, deviceId=%s, reqSeq=%u, reqDatetime=%s, "
												"securityPolicy=%d, securityKey=%hu\r\n", __FUNCTION__, __LINE__, 
												pMsg_->szEndPoint, subDevRequest.szSession, subDevRequest.szDeviceId,
												subDevRequest.uiReqSeq, szDatetime, protocolMsgHead.security_policy, 
												protocolMsgHead.security_extra);
											writeLog(szLog, pf_logger::eLOGCATEGORY_FAULT, m_usLogType);
										}
										break;
									}
									case device_protocol::CMD_CONNECTION_UNINITIALIZE_REQUEST: {
										//session,req,datetime
										device_protocol::LinkUninitializeRequest uninitRequest;
										memset(&uninitRequest, 0, sizeof(uninitRequest));
										char szDatetime[20] = { 0 };
										if (doc.HasMember("session")) {
											if (doc["session"].IsString()) {
												size_t nSize = doc["session"].GetStringLength();
												if (nSize) {
													strcpy_s(uninitRequest.szSession, sizeof(uninitRequest.szSession),
														doc["session"].GetString());
												}
											}
										}
										if (doc.HasMember("seq")) {
											if (doc["seq"].IsInt()) {
												uninitRequest.uiReqSeq = (unsigned int)doc["seq"].GetInt();
											}
										}
										if (doc.HasMember("datetime")) {
											if (doc["datetime"].IsString()) {
												size_t nSize = doc["datetime"].GetStringLength();
												if (nSize) {
													strcpy_s(szDatetime, sizeof(szDatetime), doc["datetime"].GetString());
													uninitRequest.ulReqTime = make_datetime(szDatetime);
												}
											}
										}
										if (strlen(uninitRequest.szSession) && strlen(szDatetime)) {
											handleLinkUninitialize(&uninitRequest, pMsg_->szEndPoint,
												protocolMsgHead.protocol_type, protocolMsgHead.security_policy);
										}
										else {
											sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]uninitialize from %s "
												"miss parameter, session=%s, reqSeq=%u, reqDatetime=%s, securityPolicy=%d,"
												" securityKey=%hu\r\n", __FUNCTION__, __LINE__, pMsg_->szEndPoint, 
												uninitRequest.szSession, uninitRequest.uiReqSeq, szDatetime, 
												protocolMsgHead.security_policy, protocolMsgHead.security_extra);
											writeLog(szLog, pf_logger::eLOGCATEGORY_FAULT, m_usLogType);
										}
										break;
									}
									default: {
										sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]unsupport command type=%d"
											" from %s\r\n", __FUNCTION__, __LINE__, (int)cmdType, strEndpoint.c_str());
										writeLog(szLog, pf_logger::eLOGCATEGORY_WARN, m_usLogType);
										break;
									}
								}
							}
							else {
								sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]can't parse JSON content from "
									"%s, data=%s\r\n", __FUNCTION__, __LINE__, strEndpoint.c_str(), ansiStr.c_str());
								writeLog(szLog, pf_logger::eLOGCATEGORY_FAULT, m_usLogType);
								char szReply[256] = { 0 };
								sprintf_s(szReply, sizeof(szReply), "{\"cmd\":%d,\"retcode\":%d}", 
									device_protocol::CMD_DEFAULT_REPLY, device_protocol::ERROR_PARSE_REQUEST_FAILED);
								sendDataViaEndpoint(szReply, strlen(szReply), strEndpoint.c_str(), 
									protocolMsgHead.protocol_type, protocolMsgHead.security_policy, 
									protocolMsgHead.security_extra);
							}
							delete[] pContent;
							pContent = NULL;
						}
						else if (protocolMsgHead.protocol_type == device_protocol::PROTOCOL_MQTT) {

						}
					}
				} while (1);
				delete[] pBuf;
				pBuf = NULL;
			}
		}
	}
}

int ProtocolBroker::getWholeMsg(const unsigned char * pInputData_, unsigned int uiDataLen_, 
	unsigned int uiIndex_, unsigned int & uiHeadIndex_, unsigned int & uiTailIndex_, 
	device_protocol::ProtocolMessageHead * pMsgHead_)
{
	int result = 0;
	unsigned int i = uiIndex_;
	size_t nProtocolMsgHeadSize = sizeof(device_protocol::ProtocolMessageHead);
	device_protocol::ProtocolMessageHead protocolMsgHead;
	bool bFindValidHead = false;
	do {
		if (i >= uiDataLen_) {
			break;
		}
		if (!bFindValidHead) {
			if (uiDataLen_ - i < nProtocolMsgHeadSize) {
				break;
			}
			memcpy_s(&protocolMsgHead, nProtocolMsgHeadSize, pInputData_ + i, nProtocolMsgHeadSize);
			if (protocolMsgHead.mark[0] == 'E' && protocolMsgHead.mark[1] == 'C') {
				bFindValidHead = true;
				result = 1;
				i += nProtocolMsgHeadSize;
				uiHeadIndex_ = i;
				memcpy_s(pMsgHead_, nProtocolMsgHeadSize, &protocolMsgHead, nProtocolMsgHeadSize);
			}
			else {
				i++;
			}
		}
		else {
			if (i + protocolMsgHead.payload_length <= uiDataLen_) {
				uiHeadIndex_ = i;
				uiTailIndex_ = i + protocolMsgHead.payload_length;
				result = 2;
			}
			break;
		}
	} while (1);
	return result;
}
	
void ProtocolBroker::descryptMessageViaPrivateSimple(unsigned char * pInputData_, 
	unsigned int uiStartIndex_, unsigned int uiStopIndex_, short nKey_)
{
	if (uiStopIndex_ > uiStartIndex_ && uiStartIndex_ >= 0) {
		for (unsigned int i = uiStartIndex_; i < uiStopIndex_; ++i) {
			pInputData_[i] ^= nKey_;
			pInputData_[i] -= 1;
		}
	}
}

void ProtocolBroker::encryptMessageViaPrivateSimple(unsigned char * pInputData_, 
	unsigned int uiStartIndex_, unsigned int uiStopIndex_, short nKey_)
{
	if (uiStopIndex_ > uiStartIndex_) {
		for (unsigned int i = uiStartIndex_; i < uiStopIndex_; ++i) {
			pInputData_[i] += 1;
			pInputData_[i] ^= nKey_;
		}
	}
}

int ProtocolBroker::registerEndpoint(const char * pEndpoint_)
{
	char szLog[256] = { 0 };
	if (pEndpoint_ && strlen(pEndpoint_)) {
		std::string strEndpoint = pEndpoint_;
		char szSession[20] = { 0 };
		pthread_mutex_lock(&m_mutex4LinkDataList);
		LinkDataList::iterator iter = m_linkDataList.find(strEndpoint);
		if (iter != m_linkDataList.end()) {
			broker::LinkData * pLinkData = iter->second;
			if (pLinkData && pLinkData->nLinkState == 0) {
				pLinkData->nLinkState = 1;
			}
		}
		else {
			broker::LinkData * pLinkData = new broker::LinkData();
			memset(pLinkData, 0, sizeof(broker::LinkData));
			pLinkData->userPair.clear();
			pLinkData->nLinkState = 1;
			m_linkDataList.insert(LinkDataList::value_type(strEndpoint, pLinkData));
		}
		pthread_mutex_unlock(&m_mutex4LinkDataList);
		sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]link=%s connect\r\n", __FUNCTION__, __LINE__, pEndpoint_);
		writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		return 0;
	}
	return -1;
}

int ProtocolBroker::unregisterEndpoint(const char * pEndpoint_)
{
	int result = 0;
	if (pEndpoint_ && strlen(pEndpoint_)) {
		std::string strEndpoint = pEndpoint_;
		std::set < std::pair<std::string, std::string>> userSessions;
		pthread_mutex_lock(&m_mutex4LinkDataList);
		LinkDataList::iterator iter = m_linkDataList.find(strEndpoint);
		if (iter != m_linkDataList.end()) {
			broker::LinkData * pLinkData = iter->second;
			if (pLinkData) {
				if (!pLinkData->userPair.empty()) {
					pLinkData->userPair.swap(userSessions);
				}
				if (pLinkData->pLingeData && pLinkData->uiTotalDataLen > 0) {
					delete[] pLinkData->pLingeData;
					pLinkData->pLingeData = NULL;
					pLinkData->uiTotalDataLen = 0;
				}
			}
			m_linkDataList.erase(iter);
		}
		pthread_mutex_unlock(&m_mutex4LinkDataList);
		if (!userSessions.empty()) {
			pthread_mutex_lock(&m_mutex4LinkList);
			std::set<std::pair<std::string, std::string>>::iterator iter = userSessions.begin();
			std::set<std::pair<std::string, std::string>>::iterator iter_end = userSessions.end();
			for (; iter != iter_end; iter++) {
				if (!m_linkList.empty()) {
					broker::LinkInfoList::iterator iter = m_linkList.find(iter->first);
					if (iter != m_linkList.end()) {
						broker::LinkInfo * pLinkInfo = iter->second;
						if (pLinkInfo) {
							if (strcmp(pLinkInfo->szEndpoint, pEndpoint_) == 0) {
								pLinkInfo->szEndpoint[0] = '\0';
							}
						}
					}
				}
			}
			pthread_mutex_unlock(&m_mutex4LinkList);
			userSessions.clear();
		}
	}
	return result;
}

int ProtocolBroker::sendDataViaEndpoint(const char * pData_, unsigned int uiDataLen_, 
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_, int nSecuityExtra_)
{
	int result = -1;
	if (pData_ && uiDataLen_ > 0 && pEndpoint_ && strlen(pEndpoint_)) {
		std::string utfData = ansi_to_utf8(pData_);
		size_t nUtfDataLen = utfData.size();
		device_protocol::ProtocolMessageHead msgHead;
		msgHead.mark[0] = 'E';
		msgHead.mark[1] = 'C';
		msgHead.protocol_type = (int8_t)nProtocolType_;
		msgHead.security_policy = (int8_t)nSecurityPolicy_;
		msgHead.security_extra = (unsigned short)nSecuityExtra_;
		msgHead.payload_length = nUtfDataLen;
		size_t nProtocolMsgHeadLen = sizeof(device_protocol::ProtocolMessageHead);
		if (nProtocolType_ == device_protocol::PROTOCOL_PRIVATE) {
			unsigned int uiBufLen = nProtocolMsgHeadLen + nUtfDataLen;
			unsigned char * pBuf = new unsigned char[uiBufLen + 1];
			memcpy_s(pBuf, uiBufLen, &msgHead, nProtocolMsgHeadLen);
			memcpy_s(pBuf + nProtocolMsgHeadLen, uiBufLen - nProtocolMsgHeadLen, utfData.c_str(), 
				nUtfDataLen);
			switch (nSecurityPolicy_) {
				case device_protocol::POLICY_SIMPLE_PRIVATE: {
					encryptMessageViaPrivateSimple(pBuf, nProtocolMsgHeadLen, uiBufLen, (short)nSecuityExtra_);
					break;
				}
				case device_protocol::POLICY_EMPTY: {
					break;
				}
				case device_protocol::POLICY_BASE64: {
					break;
				}
				case device_protocol::POLICY_RSA: {
					break;
				}
				default: {
					break;
				}
			}
			result = TS_SendData(m_uiSrvInst, pEndpoint_, (const char *)pBuf, uiBufLen);
			delete[] pBuf;
			pBuf = NULL;
		}
		else if (nProtocolType_ == device_protocol::PROTOCOL_MQTT) {

		}
	}
	return result;
}

void ProtocolBroker::clearLinkDataList()
{
	pthread_mutex_lock(&m_mutex4LinkDataList);
	LinkDataList::iterator iter = m_linkDataList.begin();
	while (iter != m_linkDataList.end()) {
		broker::LinkData * pLinkData = iter->second;
		if (pLinkData) {
			if (pLinkData->pLingeData && pLinkData->uiTotalDataLen) {
				delete pLinkData->pLingeData;
				pLinkData->pLingeData = NULL;
			}
			delete pLinkData;
			pLinkData = NULL;
		}
	}
	pthread_mutex_unlock(&m_mutex4LinkDataList);
}

bool ProtocolBroker::addProxyDevMsg(broker::ProxyDeviceMessage * pProxyDevMsg_)
{
	bool result = false;
	if (pProxyDevMsg_ && pProxyDevMsg_->uiMsgDataLen && pProxyDevMsg_->pMsgData) {
		pthread_mutex_lock(&m_mutex4ProxyDevMsgQue);
		int bEmpty = m_proxyDevMsgQue.empty();
		m_proxyDevMsgQue.emplace(pProxyDevMsg_);
		result = true;
		if (bEmpty) {
			pthread_cond_broadcast(&m_cond4ProxyDevMsgQue);
		}
		pthread_mutex_unlock(&m_mutex4ProxyDevMsgQue);
	}
	return result;
}

void ProtocolBroker::handleProxyDevMsg()
{
	while (1) {
		pthread_mutex_lock(&m_mutex4ProxyDevMsgQue);
		while (m_bRun && m_proxyDevMsgQue.empty()) {
			pthread_cond_wait(&m_cond4ProxyDevMsgQue, &m_mutex4ProxyDevMsgQue);
		}
		if (!m_bRun && m_proxyDevMsgQue.empty()) {
			pthread_mutex_unlock(&m_mutex4ProxyDevMsgQue);
			break;
		}
		broker::ProxyDeviceMessage * pProxyDevMsg = m_proxyDevMsgQue.front();
		m_proxyDevMsgQue.pop();
		pthread_mutex_unlock(&m_mutex4ProxyDevMsgQue);
		if (pProxyDevMsg) {
			if (pProxyDevMsg->pMsgData) {
				switch (pProxyDevMsg->usMsgType) {
					case ccrfid_device::MT_ONLINE: {
						ccrfid_device::DeviceMessage devOnlineMsg;
						size_t nNeedMsgLen = sizeof(devOnlineMsg);
						if (pProxyDevMsg->uiMsgDataLen >= nNeedMsgLen) {
							memcpy_s(&devOnlineMsg, nNeedMsgLen, pProxyDevMsg->pMsgData, nNeedMsgLen);
							handleDeviceOnlineMessage(&devOnlineMsg, pProxyDevMsg->uiMsgSeq, pProxyDevMsg->ulMsgTime);
						}
						break;
					}
					case ccrfid_device::MT_ALIVE: {
						ccrfid_device::DeviceMessage devAliveMsg;
						size_t nNeedMsgLen = sizeof(devAliveMsg);
						if (pProxyDevMsg->uiMsgDataLen >= nNeedMsgLen) {
							memcpy_s(&devAliveMsg, nNeedMsgLen, pProxyDevMsg->pMsgData, nNeedMsgLen);
							handleDeviceAliveMessage(&devAliveMsg, pProxyDevMsg->uiMsgSeq, pProxyDevMsg->ulMsgTime);
						}
						break;
					}
					case ccrfid_device::MT_OFFLINE: {
						ccrfid_device::DeviceMessage devOfflineMsg;
						size_t nNeedMsgLen = sizeof(devOfflineMsg);
						if (pProxyDevMsg->uiMsgDataLen >= nNeedMsgLen) {
							memcpy_s(&devOfflineMsg, nNeedMsgLen, pProxyDevMsg->pMsgData, nNeedMsgLen);
							handleDeviceOfflineMessage(&devOfflineMsg, pProxyDevMsg->uiMsgSeq, pProxyDevMsg->ulMsgTime);
						}
						break;
					}
					case ccrfid_device::MT_ALARM_LOWPOWER: {
						ccrfid_device::DeviceMessage devLowpoweMsg;
						size_t nNeedMsgLen = sizeof(devLowpoweMsg);
						if (pProxyDevMsg->uiMsgDataLen >= nNeedMsgLen) {
							memcpy_s(&devLowpoweMsg, nNeedMsgLen, pProxyDevMsg->pMsgData, nNeedMsgLen);
							handleDeviceLowpowerMessage(&devLowpoweMsg, pProxyDevMsg->uiMsgSeq, pProxyDevMsg->ulMsgTime);
						}
						break;
					}
					case ccrfid_device::MT_ALARM_LOOSE: {
						ccrfid_device::DeviceMessage devLooseMsg;
						size_t nNeedMsgLen = sizeof(devLooseMsg);
						if (pProxyDevMsg->uiMsgDataLen >= nNeedMsgLen) {
							memcpy_s(&devLooseMsg, nNeedMsgLen, pProxyDevMsg->pMsgData, nNeedMsgLen);
							handleDeviceLooseMessage(&devLooseMsg, pProxyDevMsg->uiMsgSeq, pProxyDevMsg->ulMsgTime);
						}
						break;
					}
					case ccrfid_device::MT_LOCATE_GPS: {
						ccrfid_device::DeviceLocateGpsMessage devGpsMsg;
						size_t nNeedMsgLen = sizeof(devGpsMsg);
						if (pProxyDevMsg->uiMsgDataLen >= nNeedMsgLen) {
							memcpy_s(&devGpsMsg, nNeedMsgLen, pProxyDevMsg->pMsgData, nNeedMsgLen);
							handleDeviceGpsMessage(&devGpsMsg, pProxyDevMsg->uiMsgSeq, pProxyDevMsg->ulMsgTime);
						}
						break;
					}
					case ccrfid_device::MT_LOCATE_LBS: {
						ccrfid_device::DeviceLocateLbsMessage devLbsMsg;
						size_t nNeedMsgLen = sizeof(devLbsMsg), nLen1 = 0, nLen2 = 0;
						if (pProxyDevMsg->uiMsgDataLen >= nNeedMsgLen) {
							memcpy_s(&devLbsMsg, nNeedMsgLen, pProxyDevMsg->pMsgData, nNeedMsgLen);
							if (devLbsMsg.nBaseStationCount) {
								nLen1 = sizeof(ccrfid_device::BaseStation) * devLbsMsg.nBaseStationCount;
								devLbsMsg.pBaseStationList = new ccrfid_device::BaseStation[devLbsMsg.nBaseStationCount];
								memcpy_s(&devLbsMsg.pBaseStationList, nLen1, pProxyDevMsg->pMsgData + nNeedMsgLen, nLen1);
							}
							if (devLbsMsg.nDetectedWifiCount) {
								nLen2 = sizeof(ccrfid_device::WifiInformation) * devLbsMsg.nDetectedWifiCount;
								devLbsMsg.pDetectedWifiList = new ccrfid_device::WifiInformation[devLbsMsg.nDetectedWifiCount];
								memcpy_s(&devLbsMsg.pDetectedWifiList, nLen2, pProxyDevMsg->pMsgData + nNeedMsgLen + nLen1, nLen2);
							}
							handleDeviceLbsMessage(&devLbsMsg, pProxyDevMsg->uiMsgSeq, pProxyDevMsg->ulMsgTime);
							if (devLbsMsg.pBaseStationList) {
								delete[] devLbsMsg.pBaseStationList;
								devLbsMsg.pBaseStationList = NULL;
							}
							if (devLbsMsg.pDetectedWifiList) {
								delete[] devLbsMsg.pDetectedWifiList;
								devLbsMsg.pDetectedWifiList = NULL;
							}
						}
						break;
					}
					case ccrfid_device::MT_COMMAND: {
						ccrfid_device::DeviceCommandInfo devCmdInfo;
						size_t nNeedMsgLen = sizeof(devCmdInfo);
						if (pProxyDevMsg->uiMsgDataLen >= nNeedMsgLen) {
							memcpy_s(&devCmdInfo, nNeedMsgLen, pProxyDevMsg->pMsgData, nNeedMsgLen);
							handleDeviceCommandMessage(&devCmdInfo, pProxyDevMsg->uiMsgSeq, 
								pProxyDevMsg->ulMsgTime);
						}
						break;
					}
				}
				delete[] pProxyDevMsg->pMsgData;
				pProxyDevMsg->pMsgData = NULL;
			}
			delete pProxyDevMsg;
			pProxyDevMsg = NULL;
		}
	}
}

void ProtocolBroker::initDB(const char * pDbFile_)
{
	if (m_pDb == NULL) {
		sqlite3_open(pDbFile_, &m_pDb);
	}
	if (m_pDb) {
		char szSql1[512] = { 0 };
		sprintf_s(szSql1, sizeof(szSql1), "create table if not exists device_info(deviceId varchar(20) primary key, "
			"factoryId varchar(4), isOnline Integer, isLoose Integer, battery Integer, lastActiveTime datetime, "
			"latitude double, longitude double, lastLocateTime datetime, coordinate Integer, locateType Integer);");
		char szSql2[512] = { 0 };
		sprintf_s(szSql2, sizeof(szSql2), "create table if not exists user_info(userId varchar(32) primary key, passwd"
			" varchar(64), limit Integer);");
		char szSql3[512] = { 0 };
		sprintf_s(szSql3, sizeof(szSql3), "create table if not exists fence_info(fenceId varchar(20) primary key, deviceId"
			" varchar(20), fenceType Integer, fenceContent varchar(256), startTime datetime, stopTime datetime, state "
			"Integer, policy Integer, coordinate Integer);");
		sqlite3_exec(m_pDb, szSql1, NULL, NULL, NULL);
		sqlite3_exec(m_pDb, szSql2, NULL, NULL, NULL);
		sqlite3_exec(m_pDb, szSql3, NULL, NULL, NULL);
	}
}

bool ProtocolBroker::isFileExists(const char * pFileName_)
{
	std::fstream fin;
	fin.open(pFileName_, std::ios::in);
	if (fin.is_open()) {
		fin.close();
		return true;
	}
	fin.close();
	return false;
}

void ProtocolBroker::loadUserList()
{
	if (m_pDb) {
		char szSql[256] = { 0 };
		sprintf_s(szSql, sizeof(szSql), "select userId, passwd, limit from user_info order by userId;");
		sqlite3_stmt * pStmt;
		int rc = sqlite3_prepare_v2(m_pDb, szSql, -1, &pStmt, NULL);
		if (rc == SQLITE_OK) {
			pthread_mutex_lock(&m_mutex4UserList);
			int nCount = 0;
			while (rc = sqlite3_step(pStmt)) {
				if (rc == SQLITE_ROW) {
					nCount++;
					const char * pUserId = (char *)sqlite3_column_text(pStmt, 0);
					const char * pPasswd = (char *)sqlite3_column_text(pStmt, 1);
					int nVal = sqlite3_column_int(pStmt, 2);
					if (pUserId) {
						broker::EscortUser * pUser = new broker::EscortUser();
						pUser->nCurrentWaterLine = 0;
						pUser->nLimitWaterLine = nVal;
						memcpy_s(pUser->szPassword, sizeof(pUser->szPassword), pPasswd, strlen(pPasswd));
						memcpy_s(pUser->szUserId, sizeof(pUser->szUserId), pUserId, strlen(pUserId));
						std::string strKey = pUser->szUserId;
						m_userList.emplace(strKey, pUser);
					}
				}
				else if (rc == SQLITE_DONE) {
					break;
				}
			}
			if (nCount == 0) {
				char szSql2[256] = { 0 };
				sprintf_s(szSql2, sizeof(szSql2), "INSERT INTO user_info(userId, passwd, limit) VALUES ('admin', "
					"'f5da4d563454cc3cf47f93fc861f3f19', -1);");
				sqlite3_exec(m_pDb, szSql2, NULL, NULL, NULL);
				broker::EscortUser * pUser = new broker::EscortUser();
				pUser->nCurrentWaterLine = 0;
				pUser->nLimitWaterLine = -1;
				sprintf_s(pUser->szPassword, sizeof(pUser->szPassword), "f5da4d563454cc3cf47f93fc861f3f19");
				sprintf_s(pUser->szUserId, sizeof(pUser->szUserId), "admin");
				std::string strKey = pUser->szUserId;
				m_userList.emplace(strKey, pUser);
			}
			pthread_mutex_unlock(&m_mutex4UserList);
			sqlite3_finalize(pStmt);
		}
		else {
			initDB(m_szDbFile);
			loadUserList();
		}
	}
}

void ProtocolBroker::loadDeviceList()
{
	if (m_pDb) {
		char szSql[512] = { 0 };
		sprintf_s(szSql, sizeof(szSql), "select deviceId, factoryId, isOnline, isLoose, battery, "
			"lastActiveTime, latitude, longitude, lastLocateTime, coordinate, locateType from "
			"device_info order by deviceId;");
		sqlite3_stmt * pStmt;
		int rc = sqlite3_prepare_v2(m_pDb, szSql, -1, &pStmt, NULL);
		if (rc == SQLITE_OK) {
			pthread_mutex_lock(&m_mutex4DevList);
			while (rc = sqlite3_step(pStmt)) {
				if (rc == SQLITE_ROW) {
					const char * pDeviceId = (char *)sqlite3_column_text(pStmt, 0);
					const char * pFactoryId = (char *)sqlite3_column_text(pStmt, 1);
					int nOnline = sqlite3_column_int(pStmt, 2);
					int nLoose = sqlite3_column_int(pStmt, 3);
					int nBattery = sqlite3_column_int(pStmt, 4);
					const char * pLastActiveTime = (char *)sqlite3_column_text(pStmt, 5);
					double dLat = sqlite3_column_double(pStmt, 6);
					double dLng = sqlite3_column_double(pStmt, 7);
					const char * pLastLocateTime = (char *)sqlite3_column_text(pStmt, 8);
					int nCoordinate = sqlite3_column_int(pStmt, 9);
					int nLocateType = sqlite3_column_int(pStmt, 10);

					if (pDeviceId && pFactoryId) {
						broker::EscortDevice * pDev = new broker::EscortDevice();
						memset(pDev, 0, sizeof(broker::EscortDevice));
						strcpy_s(pDev->szDeviceId, sizeof(pDev->szDeviceId), pDeviceId);
						strcpy_s(pDev->szFactoryId, sizeof(pDev->szFactoryId), pFactoryId);
						pDev->nLooseState = nLoose;
						pDev->nBattery = nBattery;
						pDev->nCoordinate = nCoordinate;
						pDev->nLocateType = nLocateType;
						pDev->lastLatitude = dLat;
						pDev->lastLongitude = dLng;
						if (pLastActiveTime) {
							pDev->ulLastActiveTime = make_datetime2(pLastActiveTime);
						}
						if (pLastLocateTime) {
							pDev->ulLocateTime = make_datetime2(pLastLocateTime);
						}
						pDev->fenceList.clear();

						std::string strKey = pDev->szDeviceId;
						m_devList.emplace(strKey, pDev);
					}
				}
				else if (rc == SQLITE_DONE) {
					break;
				}
			}
			pthread_mutex_unlock(&m_mutex4DevList);
			sqlite3_finalize(pStmt);
		}
		else {
			initDB(m_szDbFile);
		}
	}
}

void ProtocolBroker::loadFenceList()
{
	if (m_pDb) {
		char szSql[512] = { 0 };
		sprintf_s(szSql, sizeof(szSql), "select fenceId, deviceId, fenceType, fenceContent, startTime, "
			"stopTime, state, policy, coordinate from fence_info order by fenceId;");
		sqlite3_stmt * pStmt;
		int rc = sqlite3_prepare_v2(m_pDb, szSql, -1, &pStmt, NULL);
		if (rc == SQLITE_OK) {
			pthread_mutex_lock(&m_mutex4FenceList);
			rc = sqlite3_step(pStmt);
			while (rc) {
				if (rc == SQLITE_ROW) {
					const char * pFenceId = (char *)sqlite3_column_text(pStmt, 0);
					const char * pDeviceId = (char *)sqlite3_column_text(pStmt, 1);
					int nFenceType = sqlite3_column_int(pStmt, 2);
					const char * pFenceContent = (char *)sqlite3_column_text(pStmt, 3);
					const char * pStartTime = (char *)sqlite3_column_text(pStmt, 4);
					const char * pStopTime = (char *)sqlite3_column_text(pStmt, 5);
					int nState = sqlite3_column_int(pStmt, 6);
					int nPolicy = sqlite3_column_int(pStmt, 7);
					int nCoordinate = sqlite3_column_int(pStmt, 8);
					if (pFenceId && pDeviceId && strlen(pFenceId) && strlen(pDeviceId)) {
						broker::EscortFence * pFence = new broker::EscortFence();
						memset(pFence, 0, sizeof(broker::EscortFence));
						strcpy_s(pFence->szFenceId, sizeof(pFence->szFenceId), pFenceId);
						strcpy_s(pFence->szDeviceId, sizeof(pFence->szDeviceId), pDeviceId);
						strcpy_s(pFence->szFenceContent, sizeof(pFence->szFenceContent), pFenceContent);
						pFence->ulStartTime = make_datetime2(pStartTime);
						pFence->ulStopTime = make_datetime2(pStopTime);
						pFence->nFencePolicy = nPolicy;
						pFence->nCoordinate = nCoordinate;
						pFence->nFenceType = nFenceType;
						pFence->nFenceState = nState;
						std::string strKey = pFenceId;
						m_fenceList.emplace(strKey, pFence);
						addDeviceFence(pDeviceId, pFenceId);
					}
				}
				else if (rc == SQLITE_DONE) {
					break;
				}
				rc = sqlite3_step(pStmt);
			}
			pthread_mutex_unlock(&m_mutex4FenceList);
			sqlite3_finalize(pStmt);
		}
		else {
			initDB(m_szDbFile);
		}
	}
}

void ProtocolBroker::addDeviceFence(const char * pDeviceId_, const char * pFenceId_)
{
	if (pDeviceId_ && pFenceId_ && strlen(pDeviceId_) && strlen(pFenceId_)) {
		pthread_mutex_lock(&m_mutex4DevList);
		std::string strKey = pDeviceId_;
		broker::EscortDeviceList::iterator iter = m_devList.find(strKey);
		if (iter != m_devList.end()) {
			broker::EscortDevice * pDevice = iter->second;
			std::string strFenceId = pFenceId_;
			if (pDevice->fenceList.empty()) {
				pDevice->fenceList.emplace(strFenceId);
			}
			else {
				std::set<std::string>::iterator it_end = pDevice->fenceList.end();
				std::set<std::string>::iterator it = std::find(pDevice->fenceList.begin(), it_end, strFenceId);
				if (it != it_end) {
					pDevice->fenceList.emplace(strFenceId);
				}
			}
		}
		pthread_mutex_unlock(&m_mutex4DevList);
	}
}

void ProtocolBroker::clearUserList()
{
	pthread_mutex_lock(&m_mutex4UserList);
	if (!m_userList.empty()) {
		broker::EscortUserList::iterator iter = m_userList.begin();
		broker::EscortUserList::iterator iter_end = m_userList.end();
		while (iter != iter_end) {
			broker::EscortUser * pUser = iter->second;
			if (pUser) {
				delete pUser;
				pUser = NULL;
			}
			iter = m_userList.erase(iter);
		}
	}
	pthread_mutex_unlock(&m_mutex4UserList);
}

void ProtocolBroker::clearDeviceList()
{
	pthread_mutex_lock(&m_mutex4DevList);
	if (!m_devList.empty()) {
		broker::EscortDeviceList::iterator iter = m_devList.begin();
		broker::EscortDeviceList::iterator iter_end = m_devList.end();
		while (iter != iter_end) {
			broker::EscortDevice * pDevice = iter->second;
			if (pDevice) {
				delete pDevice;
				pDevice = NULL;
			}
			iter = m_devList.erase(iter);
		}
	}
	pthread_mutex_unlock(&m_mutex4DevList);
}

void ProtocolBroker::clearFenceList()
{
	pthread_mutex_lock(&m_mutex4FenceList);
	if (!m_fenceList.empty()) {
		broker::EscortFenceList::iterator iter = m_fenceList.begin();
		broker::EscortFenceList::iterator iter_end = m_fenceList.end();
		while (iter != iter_end) {
			broker::EscortFence * pFence = iter->second;
			if (pFence) {
				delete pFence;
				pFence = NULL;
			}
			iter = m_fenceList.erase(iter);
		}
	}
	pthread_mutex_unlock(&m_mutex4FenceList);
}

void ProtocolBroker::handleDeviceOnlineMessage(ccrfid_device::DeviceMessage * pDevOnlineMsg_, 
	unsigned int uiMsgSeq_, unsigned long ulMsgTime_)
{
	char szLog[512] = { 0 };
	if (pDevOnlineMsg_) {
		char szSql[512] = { 0 };
		std::string strDeviceId = pDevOnlineMsg_->szDeviceId;
		char szDatetime[24] = { 0 };
		format_datetime2(ulMsgTime_, szDatetime, sizeof(szDatetime));
		pthread_mutex_lock(&m_mutex4DevList);
		broker::EscortDeviceList::iterator iter = m_devList.find(strDeviceId);
		if (iter != m_devList.end()) {
			broker::EscortDevice * pDevice = iter->second;
			if (pDevice) {
				if ((pDevice->ulLastActiveTime < ulMsgTime_)
					|| (pDevice->ulLastActiveTime == ulMsgTime_ && pDevice->uiLastMsgSeq < uiMsgSeq_)) {
					pDevice->ulLastActiveTime = ulMsgTime_;
					pDevice->uiLastMsgSeq = uiMsgSeq_;
					if (pDevice->nOnline == 0) {
						pDevice->nOnline = 1;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s online, battery=%hu,"
							" msgSeq=%u, msgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevOnlineMsg_->szDeviceId,
							pDevOnlineMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_);
						writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
						sprintf_s(szSql, sizeof(szSql), "update device_info set isOnline=1, battery=%hu, "
							"lastActiveTime='%s' where deviceId='%s';", pDevOnlineMsg_->usDeviceBattery, szDatetime,
							pDevOnlineMsg_->szDeviceId);
					}
					pDevice->nBattery = pDevOnlineMsg_->usDeviceBattery;
				}
				else {
					sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]ignore deviceId=%s online, msgSeq=%u,"
						" msgTime=%lu, lastMsgTime=%lu, lastMsgSeq=%u\r\n", __FUNCTION__, __LINE__, 
						pDevOnlineMsg_->szDeviceId, pDevOnlineMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_, 
						pDevice->ulLastActiveTime, pDevice->uiLastMsgSeq);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
				}
			}
		}
		else {
			broker::EscortDevice * pDevice = new broker::EscortDevice();
			memset(pDevice, 0, sizeof(broker::EscortDevice));
			pDevice->fenceList.clear();
			strcpy_s(pDevice->szDeviceId, sizeof(pDevice->szDeviceId), pDevOnlineMsg_->szDeviceId);
			strcpy_s(pDevice->szFactoryId, sizeof(pDevice->szFactoryId), pDevOnlineMsg_->szFactoryId);
			pDevice->nOnline = 1;
			pDevice->nBattery = pDevOnlineMsg_->usDeviceBattery;
			pDevice->uiLastMsgSeq = uiMsgSeq_;
			pDevice->ulLastActiveTime = ulMsgTime_;
			m_devList.emplace(strDeviceId, pDevice);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s online, battery=%hu, "
				"msgSeq=%u, msgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevOnlineMsg_->szDeviceId, 
				pDevOnlineMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
			sprintf_s(szSql, sizeof(szSql), "insert into device_info(deviceId, factoryId, isOnline, "
				"isLoose, battery, lastActiveTime, latitude, longitude, lastLocateTime, coordinate, "
				"locateType) values('%s','%s',1, 0,%hu,'%s', 0.0000, 0.0000, '', 0, 0);", 
				pDevOnlineMsg_->szDeviceId, pDevOnlineMsg_->szFactoryId, szDatetime);
		}
		pthread_mutex_unlock(&m_mutex4DevList);
		if (strlen(szSql)) {
			int rc = sqlite3_exec(m_pDb, szSql, NULL, NULL, NULL);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]sql=%s, ret=%d\r\n", 
				__FUNCTION__, __LINE__, szSql, rc);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
	}
}

void ProtocolBroker::handleDeviceAliveMessage(ccrfid_device::DeviceMessage * pDevAliveMsg_, 
	unsigned int uiMsgSeq_, unsigned long ulMsgTime_)
{
	char szLog[512] = { 0 };
	if (pDevAliveMsg_) {
		char szSql[512] = { 0 };
		std::string strDeviceId = pDevAliveMsg_->szDeviceId;
		char szDatetime[24] = { 0 };
		format_datetime2(ulMsgTime_, szDatetime, sizeof(szDatetime));
		pthread_mutex_lock(&m_mutex4DevList);
		broker::EscortDeviceList::iterator iter = m_devList.find(strDeviceId);
		if (iter != m_devList.end()) {
			broker::EscortDevice * pDevice = iter->second;
			if (pDevice) {
				if ((pDevice->ulLastActiveTime < ulMsgTime_)
					|| (pDevice->ulLastActiveTime == ulMsgTime_ && pDevice->uiLastMsgSeq < uiMsgSeq_)) {
					if (pDevice->nOnline == 0) {
						pDevice->nOnline = 1;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]change deviceId=%s online, battery=%hu,"
							" msgSeq=%u, msgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevAliveMsg_->szDeviceId, 
							pDevAliveMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_);
						writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
					}
					pDevice->nBattery = pDevAliveMsg_->usDeviceBattery;
					pDevice->ulLastActiveTime = ulMsgTime_;
					pDevice->uiLastMsgSeq = uiMsgSeq_;
					sprintf_s(szSql, sizeof(szSql), "update device_info set isOnline=1, battery=%hu, "
						"lastActiveTime='%s' where deviceId='%s';", pDevAliveMsg_->usDeviceBattery, szDatetime,
						pDevAliveMsg_->szDeviceId);
					sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s alive, battery=%hu, "
						"msgSeq=%u, msgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevAliveMsg_->szDeviceId, 
						pDevAliveMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
				}
				else {
					sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]ignore deviceId=%s alive, msgSeq=%u,"
						" msgTime=%lu, lastMsgSeq=%u, lastMsgTime=%lu\r\n", __FUNCTION__, __LINE__, 
						pDevAliveMsg_->szDeviceId, uiMsgSeq_, ulMsgTime_, pDevice->uiLastMsgSeq, 
						pDevice->ulLastActiveTime);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
				}
			}
		}
		else {
			broker::EscortDevice * pDevice = new broker::EscortDevice();
			memset(pDevice, 0, sizeof(broker::EscortDevice));
			pDevice->fenceList.clear();
			strcpy_s(pDevice->szDeviceId, sizeof(pDevice->szDeviceId), pDevAliveMsg_->szDeviceId);
			strcpy_s(pDevice->szFactoryId, sizeof(pDevice->szFactoryId), pDevAliveMsg_->szFactoryId);
			pDevice->nOnline = 1;
			pDevice->nBattery = pDevAliveMsg_->usDeviceBattery;
			pDevice->uiLastMsgSeq = uiMsgSeq_;
			pDevice->ulLastActiveTime = ulMsgTime_;
			m_devList.emplace(strDeviceId, pDevice);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s online, battery=%hu, msgSeq=%u,"
				" msgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevAliveMsg_->szDeviceId, 
				pDevAliveMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
			sprintf_s(szSql, sizeof(szSql), "insert into device_info(deviceId, factoryId, isOnline, isLoose, "
				"battery, lastActiveTime, latitude, longitude, lastLocateTime, coordinate, locateType) values"
				"('%s','%s',1, 0, %hu,'%s', 0.0000, 0.0000, '', 0, 0);", pDevAliveMsg_->szDeviceId, 
				pDevAliveMsg_->szFactoryId, szDatetime);
		}
		pthread_mutex_unlock(&m_mutex4DevList);
		if (strlen(szSql)) {
			int rc = sqlite3_exec(m_pDb, szSql, NULL, NULL, NULL);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]sql=%s, ret=%d\r\n", 
				__FUNCTION__, __LINE__, szSql, rc);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
	}
}

void ProtocolBroker::handleDeviceLowpowerMessage(ccrfid_device::DeviceMessage * pDevLowpowerMsg_, 
	unsigned int uiMsgSeq_, unsigned long ulMsgTime_)
{
	char szLog[512] = { 0 };
	if (pDevLowpowerMsg_) {
		char szSql[512] = { 0 };
		std::string strDeviceId = pDevLowpowerMsg_->szDeviceId;
		char szDatetime[24] = { 0 };
		format_datetime2(ulMsgTime_, szDatetime, sizeof(szDatetime));
		pthread_mutex_lock(&m_mutex4DevList);
		broker::EscortDeviceList::iterator iter = m_devList.find(strDeviceId);
		if (iter != m_devList.end()) {
			broker::EscortDevice * pDevice = iter->second;
			if (pDevice) {
				if ((pDevice->ulLastActiveTime < ulMsgTime_)
					|| (pDevice->ulLastActiveTime == ulMsgTime_ && pDevice->uiLastMsgSeq < uiMsgSeq_)) {
					if (pDevice->nOnline == 0) {
						pDevice->nOnline = 1;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s online, battery=%hu,"
							" msgSeq=%u, msgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevLowpowerMsg_->szDeviceId, 
							pDevLowpowerMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_);
						writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
					}
					pDevice->nBattery = pDevLowpowerMsg_->usDeviceBattery;
					pDevice->ulLastActiveTime = ulMsgTime_;
					pDevice->uiLastMsgSeq = uiMsgSeq_;
					sprintf_s(szSql, sizeof(szSql), "update device_info set battery=%hu, isOnline=1, "
						"lastActiveTime='%s' where deviceId='%s';", pDevLowpowerMsg_->usDeviceBattery, szDatetime,
						pDevLowpowerMsg_->szDeviceId);
					sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s, lowpower, battery=%hu,"
						" msgSeq=%u, msgTime=%s\r\n", __FUNCTION__, __LINE__, pDevLowpowerMsg_->szDeviceId, 
						pDevLowpowerMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
				}
				else {
					sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]ignore deviceId=%s, battery=%hu, "
						"msgSeq=%u, msgTime=%lu, lastMsgSeq=%u, lastMsgTime=%lu\r\n", __FUNCTION__, __LINE__, 
						pDevLowpowerMsg_->szDeviceId, pDevLowpowerMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_,
						pDevice->uiLastMsgSeq, pDevice->ulLastActiveTime);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
				}
			}
		}
		else {
			broker::EscortDevice * pDevice = new broker::EscortDevice();
			memset(pDevice, 0, sizeof(broker::EscortDevice));
			pDevice->fenceList.clear();
			strcpy_s(pDevice->szDeviceId, sizeof(pDevice->szDeviceId), pDevLowpowerMsg_->szDeviceId);
			strcpy_s(pDevice->szFactoryId, sizeof(pDevice->szFactoryId), pDevLowpowerMsg_->szFactoryId);
			pDevice->nBattery = pDevLowpowerMsg_->usDeviceBattery;
			pDevice->ulLastActiveTime = ulMsgTime_;
			pDevice->uiLastMsgSeq = uiMsgSeq_;
			pDevice->nOnline = 1;
			m_devList.emplace(strDeviceId, pDevice);
			sprintf_s(szSql, sizeof(szSql), "insert into device_info(deviceId, factoryId, isOnline, "
				"isLoose, battery, lastActiveTime, latitude, longitude, lastLocateTime, coordinate, "
				"locateType) values('%s', '%s', 1, 0, %hu, '%s', 0.0000, 0.0000, '', 0, 0);", 
				pDevLowpowerMsg_->szDeviceId, pDevLowpowerMsg_->szFactoryId, pDevLowpowerMsg_->usDeviceBattery,
				szDatetime);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s online, lowpower, battery=%hu,"
				" msgSeq=%u, msgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevLowpowerMsg_->szDeviceId, 
				pDevLowpowerMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
		pthread_mutex_unlock(&m_mutex4DevList);
		if (strlen(szSql)) {
			int rc = sqlite3_exec(m_pDb, szSql, NULL, NULL, NULL);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]sql=%s, ret=%d\r\n", 
				__FUNCTION__, __LINE__, szSql, rc);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
	}
}

void ProtocolBroker::handleDeviceLooseMessage(ccrfid_device::DeviceMessage * pDevLooseMsg_, 
	unsigned int uiMsgSeq_, unsigned long ulMsgTime_)
{
	char szLog[512] = { 0 };
	if (pDevLooseMsg_ && pDevLooseMsg_->usMessageType == ccrfid_device::MT_ALARM_LOOSE) {
		char szSql[512] = { 0 };
		char szDatetime[24] = { 0 };
		format_datetime2(ulMsgTime_, szDatetime, sizeof(szDatetime));
		std::string strDeviceId = pDevLooseMsg_->szDeviceId;
		pthread_mutex_lock(&m_mutex4DevList);
		broker::EscortDeviceList::iterator iter = m_devList.find(strDeviceId);
		if (iter != m_devList.end()) {
			broker::EscortDevice * pDevice = iter->second;
			if (pDevice) {
				if ((pDevice->ulLastActiveTime < ulMsgTime_)
					|| (pDevice->ulLastActiveTime == ulMsgTime_ && pDevice->uiLastMsgSeq < uiMsgSeq_)) {
					pDevice->ulLastActiveTime = ulMsgTime_;
					pDevice->uiLastMsgSeq = uiMsgSeq_;
					if (pDevice->nOnline == 0) {
						pDevice->nOnline = 1;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s online, battery=%hu,"
							" msgSeq=%hu, msgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevLooseMsg_->szDeviceId,
							pDevLooseMsg_->usDeviceBattery);
						writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
					}
					pDevice->nLooseState = pDevLooseMsg_->usMessageTypeExtra;
					sprintf_s(szSql, sizeof(szSql), "update device_info set isOnline=1, isLoose=%hu, battery=%hu,"
						" lastActiveTime='%s' where deviceId='%s';", pDevLooseMsg_->usMessageTypeExtra,
						pDevLooseMsg_->usDeviceBattery, szDatetime, pDevLooseMsg_->szDeviceId);
					sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s, loose=%hu, battery=%hu, "
						"msgSeq=%hu, msgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevLooseMsg_->szDeviceId, 
						pDevLooseMsg_->usMessageTypeExtra, pDevLooseMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
				}
				else {
					sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]ignore deviceId=%s, loose=%hu, "
						"battery=%hu, msgSeq=%u, msgTime=%lu, lastMsgSeq=%d, lastMsgTime=%lu\r\n", __FUNCTION__,
						__LINE__, pDevLooseMsg_->szDeviceId, pDevLooseMsg_->usMessageTypeExtra, 
						pDevLooseMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_, pDevice->uiLastMsgSeq, 
						pDevice->ulLastActiveTime);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
				}
			}
		}
		else {
			broker::EscortDevice * pDevice = new broker::EscortDevice();
			memset(pDevice, 0, sizeof(broker::EscortDevice));
			pDevice->fenceList.clear();
			pDevice->nBattery = pDevLooseMsg_->usDeviceBattery;
			pDevice->nOnline = 1;
			pDevice->nLooseState = pDevLooseMsg_->usMessageTypeExtra;
			strcpy_s(pDevice->szDeviceId, sizeof(pDevice->szDeviceId), pDevLooseMsg_->szDeviceId);
			strcpy_s(pDevice->szFactoryId, sizeof(pDevice->szFactoryId), pDevLooseMsg_->szFactoryId);
			pDevice->uiLastMsgSeq = uiMsgSeq_;
			pDevice->ulLastActiveTime = ulMsgTime_;
			m_devList.emplace(strDeviceId, pDevice); 
			sprintf_s(szSql, sizeof(szSql), "insert into device_info(deviceId, factoryId, isOnline, isLoose, "
				"battery, lastActiveTime, latitude, longitude, lastLocateTime, coordinate, locateType) values"
				"('%s', '%s', 1, %d, %hu, '%s', 0.0000, 0.0000, '', 0, 0);", pDevLooseMsg_->szDeviceId, 
				pDevLooseMsg_->szFactoryId, pDevLooseMsg_->usMessageTypeExtra, pDevLooseMsg_->usDeviceBattery,
				szDatetime);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s, online, loose=%hu, battery=%hu,"
				" msgSeq=%u, msgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevLooseMsg_->szDeviceId, 
				pDevLooseMsg_->usMessageTypeExtra, pDevLooseMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
		pthread_mutex_unlock(&m_mutex4DevList);
		if (strlen(szSql)) {
			int rc = sqlite3_exec(m_pDb, szSql, NULL, NULL, NULL);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]sql=%s, ret=%d\r\n", __FUNCTION__, __LINE__,
				szSql, rc);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
	}
}

void ProtocolBroker::handleDeviceOfflineMessage(ccrfid_device::DeviceMessage * pDevOfflineMsg_, 
	unsigned int uiMsgSeq_, unsigned long ulMsgTime_)
{
	char szLog[512] = { 0 };
	if (pDevOfflineMsg_ && pDevOfflineMsg_->usMessageType == ccrfid_device::MT_OFFLINE) {
		std::string strDeviceId = pDevOfflineMsg_->szDeviceId;
		char szDatetime[24] = { 0 };
		format_datetime2(ulMsgTime_, szDatetime, sizeof(szDatetime));
		char szSql[512] = { 0 };
		pthread_mutex_lock(&m_mutex4DevList);
		broker::EscortDeviceList::iterator iter = m_devList.find(strDeviceId);
		if (iter != m_devList.end()) {
			broker::EscortDevice * pDevice = iter->second;
			if (pDevice) {
				if ((pDevice->ulLastActiveTime < ulMsgTime_)
					|| (pDevice->ulLastActiveTime == ulMsgTime_ && pDevice->uiLastMsgSeq < uiMsgSeq_)) {
					pDevice->nBattery = 0;
					pDevice->ulLastActiveTime = ulMsgTime_;
					pDevice->uiLastMsgSeq = uiMsgSeq_;
					pDevice->nOnline = 0;
					sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s offline, msgSeq=%hu,"
						" msgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevOfflineMsg_->szDeviceId, uiMsgSeq_,
						ulMsgTime_);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
					sprintf_s(szSql, sizeof(szSql), "update device_info set isOnline = 0, battery=0, "
						"lastActiveTime='%s' where deviceId='%s';", szDatetime, pDevOfflineMsg_->szDeviceId);
				}
				else {
					sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]ignore deviceId=%s offline, "
						"msgSeq=%u, msgTime=%lu, lastMsgSeq=%u, lastMsgTime=%lu\r\n", __FUNCTION__, __LINE__,
						pDevOfflineMsg_->szDeviceId, uiMsgSeq_, ulMsgTime_, pDevice->uiLastMsgSeq, 
						pDevice->ulLastActiveTime);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
				}
			}
		}
		else {
			broker::EscortDevice * pDevice = new broker::EscortDevice();
			memset(pDevice, 0, sizeof(broker::EscortDevice));
			pDevice->fenceList.clear();
			strcpy_s(pDevice->szDeviceId, sizeof(pDevice->szDeviceId), pDevOfflineMsg_->szDeviceId);
			strcpy_s(pDevice->szFactoryId, sizeof(pDevice->szFactoryId), pDevOfflineMsg_->szFactoryId);
			pDevice->ulLastActiveTime = ulMsgTime_;
			pDevice->uiLastMsgSeq = uiMsgSeq_;
			m_devList.emplace(strDeviceId, pDevice);
			sprintf_s(szSql, sizeof(szSql), "insert into device_info(deviceId, factoryId, isOnline, "
				"isLoose, battery, lastActiveTime, latitude, longitude, lastLocateTime, coordinate, "
				"locateType) values('%s', '%s', 0, 0, 0, '%s', 0.0000, 0.0000, '', 0, 0);", 
				pDevOfflineMsg_->szDeviceId, pDevOfflineMsg_->szFactoryId, szDatetime);
		}
		pthread_mutex_unlock(&m_mutex4DevList);
		if (strlen(szSql)) {
			int rc = sqlite3_exec(m_pDb, szSql, NULL, NULL, NULL);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]sql=%s, ret=%d\r\n", 
				__FUNCTION__, __LINE__, szSql, rc);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
	}
}

void ProtocolBroker::handleDeviceGpsMessage(ccrfid_device::DeviceLocateGpsMessage * pDevGpsMsg_, 
	unsigned int uiMsgSeq_, unsigned long ulMsgTime_)
{
	char szLog[512] = { 0 };
	if (pDevGpsMsg_) {
		std::string strDeviceId = pDevGpsMsg_->szDeviceId;
		char szDatetime[24] = { 0 };
		format_datetime2(ulMsgTime_, szDatetime, sizeof(szDatetime));
		char szLocateDatetime[24] = { 0 };
		format_datetime2(pDevGpsMsg_->ulLocateTime, szLocateDatetime, sizeof(szLocateDatetime));
		char szSql[512] = { 0 };
		pthread_mutex_lock(&m_mutex4DevList);
		broker::EscortDeviceList::iterator iter = m_devList.find(strDeviceId);
		if (iter != m_devList.end()) {
			broker::EscortDevice * pDevice = iter->second;
			if (pDevice) {
				if ((pDevice->ulLocateTime < ulMsgTime_)
					|| (pDevice->ulLocateTime == ulMsgTime_ && pDevice->uiLastMsgSeq < uiMsgSeq_)) {
					pDevice->ulLastActiveTime = ulMsgTime_;
					pDevice->uiLastMsgSeq = uiMsgSeq_;
					if (pDevice->nOnline == 0) {
						pDevice->nOnline = 1;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s online, "
							"battery=%hu, msgSeq=%u, msgTime=%lu\r\n", __FUNCTION__, __LINE__, 
							pDevGpsMsg_->szDeviceId, pDevGpsMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_);
						writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
					}
					if (pDevice->ulLocateTime < pDevGpsMsg_->ulLocateTime) {
						pDevice->ulLocateTime = pDevGpsMsg_->ulLocateTime;
						pDevice->lastLatitude = pDevGpsMsg_->dLatitude;
						pDevice->lastLongitude = pDevGpsMsg_->dLngitude;
						pDevice->nCoordinate = pDevGpsMsg_->nCoordinate;
						pDevice->nLocateType = 1;
						pDevice->nBattery = pDevGpsMsg_->usDeviceBattery;
						sprintf_s(szSql, sizeof(szSql), "update device_info set isOnline=1, battery=%hu, "
							"lastActiveTime='%s', latitude=%f, longitude=%f, lastLocateTime='%s', coordinate=%d, "
							"locateType=1 where deviceId='%s';", pDevGpsMsg_->usDeviceBattery, szDatetime, 
							pDevGpsMsg_->dLatitude, pDevGpsMsg_->dLngitude, szLocateDatetime, 
							pDevGpsMsg_->nCoordinate);
					}
					sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s gps location, battery=%hu,"
						" lat=%f, lng=%f, coordinate=%d, locateTime=%s, msgSeq=%u, msgTime=%s\r\n", 
						__FUNCTION__, __LINE__, pDevGpsMsg_->usDeviceBattery, pDevGpsMsg_->dLatitude, 
						pDevGpsMsg_->dLngitude, szLocateDatetime, uiMsgSeq_, ulMsgTime_);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
				}
				else {
					sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]ignore deviceId=%s gpg location, "
						"lat=%f, lng=%f, coordinate=%d, locateTime=%s, msgSeq=%u, msgTime=%lu, lastMsgSeq=%u, "
						"lastMsgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevGpsMsg_->szDeviceId, pDevGpsMsg_->dLatitude,
						pDevGpsMsg_->dLngitude, pDevGpsMsg_->nCoordinate, szLocateDatetime, uiMsgSeq_, ulMsgTime_,
						pDevice->uiLastMsgSeq, pDevice->ulLastActiveTime);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
				}
			}
		}
		else {
			broker::EscortDevice * pDevice = new broker::EscortDevice();
			memset(pDevice, 0, sizeof(broker::EscortDevice));
			pDevice->fenceList.clear();
			strcpy_s(pDevice->szDeviceId, sizeof(pDevice->szDeviceId), pDevGpsMsg_->szDeviceId);
			strcpy_s(pDevice->szFactoryId, sizeof(pDevice->szFactoryId), pDevGpsMsg_->szFactoryId);
			pDevice->nBattery = pDevGpsMsg_->usDeviceBattery;
			pDevice->nOnline = 1;
			pDevice->nLocateType = 1;
			pDevice->lastLatitude = pDevGpsMsg_->dLatitude;
			pDevice->lastLongitude = pDevGpsMsg_->dLngitude;
			pDevice->ulLastActiveTime = ulMsgTime_;
			pDevice->ulLocateTime = pDevGpsMsg_->ulLocateTime;
			pDevice->uiLastMsgSeq = uiMsgSeq_;
			pDevice->nCoordinate = pDevGpsMsg_->nCoordinate;
			m_devList.emplace(strDeviceId, pDevGpsMsg_);
			sprintf_s(szSql, sizeof(szSql), "insert into device_info(deviceId, factoryId, isOnline, isLoose"
				", battery, lastActiveTime, latitude, longitude, lastLocateTime, coordinate, locateType)"
				" values('%s', '%s', 1, 0, %hu, '%s', %f, %f, '%s', %d, 1);", pDevGpsMsg_->szDeviceId, 
				pDevGpsMsg_->szFactoryId, pDevGpsMsg_->usDeviceBattery, szDatetime, pDevGpsMsg_->dLatitude,
				pDevGpsMsg_->dLngitude, szLocateDatetime, pDevGpsMsg_->nCoordinate);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s online, battery=%hu, "
				"lastActiveTime=%s, lat=%f, lng=%f, coordinate=%d, locateTime=%s, locateType=1, msgSeq=%u, "
				"msgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevGpsMsg_->szDeviceId, pDevGpsMsg_->usDeviceBattery,
				szDatetime, pDevGpsMsg_->dLatitude, pDevGpsMsg_->dLngitude, pDevGpsMsg_->nCoordinate, 
				szLocateDatetime, uiMsgSeq_, ulMsgTime_);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
		pthread_mutex_unlock(&m_mutex4DevList);
		if (strlen(szSql)) {
			int rc = sqlite3_exec(m_pDb, szSql, NULL, NULL, NULL);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]sql=%s, ret=%d\r\n", 
				__FUNCTION__, __LINE__, szSql, rc);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
	}
}

void ProtocolBroker::handleDeviceLbsMessage(ccrfid_device::DeviceLocateLbsMessage * pDevLbsMsg_, 
	unsigned int uiMsgSeq_, unsigned long ulMsgTime_)
{
	char szLog[512] = { 0 };
	if (pDevLbsMsg_) {
		char szDatetime[24] = { 0 };
		format_datetime2(ulMsgTime_, szDatetime, sizeof(szDatetime));
		char szLocateDatetime[24] = { 0 };
		format_datetime2(pDevLbsMsg_->ulLocateTime, szLocateDatetime, sizeof(szLocateDatetime));
		char szSql[512] = { 0 };
		std::string strDeviceId = pDevLbsMsg_->szDeviceId;
		pthread_mutex_lock(&m_mutex4DevList);
		broker::EscortDeviceList::iterator iter = m_devList.find(strDeviceId);
		if (iter != m_devList.end()) {
			broker::EscortDevice * pDevice = iter->second;
			if (pDevice) {
				if ((pDevice->ulLastActiveTime < ulMsgTime_)
					|| (pDevice->ulLastActiveTime == ulMsgTime_ && pDevice->uiLastMsgSeq < uiMsgSeq_)) {
					pDevice->ulLastActiveTime = ulMsgTime_;
					pDevice->uiLastMsgSeq = uiMsgSeq_;
					if (pDevice->nOnline == 0) {
						pDevice->nOnline = 1;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s online, battery=%hu, "
							"msgSeq=%u, msgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevLbsMsg_->szDeviceId, 
							pDevLbsMsg_->usDeviceBattery, uiMsgSeq_, ulMsgTime_);
						writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
					}
					if (pDevice->ulLocateTime < pDevLbsMsg_->ulLocateTime) {
						pDevice->ulLocateTime = pDevLbsMsg_->ulLocateTime;
						pDevice->lastLatitude = pDevLbsMsg_->dRefLatitude;
						pDevice->lastLongitude = pDevLbsMsg_->dRefLngitude;
						pDevice->nCoordinate = pDevLbsMsg_->nCoordinate;
						pDevice->nLocateType = 2;
						pDevice->nBattery = pDevLbsMsg_->usDeviceBattery;
						sprintf_s(szSql, sizeof(szSql), "update device_info set isOnline=1, battery=%hu, "
							"lastActiveTime='%s', latitude=%f, longitude=%f, lastLocateTime='%s', coordinate=%d, "
							"locateType=2 where deviceId='%s';", pDevLbsMsg_->usDeviceBattery, szDatetime, 
							pDevLbsMsg_->dRefLatitude, pDevLbsMsg_->dRefLngitude, szLocateDatetime, 
							pDevLbsMsg_->nCoordinate, pDevLbsMsg_->szDeviceId);
					}
					sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s lbs location, lat=%f, "
						"lng=%f, coordinate=%d, locateTime=%s, msgSeq=%u, msgTime=%lu\r\n", __FUNCTION__, 
						__LINE__, pDevLbsMsg_->szDeviceId, pDevLbsMsg_->dRefLatitude, pDevLbsMsg_->dRefLngitude,
						pDevLbsMsg_->nCoordinate, szLocateDatetime, uiMsgSeq_, ulMsgTime_);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
				}
				else {
					sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]ignore deviceId=%s lbs location, "
						"lat=%f, lng=%f, coordinate=%d, locateTime=%s, msgSeq=%u, msgTime=%lu, lastMsgSeq=%u,"
						" lastMsgTime=%lu\r\n", __FUNCTION__, __LINE__, pDevLbsMsg_->szDeviceId, 
						pDevLbsMsg_->dRefLatitude, pDevLbsMsg_->dRefLngitude, pDevLbsMsg_->nCoordinate,
						szLocateDatetime, uiMsgSeq_, ulMsgTime_, pDevice->uiLastMsgSeq, pDevice->ulLastActiveTime);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
				}
			}
		}
		else {
			broker::EscortDevice * pDevice = new broker::EscortDevice();
			memset(pDevice, 0, sizeof(broker::EscortDevice));
			pDevice->fenceList.clear();
			strcpy_s(pDevice->szDeviceId, sizeof(pDevice->szDeviceId), pDevLbsMsg_->szDeviceId);
			strcpy_s(pDevice->szFactoryId, sizeof(pDevice->szFactoryId), pDevLbsMsg_->szFactoryId);
			pDevice->lastLatitude = pDevLbsMsg_->dRefLatitude;
			pDevice->lastLongitude = pDevLbsMsg_->dRefLngitude;
			pDevice->nOnline = 1;
			pDevice->nCoordinate = pDevLbsMsg_->nCoordinate;
			pDevice->nBattery = pDevLbsMsg_->usDeviceBattery;
			pDevice->nLocateType = 2;
			pDevice->ulLocateTime = pDevLbsMsg_->ulLocateTime;
			pDevice->ulLastActiveTime = ulMsgTime_;
			pDevice->uiLastMsgSeq = uiMsgSeq_;
			m_devList.emplace(strDeviceId, pDevice);
			sprintf_s(szSql, sizeof(szSql), "insert into device_info(deviceId, factoryId, isOnline, "
				"isLoose, battery, lastActiveTime, latitude, longitude, lastLocateTime, coordinate, "
				"locateType) values('%s', '%s', 1, 0, %hu, '%s', %f, %f, '%s', %d, 2);", 
				pDevLbsMsg_->szDeviceId, pDevLbsMsg_->szFactoryId, pDevLbsMsg_->usDeviceBattery, 
				szDatetime, pDevLbsMsg_->dRefLatitude, pDevLbsMsg_->dRefLngitude, szLocateDatetime,
				pDevLbsMsg_->nCoordinate);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]deviceId=%s online, lbs location, "
				"lat=%f, lng=%f, coordinate=%d, locateType=2, locateTime=%s, msgSeq=%u, msgTime=%lu\r\n", 
				__FUNCTION__, __LINE__, pDevLbsMsg_->szDeviceId, pDevLbsMsg_->dRefLatitude, 
				pDevLbsMsg_->dRefLngitude, pDevLbsMsg_->nCoordinate, szLocateDatetime, uiMsgSeq_, ulMsgTime_);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
		pthread_mutex_unlock(&m_mutex4DevList);
		if (strlen(szSql)) {
			int rc = sqlite3_exec(m_pDb, szSql, NULL, NULL, NULL);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]sql=%s, ret=%d\r\n", 
				__FUNCTION__, __LINE__, szSql, rc);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
	}
}

void ProtocolBroker::handleDeviceCommandMessage(ccrfid_device::DeviceCommandInfo * pDevCmdInfo_,
	unsigned int uiMsgSeq_, unsigned long ulMsgTime_)
{
	char szLog[512] = { 0 };
	if (pDevCmdInfo_) {
		std::string strSession;
		std::string strDeviceCmdKey = std::to_string(uiMsgSeq_) + "_" + std::string(pDevCmdInfo_->szDeviceId);
			//+ std::to_string(ulMsgTime_) + "_" + std::string(pDevCmdInfo_->szDeviceId);
		device_protocol::LinkDeviceControlReply devCtrlReply;
		size_t nSize = sizeof(devCtrlReply);
		memset(&devCtrlReply, 0, nSize);
		pthread_mutex_lock(&m_mutex4DevCtrlPair);
		DeviceControlPair::iterator iter = m_devCtrlPair.find(strDeviceCmdKey);
		if (iter != m_devCtrlPair.end()) {
			device_protocol::LinkDeviceControlReply * pReply = iter->second;
			if (pReply) {
				memcpy_s(&devCtrlReply, nSize, pReply, nSize);
				delete pReply;
				pReply = NULL;
			}
			m_devCtrlPair.erase(iter);
		}
		pthread_mutex_unlock(&m_mutex4DevCtrlPair);
		if (pDevCmdInfo_->nParam2 == 0) {
			devCtrlReply.nRepCode = device_protocol::ERROR_NO;
		}
		else {
			devCtrlReply.nRepCode = device_protocol::ERROR_DEVICE_COMMAND_FAILED;
		}
		if (strlen(devCtrlReply.szSession)) {
			strSession = devCtrlReply.szSession;
			std::string strLinkId;
			int nProtocolType = 0, nSecurityPolicy = 0, nResendCount = 0;
			short nSecurityExtra = 0;
			pthread_mutex_lock(&m_mutex4LinkList);
			broker::LinkInfoList::iterator iter = m_linkList.find(strSession);
			if (iter != m_linkList.end()) {
				broker::LinkInfo * pLinkInfo = iter->second;
				if (pLinkInfo) {
					strLinkId = pLinkInfo->szEndpoint;
					nProtocolType = pLinkInfo->nProtocolType;
					nSecurityPolicy = pLinkInfo->nSecurityPolicy;
					nResendCount = pLinkInfo->nResendCount;
					nSecurityExtra = pLinkInfo->nSecurityExtra;
				}
			}
			pthread_mutex_unlock(&m_mutex4LinkList);
			if (!strLinkId.empty()) {
				int nVal = replyLinkControlDevice(&devCtrlReply, strLinkId.c_str(), nProtocolType, 
					nSecurityPolicy, nSecurityExtra);
				if (nVal == -1) {
					//add into 
				}
			}
		}
	}
}

void ProtocolBroker::setDeviceProxyConnect(bool bFlag_)
{
	pthread_mutex_lock(&m_mutex4ProxyConnect);
	m_bConnectProxy = bFlag_;
	pthread_mutex_unlock(&m_mutex4ProxyConnect);
}

bool ProtocolBroker::getDeviceProxyConnect()
{
	bool result = false;
	pthread_mutex_lock(&m_mutex4ProxyConnect);
	result = m_bConnectProxy;
	pthread_mutex_unlock(&m_mutex4ProxyConnect);
	return result;
}

void ProtocolBroker::dispatchMessage(const char * pMsgKey_, const char * pMsgValue_, 
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_)
{

}

void ProtocolBroker::handleLinkInitialize(device_protocol::LinkInitializeRequest * pRequest_, 
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_)
{
	char szLog[512] = { 0 };
	if (pRequest_ && pEndpoint_ && strlen(pEndpoint_)) {
		if (strlen(pRequest_->szAccount) && strlen(pRequest_->szPasswd)) {
			int nRetCode = device_protocol::ERROR_UNKNOW;
			char szSession[20] = { 0 };
			bool bValidated = false;
			int nSecurityExtra = 0;
			std::string strLinkId_old;
			std::string strLinkId = pEndpoint_;
			{
				pthread_mutex_lock(&m_mutex4UserList);
				std::string strUserKey = pRequest_->szAccount;
				broker::EscortUserList::iterator iter = m_userList.find(strUserKey);
				if (iter != m_userList.end()) {
					broker::EscortUser * pUser = iter->second;
					if (pUser) {
						if (strcmp(pUser->szUserId, pRequest_->szAccount) == 0 
							&& strcmp(pUser->szPassword, pRequest_->szPasswd) == 0) {
							if (pUser->nLimitWaterLine == -1) {
								bValidated = true;
							}
							else {
								if (pUser->nCurrentWaterLine < pUser->nLimitWaterLine) {
									bValidated = false;
								}
								else {
									nRetCode = device_protocol::ERROR_ACCOUNT_REACH_PARALLEL_UPPER_LIMIT;
								}
							}
						}
						else {
							nRetCode = device_protocol::ERROR_PASSWD_INCORRECT;
						}
					}
				}
				else {
					nRetCode = device_protocol::ERROR_ACCOUNT_NOT_EXISTS;
				}
				pthread_mutex_unlock(&m_mutex4UserList);
			}
			if (bValidated) {
				bool bLinkHaveSession = false;
				pthread_mutex_lock(&m_mutex4LinkDataList);
				LinkDataList::iterator iter = m_linkDataList.find(strLinkId);
				if (iter != m_linkDataList.end()) {
					broker::LinkData * pLinkData = iter->second;
					if (pLinkData && !pLinkData->userPair.empty()) {
						std::set<std::pair<std::string, std::string>>::iterator iter = pLinkData->userPair.begin();
						std::set<std::pair<std::string, std::string>>::iterator iter_end = pLinkData->userPair.end();
						for (; iter != iter_end; iter++) {
							if (strcmp(iter->first.c_str(), pRequest_->szAccount) == 0) {
								strcpy_s(szSession, sizeof(szSession), iter->second.c_str());
								bLinkHaveSession = true;
								break;
							}
						}
					}
				}
				pthread_mutex_unlock(&m_mutex4LinkDataList);
				if (bLinkHaveSession) {
					if (strlen(pRequest_->szSession)) { //re-init
						std::string strSession = szSession;
						if (strcmp(szSession, pRequest_->szSession) == 0) { //the same session re-init
							pthread_mutex_lock(&m_mutex4LinkList);
							broker::LinkInfoList::iterator it = m_linkList.find(strSession);
							if (it != m_linkList.end()) {
								broker::LinkInfo * pLinkInfo = it->second;
								if (pLinkInfo) {
									nSecurityExtra = pLinkInfo->nSecurityExtra;
									if ((pRequest_->ulReqTime > pLinkInfo->ulLastRequestTime)
										|| (pRequest_->ulReqTime == pLinkInfo->ulLastRequestTime
											&& pRequest_->uiReqSeq > pLinkInfo->uiLastRequestSeq)) {
										if (pLinkInfo->nActiveFlag == 0) {
											pLinkInfo->nActiveFlag = 1;
										}
										pLinkInfo->ulLastRequestTime = pRequest_->ulReqTime;
										pLinkInfo->ulLastActiveTime = (unsigned long)time(NULL);
										pLinkInfo->uiLastRequestSeq = pRequest_->uiReqSeq;
										if (strcmp(pLinkInfo->szEndpoint, pEndpoint_) != 0) {
											strLinkId_old = pLinkInfo->szEndpoint;
											strcpy_s(pLinkInfo->szEndpoint, sizeof(pLinkInfo->szEndpoint), pEndpoint_);
										}
										nRetCode = device_protocol::ERROR_NO;
									}
									else {
										nRetCode = device_protocol::ERROR_REQUEST_IGNORED;
										sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]initialize request from %s "
											"ignore, session=%s, user=%s, reqSeq=%u, reqTime=%lu, lastSeq=%u, lastReqTime=%lu"
											"\r\n", __FUNCTION__, __LINE__, pEndpoint_, pRequest_->szSession,
											pRequest_->szAccount, pRequest_->uiReqSeq, pRequest_->ulReqTime,
											pLinkInfo->uiLastRequestSeq, pLinkInfo->ulLastRequestTime);
										writeLog(szLog, pf_logger::eLOGCATEGORY_WARN, m_usLogType);
									}
								}
							}
							pthread_mutex_unlock(&m_mutex4LinkList);
						}
						else { //diff session
							nRetCode = device_protocol::ERROR_REQUEST_IGNORED;
							sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]initialize request from %s "
								"ignore, reqSession=%s, account=%s, reqSeq=%u, reqTime=%lu, currentSession=%s\r\n",
								__FUNCTION__, __LINE__, pEndpoint_, pRequest_->szSession, pRequest_->szAccount,
								pRequest_->uiReqSeq, pRequest_->ulReqTime, szSession);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
							pthread_mutex_lock(&m_mutex4LinkList);
							broker::LinkInfoList::iterator it = m_linkList.find(strSession);
							if (it != m_linkList.end()) {
								broker::LinkInfo * pLinkInfo = it->second;
								if (pLinkInfo) {
									nSecurityExtra = pLinkInfo->nSecurityExtra;
									if ((pRequest_->ulReqTime > pLinkInfo->ulLastRequestTime)
										|| (pRequest_->ulReqTime == pLinkInfo->ulLastRequestTime
											&& pRequest_->uiReqSeq > pLinkInfo->uiLastRequestSeq)) {
										if (pLinkInfo->nActiveFlag == 0) {
											pLinkInfo->nActiveFlag = 1;
										}
										pLinkInfo->ulLastRequestTime = pRequest_->ulReqTime;
										pLinkInfo->ulLastActiveTime = (unsigned long)time(NULL);
										pLinkInfo->uiLastRequestSeq = pRequest_->uiReqSeq;
										if (strcmp(pLinkInfo->szEndpoint, pEndpoint_) != 0) {
											strLinkId_old = pLinkInfo->szEndpoint;
											strcpy_s(pLinkInfo->szEndpoint, sizeof(pLinkInfo->szEndpoint), pEndpoint_);
										}
									}
								}
							}
							pthread_mutex_unlock(&m_mutex4LinkList);
						}
					}
					else { //init 
						std::string strSession = szSession;
						pthread_mutex_lock(&m_mutex4LinkList);
						broker::LinkInfoList::iterator it = m_linkList.find(strSession);
						if (it != m_linkList.end()) {
							broker::LinkInfo * pLinkInfo = it->second;
							if (pLinkInfo) {
								nSecurityExtra = pLinkInfo->nSecurityExtra;
								if ((pRequest_->ulReqTime > pLinkInfo->ulLastRequestTime)
									|| (pRequest_->ulReqTime == pLinkInfo->ulLastRequestTime
										&& pRequest_->uiReqSeq > pLinkInfo->uiLastRequestSeq)) {
									if (pLinkInfo->nActiveFlag == 0) {
										pLinkInfo->nActiveFlag = 1;
									}
									pLinkInfo->ulLastActiveTime = (unsigned long)time(NULL);
									pLinkInfo->ulLastRequestTime = pRequest_->ulReqTime;
									pLinkInfo->uiLastRequestSeq = pRequest_->uiReqSeq;
									if (strcmp(pLinkInfo->szEndpoint, pEndpoint_) != 0) {
										strLinkId_old = pLinkInfo->szEndpoint;
										strcpy_s(pLinkInfo->szEndpoint, sizeof(pLinkInfo->szEndpoint), pEndpoint_);
									}
								}
							}
						}
						pthread_mutex_unlock(&m_mutex4LinkList);
						nRetCode = device_protocol::ERROR_REQUEST_IGNORED;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]initialize request from %s ignore,"
							" account=%s, reqSeq=%u, reqTime=%lu, current session=%s\r\n", __FUNCTION__, __LINE__,
							pEndpoint_, pRequest_->szAccount, pRequest_->uiReqSeq, pRequest_->ulReqTime,
							szSession);
						writeLog(szLog, pf_logger::eLOGCATEGORY_WARN, m_usLogType);
					}
				}
				else { //not holding session
					if (strlen(pRequest_->szSession)) { //re-init
						pthread_mutex_lock(&m_mutex4LinkList);
						std::string strSession = pRequest_->szSession;
						broker::LinkInfoList::iterator it = m_linkList.find(strSession);
						if (it != m_linkList.end()) {
							broker::LinkInfo * pLink = it->second;
							if (pLink) {
								nSecurityExtra = pLink->nSecurityExtra;
								if (strcmp(pLink->szAccount, pRequest_->szAccount) == 0) { //check session with account
									if (strlen(pLink->szEndpoint) == 0) { //link endpoint is empty
										if (pRequest_->ulReqTime > pLink->ulLastActiveTime
											|| (pRequest_->ulReqTime == pLink->ulLastActiveTime 
												&& pRequest_->uiReqSeq < pLink->uiLastRequestSeq)) {
											if (pLink->nActiveFlag == 0) {
												pLink->nActiveFlag = 1;
											}
											pLink->ulLastActiveTime = pRequest_->ulReqTime;
											pLink->uiLastRequestSeq = pRequest_->uiReqSeq;
											pLink->nProtocolType = nProtocolType_;
											pLink->nSecurityPolicy = nSecurityPolicy_;
											strLinkId_old = pLink->szEndpoint;
											strcpy_s(pLink->szEndpoint, sizeof(pLink->szEndpoint), pEndpoint_);
											strcpy_s(szSession, sizeof(szSession), pRequest_->szSession);
											nRetCode = device_protocol::ERROR_NO;
										}
										else {
											nRetCode = device_protocol::ERROR_REQUEST_IGNORED;
											sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]initialize request from %s "
												"ignore, account=%s, reqSession=%s, reqSeq=%u, reqTime=%lu, lastReqSeq=%u, "
												"lastReqTime=%lu\r\n", __FUNCTION__, __LINE__, pEndpoint_, pRequest_->szAccount,
												pRequest_->szSession, pRequest_->uiReqSeq, pRequest_->ulReqTime,
												pLink->uiLastRequestSeq, pLink->ulLastRequestTime);
											writeLog(szLog, pf_logger::eLOGCATEGORY_WARN, m_usLogType);
										}
									}
									else { //link endpoint is not empty
										if (strcmp(pLink->szEndpoint, pEndpoint_) == 0) { //same endpoint init request
											if (pRequest_->ulReqTime > pLink->ulLastActiveTime
												|| (pRequest_->ulReqTime == pLink->ulLastActiveTime 
													&& pRequest_->uiReqSeq > pLink->uiLastRequestSeq)) {
												if (pLink->nActiveFlag == 0) {
													pLink->nActiveFlag = 1;
												}
												pLink->ulLastActiveTime = pRequest_->ulReqTime;
												pLink->nProtocolType = nProtocolType_;
												pLink->nSecurityPolicy = nSecurityPolicy_;
												strcpy_s(szSession, sizeof(szSession), pRequest_->szSession);
												nRetCode = device_protocol::ERROR_NO;
											}
										}
										else { //not same endpoint init request
											if (pLink->nActiveFlag == 0) { //old endpoint is deactived
												pLink->nActiveFlag = 1;
												pLink->ulLastActiveTime = pRequest_->ulReqTime;
												pLink->uiLastRequestSeq = pRequest_->uiReqSeq;
												pLink->nProtocolType = nProtocolType_;
												pLink->nSecurityPolicy = nSecurityPolicy_;
												strLinkId_old = pLink->szEndpoint;
												strcpy_s(pLink->szEndpoint, sizeof(pLink->szEndpoint), pEndpoint_);
												strcpy_s(szSession, sizeof(szSession), pRequest_->szSession);
												nRetCode = device_protocol::ERROR_NO;
											}
											else { //endpoint is actived
												generateSession(szSession, sizeof(szSession));
												broker::LinkInfo * pLink = new broker::LinkInfo();
												memset(pLink, 0, sizeof(broker::LinkInfo));
												pLink->nActiveFlag = 1;
												pLink->nAliveMissToleranceCount = 1;
												pLink->nKeepAliveInterval = 30;
												pLink->nReplyWaitTimeout = 10;
												pLink->nResendCount = 0;
												pLink->nProtocolType = nProtocolType_;
												pLink->nSecurityPolicy = nSecurityPolicy_;
												pLink->nSecurityExtra = rand() % 65536;
												nSecurityExtra = pLink->nSecurityExtra;
												strcpy_s(pLink->szAccount, sizeof(pLink->szAccount), pRequest_->szAccount);
												strcpy_s(pLink->szSession, sizeof(pLink->szSession), pRequest_->szSession);
												strLinkId_old = pLink->szEndpoint;
												strcpy_s(pLink->szEndpoint, sizeof(pLink->szEndpoint), pEndpoint_);
												pLink->ulLastActiveTime = pRequest_->ulReqTime;
												if (increateUserInstance(pRequest_->szAccount)) {
													std::string strSession = szSession;
													m_linkList.emplace(strSession, pLink);
													nRetCode = device_protocol::ERROR_NO;
												}
												else {
													delete pLink;
													pLink = NULL;
													nRetCode = device_protocol::ERROR_ACCOUNT_REACH_PARALLEL_UPPER_LIMIT;
												}
											}
										}
									}
								}
								else { 
									//not match account, open new session
									generateSession(szSession, sizeof(szSession));
									broker::LinkInfo * pLink = new broker::LinkInfo();
									memset(pLink, 0, sizeof(broker::LinkInfo));
									pLink->nActiveFlag = 1;
									pLink->nAliveMissToleranceCount = 1;
									pLink->nKeepAliveInterval = 30;
									pLink->nReplyWaitTimeout = 10;
									pLink->nResendCount = 0;
									pLink->nProtocolType = nProtocolType_;
									pLink->nSecurityPolicy = nSecurityPolicy_;
									strcpy_s(pLink->szAccount, sizeof(pLink->szAccount), pRequest_->szAccount);
									strcpy_s(pLink->szSession, sizeof(pLink->szSession), pRequest_->szSession);
									strcpy_s(pLink->szEndpoint, sizeof(pLink->szEndpoint), pEndpoint_);
									pLink->ulLastActiveTime = pRequest_->ulReqTime;
									if (increateUserInstance(pRequest_->szAccount)) {
										std::string strSession = szSession;
										m_linkList.emplace(strSession, pLink);
										nRetCode = device_protocol::ERROR_NO;
									}
									else {
										delete pLink;
										pLink = NULL;
										nRetCode = device_protocol::ERROR_ACCOUNT_REACH_PARALLEL_UPPER_LIMIT;
									}
								}
							}
						}
						else {
							//invalid session
							generateSession(szSession, sizeof(szSession));
							broker::LinkInfo * pLink = new broker::LinkInfo();
							memset(pLink, 0, sizeof(broker::LinkInfo));
							pLink->nActiveFlag = 1;
							pLink->nAliveMissToleranceCount = 1;
							pLink->nKeepAliveInterval = 30;
							pLink->nReplyWaitTimeout = 10;
							pLink->nResendCount = 1;
							pLink->nProtocolType = nProtocolType_;
							pLink->nSecurityPolicy = nSecurityPolicy_;
							strcpy_s(pLink->szAccount, sizeof(pLink->szAccount), pRequest_->szAccount);
							strcpy_s(pLink->szSession, sizeof(pLink->szSession), pRequest_->szSession);
							strcpy_s(pLink->szEndpoint, sizeof(pLink->szEndpoint), pEndpoint_);
							pLink->ulLastActiveTime = pRequest_->ulReqTime;
							if (increateUserInstance(pRequest_->szAccount)) {
								std::string strSession = szSession;
								m_linkList.emplace(strSession, pLink);
								nRetCode = device_protocol::ERROR_NO;
							}
							else {
								delete pLink;
								pLink = NULL;
								nRetCode = device_protocol::ERROR_ACCOUNT_REACH_PARALLEL_UPPER_LIMIT;
							}
						}
						pthread_mutex_unlock(&m_mutex4LinkList);
					}
					else { //fresh
						generateSession(szSession, sizeof szSession);
						broker::LinkInfo * pLink = new broker::LinkInfo();
						memset(pLink, 0, sizeof(broker::LinkInfo));
						pLink->nActiveFlag = 1;
						pLink->nAliveMissToleranceCount = 1;
						pLink->nKeepAliveInterval = 30;
						pLink->nReplyWaitTimeout = 10;
						pLink->nResendCount = 0;
						pLink->nProtocolType = nProtocolType_;
						pLink->nSecurityPolicy = nSecurityPolicy_;
						strcpy_s(pLink->szAccount, sizeof(pLink->szAccount), pRequest_->szAccount);
						strcpy_s(pLink->szSession, sizeof(pLink->szSession), pRequest_->szSession);
						strcpy_s(pLink->szEndpoint, sizeof(pLink->szEndpoint), pEndpoint_);
						pLink->ulLastActiveTime = pRequest_->ulReqTime;
						pLink->nSecurityExtra = rand() % 65536;
						nSecurityExtra = pLink->nSecurityExtra;
						if (increateUserInstance(pRequest_->szAccount)) {
							std::string strSession = szSession;
							pthread_mutex_lock(&m_mutex4LinkList);
							m_linkList.emplace(strSession, pLink);
							pthread_mutex_unlock(&m_mutex4LinkList);
							nRetCode = device_protocol::ERROR_NO;
						}
						else {
							delete pLink;
							pLink = NULL;
							nRetCode = device_protocol::ERROR_ACCOUNT_REACH_PARALLEL_UPPER_LIMIT;
						}
					}
				}
			}
			if (nRetCode == device_protocol::ERROR_NO) {
				//update linkData
				std::string strUser = pRequest_->szAccount;
				std::string strSession = szSession;
				std::pair<std::string, std::string> foo = std::make_pair(strUser, strSession);
				pthread_mutex_lock(&m_mutex4LinkDataList);
				LinkDataList::iterator iter = m_linkDataList.find(strLinkId);
				if (iter != m_linkDataList.end()) {
					broker::LinkData * pLinkData = iter->second;
					if (pLinkData) {
						if (pLinkData->userPair.count(foo) == 0) {
							pLinkData->userPair.emplace(foo);
						}
					}
				}
				if (!strLinkId_old.empty()) {
					LinkDataList::iterator iter2 = m_linkDataList.find(strLinkId_old);
					if (iter2 != m_linkDataList.end()) {
						broker::LinkData * pLinkData2 = iter2->second;
						if (pLinkData2) {
							if (pLinkData2->userPair.count(foo)) {
								pLinkData2->userPair.erase(foo);
							}
						}
					}
				}
				pthread_mutex_unlock(&m_mutex4LinkDataList);
			}
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]link initialize request from %s, "
				"account=%s, seq=%u, time=%lu, session=%s, retcode=%d\r\n", __FUNCTION__, __LINE__, 
				pEndpoint_, pRequest_->szAccount, pRequest_->uiReqSeq, pRequest_->ulReqTime, szSession,
				nRetCode);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
			device_protocol::LinkInitializeReply linkReply;
			linkReply.nRepCode = nRetCode;
			strcpy_s(linkReply.szAccount, sizeof(linkReply.szAccount), pRequest_->szAccount);
			strcpy_s(linkReply.szSession, sizeof(linkReply.szSession), szSession);
			linkReply.uiRepSeq = pRequest_->uiReqSeq;
			linkReply.ulRepTime = pRequest_->ulReqTime;
			if (replyLinkInitialize(&linkReply, pEndpoint_, nProtocolType_, nSecurityPolicy_,
				nSecurityExtra) == -1) {
				
			}
		}
	}
}

int ProtocolBroker::replyLinkInitialize(device_protocol::LinkInitializeReply * pReply_, 
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_, int nSecurityExtra_)
{
	int result = -1;
	if (pReply_ && pEndpoint_ && strlen(pEndpoint_) && strlen(pReply_->szSession)) {
		char szRepDatetime[20] = { 0 };
		format_datetime(pReply_->ulRepTime, szRepDatetime, sizeof(szRepDatetime));
		char szReply[512] = { 0 };
		sprintf_s(szReply, sizeof(szReply), "{\"cmd\":%d,\"account\":\"%s\",\"seq\":%u,\"datetime\":\"%s\","
			"\"sessoion\":\"%s\",\"retcode\":%d}", device_protocol::CMD_CONNECTION_INITIALIZE_REPLY, 
			pReply_->szAccount, pReply_->uiRepSeq, szRepDatetime, pReply_->szSession, pReply_->nRepCode);
		int nRetVal = sendDataViaEndpoint(szReply, strlen(szReply), pEndpoint_, nProtocolType_, 
			nSecurityPolicy_, nSecurityExtra_);
		if (nRetVal == 0) {
			result = 0;
		}
	}
	return result;
}

void ProtocolBroker::handleLinkUninitialize(device_protocol::LinkUninitializeRequest * pRequest_, 
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_)
{
	char szLog[512] = { 0 };
	if (pRequest_ && pEndpoint_ && strlen(pRequest_->szSession) && strlen(pEndpoint_)) {
		int nRetCode = device_protocol::ERROR_UNKNOW;
		std::string strSession = pRequest_->szSession;
		std::string strUser;
		std::string strLinkIdWithSession;
		int nResendCount = 0;
		int nSecurityExtra = 0;
		bool bValidLink = false;
		{
			pthread_mutex_lock(&m_mutex4LinkList);
			broker::LinkInfoList::iterator iter = m_linkList.find(strSession);
			if (iter != m_linkList.end()) {
				bValidLink = true;
				broker::LinkInfo * pLinkInfo = iter->second;
				if (pLinkInfo) {
					strUser = pLinkInfo->szAccount;
					strLinkIdWithSession = pLinkInfo->szEndpoint;
					nResendCount = pLinkInfo->nResendCount;
					nSecurityExtra = pLinkInfo->nSecurityExtra;
					delete pLinkInfo;
					pLinkInfo = NULL;
				}
				m_linkList.erase(iter);
			}
			else {
				nRetCode = device_protocol::ERROR_SESSION_INVALID;
			}
			pthread_mutex_unlock(&m_mutex4LinkList);
		}
		if (bValidLink) {
			nRetCode = device_protocol::ERROR_NO;
			{
				pthread_mutex_lock(&m_mutex4LinkDataList);
				LinkDataList::iterator iter = m_linkDataList.find(strLinkIdWithSession);
				if (iter != m_linkDataList.end()) {
					broker::LinkData * pLinkData = iter->second;
					if (pLinkData) {
						std::pair<std::string, std::string> foo = std::make_pair(strUser, strSession);
						if (pLinkData->userPair.count(foo) != 0) {
							pLinkData->userPair.erase(foo);
						}
					}
				}
				pthread_mutex_unlock(&m_mutex4LinkDataList);
			}
			{
				pthread_mutex_lock(&m_mutex4UserList);
				broker::EscortUserList::iterator iter = m_userList.find(strUser);
				if (iter != m_userList.end()) {
					broker::EscortUser * pUserInfo = iter->second;
					if (pUserInfo) {
						pUserInfo->nCurrentWaterLine -= 1;
						if (pUserInfo->nCurrentWaterLine < 0) {
							pUserInfo->nCurrentWaterLine = 0;
						}
					}
				}
				pthread_mutex_unlock(&m_mutex4UserList);
			}
		}
		sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]link uninitialize request from %s, "
			"session=%s, reqSeq=%u, reqTime=%lu, retcode=%d, accout=%s\r\n", __FUNCTION__, __LINE__,
			strSession.c_str(), pRequest_->uiReqSeq, pRequest_->ulReqTime, nRetCode, strUser.c_str());
		writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		device_protocol::LinkUnitializeReply uninitReply;
		memset(&uninitReply, 0, sizeof(uninitReply));
		uninitReply.nRepCode = nRetCode;
		strcpy_s(uninitReply.szSession, sizeof(uninitReply.szSession), strSession.c_str());
		uninitReply.uiReqSeq = pRequest_->uiReqSeq;
		uninitReply.ulReqTime = pRequest_->ulReqTime;
		if (replyLinkUninitialize(&uninitReply, pEndpoint_, nProtocolType_, nSecurityPolicy_,
			nSecurityExtra) == -1) {
			if (nResendCount) {

			}
		}
	}
}

int ProtocolBroker::replyLinkUninitialize(device_protocol::LinkUnitializeReply * pReply_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_, int nSecurityExtra_)
{
	int result = -1;
	if (pReply_ && pEndpoint_ && strlen(pReply_->szSession) && strlen(pEndpoint_)) {
		char szRepDatetime[20] = { 0 };
		format_datetime(pReply_->ulReqTime, szRepDatetime, sizeof(szRepDatetime));
		char szReply[512] = { 0 };
		sprintf_s(szReply, sizeof(szReply), "{\"cmd\":%d,\"session\":\"%s\",\"seq\":%u,\"datetime\":\"%s\""
			",\"retcode\":%d}", device_protocol::CMD_CONNECTION_UNINITIALIZE_REPLY, pReply_->szSession,
			pReply_->uiReqSeq, szRepDatetime, pReply_->nRepCode);
		int nRetVal = sendDataViaEndpoint(szReply, strlen(szReply), pEndpoint_, nProtocolType_,
			nSecurityPolicy_, nSecurityExtra_);
		if (nRetVal == 0) {
			result = 0;
		}
	}
	return result;
}

void ProtocolBroker::handleLinkSubscribeDevice(device_protocol::LinkSubscribeDeviceRequest * pRequest_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_)
{
	if (pRequest_ && pEndpoint_ && strlen(pRequest_->szSession) && strlen(pRequest_->szDeviceId)
		&& strlen(pRequest_->szDeviceId)) {
		std::string strSession = pRequest_->szSession;
		std::string strDeviceId = pRequest_->szDeviceId;
		std::string strLinkId = pEndpoint_;
		std::string strLinkId_old;
		std::string strUser;
		bool bUpdateLink = false;
		bool bLastest = false;
		int nRetCode = device_protocol::ERROR_UNKNOW;
		int nResendCount = 0;
		int nSecurityExtra = 0;
		char szLog[512] = { 0 };
		{
			pthread_mutex_lock(&m_mutex4LinkList);
			broker::LinkInfoList::iterator iter = m_linkList.find(strSession);
			if (iter != m_linkList.end()) {
				broker::LinkInfo * pLinkInfo = iter->second;
				if (pLinkInfo) {
					nResendCount = pLinkInfo->nResendCount;
					nSecurityExtra = pLinkInfo->nSecurityExtra;
					if (pLinkInfo->ulLastRequestTime < pRequest_->ulReqTime
						|| (pLinkInfo->ulLastRequestTime == pRequest_->ulReqTime
							&& pLinkInfo->uiLastRequestSeq < pRequest_->uiReqSeq)) {
						bLastest = true;
						pLinkInfo->ulLastActiveTime = (unsigned long)time(NULL);
						pLinkInfo->ulLastRequestTime = pRequest_->ulReqTime;
						pLinkInfo->uiLastRequestSeq = pRequest_->uiReqSeq;
						if (pLinkInfo->nActiveFlag == 0) {
							pLinkInfo->nActiveFlag = 1;
						}
						if (strcmp(pLinkInfo->szEndpoint, pEndpoint_) != 0) {
							bUpdateLink = true;
							strLinkId_old = pLinkInfo->szEndpoint;
							strUser = pLinkInfo->szAccount;
							strcpy_s(pLinkInfo->szEndpoint, sizeof(pLinkInfo->szEndpoint), pEndpoint_);
						}
					}
					else {
						nRetCode = device_protocol::ERROR_REQUEST_IGNORED;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]subscribe device from %s ignore, "
							"session=%s, deviceId=%s, reqSeq=%u, reqTime=%lu, lastReqSeq=%u, lastReqTime=%lu\r\n", 
							__FUNCTION__, __LINE__, pEndpoint_, pRequest_->szSession, pRequest_->szDeviceId, 
							pRequest_->uiReqSeq, pRequest_->ulReqTime, pLinkInfo->uiLastRequestSeq, 
							pLinkInfo->ulLastRequestTime);
						writeLog(szLog, pf_logger::eLOGCATEGORY_WARN, m_usLogType);
					}
				}
			}
			else {
				nRetCode = device_protocol::ERROR_SESSION_INVALID;
			}
			pthread_mutex_unlock(&m_mutex4LinkList);
		}
		if (bLastest) {
			{
				pthread_mutex_lock(&m_mutex4DeviceSubscribers);
				if (pRequest_->nAct == 0) {
					if (m_deviceSubscribers.empty()) {
						SubscriberSessions subSessions;
						subSessions.emplace(strSession);
						m_deviceSubscribers.emplace(strDeviceId, subSessions);
					}
					else {
						DeviceSubscribers::iterator iter = m_deviceSubscribers.find(strDeviceId);
						if (iter != m_deviceSubscribers.end()) {
							if (iter->second.count(strSession) == 0) {
								iter->second.emplace(strSession);
							}
						}
						else {
							SubscriberSessions subSessions;
							subSessions.emplace(strSession);
							m_deviceSubscribers.emplace(strDeviceId, subSessions);
						}
					}
				}
				else {
					if (!m_deviceSubscribers.empty()) {
						DeviceSubscribers::iterator iter = m_deviceSubscribers.find(strDeviceId);
						if (iter != m_deviceSubscribers.end()) {
							if (iter->second.count(strSession)) {
								iter->second.erase(strSession);
							}
						}
					}
				}
				pthread_mutex_unlock(&m_mutex4DeviceSubscribers);
				nRetCode = device_protocol::ERROR_NO;
			}
			if (bUpdateLink) {
				std::pair<std::string, std::string> foo = std::make_pair(strUser, strSession);
				pthread_mutex_lock(&m_mutex4LinkDataList);
				LinkDataList::iterator iter = m_linkDataList.find(strLinkId);
				if (iter != m_linkDataList.end()) {
					broker::LinkData * pLinkData = iter->second;
					if (pLinkData) {
						if (pLinkData->userPair.count(foo) == 0) {
							pLinkData->userPair.emplace(foo);
						}
					}
				}
				if (!strLinkId_old.empty()) {
					LinkDataList::iterator iter2 = m_linkDataList.find(strLinkId_old);
					if (iter2 != m_linkDataList.end()) {
						broker::LinkData * pLinkData2 = iter2->second;
						if (pLinkData2) {
							if (pLinkData2->userPair.count(foo)) {
								pLinkData2->userPair.erase(foo);
							}
						}
					}
				}
				pthread_mutex_unlock(&m_mutex4LinkDataList);
			}
		}
		sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]subscribe device request from %s, "
			"session=%s, deviceId=%s, act=%d, reqSeq=%u, reqTime=%lu, retcode=%d\r\n", __FUNCTION__,
			__LINE__, pRequest_->szSession, pRequest_->szDeviceId, pRequest_->nAct, pRequest_->uiReqSeq,
			pRequest_->ulReqTime, nRetCode);
		writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		device_protocol::LinkSubscribeDeviceReply subDeviceReply;
		memset(&subDeviceReply, 0, sizeof(subDeviceReply));
		subDeviceReply.nRepCode = nRetCode;
		subDeviceReply.nAct = pRequest_->nAct;
		subDeviceReply.uiRepSeq = pRequest_->uiReqSeq;
		subDeviceReply.ulRepTime = pRequest_->ulReqTime;
		strcpy_s(subDeviceReply.szSession, sizeof(subDeviceReply.szSession), pRequest_->szSession);
		strcpy_s(subDeviceReply.szDeviceId, sizeof(subDeviceReply.szDeviceId), pRequest_->szDeviceId);
		if (replyLinkSubscribeDevice(&subDeviceReply, pEndpoint_, nProtocolType_,
			nSecurityPolicy_, nSecurityExtra) == -1) {
			if (nResendCount) {

			}
		}
	}
}

int ProtocolBroker::replyLinkSubscribeDevice(device_protocol::LinkSubscribeDeviceReply * pReply_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_, int nSecurityExtra_)
{
	int result = -1;
	if (pEndpoint_ && pReply_ && strlen(pReply_->szSession) && strlen(pReply_->szDeviceId)
		&& strlen(pEndpoint_)) {
		char szRepDatetime[20];
		format_datetime(pReply_->ulRepTime, szRepDatetime, sizeof(szRepDatetime));
		char szReply[512] = { 0 };
		sprintf_s(szReply, sizeof(szReply), "{\"cmd\":%d,\"session\":\"%s\",\"deviceId\":\"%s\",\"act\":%d"
			",\"seq\":%u,\"datetime\":\"%s\",\"retcode\":%d}",
			device_protocol::CMD_CONNECTION_SUBSCRIBE_DEVICE_REPLY, pReply_->szSession, pReply_->szDeviceId,
			pReply_->nAct, pReply_->uiRepSeq, szRepDatetime, pReply_->nRepCode);
		int nRetVal = sendDataViaEndpoint(szReply, strlen(szReply), pEndpoint_, nProtocolType_,
			nSecurityPolicy_, nSecurityExtra_);
		if (nRetVal == 0) {
			result = 0;
		}

	}
	return result;
}

void ProtocolBroker::handleLinkSetDeviceFence(device_protocol::LinkSetFenceRequest * pRequest_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_)
{
	if (pRequest_ && pEndpoint_ && strlen(pRequest_->szSession) && strlen(pRequest_->szDeviceId)
		&& strlen(pRequest_->fenceInfo.szFenceContent) && strlen(pEndpoint_)) {
		std::string strSession = pRequest_->szSession;
		std::string strDeviceId = pRequest_->szDeviceId;
		std::string strLinkId = pEndpoint_;
		std::string strLinkId_old;
		std::string strUser;
		char szFenceId[20] = { 0 };
		bool bUpdateLink = false;
		bool bLastest = false;
		bool bValidDevice = false;
		int nRetCode = device_protocol::ERROR_UNKNOW;
		int nResendCount = 0;
		int nSecurityExtra = 0;
		char szLog[1024] = { 0 };
		char szSql[512] = { 0 };
		{
			pthread_mutex_lock(&m_mutex4LinkList);
			broker::LinkInfoList::iterator iter = m_linkList.find(strSession);
			if (iter != m_linkList.end()) {
				broker::LinkInfo * pLinkInfo = iter->second;
				if (pLinkInfo) {
					nResendCount = pLinkInfo->nResendCount;
					nSecurityExtra = pLinkInfo->nSecurityExtra;
					if (pLinkInfo->ulLastRequestTime < pRequest_->ulReqTime
						|| (pLinkInfo->ulLastRequestTime == pRequest_->ulReqTime
							&& pLinkInfo->uiLastRequestSeq < pRequest_->uiReqSeq)) {
						bLastest = true;
						pLinkInfo->ulLastActiveTime = (unsigned long)time(NULL);
						pLinkInfo->ulLastRequestTime = pRequest_->ulReqTime;
						pLinkInfo->uiLastRequestSeq = pRequest_->uiReqSeq;
						if (pLinkInfo->nActiveFlag == 0) {
							pLinkInfo->nActiveFlag = 1;
						}
						if (strcmp(pLinkInfo->szEndpoint, pEndpoint_) != 0) {
							bUpdateLink = true;
							strLinkId_old = pLinkInfo->szEndpoint;
							strUser = pLinkInfo->szAccount;
							strcpy_s(pLinkInfo->szEndpoint, sizeof(pLinkInfo->szEndpoint), pEndpoint_);
						}
					}
					else {
						nRetCode = device_protocol::ERROR_REQUEST_IGNORED;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]set device fence request from %s ignore"
							", session=%s, deviceId=%s, reqSeq=%u, reqTime=%lu, lastReqSeq=%u, lastReqTime=%lu\r\n",
						  __FUNCTION__, __LINE__, pEndpoint_, pRequest_->szSession, pRequest_->szDeviceId,
							pRequest_->uiReqSeq, pRequest_->ulReqTime, pLinkInfo->uiLastRequestSeq,
							pLinkInfo->ulLastRequestTime);
						writeLog(szLog, pf_logger::eLOGCATEGORY_WARN, m_usLogType);
					}
				}
			}
			else {
				nRetCode = device_protocol::ERROR_SESSION_INVALID;
			}
			pthread_mutex_unlock(&m_mutex4LinkList);
		}
		if (bLastest) {
			{
				std::set<std::string> devFenceIds;
				std::string strFenceInfo = pRequest_->fenceInfo.toString();
				pthread_mutex_lock(&m_mutex4DevList);
				broker::EscortDeviceList::iterator iter = m_devList.find(strDeviceId);
				if (iter != m_devList.end()) {
					broker::EscortDevice * pDevice = iter->second;
					if (pDevice) {
						bValidDevice = true;
						if (!pDevice->fenceList.empty()) {
							std::set<std::string>::iterator it = pDevice->fenceList.begin();
							std::set<std::string>::iterator it_end = pDevice->fenceList.end();
							for (; it != it_end; it++) {
								devFenceIds.emplace((*it));
							}
						}
					}
					else {
						nRetCode = device_protocol::ERROR_DEVICE_NOT_FOUND;
					}
				}
				pthread_mutex_unlock(&m_mutex4DevList);
				if (bValidDevice) {
					bool bDuplicated = false;
					pthread_mutex_lock(&m_mutex4FenceList);
					if (!devFenceIds.empty()) {
						for (std::set<std::string>::iterator it = devFenceIds.begin(),
							it_end = devFenceIds.end(); it != it_end; ++it) {
							std::string strCellFenceId = *it;
							broker::EscortFenceList::iterator iter = m_fenceList.find(strCellFenceId);
							if (iter != m_fenceList.end()) {
								broker::EscortFence * pFence = iter->second;
								if (pFence) {
									if (pFence->describeFence() == strFenceInfo) {
										bDuplicated = true;
										nRetCode = device_protocol::ERROR_DEVICE_FENCE_ALREADY_EXISTS;
										break;
									}
								}
							}
						}
					}
					if (!bDuplicated) {
						nRetCode = device_protocol::ERROR_NO;
						generateFenceId(szFenceId, sizeof(szFenceId));
						strcpy_s(pRequest_->fenceInfo.szFenceId, sizeof(pRequest_->fenceInfo.szFenceId), szFenceId);
						broker::EscortFence * pFence = new broker::EscortFence();
						pFence->nFenceType = pRequest_->fenceInfo.nFenceType;
						pFence->nCoordinate = pRequest_->fenceInfo.nCoordinate;
						pFence->nFenceState = pRequest_->fenceInfo.nState;
						pFence->nFencePolicy = pRequest_->fenceInfo.nPolicy;
						pFence->ulStartTime = pRequest_->fenceInfo.ulStartTime;
						pFence->ulStopTime = pRequest_->fenceInfo.ulStopTime;
						strcpy_s(pFence->szFenceId, sizeof(pFence->szFenceId), szFenceId);
						strcpy_s(pFence->szDeviceId, sizeof(pFence->szDeviceId), pRequest_->szDeviceId);
						strcpy_s(pFence->szFenceContent, sizeof(pFence->szFenceContent), 
							pRequest_->fenceInfo.szFenceContent);
						m_fenceList.emplace((std::string)szFenceId, pFence);
						char szStartTime[20] = { 0 };
						char szStopTime[20] = { 0 };
						format_datetime2(pFence->ulStartTime, szStartTime, sizeof(szStartTime));
						format_datetime2(pFence->ulStopTime, szStopTime, sizeof(szStopTime));
						sprintf_s(szSql, sizeof(szSql), "insert into fence_info(fenceId, deviceId, fenceType, "
							"fenceContent, startTime, stopTime, state, policy, coordinate) values('%s', '%s', %d, "
							"'%s', '%s', '%s', 0, %d, %d);", szFenceId, pFence->szDeviceId, pFence->nFenceType,
							pFence->szFenceContent, szStartTime, szStopTime, pFence->nFencePolicy, pFence->nCoordinate);
					}
					pthread_mutex_unlock(&m_mutex4FenceList);
				}
			}
			if (bUpdateLink) {
				std::pair<std::string, std::string> foo = std::make_pair(strUser, strSession);
				pthread_mutex_lock(&m_mutex4LinkDataList);
				LinkDataList::iterator iter = m_linkDataList.find(strLinkId);
				if (iter != m_linkDataList.end()) {
					broker::LinkData * pLinkData = iter->second;
					if (pLinkData) {
						if (pLinkData->userPair.count(foo) == 0) {
							pLinkData->userPair.emplace(foo);
						}
					}
				}
				if (!strLinkId_old.empty()) {
					LinkDataList::iterator iter2 = m_linkDataList.find(strLinkId_old);
					if (iter2 != m_linkDataList.end()) {
						broker::LinkData * pLinkData2 = iter2->second;
						if (pLinkData2) {
							if (pLinkData2->userPair.count(foo)) {
								pLinkData2->userPair.erase(foo);
							}
						}
					}
				}
				pthread_mutex_unlock(&m_mutex4LinkDataList);
			}
		}
		sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]set device fence from %s, session=%s, "
			"deviceId=%s, reqSeq=%u, reqTime=%lu, fenceId=%s, fenceType=%d, fencePolicy=%d, coordinate=%d, "
			"stratTime=%lu, stopTime=%lu, content=%s, retcode=%d\r\n", __FUNCTION__, __LINE__, pEndpoint_,
			pRequest_->szSession, pRequest_->szDeviceId, pRequest_->uiReqSeq, pRequest_->ulReqTime, szFenceId,
			pRequest_->fenceInfo.nFenceType, pRequest_->fenceInfo.nPolicy, pRequest_->fenceInfo.nCoordinate,
			pRequest_->fenceInfo.ulStartTime, pRequest_->fenceInfo.ulStopTime, 
			pRequest_->fenceInfo.szFenceContent, nRetCode);
		writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		device_protocol::LinkSetFenceReply setFenceReply;
		memset(&setFenceReply, 0, sizeof(setFenceReply));
		setFenceReply.nRetCode = nRetCode;
		setFenceReply.uiRepSeq = pRequest_->uiReqSeq;
		setFenceReply.ulRepTime = pRequest_->ulReqTime;
		strcpy_s(setFenceReply.szSession, sizeof(setFenceReply.szSession), pRequest_->szSession);
		strcpy_s(setFenceReply.szDeviceId, sizeof(setFenceReply.szDeviceId), pRequest_->szDeviceId);
		strcpy_s(setFenceReply.szFenceId, sizeof(setFenceReply.szFenceId), szFenceId);
		if (nRetCode == device_protocol::ERROR_NO) {
			addDeviceFence(strDeviceId.c_str(), szFenceId);
		}
		int nRet = replyLinkSetDeviceFence(&setFenceReply, pEndpoint_, nProtocolType_, nSecurityPolicy_,
			nSecurityExtra);
		if (strlen(szSql)) {
			int rc = sqlite3_exec(m_pDb, szSql, NULL, NULL, NULL);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]sql=%s, ret=%d\r\n",
				__FUNCTION__, __LINE__, szSql, rc);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
	}
}

int ProtocolBroker::replyLinkSetDeviceFence(device_protocol::LinkSetFenceReply * pReply_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_, int nSecurityExtra_)
{
	int result = -1;
	if (pReply_ && pEndpoint_ && strlen(pReply_->szSession) && strlen(pReply_->szDeviceId)
		&& strlen(pEndpoint_)) {
		char szRepDatetime[20] = { 0 };
		format_datetime(pReply_->ulRepTime, szRepDatetime, sizeof(szRepDatetime));
		char szReply[512] = { 0 };
		sprintf_s(szReply, sizeof(szReply), "{\"cmd\":%d,\"session\":\"%s\",\"deviceId\":\"%s\","
			"\"seq\":%u,\"datetime\":\"%s\",\"fenceId\":\"%s\",\"retcode\":%d}",
			device_protocol::CMD_CONNECTION_DEVICE_SET_FENCE_REPLY, pReply_->szSession, pReply_->szDeviceId,
			pReply_->uiRepSeq, szRepDatetime, pReply_->szFenceId, pReply_->nRetCode);
		int nRetVal = sendDataViaEndpoint(szReply, strlen(szReply), pEndpoint_, nProtocolType_,
			nSecurityPolicy_, nSecurityExtra_);
		if (nRetVal == 0) {
			result = 0;
		}
	}
	return result;
}

void ProtocolBroker::handleLinkGetDeviceFence(device_protocol::LinkGetFenceRequest * pRequest_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_)
{
	if (pRequest_ && pEndpoint_ && strlen(pRequest_->szDeviceId) && strlen(pRequest_->szSession)) {
		std::string strSession = pRequest_->szSession;
		std::string strDeviceId = pRequest_->szDeviceId;
		std::string strLinkId = pEndpoint_;
		std::string strLinkId_old;
		std::string strUser;
		bool bLastest = false;
		bool bUpdateLink = false;
		bool bValidDevice = false;
		int nResendCount = 0;
		int nSecurityExtra = 0;
		int nRetCode = device_protocol::ERROR_UNKNOW;
		char szLog[512] = { 0 };
		device_protocol::LinkGetFenceReply getFenceReply;
		memset(&getFenceReply, 0, sizeof(getFenceReply));
		getFenceReply.uiRepSeq = pRequest_->uiReqSeq;
		getFenceReply.ulRepTime = pRequest_->ulReqTime;
		strcpy_s(getFenceReply.szSession, sizeof(getFenceReply.szSession), pRequest_->szSession);
		strcpy_s(getFenceReply.szDeviceId, sizeof(getFenceReply.szDeviceId), pRequest_->szDeviceId);
		{
			pthread_mutex_lock(&m_mutex4LinkList);
			broker::LinkInfoList::iterator iter = m_linkList.find(strSession);
			if (iter != m_linkList.end()) {
				broker::LinkInfo * pLinkInfo = iter->second;
				if (pLinkInfo) {
					nResendCount = pLinkInfo->nResendCount;
					nSecurityExtra = pLinkInfo->nSecurityExtra;
					if (pLinkInfo->ulLastRequestTime < pRequest_->ulReqTime 
						|| (pLinkInfo->ulLastRequestTime == pRequest_->ulReqTime
							&& pLinkInfo->uiLastRequestSeq < pRequest_->uiReqSeq)) {
						bLastest = true;
						pLinkInfo->ulLastRequestTime = pRequest_->ulReqTime;
						pLinkInfo->uiLastRequestSeq = pRequest_->uiReqSeq;
						pLinkInfo->ulLastActiveTime = (unsigned long)time(NULL);
						if (pLinkInfo->nActiveFlag == 0) {
							pLinkInfo->nActiveFlag = 1;
						}
						if (strcmp(pLinkInfo->szEndpoint, pEndpoint_) != 0) {
							strLinkId_old = pLinkInfo->szEndpoint;
							strUser = pLinkInfo->szAccount;
							bUpdateLink = true;
							strcpy_s(pLinkInfo->szEndpoint, sizeof(pLinkInfo->szEndpoint), pEndpoint_);
						}
					}
					else {
						nRetCode = device_protocol::ERROR_REQUEST_IGNORED;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]get device fence request from %s "
							"ignore, session=%s, deviceId=%s, reqSeq=%u, reqTime=%lu, lastReqSeq=%u, lastReqTime=%lu"
							"\r\n", __FUNCTION__, __LINE__, pEndpoint_, pRequest_->szSession, pRequest_->szDeviceId,
							pRequest_->uiReqSeq, pRequest_->ulReqTime, pLinkInfo->uiLastRequestSeq,
							pLinkInfo->ulLastRequestTime);
						writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
					}
				}
			}
			else {
				nRetCode = device_protocol::ERROR_SESSION_INVALID;
			}
			pthread_mutex_unlock(&m_mutex4LinkList);
		}
		if (bLastest) {
			std::set<std::string> strFenceIds;
			{
				pthread_mutex_lock(&m_mutex4DevList);
				broker::EscortDeviceList::iterator iter = m_devList.find(strDeviceId);
				if (iter != m_devList.end()) {
					broker::EscortDevice * pDevice = iter->second;
					if (pDevice) {
						bValidDevice = true;
						if (!pDevice->fenceList.empty()) {
							std::set<std::string>::iterator it = pDevice->fenceList.begin();
							std::set<std::string>::iterator it_end = pDevice->fenceList.end();
							for (; it != it_end; it++) {
								strFenceIds.emplace((*it));
							}
						}
					}
				}
				else {
					nRetCode = device_protocol::ERROR_DEVICE_NOT_FOUND;
				}
				pthread_mutex_unlock(&m_mutex4DevList);
			}
			if (bValidDevice) {
				nRetCode = device_protocol::ERROR_NO;
				if (strFenceIds.empty()) {
					getFenceReply.uiFenceCount = 0;
					getFenceReply.pFenceList = NULL;
				}
				else {
					getFenceReply.uiFenceCount = strFenceIds.size();
					getFenceReply.pFenceList = new device_protocol::FenceInfo[getFenceReply.uiFenceCount];
					memset(getFenceReply.pFenceList, 0, 
						sizeof(device_protocol::FenceInfo) * getFenceReply.uiFenceCount);
					size_t i = 0;
					std::set<std::string>::iterator it = strFenceIds.begin();
					std::set<std::string>::iterator it_end = strFenceIds.end();
					pthread_mutex_lock(&m_mutex4FenceList);
					for (; it != it_end; it++) {
						broker::EscortFenceList::iterator iter = m_fenceList.find((*it));
						if (iter != m_fenceList.end()) {
							broker::EscortFence * pFence = iter->second;
							if (pFence) {
								getFenceReply.pFenceList[i].nCoordinate = pFence->nCoordinate;
								getFenceReply.pFenceList[i].nFenceType = pFence->nFenceType;
								getFenceReply.pFenceList[i].nPolicy = pFence->nFencePolicy;
								getFenceReply.pFenceList[i].nState = pFence->nFenceState;
								strcpy_s(getFenceReply.pFenceList[i].szFenceId,
									sizeof(getFenceReply.pFenceList[i].szFenceId), pFence->szFenceId);
								strcpy_s(getFenceReply.pFenceList[i].szFenceContent,
									sizeof(getFenceReply.pFenceList[i].szFenceContent), pFence->szFenceContent);
								getFenceReply.pFenceList[i].ulStartTime = pFence->ulStartTime;
								getFenceReply.pFenceList[i].ulStopTime = pFence->ulStopTime;
								i++;
							}
						}
					}
					pthread_mutex_unlock(&m_mutex4FenceList);
				}
			}
			if (bUpdateLink) {
				std::pair<std::string, std::string> foo = std::make_pair(strUser, strSession);
				pthread_mutex_lock(&m_mutex4LinkDataList);
				LinkDataList::iterator iter = m_linkDataList.find(strLinkId);
				if (iter != m_linkDataList.end()) {
					broker::LinkData * pLinkData = iter->second;
					if (pLinkData) {
						if (pLinkData->userPair.count(foo) == 0) {
							pLinkData->userPair.emplace(foo);
						}
					}
				}
				if (!strLinkId_old.empty()) {
					LinkDataList::iterator iter2 = m_linkDataList.find(strLinkId_old);
					if (iter2 != m_linkDataList.end()) {
						broker::LinkData * pLinkData2 = iter2->second;
						if (pLinkData2) {
							if (pLinkData2->userPair.count(foo)) {
								pLinkData2->userPair.erase(foo);
							}
						}
					}
				}
				pthread_mutex_unlock(&m_mutex4LinkDataList);
			}
		}
		getFenceReply.nRepCode = nRetCode;
		sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]get device fence request from %s, "
			"session=%s, deviceId=%s, reqSeq=%u, reqTime=%lu, retCode=%d\r\n", __FUNCTION__, __LINE__,
			pEndpoint_, pRequest_->szSession, pRequest_->szDeviceId, pRequest_->uiReqSeq, 
			pRequest_->ulReqTime, nRetCode);
		writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		if (replyLinkGetDeviceFence(&getFenceReply, pEndpoint_, nProtocolType_, nSecurityPolicy_,
			nSecurityExtra) == -1) {
			if (nResendCount) {

			}
		}
		if (getFenceReply.pFenceList && getFenceReply.uiFenceCount) {
			delete[] getFenceReply.pFenceList;
			getFenceReply.pFenceList = NULL;
			getFenceReply.uiFenceCount = 0;
		}
	}
}

int ProtocolBroker::replyLinkGetDeviceFence(device_protocol::LinkGetFenceReply * pReply_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_, int nSecurityExtra_)
{
	int result = -1;
	if (pReply_  && pEndpoint_ && strlen(pReply_->szSession) && strlen(pReply_->szDeviceId)
		&& strlen(pEndpoint_)) {
		char szRepDatetime[20] = { 0 };
		format_datetime(pReply_->ulRepTime, szRepDatetime, sizeof(szRepDatetime));
		if (pReply_->uiFenceCount && pReply_->pFenceList) {
			std::string strFenceInfos;
			for (size_t i = 0; i < pReply_->uiFenceCount; ++i) {
				if (strlen(pReply_->pFenceList[i].szFenceId)) {
					char szCell[512] = { 0 };
					sprintf_s(szCell, sizeof(szCell), "\"%s|%d|%d|%d|%d|%s|%lu|%lu\"",
						pReply_->pFenceList[i].szFenceId, pReply_->pFenceList[i].nFenceType,
						pReply_->pFenceList[i].nCoordinate, pReply_->pFenceList[i].nPolicy,
						pReply_->pFenceList[i].nState, pReply_->pFenceList[i].szFenceContent,
						pReply_->pFenceList[i].ulStartTime, pReply_->pFenceList[i].ulStopTime);
					if (strFenceInfos.empty()) {
						strFenceInfos = std::string(szCell);
					}
					else {
						strFenceInfos = strFenceInfos + "," + std::string(szCell);
					}
				}
			}
			size_t nSize = 256 + strFenceInfos.size();
			char * pReply = new char[nSize];
			sprintf_s(pReply, nSize, "{\"cmd\":%d,\"session\":\"%s\",\"deviceId\":\"%s\",\"req\":%u,"
				"\"datetime\":\"%s\",\"retcode\":%d,\"list\":[%s]}",
				device_protocol::CMD_CONNECTION_DEVICE_GET_FENCE_REPLY, pReply_->szSession, pReply_->szDeviceId,
				pReply_->uiRepSeq, szRepDatetime, pReply_->nRepCode, strFenceInfos.c_str());
			int nRetVal = sendDataViaEndpoint(pReply, strlen(pReply), pEndpoint_, nProtocolType_,
				nSecurityPolicy_, nSecurityExtra_);
			if (nRetVal == 0) {
				result = 0;
			}
			delete[] pReply;
			pReply = NULL;
		}
		else {
			char szReply[512] = { 0 };
			sprintf_s(szReply, sizeof(szReply), "{\"cmd\":%d,\"session\":\"%s\",\"deviceId\":\"%s\","
				"\"req\":%u,\"datetime\":\"%s\",\"retcode\":%d,\"list\":[]}",
				device_protocol::CMD_CONNECTION_DEVICE_GET_FENCE_REPLY, pReply_->szSession, pReply_->szDeviceId,
				pReply_->uiRepSeq, szRepDatetime, pReply_->nRepCode);
			int nRetVal = sendDataViaEndpoint(szReply, strlen(szReply), pEndpoint_, nProtocolType_,
				nSecurityPolicy_, nSecurityExtra_);
			if (nRetVal == 0) {
				result = 0;
			}
		}
	}
	return result;
}

void ProtocolBroker::handleLinkRemoveDeviceFence(device_protocol::LinkRemoveFenceRequest * pRequest_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_)
{
	if (pRequest_ && pEndpoint_ && strlen(pRequest_->szDeviceId) && strlen(pRequest_->szSession)
		&& strlen(pRequest_->szFenceId) && strlen(pEndpoint_)) {
		std::string strSession = pRequest_->szSession;
		std::string strDeviceId = pRequest_->szDeviceId;
		std::string strLinkId = pEndpoint_;
		std::string strFenceId = pRequest_->szFenceId;
		bool bLastest = false;
		bool bUpdateLink = false;
		std::string strLinkId_old;
		std::string strUser;
		bool bValidDevice = false;
		int nRetCode = device_protocol::ERROR_UNKNOW;
		int nResendCount = 0;
		int nSecurityExtra = 0;
		char szLog[512] = { 0 };
		char szSql[512] = { 0 };
		{
			pthread_mutex_lock(&m_mutex4LinkList);
			broker::LinkInfoList::iterator iter = m_linkList.find(strSession);
			if (iter != m_linkList.end()) {
				broker::LinkInfo * pLinkInfo = iter->second;
				if (pLinkInfo) {
					nResendCount = pLinkInfo->nResendCount;
					nSecurityExtra = pLinkInfo->nSecurityExtra;
					if (pLinkInfo->ulLastRequestTime < pRequest_->ulReqTime
						|| (pLinkInfo->ulLastRequestTime == pRequest_->ulReqTime
							&& pLinkInfo->uiLastRequestSeq < pRequest_->uiReqSeq)) {
						bLastest = true;
						pLinkInfo->uiLastRequestSeq = pRequest_->uiReqSeq;
						pLinkInfo->ulLastRequestTime = pRequest_->ulReqTime;
						pLinkInfo->ulLastActiveTime = (unsigned long)time(NULL);
						if (pLinkInfo->nActiveFlag == 0) {
							pLinkInfo->nActiveFlag = 1;
						}
						if (strcmp(pLinkInfo->szEndpoint, pEndpoint_) != 0) {
							strLinkId_old = pLinkInfo->szEndpoint;
							strUser = pLinkInfo->szAccount;
							bUpdateLink = true;
							strcpy_s(pLinkInfo->szEndpoint, sizeof(pLinkInfo->szEndpoint), pEndpoint_);
						}
					}
					else {
						nRetCode = device_protocol::ERROR_REQUEST_IGNORED;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]remove device fence request from %s "
							"ignore, session=%s, deviceId=%s, fenceId=%s, reqSeq=%u, reqTime=%lu, lastReqSeq=%u, "
							"lastReqTime=%lu\r\n", __FUNCTION__, __LINE__, pEndpoint_, pRequest_->szSession,
							pRequest_->szDeviceId, pRequest_->szFenceId, pRequest_->uiReqSeq, pRequest_->ulReqTime,
							pLinkInfo->uiLastRequestSeq, pLinkInfo->ulLastRequestTime);
						writeLog(szLog, pf_logger::eLOGCATEGORY_WARN, m_usLogType);
					}
				}
			} 
			else {
				nRetCode = device_protocol::ERROR_SESSION_INVALID;
			}
			pthread_mutex_unlock(&m_mutex4LinkList);
		}
		if (bLastest) {
			bool bRemoveAllFence = false;
			if (strFenceId == "*") {
				bRemoveAllFence = true;
			}
			std::set<std::string> fenceIds;
			{
				pthread_mutex_lock(&m_mutex4DevList);
				broker::EscortDeviceList::iterator iter = m_devList.find(strDeviceId);
				if (iter != m_devList.end()) {
					broker::EscortDevice * pDevice = iter->second;
					if (pDevice) {
						bValidDevice = true;
						if (pDevice->fenceList.empty()) {
							if (bRemoveAllFence) {
								nRetCode = device_protocol::ERROR_NO;
							}
							else {
								nRetCode = device_protocol::ERROR_DEVICE_FENCE_NOT_EXISTS;
							}
						}
						else {
							if (bRemoveAllFence) {
								pDevice->fenceList.swap(fenceIds);
								nRetCode = device_protocol::ERROR_NO;
							}
							else {
								//find if exists
								std::set<std::string>::iterator it_end = pDevice->fenceList.end();
								std::set<std::string>::iterator it = std::find(pDevice->fenceList.begin(),
									it_end, strFenceId);
								if (it != it_end) {
									fenceIds.emplace(strFenceId);
									pDevice->fenceList.erase(strFenceId);
									nRetCode = device_protocol::ERROR_NO;
								}
								else {
									nRetCode = device_protocol::ERROR_DEVICE_FENCE_NOT_EXISTS;
								}
							}
						}
					}
				}
				else {
					nRetCode = device_protocol::ERROR_DEVICE_NOT_FOUND;
				}
				pthread_mutex_unlock(&m_mutex4DevList);
			}
			if (bValidDevice) {
				if (!fenceIds.empty()) {
					std::string strFenceIds;
					pthread_mutex_lock(&m_mutex4FenceList);
					std::set<std::string>::iterator it = fenceIds.begin();
					for (; it != fenceIds.end(); ++it) {
						char szCell[20] = { 0 };
						sprintf_s(szCell, sizeof(szCell), "'%s'", (*it).c_str());
						if (strFenceIds.empty()) {
							strFenceIds = (std::string)szCell;
						}
						else {
							strFenceIds = strFenceIds + "," + (std::string)szCell;
						}
						broker::EscortFenceList::iterator iter = m_fenceList.find((*it));
						if (iter != m_fenceList.end()) {
							broker::EscortFence * pFence = iter->second;
							if (pFence) {
								delete pFence;
								pFence = NULL;
							}
							m_fenceList.erase(iter);
						}
					}
					pthread_mutex_unlock(&m_mutex4FenceList);
					sprintf_s(szSql, sizeof(szSql), "delete from fence_info where fenceId in (%s);",
						strFenceIds.c_str());
				}
			}
			if (bUpdateLink) {
				std::pair<std::string, std::string> foo = std::make_pair(strUser, strSession);
				pthread_mutex_lock(&m_mutex4LinkDataList);
				LinkDataList::iterator iter = m_linkDataList.find(strLinkId);
				if (iter != m_linkDataList.end()) {
					broker::LinkData * pLinkData = iter->second;
					if (pLinkData) {
						if (pLinkData->userPair.count(foo) == 0) {
							pLinkData->userPair.emplace(foo);
						}
					}
				}
				if (!strLinkId_old.empty()) {
					LinkDataList::iterator iter2 = m_linkDataList.find(strLinkId_old);
					if (iter2 != m_linkDataList.end()) {
						broker::LinkData * pLinkData2 = iter2->second;
						if (pLinkData2) {
							if (pLinkData2->userPair.count(foo)) {
								pLinkData2->userPair.erase(foo);
							}
						}
					}
				}
				pthread_mutex_unlock(&m_mutex4LinkDataList);
			}
		}
		sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]remove device fence request from %s, "
			"session=%s, deviceId=%s, fenceId=%s, reqSeq=%u, reqTime=%lu, retcode=%d\r\n", __FUNCTION__,
			__LINE__, pRequest_->szSession, pRequest_->szDeviceId, pRequest_->szFenceId, pRequest_->uiReqSeq,
			pRequest_->ulReqTime, nRetCode);
		writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		device_protocol::LinkRemoveFenceReply removeFenceReply;
		memset(&removeFenceReply, 0, sizeof(removeFenceReply));
		strcpy_s(removeFenceReply.szSession, sizeof(removeFenceReply.szSession), pRequest_->szSession);
		strcpy_s(removeFenceReply.szDeviceId, sizeof(removeFenceReply.szDeviceId), pRequest_->szDeviceId);
		strcpy_s(removeFenceReply.szFenceId, sizeof(removeFenceReply.szFenceId), pRequest_->szFenceId);
		removeFenceReply.uiRepSeq = pRequest_->uiReqSeq;
		removeFenceReply.ulReqTime = pRequest_->ulReqTime;
		removeFenceReply.nRepCode = nRetCode;
		replyLinkRemoveDeviceFence(&removeFenceReply, pEndpoint_, nProtocolType_, nSecurityPolicy_,
			nSecurityExtra);
		if (strlen(szSql)) {
			int rc = sqlite3_exec(m_pDb, szSql, NULL, NULL, NULL);
			sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]sql=%s, ret=%d\r\n",
				__FUNCTION__, __LINE__, szSql, rc);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
	}
}

int ProtocolBroker::replyLinkRemoveDeviceFence(device_protocol::LinkRemoveFenceReply * pReply_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_, int nSecurityExtra_)
{
	int result = -1;
	if (pReply_ && pEndpoint_ && strlen(pReply_->szSession) && strlen(pReply_->szDeviceId)
		&& strlen(pReply_->szFenceId) && strlen(pEndpoint_)) {
		char szRepDatetime[20] = { 0 };
		format_datetime(pReply_->ulReqTime, szRepDatetime, sizeof(szRepDatetime));
		char szReply[512] = { 0 };
		sprintf_s(szReply, sizeof(szReply), "{\"cmd\":%d,\"session\":\"%s\",\"deviceId\":\"%s\","
			"\"fenceId\":\"%s\",\"req\":%u,\"datetime\":\"%s\",\"retcode\":%d}",
			device_protocol::CMD_CONNECTION_DEVICE_REMOVE_FENCE_REPLY, pReply_->szSession, pReply_->szDeviceId,
			pReply_->szFenceId, pReply_->uiRepSeq, szRepDatetime, pReply_->nRepCode);
		int nRetVal = sendDataViaEndpoint(szReply, strlen(szReply), pEndpoint_, nProtocolType_,
			nSecurityPolicy_, nSecurityExtra_);
		if (nRetVal == 0) {
			result = 0;
		}
	}
	return result;
}

void ProtocolBroker::handleLinkControlDevice(device_protocol::LinkDeviceControlRequest * pRequest_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_)
{
	if (pRequest_ && pEndpoint_ && strlen(pRequest_->szDeviceId) && strlen(pRequest_->szSession)
		&& strlen(pEndpoint_)) {
		char szLog[512] = { 0 };
		std::string strSession = pRequest_->szSession;
		std::string strDeviceId = pRequest_->szDeviceId;
		std::string strLinkId = pEndpoint_;
		std::string strFactoryId;
		int nResendCount = 0;
		bool bLastest = false;
		bool bValidDevice = false;
		bool bUpdateLink = false;
		std::string strUser;
		std::string strLinkId_old;
		int nRetCode = device_protocol::ERROR_UNKNOW;
		int nSecurityExtra = 0;
		{
			pthread_mutex_lock(&m_mutex4LinkList);
			broker::LinkInfoList::iterator iter = m_linkList.find(strSession);
			if (iter != m_linkList.end()) {
				broker::LinkInfo * pLinkInfo = iter->second;
				if (pLinkInfo) {
					nSecurityExtra = pLinkInfo->nSecurityExtra;
					nResendCount = pLinkInfo->nResendCount;
					if (pLinkInfo->ulLastRequestTime < pRequest_->ulReqDatetime ||
						(pLinkInfo->ulLastRequestTime == pRequest_->ulReqDatetime
							&& pLinkInfo->uiLastRequestSeq < pRequest_->uiReqSeq)) {
						pLinkInfo->uiLastRequestSeq = pRequest_->uiReqSeq;
						pLinkInfo->ulLastRequestTime = pRequest_->ulReqDatetime;
						pLinkInfo->ulLastActiveTime = (unsigned long)time(NULL);
						if (pLinkInfo->nActiveFlag == 0) {
							pLinkInfo->nActiveFlag = 1;
						}
						if (strcmp(pLinkInfo->szEndpoint, pEndpoint_) != 0) {
							strLinkId_old = pLinkInfo->szEndpoint;
							strcpy_s(pLinkInfo->szEndpoint, sizeof(pLinkInfo->szEndpoint), pEndpoint_);
							bUpdateLink = true;
							strUser = pLinkInfo->szAccount;
						}
						bLastest = true;
					}
					else {
						nRetCode = device_protocol::ERROR_REQUEST_IGNORED;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]control device from %s ingore, "
							"session=%s, deviceId=%s, subType=%d, parameter=%d, reqSeq=%u, reqTime=%lu, lastReqSeq=%u"
							", lastReqTime=%lu\r\n", __FUNCTION__, __LINE__, pEndpoint_, pRequest_->szSession,
							pRequest_->szDeviceId, pRequest_->nSubType, pRequest_->nParameter, pRequest_->uiReqSeq,
							pRequest_->ulReqDatetime, pLinkInfo->uiLastRequestSeq, pLinkInfo->ulLastRequestTime);
						writeLog(szLog, pf_logger::eLOGCATEGORY_WARN, m_usLogType);
					}
				}
			}
			else {
				nRetCode = device_protocol::ERROR_SESSION_INVALID;
			}
			pthread_mutex_unlock(&m_mutex4LinkList);
		}
		if (bLastest) {
			{
				pthread_mutex_lock(&m_mutex4DevList);
				broker::EscortDeviceList::iterator iter = m_devList.find(strDeviceId);
				if (iter != m_devList.end()) {
					broker::EscortDevice * pDevice = iter->second;
					if (pDevice) {
						strFactoryId = pDevice->szFactoryId;
						if (pDevice->nOnline == 0) {
							nRetCode = device_protocol::ERROR_DEVICE_OFFLINE;
						}
						else {
							bValidDevice = true;
						}
					}
				}
				else {
					nRetCode = device_protocol::ERROR_DEVICE_NOT_FOUND;
				}
				pthread_mutex_unlock(&m_mutex4DevList);
			}
			if (bUpdateLink) {
				pthread_mutex_lock(&m_mutex4LinkDataList);
				std::pair<std::string, std::string> foo = std::make_pair(strUser, strSession);
				LinkDataList::iterator iter = m_linkDataList.find(strLinkId);
				if (iter != m_linkDataList.end()) {
					broker::LinkData * pLinkData = iter->second;
					if (pLinkData) {
						if (pLinkData->userPair.count(foo) == 0) {
							pLinkData->userPair.emplace(foo);
						}
					}
				}
				if (!strLinkId_old.empty()) {
					LinkDataList::iterator iter2 = m_linkDataList.find(strLinkId_old);
					if (iter2 != m_linkDataList.end()) {
						broker::LinkData * pLinkData = iter2->second;
						if (pLinkData) {
							if (pLinkData->userPair.count(foo) == 1) {
								pLinkData->userPair.erase(foo);
							}
						}
					}
				}
				pthread_mutex_unlock(&m_mutex4LinkDataList);
			}
		}
		if (bValidDevice) {
			if (getDeviceProxyConnect() && m_uiSrvInst) {
				ccrfid_device::DeviceCommandInfo devCmdInfo;
				memset(&devCmdInfo, 0, sizeof(devCmdInfo));
				bool bContinue = true;
				if (pRequest_->nSubType == device_protocol::DEV_CMD_DEVICE_BIND) {
					devCmdInfo.nCommand = ccrfid_device::CMD_BIND;
				}
				else if (pRequest_->nSubType == device_protocol::DEV_CMD_DEVICE_ALARM) {
					devCmdInfo.nCommand = ccrfid_device::CMD_FLEE;
				}
				else if (pRequest_->nSubType == device_protocol::DEV_CMD_DEVICE_TASK) {
					devCmdInfo.nCommand = ccrfid_device::CMD_TASK;
				}
				else if (pRequest_->nSubType == device_protocol::DEV_CMD_DEVICE_SET_LOCATE_INTERVAL) {
					devCmdInfo.nCommand = ccrfid_device::CMD_SET_INTERVAL;
				}
				else if (pRequest_->nSubType == device_protocol::DEV_CMD_DEVICE_REBOOT) {
					devCmdInfo.nCommand = ccrfid_device::CMD_RESET;
				}
				else {
					nRetCode = device_protocol::ERROR_DEVICE_COMMAND_TYPE_NOT_SUPPORT;
					bContinue = false;
				}
				if (bContinue) {
					devCmdInfo.nParam1 = pRequest_->nParameter;
					strcpy_s(devCmdInfo.szDeviceId, sizeof(devCmdInfo.szDeviceId), strDeviceId.c_str());
					strcpy_s(devCmdInfo.szFactoryId, sizeof(devCmdInfo.szFactoryId), strFactoryId.c_str());
					int nVal = EDS_SendCommand(m_uiSrvInst, devCmdInfo);
					if (nVal) {
						nRetCode = device_protocol::ERROR_NO;
						std::string strDeviceCmdKey = std::to_string(pRequest_->uiReqSeq) + "_" + strDeviceId;
							//+ std::to_string(pRequest_->ulReqDatetime) + "_" + strDeviceId;
						device_protocol::LinkDeviceControlReply * pDevCtrlReply = 
							new device_protocol::LinkDeviceControlReply();
						memset(pDevCtrlReply, 0, sizeof(device_protocol::LinkDeviceControlReply));
						pDevCtrlReply->nSubType = pRequest_->nSubType;
						pDevCtrlReply->uiReqSeq = pRequest_->uiReqSeq;
						pDevCtrlReply->ulRepDatetime = pRequest_->ulReqDatetime;
						strcpy_s(pDevCtrlReply->szDeviceId, sizeof(pDevCtrlReply->szDeviceId), strDeviceId.c_str());
						strcpy_s(pDevCtrlReply->szSession, sizeof(pDevCtrlReply->szSession), strSession.c_str());
						pthread_mutex_lock(&m_mutex4DevCtrlPair);
						m_devCtrlPair.emplace(std::make_pair(strDeviceCmdKey, pDevCtrlReply));
						pthread_mutex_unlock(&m_mutex4DevCtrlPair);
					}
				}
			}
			else {
				nRetCode = device_protocol::ERROR_BROKER_CONNECT_PROXY_FAILED;
			}
		}
		sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]device control request from %s, session=%s,"
			" deviceId=%s, cmdType=%d, parameter=%d, reqSeq=%u, reqTime=%lu, retcode=%d\r\n", __FUNCTION__,
			__LINE__, strSession.c_str(), strDeviceId.c_str(), pRequest_->nSubType, pRequest_->nParameter,
			pRequest_->uiReqSeq, pRequest_->ulReqDatetime, nRetCode);
		writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		if (nRetCode != device_protocol::ERROR_NO) {
			device_protocol::LinkDeviceControlReply devCtrlReply;
			memset(&devCtrlReply, 0, sizeof(devCtrlReply));
			devCtrlReply.nRepCode = nRetCode;
			devCtrlReply.nSubType = pRequest_->nSubType;
			devCtrlReply.uiReqSeq = pRequest_->uiReqSeq;
			devCtrlReply.ulRepDatetime = pRequest_->ulReqDatetime;
			strcpy_s(devCtrlReply.szDeviceId, sizeof(devCtrlReply.szDeviceId), strDeviceId.c_str());
			strcpy_s(devCtrlReply.szSession, sizeof(devCtrlReply.szSession), strSession.c_str());
			int nRetVal = replyLinkControlDevice(&devCtrlReply, pEndpoint_, nProtocolType_, nSecurityPolicy_,
				nSecurityExtra);
			if (nRetVal == -1) {

			}
		}
	}
}

int ProtocolBroker::replyLinkControlDevice(device_protocol::LinkDeviceControlReply * pReply_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_, int nSecurityExtra_)
{
	int result = -1;
	if (pReply_ && pEndpoint_ && strlen(pReply_->szSession) && strlen(pReply_->szDeviceId)
		&& strlen(pEndpoint_)) {
		char szRepDatetime[20] = { 0 };
		format_datetime(pReply_->ulRepDatetime, szRepDatetime, sizeof(szRepDatetime));
		char szReply[512] = { 0 };
		sprintf_s(szReply, sizeof(szReply), "{\"cmd\":%d,\"session\":\"%s\",\"deviceId\":\"%s\","
			"\"subType\":%d,\"seq\":%u,\"datetime\":\"%s\",\"retcode\":%d}",
			device_protocol::CMD_CONNECTION_DEVICE_CONTROL_REPLY, pReply_->szSession, pReply_->szDeviceId,
			pReply_->nSubType, pReply_->uiReqSeq, szRepDatetime, pReply_->nRepCode);
		int nRetVal = sendDataViaEndpoint(szReply, sizeof(szReply), pEndpoint_, nProtocolType_,
			nSecurityPolicy_, nSecurityExtra_);
		if (nRetVal == 0) {
			result = 0;
		}
		else {

		}
	}
	return result;
}

void ProtocolBroker::handleLinkKeepAlive(device_protocol::LinkHeartBeatRequest * pRequest_, 
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_)
{
	if (pRequest_ && pEndpoint_ && strlen(pRequest_->szSession) && strlen(pEndpoint_)) {
		std::string strSession = pRequest_->szSession;
		std::string strLinkId = pEndpoint_;
		std::string strLinkId_old;
		std::string strUser;
		bool bUpdateLink = false;
		int nRetCode = device_protocol::ERROR_UNKNOW;
		int nResendCount = 0;
		int nSecurityExtra = 0;
		char szLog[512] = { 0 };
		{
			pthread_mutex_lock(&m_mutex4LinkList);
			broker::LinkInfoList::iterator iter = m_linkList.find(strSession);
			if (iter != m_linkList.end()) {
				broker::LinkInfo * pLinkInfo = iter->second;
				if (pLinkInfo) {
					nResendCount = pLinkInfo->nResendCount;
					nSecurityExtra = pLinkInfo->nSecurityExtra;
					if (pLinkInfo->ulLastRequestTime < pRequest_->ulHeartBeatTime
						|| (pLinkInfo->ulLastRequestTime == pRequest_->ulHeartBeatTime
							&& pLinkInfo->uiLastRequestSeq < pRequest_->uiHeartBeatSeq)) {
						if (pLinkInfo->nActiveFlag == 0) {
							pLinkInfo->nActiveFlag = 1;
						}
						pLinkInfo->uiLastNotifySeq = pRequest_->uiHeartBeatSeq;
						pLinkInfo->ulLastRequestTime = pRequest_->ulHeartBeatTime;
						pLinkInfo->ulLastActiveTime = (unsigned long)time(NULL);
						if (strcmp(pLinkInfo->szEndpoint, pEndpoint_) != 0) {
							bUpdateLink = true;
							strLinkId_old = pLinkInfo->szEndpoint;
							strcpy_s(pLinkInfo->szEndpoint, sizeof(pLinkInfo->szEndpoint), pEndpoint_);
							strUser = pLinkInfo->szAccount;
						}
						nRetCode = device_protocol::ERROR_NO;
					}
					else {
						nRetCode = device_protocol::ERROR_REQUEST_IGNORED;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]keep alive from %s ignore, "
							"session=%s, reqSeq=%u, reqTime=%lu, lastReqSeq=%u, lastReqTime=%lu\r\n",
							__FUNCTION__, __LINE__, pRequest_->szSession, pRequest_->uiHeartBeatSeq,
							pRequest_->ulHeartBeatTime, pLinkInfo->uiLastRequestSeq, pLinkInfo->ulLastRequestTime);
						writeLog(szLog, pf_logger::eLOGCATEGORY_WARN, m_usLogType);
					}
				}
			}
			else {
				nRetCode = device_protocol::ERROR_SESSION_INVALID;
			}
			pthread_mutex_unlock(&m_mutex4LinkList);
		}
		if (bUpdateLink) {
			pthread_mutex_lock(&m_mutex4LinkDataList);
			std::pair<std::string, std::string> foo = std::make_pair(strUser, strSession);
			LinkDataList::iterator iter = m_linkDataList.find(strLinkId);
			if (iter != m_linkDataList.end()) {
				broker::LinkData * pLinkData = iter->second;
				if (pLinkData) {
					if (pLinkData->userPair.count(foo) == 0) {
						pLinkData->userPair.emplace(foo);
					}
				}
			}
			if (!strLinkId_old.empty()) {
				LinkDataList::iterator iter2 = m_linkDataList.find(strLinkId_old);
				if (iter2 != m_linkDataList.end()) {
					broker::LinkData * pLinkData2 = iter2->second;
					if (pLinkData2) {
						if (pLinkData2->userPair.count(foo)) {
							pLinkData2->userPair.erase(foo);
						}
					}
				}
			}
			pthread_mutex_unlock(&m_mutex4LinkDataList);
		}
		char szLog[512] = { 0 };
		sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]keep alive request from %s, session=%s, "
			"reqSeq=%u, reqTime=%lu, retCode=%d\r\n", __FUNCTION__, __LINE__, pEndpoint_, 
			pRequest_->szSession, pRequest_->uiHeartBeatSeq, pRequest_->ulHeartBeatTime, nRetCode);
		writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		device_protocol::LinkHeartBeatReply hbReply;
		hbReply.nRepCode = nRetCode;
		hbReply.uiHeartBeatSeq = pRequest_->uiHeartBeatSeq;
		hbReply.ulHeartBeatTime = pRequest_->ulHeartBeatTime;
		strcpy_s(hbReply.szSession, sizeof(hbReply.szSession), pRequest_->szSession);
		replyLinkKeepAlive(&hbReply, pEndpoint_, nProtocolType_, nSecurityPolicy_, nSecurityExtra);
	}
}

int ProtocolBroker::replyLinkKeepAlive(device_protocol::LinkHeartBeatReply * pReply_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_, int nSecurityExtra_)
{
	int result = -1;
	if (pReply_ && pEndpoint_ && strlen(pReply_->szSession) && strlen(pEndpoint_)) {
		char szRepDatetime[20] = { 0 };
		format_datetime(pReply_->ulHeartBeatTime, szRepDatetime, sizeof(szRepDatetime));
		char szReply[512] = { 0 };
		sprintf_s(szReply, sizeof(szReply), "{\"cmd\":%d,\"session\":\"%s\",\"seq\":%u,\"datetime\":\"%s\""
			",\"retcode\":%d}", device_protocol::CMD_CONNECTION_KEEP_ALIVE_REPLY, pReply_->szSession,
			pReply_->uiHeartBeatSeq, szRepDatetime, pReply_->nRepCode);
		int nRetVal = sendDataViaEndpoint(szReply, strlen(szReply), pEndpoint_, nProtocolType_,
			nSecurityPolicy_, nSecurityExtra_);
		if (nRetVal == 0) {
			result = 0;
		}
	}
	return result;
}

void ProtocolBroker::handleLinkSetParameter(device_protocol::LinkSetParameterRequest * pRequest_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_)
{
	if (pRequest_ && pEndpoint_ && strlen(pRequest_->szSession) && strlen(pEndpoint_)) {
		char szLog[512] = { 0 };
		std::string strSession = pRequest_->szSession;
		std::string strLinkId = pEndpoint_;
		bool bLastest = false;
		bool bUpdateLink = false;
		int nResendCount = 0;
		int nSecurityExtra = 0;
		std::string strUser;
		std::string strLinkId_old;
		int nRetCode = device_protocol::ERROR_UNKNOW;
		{
			pthread_mutex_lock(&m_mutex4LinkList);
			broker::LinkInfoList::iterator iter = m_linkList.find(strSession);
			if (iter != m_linkList.end()) {
				broker::LinkInfo * pLinkInfo = iter->second;
				if (pLinkInfo) {
					nResendCount = pLinkInfo->nResendCount;
					nSecurityExtra = pLinkInfo->nSecurityExtra;
					if (pLinkInfo->ulLastRequestTime < pRequest_->ulReqTime
						|| (pLinkInfo->ulLastRequestTime == pRequest_->ulReqTime
							&& pLinkInfo->uiLastRequestSeq < pRequest_->uiReqSeq)) {
						if (pLinkInfo->nActiveFlag == 0) {
							pLinkInfo->nActiveFlag = 1;
						}
						pLinkInfo->ulLastRequestTime = pRequest_->ulReqTime;
						pLinkInfo->uiLastRequestSeq = pRequest_->uiReqSeq;
						pLinkInfo->ulLastActiveTime = (unsigned long)time(NULL);
						if (strcmp(pLinkInfo->szEndpoint, pEndpoint_) != 0) {
							strLinkId_old = pLinkInfo->szEndpoint;
							strcpy_s(pLinkInfo->szEndpoint, sizeof(pLinkInfo->szEndpoint), pEndpoint_);
							bUpdateLink = true;
							strUser = pLinkInfo->szAccount;
						}
						bLastest = true;
						int nValue = 0;
						switch (pRequest_->nParameterKey) {
							case device_protocol::CONN_PARAM_ALIVE_MISS_TOLERANCE_COUNT: {
								if (isdigit(pRequest_->szParameterValue[0])) {
									nValue = atoi(pRequest_->szParameterValue);
								}
								if (nValue < 1) {
									nValue = 1;
								}
								else if (nValue > 8) {
									nValue = 8;
								}
								pLinkInfo->nAliveMissToleranceCount = nValue;
								nRetCode = device_protocol::ERROR_NO;
								break;
							}
							case device_protocol::CONN_PARAM_KEEP_ALIVE_INTERVAL: {
								if (isdigit(pRequest_->szParameterValue[0])) {
									nValue = atoi(pRequest_->szParameterValue);
								}
								if (nValue == 0) {
									nValue = 30;
								}
								else if (nValue < 10) {
									nValue = 10;
								}
								else if (nValue > 600) {
									nValue = 600;
								}
								pLinkInfo->nKeepAliveInterval = nValue;
								nRetCode = device_protocol::ERROR_NO;
								break;
							}
							case device_protocol::CONN_PARAM_REPLY_WAIT_TIMEOUT: {
								if (isdigit(pRequest_->szParameterValue[0])) {
									nValue = atoi(pRequest_->szParameterValue);
								}
								if (nValue == 0) {
									nValue = 10;
								}
								else if (nValue < 3) {
									nValue = 3;
								}
								else if (nValue > 60) {
									nValue = 60;
								}
								pLinkInfo->nReplyWaitTimeout = nValue;
								nRetCode = device_protocol::ERROR_NO;
								break;
							}
							case device_protocol::CONN_PARAM_RESEND_COUNT: {
								if (isdigit(pRequest_->szParameterValue[0])) {
									nValue = atoi(pRequest_->szParameterValue);
								}
								if (nValue > 5) {
									nValue = 5;
								}
								pLinkInfo->nResendCount = nValue;
								nRetCode = device_protocol::ERROR_NO;
								break;
							}
							default: {
								nRetCode = device_protocol::ERROR_CONNECTION_PARAMETER_TYPE_NOT_SUPPORT;
							}
						}
						nResendCount = pLinkInfo->nResendCount;
					}
					else {
						nRetCode = device_protocol::ERROR_REQUEST_IGNORED;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]set parameter request from %s ignore,"
							" session=%s, parameter=%d, parmeterValue=%s, reqSeq=%u, reqTime=%lu, lastReqSeq=%u, "
							"lastReqTime=%lu\r\n", __FUNCTION__, __LINE__, pEndpoint_, pRequest_->szSession, 
							pRequest_->nParameterKey, pRequest_->szParameterValue, pRequest_->uiReqSeq, 
							pRequest_->ulReqTime, pLinkInfo->uiLastRequestSeq, pLinkInfo->ulLastRequestTime);
						writeLog(szLog, pf_logger::eLOGCATEGORY_WARN, m_usLogType);
					}
				}
			}
			else {
				nRetCode = device_protocol::ERROR_SESSION_INVALID;
			}
			pthread_mutex_unlock(&m_mutex4LinkList);
		}
		if (bLastest) {
			if (bUpdateLink) {
				std::pair <std::string, std::string> foo = std::make_pair(strUser, strSession);
				pthread_mutex_lock(&m_mutex4LinkDataList);
				LinkDataList::iterator iter = m_linkDataList.find(strLinkId);
				if (iter != m_linkDataList.end()) {
					broker::LinkData * pLinkData = iter->second;
					if (pLinkData) {
						if (pLinkData->userPair.count(foo) == 0) {
							pLinkData->userPair.emplace(foo);
						}
					}
				}
				if (!strLinkId_old.empty()) {
					LinkDataList::iterator iter2 = m_linkDataList.find(strLinkId_old);
					if (iter2 != m_linkDataList.end()) {
						broker::LinkData * pLinkData2 = iter->second;
						if (pLinkData2) {
							if (pLinkData2->userPair.count(foo)) {
								pLinkData2->userPair.erase(foo);
							}
						}
					}
				}
				pthread_mutex_unlock(&m_mutex4LinkDataList);
			}
		}
		sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]set parameter from %s, session=%s, "
			"parameterKey=%d, parameterValue=%d, reqSeq=%u, reqTime=%lu, retCode=%d\r\n", __FUNCTION__,
			__LINE__, pRequest_->szSession, pRequest_->nParameterKey, pRequest_->szParameterValue,
			pRequest_->uiReqSeq, pRequest_->ulReqTime, nRetCode);
		writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		device_protocol::LinkSetParameterReply setParamReply;
		setParamReply.nParameterKey = pRequest_->nParameterKey;
		setParamReply.nRepCode = nRetCode;
		setParamReply.uiRepSeq = pRequest_->uiReqSeq;
		setParamReply.ulRepTime = pRequest_->ulReqTime;
		strcpy_s(setParamReply.szSession, sizeof(setParamReply.szSession), pRequest_->szSession);
		replyLinkSetParameter(&setParamReply, pEndpoint_, nProtocolType_, nSecurityPolicy_, 
			nSecurityExtra);
	}
}

int ProtocolBroker::replyLinkSetParameter(device_protocol::LinkSetParameterReply * pReply_, 
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_, int nSecurityExtra_)
{
	int result = -1;
	if (pReply_ && pEndpoint_ && strlen(pReply_->szSession) && strlen(pEndpoint_)) {
		char szRepDatetime[20] = { 0 };
		format_datetime(pReply_->ulRepTime, szRepDatetime, sizeof(szRepDatetime));
		char szReply[512] = { 0 };
		sprintf_s(szReply, sizeof(szReply), "{\"cmd\":%d,\"session\":\"%s\",\"parameterKey\":%d,\"seq\":%u,"
			"\"datetime\":\"%s\",\"retcode\":%d}", device_protocol::CMD_CONNECTION_SET_PARAMETER_REPLY,
			pReply_->szSession, pReply_->uiRepSeq, szRepDatetime, pReply_->nRepCode);
		int nRetVal = sendDataViaEndpoint(szReply, strlen(szReply), pEndpoint_, nProtocolType_,
			nSecurityPolicy_, nSecurityExtra_);
		if (nRetVal == 0) {
			result = 0;
		}
	}
	return result;
}

void ProtocolBroker::handleLinkGetParameter(device_protocol::LinkGetParameterRequest * pRequest_, 
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_)
{
	if (pRequest_ && pEndpoint_ && strlen(pRequest_->szSession) && strlen(pEndpoint_)) {
		std::string strSession = pRequest_->szSession;
		std::string strLinkId = pEndpoint_;
		std::string strUser;
		std::string strLinkId_old;
		bool bUpdateLink = false;
		int nResendCount = 0;
		int nSecurityExtra = 0;
		int nRetCode = device_protocol::ERROR_UNKNOW;
		char szLog[512] = { 0 };
		char szParamValue[32] = { 0 };
		{
			pthread_mutex_lock(&m_mutex4LinkList);
			broker::LinkInfoList::iterator iter = m_linkList.find(strSession);
			if (iter != m_linkList.end()) {
				broker::LinkInfo * pLinkInfo = iter->second;
				if (pLinkInfo) {
					pLinkInfo->nResendCount = pLinkInfo->nResendCount;
					pLinkInfo->nSecurityExtra = pLinkInfo->nSecurityExtra;
					if ((pLinkInfo->ulLastRequestTime < pRequest_->ulReqTime)
						|| (pLinkInfo->ulLastRequestTime == pRequest_->ulReqTime
							&& pLinkInfo->uiLastRequestSeq < pRequest_->uiReqSeq)) {
						pLinkInfo->ulLastRequestTime = pRequest_->ulReqTime;
						pLinkInfo->uiLastRequestSeq = pRequest_->uiReqSeq;
						pLinkInfo->ulLastActiveTime = (unsigned long)time(NULL);
						if (pLinkInfo->nActiveFlag == 0) {
							pLinkInfo->nActiveFlag = 1;
						}
						switch (pRequest_->nParameterKey) {
							case device_protocol::CONN_PARAM_ALIVE_MISS_TOLERANCE_COUNT: {
								sprintf_s(szParamValue, sizeof(szParamValue), "%d", pLinkInfo->nAliveMissToleranceCount);
								nRetCode = device_protocol::ERROR_NO;
								break;
							}
							case device_protocol::CONN_PARAM_KEEP_ALIVE_INTERVAL: {
								sprintf_s(szParamValue, sizeof(szParamValue), "%d", pLinkInfo->nKeepAliveInterval);
								nRetCode = device_protocol::ERROR_NO;
								break;
							}
							case device_protocol::CONN_PARAM_REPLY_WAIT_TIMEOUT: {
								sprintf_s(szParamValue, sizeof(szParamValue), "%d", pLinkInfo->nReplyWaitTimeout);
								nRetCode = device_protocol::ERROR_NO;
								break;
							}
							case device_protocol::CONN_PARAM_RESEND_COUNT: {
								sprintf_s(szParamValue, sizeof(szParamValue), "%d", pLinkInfo->nResendCount);
								nRetCode = device_protocol::ERROR_NO;
								break;
							}
							default: {
								nRetCode = device_protocol::ERROR_CONNECTION_PARAMETER_TYPE_NOT_SUPPORT;
							}
						}
						if (strcmp(pLinkInfo->szEndpoint, pEndpoint_) != 0) {
							strLinkId_old = pLinkInfo->szEndpoint;
							strUser = pLinkInfo->szAccount;
							bUpdateLink = true;
							strcpy_s(pLinkInfo->szEndpoint, sizeof(pLinkInfo->szEndpoint), pEndpoint_);
						}
					}
					else {
						nRetCode = device_protocol::ERROR_SESSION_INVALID;
						sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]get parameter request from %s "
							"ignore, session=%s, reqSeq=%u, reqTime=%lu, lastReqSeq=%u, lastReqTime=%lu\r\n",
							__FUNCTION__, __LINE__, pEndpoint_, pRequest_->szSession, pRequest_->uiReqSeq,
							pRequest_->ulReqTime, pLinkInfo->uiLastRequestSeq, pLinkInfo->ulLastRequestTime);
						writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
					}
				}
			}
			else {
				nRetCode = device_protocol::ERROR_SESSION_INVALID;
			}
			pthread_mutex_unlock(&m_mutex4LinkList);
		}
		if (bUpdateLink) {
			std::pair<std::string, std::string> foo = std::make_pair(strUser, strSession);
			pthread_mutex_lock(&m_mutex4LinkDataList);
			LinkDataList::iterator iter = m_linkDataList.find(strLinkId);
			if (iter != m_linkDataList.end()) {
				broker::LinkData * pLinkData = iter->second;
				if (pLinkData) {
					if (pLinkData->userPair.count(foo) == 0) {
						pLinkData->userPair.emplace(foo);
					}
				}
			}
			if (!strLinkId_old.empty()) {
				LinkDataList::iterator iter2 = m_linkDataList.find(strLinkId_old);
				if (iter2 != m_linkDataList.end()) {
					broker::LinkData * pLinkData2 = iter->second;
					if (pLinkData2) {
						if (pLinkData2->userPair.count(foo)) {
							pLinkData2->userPair.erase(foo);
						}
					}
				}
			}
			pthread_mutex_unlock(&m_mutex4LinkDataList);
		}
		sprintf_s(szLog, sizeof(szLog), "[ProtocolBroker]%s[%d]get parameter from %s, session=%s, "
			"parameterKey=%d, reqSeq=%u, reqTime=%lu, retcode=%d\r\n", __FUNCTION__, __LINE__,
			pEndpoint_, pRequest_->szSession, pRequest_->nParameterKey, pRequest_->uiReqSeq,
			pRequest_->ulReqTime, nRetCode);
		writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		device_protocol::LinkGetParameterReply getParamReply;
		memset(&getParamReply, 0, sizeof(getParamReply));
		getParamReply.nRepCode = nRetCode;
		getParamReply.nParameterKey = pRequest_->nParameterKey;
		getParamReply.uiRepSeq = pRequest_->uiReqSeq;
		getParamReply.ulRepTime = pRequest_->ulReqTime;
		strcpy_s(getParamReply.szParameterValue, sizeof(getParamReply.szParameterValue), szParamValue);
		strcpy_s(getParamReply.szSession, sizeof(getParamReply.szSession), pRequest_->szSession);
		if (replyLinkGetParameter(&getParamReply, pEndpoint_, nProtocolType_, nSecurityPolicy_,
			nSecurityExtra) == -1) {

		}
	}
}

int ProtocolBroker::replyLinkGetParameter(device_protocol::LinkGetParameterReply * pReply_,
	const char * pEndpoint_, int nProtocolType_, int nSecurityPolicy_, int nSecurityExtra_)
{
	int result = -1;
	if (pReply_ && pEndpoint_ && strlen(pReply_->szSession) && strlen(pEndpoint_)) {
		char szRepDatatime[20] = { 0 };
		format_datetime(pReply_->ulRepTime, szRepDatatime, sizeof(szRepDatatime));
		char szReply[512] = { 0 };
		sprintf_s(szReply, sizeof(szReply), "{\"cmd\":%d,\"session\":\"%s\",\"parameterKey\":%d,"
			"\"parameterValue\":\"%s\",\"seq\":%u,\"datetime\":\"%s\",\"retcode\":%d}",
			device_protocol::CMD_CONNECTION_GET_PARAMETER_REPLY, pReply_->szSession,
			pReply_->nParameterKey, pReply_->szParameterValue, pReply_->uiRepSeq,
			szRepDatatime, pReply_->nRepCode);
		int nRetVal = sendDataViaEndpoint(szReply, strlen(szReply), pEndpoint_, nProtocolType_,
			nSecurityPolicy_, nSecurityExtra_);
		if (nRetVal == 0) {
			result = 0;
		}
	}
	return result;
}

int ProtocolBroker::generateSession(char * pSession_, size_t nSize_)
{
	long now = (long)time(NULL);
	char szSession[16] = { 0 };
	sprintf_s(szSession, sizeof(szSession), "%ld", now);
	unsigned char key[crypto_generichash_KEYBYTES];
	randombytes_buf(key, sizeof(key));
	unsigned char szOut[10] = { 0 };
	crypto_shorthash(szOut, (const unsigned char *)szSession, strlen(szSession), key);
	if (nSize_ > 16 && pSession_) {
		for (int i = 0; i < 8; i++) {
			char szCell[4] = { 0 };
			sprintf_s(szCell, sizeof(szCell), "%02x", szOut[i]);
			strcat_s(pSession_, nSize_, szCell);
		}
		return 0;
	}
	else {
		return -1;
	}
}

bool ProtocolBroker::increateUserInstance(const char * pUserId_)
{
	bool result = false;
	if (pUserId_ && strlen(pUserId_)) {
		pthread_mutex_lock(&m_mutex4UserList);
		std::string strUserId = pUserId_;
		broker::EscortUserList::iterator iter = m_userList.find(strUserId);
		if (iter != m_userList.end()) {
			broker::EscortUser * pUser = iter->second;
			if (pUser) {
				if (pUser->nLimitWaterLine == -1) {
					pUser->nCurrentWaterLine += 1;
					result = true;
				}
				else {
					if (pUser->nLimitWaterLine < pUser->nLimitWaterLine) {
						pUser->nLimitWaterLine++;
						result = true;
					}
				}
			}
		}
		pthread_mutex_unlock(&m_mutex4UserList);
	}
	return result;
}

void * startDealLogThread(void * param_)
{
	ProtocolBroker * pBroker = (ProtocolBroker *)param_;
	if (pBroker) {
		pBroker->handleLog();
	}
	pthread_exit(NULL);
	return NULL;
}

void * startDealMsgThread(void * param_)
{
	ProtocolBroker * pBroker = (ProtocolBroker *)param_;
	if (pBroker) {
		pBroker->handleMsg();
	} 
	pthread_exit(NULL);
	return NULL;
}

void * startDealProxyDevMsgThread(void * param_)
{
	ProtocolBroker * pBroker = (ProtocolBroker *)param_;
	if (pBroker) {
		pBroker->handleProxyDevMsg();
	}
	pthread_exit(NULL);
	return NULL;
}




