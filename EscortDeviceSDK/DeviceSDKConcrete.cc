#include "DeviceSDKConcrete.h"

unsigned int DeviceManager::g_uiInteractSequence = 0;
pthread_mutex_t DeviceManager::g_mutex4InteractSequence;
int DeviceManager::g_nRefCount = 0;


DeviceManager::DeviceManager(const char * pRootDir_)
{
	m_bInit = true;
	m_nRun = 0;
	m_ullLogInst = LOG_Init();
	m_usLogType = pf_logger::eLOGTYPE_FILE;
	m_ctx = zctx_new();

	m_pthdLog.p = NULL;
	m_pthdNetwork.p = NULL;
	m_pthdPublishMsg.p = NULL;
	//m_pthdInteractMsg.p = NULL;
	m_pthdSupervise.p = NULL;

	m_subscriber = NULL;
	m_interactor = NULL;
	
	m_fMsgCb = NULL;
	m_pUserData = NULL;

	m_filterDeviceList.clear();

	pthread_mutex_init(&m_mutex4LogQue, NULL);
	pthread_cond_init(&m_cond4LogQue, NULL);
	pthread_mutex_init(&m_mutex4PublishMsgQue, NULL);
	pthread_cond_init(&m_cond4PublishMsgQue, NULL);
	//pthread_mutex_init(&m_mutex4InteractMsgQue, NULL);
	//pthread_cond_init(&m_cond4InteractMsgQue, NULL);
	pthread_mutex_init(&m_mutex4FilterDeviceList, NULL);
	pthread_mutex_init(&m_mutex4RemoteActiveTime, NULL);
	pthread_mutex_init(&m_mutex4Interact, NULL);

	if (m_ullLogInst) {
		char szLogPath[256] = { 0 };
		sprintf_s(szLogPath, sizeof(szLogPath), "%slog\\", pRootDir_);
		CreateDirectoryExA(".\\", szLogPath, NULL);
		strcat_s(szLogPath, sizeof(szLogPath), "DeviceSDK\\");
		CreateDirectoryExA(".\\", szLogPath, NULL);
		pf_logger::LogConfig logConf;
		logConf.usLogPriority = pf_logger::eLOGPRIO_ALL;
		logConf.usLogType = pf_logger::eLOGTYPE_FILE;
		strncpy_s(logConf.szLogPath, sizeof(logConf.szLogPath), szLogPath, strlen(szLogPath));
		LOG_SetConfig(m_ullLogInst, logConf);
	}

	pthread_create(&m_pthdLog, NULL, dealLogThread, this);
	if (g_nRefCount == 0) {
		pthread_mutex_init(&g_mutex4InteractSequence, NULL);
		g_uiInteractSequence = 0;
	}
	g_nRefCount++;
}

DeviceManager::~DeviceManager()
{
	m_bInit = false;
	if (m_nRun) {
		Stop();
	}

	if (m_pthdLog.p) {
		pthread_cond_broadcast(&m_cond4LogQue);
		pthread_join(m_pthdLog, NULL);
		m_pthdLog.p = NULL;
	}

	pthread_mutex_destroy(&m_mutex4PublishMsgQue);
	pthread_mutex_destroy(&m_mutex4FilterDeviceList);
	pthread_mutex_destroy(&m_mutex4RemoteActiveTime);
	pthread_mutex_destroy(&m_mutex4LogQue);
	pthread_mutex_destroy(&m_mutex4Interact);
	pthread_cond_destroy(&m_cond4LogQue);
	pthread_cond_destroy(&m_cond4PublishMsgQue);
	if (m_ullLogInst) {
		LOG_Release(m_ullLogInst);
		m_ullLogInst = 0;
	}
	if (m_ctx) {
		zctx_destroy(&m_ctx);
	}
	g_nRefCount--;
	if (g_nRefCount <= 0) {
		pthread_mutex_destroy(&g_mutex4InteractSequence);
	}
}

int DeviceManager::Start(const char * szHost_, unsigned short usPublishPort_, unsigned short usInteractPort_)
{
	if (m_nRun) {
		return 0;
	}
	if (m_ctx == NULL) {
		m_ctx = zctx_new();
	}
	do {
		m_subscriber = zsocket_new(m_ctx, ZMQ_SUB);
		zsocket_set_subscribe(m_subscriber, "");
		if (0 != zsocket_connect(m_subscriber, "tcp://%s:%hu", szHost_, usPublishPort_)) {
			break;
		}
		m_interactor = zsocket_new(m_ctx, ZMQ_DEALER);
		zuuid_t * uuid = zuuid_new();
		const char * szUuid = zuuid_str(uuid);
		zsocket_set_identity(m_interactor, szUuid);
		if (0 != zsocket_connect(m_interactor, "tcp://%s:%hu", szHost_, usInteractPort_)) {
			zuuid_destroy(&uuid);
			break;
		}
		zuuid_destroy(&uuid);
		m_nRun = 1;
		m_nTimerTickCount = 0;
		m_loop = zloop_new();
		m_nTimer4Supervisor = zloop_timer(m_loop, 1000, 0, supervise, this);
		memset(&m_serverLink, 0, sizeof(m_serverLink));

		m_filterDeviceList.clear();

		if (m_pthdNetwork.p == NULL) {
			pthread_create(&m_pthdNetwork, NULL, dealNetworkThread, this);
		}
		if (m_pthdPublishMsg.p == NULL) {
			pthread_create(&m_pthdPublishMsg, NULL, dealPublishMessageThread, this);
		}
		//if (m_pthdInteractMsg.p == NULL) {
		//	pthread_create(&m_pthdInteractMsg, NULL, dealInteractMessageThread, this);
		//}
		if (m_pthdSupervise.p == NULL) {
			pthread_create(&m_pthdSupervise, NULL, superviseThread, this);
		}

		memset(&m_proxyInfo, 0, sizeof(m_proxyInfo));
		m_proxyInfo.usPort1 = usPublishPort_;
		m_proxyInfo.usPort2 = usInteractPort_;
		strncpy_s(m_proxyInfo.szProxyIp, sizeof(m_proxyInfo.szProxyIp), szHost_, strlen(szHost_));
		m_bConnected = false;

		return 0;
	} while (0);
	if (m_subscriber) {
		zsocket_destroy(m_ctx, m_subscriber);
		m_subscriber = NULL;
	}
	if (m_interactor) {
		zsocket_destroy(m_ctx, m_interactor);
		m_interactor = NULL;
	}
	return -1;
}

int DeviceManager::Stop()
{
	if (!m_nRun) {
		return 0;
	}
	m_nRun = 0;
	if (m_pthdPublishMsg.p) {
		pthread_cond_broadcast(&m_cond4PublishMsgQue);
		pthread_join(m_pthdPublishMsg, NULL);
		m_pthdPublishMsg.p = NULL;
	}
	//if (m_pthdInteractMsg.p) {
	//	pthread_cond_broadcast(&m_cond4InteractMsgQue);
	//	pthread_join(m_pthdInteractMsg, NULL);
	//	m_pthdInteractMsg.p = NULL;
	//}
	if (m_pthdNetwork.p) {
		pthread_join(m_pthdNetwork, NULL);
		m_pthdNetwork.p = NULL;
	}
	if (m_pthdSupervise.p) {
		pthread_join(m_pthdSupervise, NULL);
		m_pthdSupervise.p = NULL;
	}
	if (m_loop) {
		zloop_timer_end(m_loop, m_nTimer4Supervisor);
		zloop_destroy(&m_loop);
	}
	//if (m_ctx) {
		//zsocket_destroy(m_ctx, m_subscriber);
		//zsocket_destroy(m_ctx, m_interactor);
		//zctx_destroy(&m_ctx);
	//}
	return 0;
}

void DeviceManager::SetMessageCallback(ccrfid_device::fMessageCallback fMsgCb_, void * pUserData_)
{
	m_fMsgCb = fMsgCb_;
	m_pUserData = pUserData_;
}

int DeviceManager::SendCommand(ccrfid_device::DeviceCommandInfo cmdInfo_)
{
	if (!m_bConnected) {
		printf("send command failed\n");
		return -1;
	}
	int result = 0;
	if (m_nRun) {
		pthread_mutex_lock(&m_mutex4Interact);
		zmsg_t * msg_cmd = zmsg_new();
		unsigned int uiSequence = getNextInteractSequence();
		char szSequence[16] = { 0 };
		sprintf_s(szSequence, sizeof(szSequence), "%u", uiSequence);
		if (strlen(szSequence) == 0) {
			szSequence[0] = 0;
		}
		zframe_t * frame_sequence = zframe_from(szSequence);
		char szDatetime[20] = { 0 };
		formatDatetime((unsigned long long)time(NULL), szDatetime, sizeof(szDatetime));
		zframe_t * frame_datetime = zframe_from(szDatetime);
		unsigned short usType = INTERACTOR_CONTROL;
		char szType[6] = { 0 };
		sprintf_s(szType, sizeof(szType), "%hu", usType);
		zframe_t * frame_type = zframe_from(szType);
		zframe_t * frame_data = zframe_new(&cmdInfo_, sizeof(cmdInfo_));
		zmsg_append(msg_cmd, &frame_sequence);
		zmsg_append(msg_cmd, &frame_datetime);
		zmsg_append(msg_cmd, &frame_type);
		zmsg_append(msg_cmd, &frame_data);
		zmsg_send(&msg_cmd, m_interactor);
		pthread_mutex_unlock(&m_mutex4Interact);
		result = (int)uiSequence;
	}
	return result;
}

int DeviceManager::AddDeviceListen(const char * pFactoryId_, const char * pDeviceId_)
{
	int result = -1;
	if (pFactoryId_ && pDeviceId_) {
		char szLog[256] = { 0 };
		size_t nLen = strlen(pFactoryId_) + strlen(pDeviceId_) + 1;
		char * pKey = new char[nLen + 1];
		sprintf_s(pKey, nLen + 1, "%s_%s", pFactoryId_, pDeviceId_);
		std::string strKey = pKey;
		delete[] pKey;
		pKey = NULL;
		pthread_mutex_lock(&m_mutex4FilterDeviceList);
		if (m_filterDeviceList.empty()) {
			m_filterDeviceList.push_back(strKey);
			sprintf_s(szLog, sizeof(szLog), "[DeviceSdk]%s[%d]add filter %s\r\n", __FUNCTION__, __LINE__,
				strKey.c_str());
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		}
		else {
			size_t nSize = m_filterDeviceList.size();
			bool bExists = false;
			for (size_t i = 0; i < nSize; i++) {
				std::string strFilterDevice = m_filterDeviceList[i];
				if (strFilterDevice == strKey) {
					bExists = true;
					break;
				}
			}
			if (!bExists) {
				m_filterDeviceList.push_back(strKey);
				sprintf_s(szLog, sizeof(szLog), "[DeviceSDK]%s[%d]add filter %s\r\n", __FUNCTION__, __LINE__,
					strKey.c_str());
				writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
			}
		}
		pthread_mutex_unlock(&m_mutex4FilterDeviceList);
		result = 0;
	}
	else if (pFactoryId_ == NULL && pDeviceId_ == NULL) {
		pthread_mutex_lock(&m_mutex4FilterDeviceList);
		m_filterDeviceList.clear();
		pthread_mutex_unlock(&m_mutex4FilterDeviceList);
		result = 0;
	}
	
	return result;
}

int DeviceManager::RemoveDeviceListen(const char * pFactoryId_, const char * pDeviceId_)
{
	if (pFactoryId_ && pDeviceId_) {
		size_t nLen = strlen(pFactoryId_) + strlen(pDeviceId_) + 1;
		char * pKey = new char[nLen + 1];
		sprintf_s(pKey, nLen + 1, "%s_%s", pFactoryId_, pDeviceId_);
		std::string strKey = pKey;
		delete[] pKey;
		pKey = NULL;
		pthread_mutex_lock(&m_mutex4FilterDeviceList);
		size_t nSize = m_filterDeviceList.size();
		for (size_t i = 0; i < nSize; i++) {
			std::string strFilterDevice = m_filterDeviceList[i];
			if (strFilterDevice == strKey) {
				m_filterDeviceList.erase(m_filterDeviceList.begin() + i);
				char szLog[256] = { 0 };
				sprintf_s(szLog, sizeof(szLog), "[DeviceSDK]%s[%d]remove filter %s\r\n", __FUNCTION__, __LINE__,
					strKey.c_str());
				writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
				break;
			}
		}
		pthread_mutex_unlock(&m_mutex4FilterDeviceList);
	}
	else if (pFactoryId_ == NULL && pDeviceId_ == NULL) {
		pthread_mutex_lock(&m_mutex4FilterDeviceList);
		m_filterDeviceList.clear();
		pthread_mutex_unlock(&m_mutex4FilterDeviceList);
	}
	return 0;
}

bool DeviceManager::addLog(LogContext * pLogCtx_)
{
	bool result = false;
	if (pLogCtx_ && pLogCtx_->pLogData) {
		pthread_mutex_lock(&m_mutex4LogQue);
		m_logQue.push(pLogCtx_);
		if (m_logQue.size() == 1) {
			pthread_cond_broadcast(&m_cond4LogQue);
		}
		pthread_mutex_unlock(&m_mutex4LogQue);
		result = true;
	}
	return result;
}

void DeviceManager::handleLog()
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
		LogContext * pLogCtx = m_logQue.front();
		m_logQue.pop();
		pthread_mutex_unlock(&m_mutex4LogQue);
		if (pLogCtx) {
			if (pLogCtx->pLogData) {
				if (m_ullLogInst) {
					LOG_Log(m_ullLogInst, pLogCtx->pLogData, pLogCtx->usLogCategory, pLogCtx->usLogType);
				}	
				delete [] pLogCtx->pLogData;
				pLogCtx->pLogData = NULL;
			}
			delete pLogCtx;
			pLogCtx = NULL;	
		}
	} while (1);
}

void DeviceManager::writeLog(const char * pLogContent_, unsigned short usLogCategory_, 
	unsigned short usLogType_)
{
	if (pLogContent_ && strlen(pLogContent_)) {
		LogContext * pLogCtx = new LogContext();
		pLogCtx->uiDataLen = (unsigned int)strlen(pLogContent_);
		pLogCtx->pLogData = new char [pLogCtx->uiDataLen + 1];
		memcpy_s(pLogCtx->pLogData, pLogCtx->uiDataLen + 1, pLogContent_, pLogCtx->uiDataLen);
		pLogCtx->pLogData[pLogCtx->uiDataLen] = '\0';
		pLogCtx->usLogCategory = usLogCategory_;
		pLogCtx->usLogType = usLogType_;
		if (!addLog(pLogCtx)) {
			delete [] pLogCtx->pLogData;
			pLogCtx->pLogData = NULL;
			delete pLogCtx;
			pLogCtx = NULL;
		}
	}
}

void DeviceManager::handleNetwork()
{
	zmq_pollitem_t items[] = {{m_subscriber, 0, ZMQ_POLLIN, 0}, {m_interactor, 0, ZMQ_POLLIN, 0}};
	while (m_nRun) {
		int rc = zmq_poll(items, 2, 1000 * ZMQ_POLL_MSEC);
		if (rc == -1 && errno == ETERM) {
			break;
		}
		if (items[0].revents & ZMQ_POLLIN) {
			zmsg_t * msg_publish = zmsg_recv(items[0].socket);
			if (msg_publish) {
				m_bConnected = true;
				pthread_mutex_lock(&m_mutex4RemoteActiveTime);
				if (!m_serverLink.nActiveFlag) {
					m_serverLink.nActiveFlag = 1;
					//notify server connect
					if (!m_bConnected) {
						m_bConnected = true;
					}
					if (m_fMsgCb) {
						m_fMsgCb(ccrfid_device::MT_SERVER_CONNECT, 0, (unsigned long long)time(NULL), 
							&m_proxyInfo, m_pUserData);
					}
				}
				unsigned long long ulTime = (unsigned long long)time(NULL);
				if (m_serverLink.ulLastActiveTime < ulTime) {
					m_serverLink.ulLastActiveTime = ulTime;
				}
				pthread_mutex_unlock(&m_mutex4RemoteActiveTime);
				if (zmsg_size(msg_publish) >= 4) {
					zframe_t * frame_msg_topic = zmsg_pop(msg_publish);
					zframe_t * frame_msg_sequence = zmsg_pop(msg_publish);
					zframe_t * frame_msg_datetime = zmsg_pop(msg_publish);
					zframe_t * frame_msg_type = zmsg_pop(msg_publish);
					zframe_t * frame_msg_data = zmsg_pop(msg_publish);
					PublishMessage * pPubMsg = new PublishMessage();
					memset(pPubMsg, 0, sizeof(PublishMessage));
					memcpy_s(pPubMsg->szMsgTopic, sizeof(pPubMsg->szMsgTopic), zframe_data(frame_msg_topic), 
						zframe_size(frame_msg_topic));
					char szMsgSeq[16] = { 0 };
					memcpy_s(szMsgSeq, sizeof(szMsgSeq), zframe_data(frame_msg_sequence), zframe_size(frame_msg_sequence));
					pPubMsg->uiMsgSeq = (unsigned int)atoi(szMsgSeq);
					char szMsgDatetime[20] = { 0 };
					memcpy_s(szMsgDatetime, sizeof(szMsgDatetime), zframe_data(frame_msg_datetime), 
						zframe_size(frame_msg_datetime));
					pPubMsg->ulMsgTime = makeDatetime(szMsgDatetime);
					char szMsgType[16] = { 0 };
					memcpy_s(szMsgType, sizeof(szMsgType), zframe_data(frame_msg_type), zframe_size(frame_msg_type));
					pPubMsg->uiMsgType = (unsigned int)atoi(szMsgType);
					size_t nFrameDataLen = zframe_size(frame_msg_data);
					if (nFrameDataLen > 0) {
						pPubMsg->pMsgData = new unsigned char [nFrameDataLen + 1];
						memcpy_s(pPubMsg->pMsgData, nFrameDataLen + 1, zframe_data(frame_msg_data), nFrameDataLen);
						pPubMsg->pMsgData[nFrameDataLen] = '\0';
						pPubMsg->uiMsgDataLen = (unsigned int)nFrameDataLen;
						decryptMessage(pPubMsg->pMsgData, 0, (unsigned int)nFrameDataLen);
					}
					if (!addPublishMessage(pPubMsg)) {
						if (pPubMsg->pMsgData) {
							delete[] pPubMsg->pMsgData;
							pPubMsg->pMsgData = NULL;
						}
						delete pPubMsg;
						pPubMsg = NULL;
					}
					zframe_destroy(&frame_msg_topic);
					zframe_destroy(&frame_msg_sequence);
					zframe_destroy(&frame_msg_datetime);
					zframe_destroy(&frame_msg_type);
					zframe_destroy(&frame_msg_data);
				}
				zmsg_destroy(&msg_publish);
			}
		}
		if (items[1].revents & ZMQ_POLLIN) {
			zmsg_t * msg_interactor = zmsg_recv(items[1].socket);
			if (msg_interactor) {
				m_bConnected = true;
				if (zmsg_size(msg_interactor) >= 4) {
					zframe_t * frame_interactor_sequence = zmsg_pop(msg_interactor);
					zframe_t * frame_interactor_datetime = zmsg_pop(msg_interactor);
					zframe_t * frame_interactor_type = zmsg_pop(msg_interactor);
					zframe_t * frame_interactor_data = zmsg_pop(msg_interactor);
					char szMsgSeq[20] = { 0 };
					memcpy_s(szMsgSeq, sizeof(szMsgSeq), zframe_data(frame_interactor_sequence),
						zframe_size(frame_interactor_sequence));
					unsigned int uiMsgSeq = (unsigned int)atoi(szMsgSeq);
					char szMsgType[16] = { 0 };
					memcpy_s(szMsgType, sizeof(szMsgType), zframe_data(frame_interactor_type),
						zframe_size(frame_interactor_type));
					unsigned short usMsgType = (unsigned short)atoi(szMsgType);
					char szMsgDatetime[20] = { 0 };
					memcpy_s(szMsgDatetime, sizeof(szMsgDatetime), zframe_data(frame_interactor_datetime),
						zframe_size(frame_interactor_datetime));
					unsigned long long ulReplyTime = makeDatetime(szMsgDatetime);
					
					switch (usMsgType) {
						case INTERACTOR_KEEPALIVE: {
							pthread_mutex_lock(&m_mutex4RemoteActiveTime);
							if (m_serverLink.nActiveFlag == 0) {
								m_serverLink.nActiveFlag = 1;
								//notify server connect
								m_bConnected = true;
								if (m_fMsgCb) {
									m_fMsgCb(ccrfid_device::MT_SERVER_CONNECT, 0, (unsigned long long)time(NULL), 
										&m_proxyInfo, m_pUserData);
								}
							}
							if (m_serverLink.nActiveFlag) {
								if (m_serverLink.ulLastActiveTime < ulReplyTime) {
									m_serverLink.ulLastActiveTime = ulReplyTime;
								}
							}
							pthread_mutex_unlock(&m_mutex4RemoteActiveTime);
							break;
						}
						case INTERACTOR_SNAPSHOT: {
							break;
						}
						case INTERACTOR_CONTROL: {
							pthread_mutex_lock(&m_mutex4RemoteActiveTime);
							if (!m_serverLink.nActiveFlag) {
								m_serverLink.nActiveFlag = 1;
								//notify server connect
								m_bConnected = true;
								if (m_fMsgCb) {
									m_fMsgCb(ccrfid_device::MT_SERVER_CONNECT, 0, (unsigned long long)time(NULL),
										&m_proxyInfo, m_pUserData);
								}
							}
							if (m_serverLink.ulLastActiveTime < ulReplyTime) {
								m_serverLink.ulLastActiveTime = ulReplyTime;
							}
							pthread_mutex_unlock(&m_mutex4RemoteActiveTime);
							size_t nFrameDataLen = zframe_size(frame_interactor_data);
							ccrfid_device::DeviceCommandInfo devCmdInfo;
							size_t nCmdInfoLen = sizeof(ccrfid_device::DeviceCommandInfo);
							if (nFrameDataLen >= nCmdInfoLen) {
								memcpy_s(&devCmdInfo, nCmdInfoLen, zframe_data(frame_interactor_data), nCmdInfoLen);
								char szMsgTopic[40] = { 0 };
								sprintf_s(szMsgTopic, sizeof(szMsgTopic), "%s_%s", devCmdInfo.szFactoryId, 
									devCmdInfo.szDeviceId);
								if (verifyMessage(szMsgTopic) && m_fMsgCb) {
									m_fMsgCb(ccrfid_device::MT_COMMAND, uiMsgSeq, ulReplyTime, &devCmdInfo, m_pUserData);
								}
							}
							break;
						}
					}
					zframe_destroy(&frame_interactor_sequence);
					zframe_destroy(&frame_interactor_datetime);
					zframe_destroy(&frame_interactor_type);
					zframe_destroy(&frame_interactor_data);
				}
				zmsg_destroy(&msg_interactor);
			}
		}
	}
}

bool DeviceManager::addPublishMessage(PublishMessage * pPubMsg_)
{
	bool result = false;
	if (pPubMsg_ && pPubMsg_->pMsgData) {
		pthread_mutex_lock(&m_mutex4PublishMsgQue);
		m_publishMsgQue.push(pPubMsg_);
		if (m_publishMsgQue.size() == 1) {
			pthread_cond_broadcast(&m_cond4PublishMsgQue);
		}
		pthread_mutex_unlock(&m_mutex4PublishMsgQue);
		result = true;
	}
	return result;
}

void DeviceManager::handlePublishMessage()
{
	char szLog[512] = { 0 };
	while (1) {
		pthread_mutex_lock(&m_mutex4PublishMsgQue);
		while (m_nRun && m_publishMsgQue.empty()) {
			pthread_cond_wait(&m_cond4PublishMsgQue, &m_mutex4PublishMsgQue);
		}
		if (!m_nRun && m_publishMsgQue.empty()) {
			pthread_mutex_unlock(&m_mutex4PublishMsgQue);
			break;
		}
		PublishMessage * pPubMsg = m_publishMsgQue.front();
		m_publishMsgQue.pop();
		pthread_mutex_unlock(&m_mutex4PublishMsgQue);
		if (pPubMsg) {
			if (pPubMsg->pMsgData) {
				switch (pPubMsg->uiMsgType) {
					case ccrfid_device::MT_ONLINE: {
						ccrfid_device::DeviceMessage onlineMsg;
						size_t nOnlineMsgSize = sizeof(onlineMsg);
						if (pPubMsg->uiMsgDataLen >= nOnlineMsgSize) {
							memcpy_s(&onlineMsg, nOnlineMsgSize, pPubMsg->pMsgData, nOnlineMsgSize);
							if (verifyMessage(pPubMsg->szMsgTopic) && m_fMsgCb) {
								m_fMsgCb(pPubMsg->uiMsgType, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, &onlineMsg, m_pUserData);
							}
							sprintf_s(szLog, sizeof(szLog), "[DeviceSDK]%s[%d]receive publish online message topic=%s, "
								"sequence=%hu, datetime=%llu, type=%u, battery=%hu, onlineTime=%llu\r\n", __FUNCTION__,
								__LINE__, pPubMsg->szMsgTopic, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, pPubMsg->uiMsgType, 
								onlineMsg.usDeviceBattery, onlineMsg.ulMessageTime);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
						}
						
						break;
					}
					case ccrfid_device::MT_ALIVE: {
						ccrfid_device::DeviceMessage aliveMsg;
						size_t nAliveMsgSize = sizeof(aliveMsg);
						if (pPubMsg->uiMsgDataLen >= nAliveMsgSize) {
							memcpy_s(&aliveMsg, nAliveMsgSize, pPubMsg->pMsgData, nAliveMsgSize);
							if (verifyMessage(pPubMsg->szMsgTopic) && m_fMsgCb) {
								m_fMsgCb(pPubMsg->uiMsgType, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, &aliveMsg, m_pUserData);
							}
							sprintf_s(szLog, sizeof(szLog), "[DeviceSDK]%s[%d]receive publish alive message topic=%s, "
								"sequence=%u, datetime=%llu, type=%u, battery=%hu, aliveTime=%llu\r\n", __FUNCTION__, __LINE__,
								pPubMsg->szMsgTopic, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, pPubMsg->uiMsgType, 
								aliveMsg.usDeviceBattery, aliveMsg.ulMessageTime);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
						}
						break;
					}
					case ccrfid_device::MT_OFFLINE: {
						ccrfid_device::DeviceMessage offlineMsg;
						size_t nOfflineMsgSize = sizeof(offlineMsg);
						if (pPubMsg->uiMsgDataLen >= nOfflineMsgSize) {
							memcpy_s(&offlineMsg, nOfflineMsgSize, pPubMsg->pMsgData, nOfflineMsgSize);
							if (verifyMessage(pPubMsg->szMsgTopic) && m_fMsgCb) {
								m_fMsgCb(pPubMsg->uiMsgType, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, &offlineMsg, m_pUserData);
							}
							sprintf_s(szLog, sizeof(szLog), "[DeviceSDK]%s[%d]receive publish offline message topic=%s, "
								"sequence=%u, datetime=%llu, type=%u, offlineTime=%llu\r\n", __FUNCTION__, __LINE__, 
								pPubMsg->szMsgTopic, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, pPubMsg->uiMsgType, 
								offlineMsg.ulMessageTime);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
						}
						break;
					}
					case ccrfid_device::MT_ALARM_LOOSE: {
						ccrfid_device::DeviceMessage looseAlarmMsg;
						size_t nLooseMsgSize = sizeof(looseAlarmMsg);
						if (pPubMsg->uiMsgDataLen >= nLooseMsgSize) {
							memcpy_s(&looseAlarmMsg, nLooseMsgSize, pPubMsg->pMsgData, nLooseMsgSize);
							if (verifyMessage(pPubMsg->szMsgTopic) && m_fMsgCb) {
								m_fMsgCb(pPubMsg->uiMsgType, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, &looseAlarmMsg, m_pUserData);
							}
							sprintf_s(szLog, sizeof(szLog), "[DeviceSDK]%s[%d]receive publish loose alarm message topic=%s, "
								"sequence=%u, datetime=%llu, type=%u, mode=%hu\r\n", __FUNCTION__, __LINE__, pPubMsg->szMsgTopic,
								pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, pPubMsg->uiMsgType, looseAlarmMsg.usMessageTypeExtra);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
						}
						break;
					}
					case ccrfid_device::MT_ALARM_LOWPOWER: {
						ccrfid_device::DeviceMessage lowpowerAlarmMsg;
						size_t nLowpowerAlarmMsgSize = sizeof(lowpowerAlarmMsg);
						if (pPubMsg->uiMsgDataLen >= nLowpowerAlarmMsgSize) {
							memcpy_s(&lowpowerAlarmMsg, nLowpowerAlarmMsgSize, pPubMsg->pMsgData, nLowpowerAlarmMsgSize);
							if (verifyMessage(pPubMsg->szMsgTopic) && m_fMsgCb) {
								m_fMsgCb(pPubMsg->uiMsgType, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, &lowpowerAlarmMsg, m_pUserData);
							}
							sprintf_s(szLog, sizeof(szLog), "[DeviceSDK]%s[%d]receive publish lowpower alarm message topic=%s, "
								"sequence=%u, datetime=%llu, type=%u, mode=%hu\r\n", __FUNCTION__, __LINE__, pPubMsg->szMsgTopic,
								pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, pPubMsg->uiMsgType, lowpowerAlarmMsg.usMessageTypeExtra);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
						}
						break;
					}
					case ccrfid_device::MT_LOCATE_GPS: {
						ccrfid_device::DeviceLocateGpsMessage locateGpsMsg;
						size_t nLocateGpsMsgSize = sizeof(locateGpsMsg);
						memset(&locateGpsMsg, 0, sizeof(locateGpsMsg));
						if (pPubMsg->uiMsgDataLen >= nLocateGpsMsgSize) {
							memcpy_s(&locateGpsMsg, nLocateGpsMsgSize, pPubMsg->pMsgData, nLocateGpsMsgSize);
							if (verifyMessage(pPubMsg->szMsgTopic) && m_fMsgCb) {
								m_fMsgCb(pPubMsg->uiMsgType, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, &locateGpsMsg, m_pUserData);
							}
							sprintf_s(szLog, sizeof(szLog), "[DeviceSDK]%s[%d]receive publish gps locate message topic=%s, "
								"sequence=%u, datetime=%llu, type=%u, lat=%f, lng=%f, battery=%hu, locateTime=%llu\r\n", 
								__FUNCTION__, __LINE__, pPubMsg->szMsgTopic, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, 
								pPubMsg->uiMsgType, locateGpsMsg.dLatitude, locateGpsMsg.dLngitude, locateGpsMsg.usDeviceBattery,
								locateGpsMsg.ulLocateTime);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
						}
						break;
					}
					case ccrfid_device::MT_LOCATE_LBS: {
						ccrfid_device::DeviceLocateLbsMessage locateLbsMsg;
						size_t nLocateLbsMsgSize = sizeof(locateLbsMsg);
						memset(&locateLbsMsg, 0, nLocateLbsMsgSize);
						if (pPubMsg->uiMsgDataLen >= nLocateLbsMsgSize) {
							size_t nOffset = 0;
							memcpy_s(&locateLbsMsg, nLocateLbsMsgSize, pPubMsg->pMsgData, nLocateLbsMsgSize);
							nOffset = nLocateLbsMsgSize;
							if (locateLbsMsg.nBaseStationCount > 0) {
								size_t nBSListLen = sizeof(ccrfid_device::BaseStation) * locateLbsMsg.nBaseStationCount;
								locateLbsMsg.pBaseStationList = new ccrfid_device::BaseStation[locateLbsMsg.nBaseStationCount];
								memcpy_s(locateLbsMsg.pBaseStationList, nBSListLen, pPubMsg->pMsgData + nOffset, nBSListLen);
								nOffset += nBSListLen;
							}
							if (locateLbsMsg.nDetectedWifiCount > 0) {
								size_t nWifiListLen = sizeof(ccrfid_device::WifiInformation) * locateLbsMsg.nDetectedWifiCount;
								locateLbsMsg.pDetectedWifiList = new ccrfid_device::WifiInformation[locateLbsMsg.nDetectedWifiCount];
								memcpy_s(locateLbsMsg.pDetectedWifiList, nWifiListLen, pPubMsg->pMsgData + nOffset, nWifiListLen);
								nOffset += nWifiListLen;
							}
							if (verifyMessage(pPubMsg->szMsgTopic) && m_fMsgCb) {
								m_fMsgCb(pPubMsg->uiMsgType, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, &locateLbsMsg, m_pUserData);
							}
							sprintf_s(szLog, sizeof(szLog), "[DeviceSDK]%s[%d]receive publish locate lbs message topic=%s, "
								"sequence=%u, datetime=%llu, type=%u, battery=%hu, locateTime=%llu, lat=%f, lng=%f, coordinate=%d\r\n",
								__FUNCTION__, __LINE__, pPubMsg->szMsgTopic, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, pPubMsg->uiMsgType,
								locateLbsMsg.usDeviceBattery, locateLbsMsg.ulLocateTime, locateLbsMsg.dRefLatitude, 
								locateLbsMsg.dRefLngitude, locateLbsMsg.nCoordinate);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);

							if (locateLbsMsg.pBaseStationList && locateLbsMsg.nBaseStationCount) {
								delete[] locateLbsMsg.pBaseStationList;
								locateLbsMsg.pBaseStationList = NULL;
								locateLbsMsg.nBaseStationCount = 0;
							}
							if (locateLbsMsg.pDetectedWifiList && locateLbsMsg.nDetectedWifiCount) {
								delete[] locateLbsMsg.pDetectedWifiList;
								locateLbsMsg.pDetectedWifiList = NULL;
								locateLbsMsg.nDetectedWifiCount = 0;
							}
						}
						break;
					}
					case ccrfid_device::MT_COMMAND: {
						ccrfid_device::DeviceCommandInfo devCmdInfo;
						size_t nCmdInfoLen = sizeof(devCmdInfo);

						if (pPubMsg->uiMsgDataLen >= nCmdInfoLen) {
							memcpy_s(&devCmdInfo, nCmdInfoLen, pPubMsg->pMsgData, nCmdInfoLen);
							if (verifyMessage(pPubMsg->szMsgTopic) && m_fMsgCb) {
								m_fMsgCb(pPubMsg->uiMsgType, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, &devCmdInfo, m_pUserData);
							}
							sprintf_s(szLog, sizeof(szLog), "[DeviceSDK]%s[%d]receive publish command message topic=%s, "
								"sequence=%u, datetime=%llu, type=%u, cmd=%d, param=%d, retcode=%d\r\n", __FUNCTION__, __LINE__, 
								pPubMsg->szMsgTopic, pPubMsg->uiMsgSeq, pPubMsg->ulMsgTime, pPubMsg->uiMsgType, devCmdInfo.nCommand,
								devCmdInfo.nParam1, devCmdInfo.nParam2);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
						}
						break;
					}
					default: {
						break;
					}
				}
				
				delete[] pPubMsg->pMsgData;
				pPubMsg->pMsgData = NULL;
			}
			delete pPubMsg;
			pPubMsg = NULL;
		}
	}
}

unsigned int DeviceManager::getNextInteractSequence()
{
	unsigned int result = 0;
	pthread_mutex_lock(&g_mutex4InteractSequence);
	g_uiInteractSequence++;
	if (g_uiInteractSequence == 0) {
		g_uiInteractSequence = 1;
	}
	result = g_uiInteractSequence;
	pthread_mutex_unlock(&g_mutex4InteractSequence);
	return result;
}

void DeviceManager::encryptMessage(unsigned char * pData_, unsigned int uiBeginIndex_, 
	unsigned int uiEndIndex_)
{
	char secret = '8';
	if (uiEndIndex_ > uiBeginIndex_ && uiBeginIndex_ >= 0) {
		for (unsigned int i = uiBeginIndex_; i < uiEndIndex_; i++) {
			pData_[i] += 1;
			pData_[i] ^= secret;
		}
	}
}

void DeviceManager::decryptMessage(unsigned char * pData_, unsigned int uiBeginIndex_, 
	unsigned int uiEndIndex_)
{
	char secret = '8';
	if (uiEndIndex_ > uiBeginIndex_ && uiBeginIndex_ >= 0) {
		for (unsigned int i = uiBeginIndex_; i < uiEndIndex_; i++) {
			pData_[i] = pData_[i] ^ secret;
			pData_[i] -= 1;
		}
	}
}

unsigned long long DeviceManager::makeDatetime(const char * pDatetime_)
{
	struct tm tm_time;
	sscanf_s(pDatetime_, "%04d%02d%02d%02d%02d%02d", &tm_time.tm_year, &tm_time.tm_mon,
		&tm_time.tm_mday, &tm_time.tm_hour, &tm_time.tm_min, &tm_time.tm_sec);
	tm_time.tm_year -= 1900;
	tm_time.tm_mon -= 1;
	time_t nTime = mktime(&tm_time);
	return (unsigned long long)nTime;
}

void DeviceManager::formatDatetime(unsigned long long ulTime, char * pDatetime_, unsigned int uiLen_)
{
	struct tm tm_time;
	time_t nTime = ulTime;
	localtime_s(&tm_time, &nTime);
	if (uiLen_ >= 16 && pDatetime_) {
		sprintf_s(pDatetime_, uiLen_, "%04d%02d%02d%02d%02d%02d", tm_time.tm_year + 1900, tm_time.tm_mon + 1,
			tm_time.tm_mday, tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec);
	}
}

bool DeviceManager::verifyMessage(const char * pMsgTopic_)
{
	bool result = false;
	if (pMsgTopic_) {
		pthread_mutex_lock(&m_mutex4FilterDeviceList);
		if (m_filterDeviceList.empty()) {
			result = true;
		}
		else {
			size_t nSize = m_filterDeviceList.size();
			for (size_t i = 0; i < nSize; i++) {
				std::string strFilterDevice = m_filterDeviceList[i];
				if (strcmp(strFilterDevice.c_str(), pMsgTopic_) == 0) {
					char szLog[256] = { 0 };
					sprintf_s(szLog, sizeof(szLog), "[DeviceSDK]%s[%d]verify message topic=%s ok\r\n", 
						__FUNCTION__, __LINE__, pMsgTopic_);
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
					result = true;
					break;
				}
			}
		}
		pthread_mutex_unlock(&m_mutex4FilterDeviceList);
	}
	return result;
}

void DeviceManager::keepAlive()
{
	//sequence, datetime, type, data(empty)
	bool bNeedKeepAlive = false;
	pthread_mutex_lock(&m_mutex4RemoteActiveTime);
	unsigned long long ulNow = (unsigned long long)time(NULL);
	if (m_serverLink.nActiveFlag) {
		unsigned long long ulInterval = ulNow - m_serverLink.ulLastActiveTime;
		if (ulInterval >= 30 && ulInterval <= 60) {
			bNeedKeepAlive = true;
		}
		else if (ulInterval > 60){
			m_serverLink.nActiveFlag = 0;
			m_serverLink.ulLastActiveTime = 0;
			m_serverLink.nFirstSend = 0;
			m_serverLink.ulLastSendTime = 0;
			//notify server disconnect
			m_bConnected = false;
			if (m_fMsgCb) {
				m_fMsgCb(ccrfid_device::MT_SERVER_DISCONNECT, 0, ulNow, (void *)&m_proxyInfo, m_pUserData);
			}
		}
	}
	else {
		if (!m_serverLink.nFirstSend) {
			m_serverLink.nFirstSend = 1;
			m_serverLink.ulLastSendTime = ulNow;
			bNeedKeepAlive = true;
		}
		else {
			if (m_serverLink.ulLastSendTime > 0) {
				unsigned long long ulInterval = ulNow - m_serverLink.ulLastSendTime;
				if (ulInterval > 60) {
					//notify server disconnect
					m_serverLink.ulLastSendTime = 0;
					m_bConnected = false;
					if (m_fMsgCb) {
						m_fMsgCb(ccrfid_device::MT_SERVER_DISCONNECT, 0, ulNow, (void *)&m_proxyInfo, m_pUserData);
					}
				}
			}
		}
	}
	pthread_mutex_unlock(&m_mutex4RemoteActiveTime);
	if (bNeedKeepAlive) {
		pthread_mutex_lock(&m_mutex4Interact);
		unsigned int uiMsgSeq = getNextInteractSequence();
		char szMsgSeq[16] = { 0 };
		sprintf_s(szMsgSeq, sizeof(szMsgSeq), "%u", uiMsgSeq);
		char szMsgDatetime[20] = { 0 };
		formatDatetime((unsigned long long)time(NULL), szMsgDatetime, sizeof(szMsgDatetime));
		unsigned short usMsgType = INTERACTOR_KEEPALIVE;
		char szMsgType[6] = { 0 };
		sprintf_s(szMsgType, sizeof(szMsgType), "%hu", usMsgType);
		zmsg_t * msg_interact = zmsg_new();
		zframe_t * frame_msg_seq = zframe_from(szMsgSeq);
		zframe_t * frame_msg_datetime = zframe_from(szMsgDatetime);
		zframe_t * frame_msg_type = zframe_from(szMsgType);
		zframe_t * frame_msg_data = zframe_new(NULL, 0);
		zmsg_append(msg_interact, &frame_msg_seq);
		zmsg_append(msg_interact, &frame_msg_datetime);
		zmsg_append(msg_interact, &frame_msg_type);
		zmsg_append(msg_interact, &frame_msg_data);
		zmsg_send(&msg_interact, m_interactor);
		pthread_mutex_unlock(&m_mutex4Interact);
	}
}

void * dealLogThread(void * param_)
{
	DeviceManager * pManager = (DeviceManager *)param_;
	if (pManager) {
		pManager->handleLog();
	}
	pthread_exit(NULL);
	return NULL;
}

void * dealPublishMessageThread(void * param_)
{
	DeviceManager * pManager = (DeviceManager *)param_;
	if (pManager) {
		pManager->handlePublishMessage();
	}
	pthread_exit(NULL);
	return NULL;
}

//void * dealInteractMessageThread(void * param_)
//{
//	DeviceManager * pManager = (DeviceManager *)param_;
//	if (pManager) {
//		pManager->handle
//	}
//	pthread_exit(NULL);
//	return NULL;
//}

void * dealNetworkThread(void * param_)
{
	DeviceManager * pManager = (DeviceManager *)param_;
	if (pManager) {
		pManager->handleNetwork();
	}
	pthread_exit(NULL);
	return NULL;
}

void * superviseThread(void * param_)
{
	DeviceManager * pManager = (DeviceManager *)param_;
	if (pManager) {
		zloop_start(pManager->m_loop);
	}
	pthread_exit(NULL);
	return NULL;
}

int supervise(zloop_t * loop_, int nTimerId_, void * param_)
{
	int result = 0;
	DeviceManager * pManager = (DeviceManager *)param_;
	if (pManager) {
		if (pManager->m_nRun == 0) {
			result = -1;
		}
		else {
			if (pManager->m_nTimerTickCount % 10 == 0) { //10sec
				//send kepp-alive
				pManager->keepAlive();
			}
			pManager->m_nTimerTickCount++;
			if (pManager->m_nTimerTickCount == 7200) {
				pManager->m_nTimerTickCount = 0;
			}
		}
	}
	return result;
}