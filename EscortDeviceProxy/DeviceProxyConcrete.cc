#include "DeviceProxyConcrete.h"

unsigned int ccrfid_proxy::DeviceProxy::g_uiPubSequence = 0;
pthread_mutex_t ccrfid_proxy::DeviceProxy::g_mutex4PubSequence;
int ccrfid_proxy::DeviceProxy::g_nRefCount = 0;


ccrfid_proxy::DeviceProxy::DeviceProxy(const char * pRootPath_)
{
	m_nErrCode = 0;
	m_ctx = zctx_new();
	m_usLogType = pf_logger::eLOGTYPE_FILE;
	m_endpointLingerDataList = zhash_new();
	//m_deviceList = zhash_new();
	m_linkDeviceList = zhash_new();
	m_bInit = true;
	memset(m_szKey, 0, sizeof(m_szKey));
	m_nQryLbs = 0;

	pthread_mutex_init(&m_mutex4LogQue, NULL);
	pthread_cond_init(&m_cond4LogQue, NULL);
	pthread_mutex_init(&m_mutex4DeviceMsgQue, NULL);
	pthread_cond_init(&m_cond4DeviceMsgQue, NULL);
	pthread_mutex_init(&m_mutex4PublishMsgQue, NULL);
	pthread_cond_init(&m_cond4PublishMsgQue, NULL);
	pthread_mutex_init(&m_mutex4InteractMsgQue, NULL);
	pthread_cond_init(&m_cond4InteractMsgQue, NULL);
	pthread_mutex_init(&m_mutex4EndpointLingerDataList, NULL);
	pthread_mutex_init(&m_mutex4DeviceList, NULL);
	pthread_mutex_init(&m_mutex4LinkDeviceList, NULL);

	if (g_nRefCount == 0) {
		pthread_mutex_init(&g_mutex4PubSequence, NULL);
		g_uiPubSequence = 1;
	}
	g_nRefCount++;

	m_ullLogInst = LOG_Init();
	if (m_ullLogInst) {
		char szLogPath[256] = { 0 };
		snprintf(szLogPath, sizeof(szLogPath), "%slog\\", pRootPath_);
		CreateDirectoryExA(".\\", szLogPath, NULL);
		strcat_s(szLogPath, sizeof(szLogPath), "DeviceProxy\\");
		CreateDirectoryExA(".\\", szLogPath, NULL);
		pf_logger::LogConfig logConf;
		memset(logConf.szLogPath, 0, sizeof(logConf.szLogPath));
		logConf.usLogPriority = pf_logger::eLOGPRIO_ALL;
		logConf.usLogType = pf_logger::eLOGTYPE_FILE;
		strncpy_s(logConf.szLogPath, sizeof(logConf.szLogPath), szLogPath, strlen(szLogPath));
		LOG_SetConfig(m_ullLogInst, logConf);
	}
	pthread_create(&m_pthdLog, NULL, dealLogThread, this);
}

ccrfid_proxy::DeviceProxy::~DeviceProxy()
{
	m_nErrCode = 0;
	m_bInit = false;
	if (m_nRun) {
		Stop();
	}
	if (m_endpointLingerDataList) {
		zhash_destroy(&m_endpointLingerDataList);
	}
	//if (m_deviceList) {
	//	zhash_destroy(&m_deviceList);
	//}
	pthread_mutex_lock(&m_mutex4DeviceList);
	if (!m_deviceList2.empty()) {
		std::map<std::string, ccrfid_proxy::DeviceInfo *>::iterator iter = m_deviceList2.begin();
		while (iter != m_deviceList2.end()) {
			ccrfid_proxy::DeviceInfo * pDevInfo = iter->second;
			if (pDevInfo) {
				free(pDevInfo);
				pDevInfo = NULL;
			}
			iter = m_deviceList2.erase(iter);
		}
	}
	pthread_mutex_unlock(&m_mutex4DeviceList);
	if (m_linkDeviceList) {
		zhash_destroy(&m_linkDeviceList);
	}

	if (m_pthdLog.p) {
		pthread_cond_broadcast(&m_cond4LogQue);
		pthread_join(m_pthdLog, NULL);
		m_pthdLog.p = NULL;
	}
	pthread_mutex_destroy(&m_mutex4LogQue);
	pthread_cond_destroy(&m_cond4LogQue);
	pthread_mutex_destroy(&m_mutex4DeviceMsgQue);
	pthread_cond_destroy(&m_cond4DeviceMsgQue);
	pthread_mutex_destroy(&m_mutex4InteractMsgQue);
	pthread_cond_destroy(&m_cond4InteractMsgQue);
	pthread_mutex_destroy(&m_mutex4PublishMsgQue);
	pthread_cond_destroy(&m_cond4PublishMsgQue);
	pthread_mutex_destroy(&m_mutex4EndpointLingerDataList);
	pthread_mutex_destroy(&m_mutex4DeviceList);
	pthread_mutex_destroy(&m_mutex4LinkDeviceList);
	g_nRefCount--;
	if (g_nRefCount <= 0) {
		g_nRefCount = 0;
		pthread_mutex_destroy(&g_mutex4PubSequence);
	}
}

int ccrfid_proxy::DeviceProxy::Start(unsigned short usDataPort_, unsigned short usPublishPort_, 
	unsigned short usInteractPort_, unsigned short usLogType_)
{
	char szLog[256] = { 0 };
	m_nErrCode = ERR_OK;
	if (m_nRun) {
		m_nErrCode = ERR_PROXY_ALREADY_RUNNING;
		sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d], proxy already running at %u,%u,%u\r\n", 
			__FUNCTION__, __LINE__, m_usDataPort, m_usPublishPort, m_usInteractPort);
		writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGCATEGORY_INFO);
		return -1;
	}
	if (usPublishPort_ > 0 && usInteractPort_ > 0) {
		unsigned long long ullInstVal = TS_StartServer(usDataPort_ > 0 ? usDataPort_ : DEFAULT_DATA_PORT,
			fMsgCb, this, 300);
		if (ullInstVal > 0) {
			do {
				m_publisher = zsocket_new(m_ctx, ZMQ_PUB);
				if (zsocket_bind(m_publisher, "tcp://*:%u", usPublishPort_) == -1) {
					m_nErrCode = ERR_PROXY_PORT_IS_USED;
					break;
				}
				m_interactor = zsocket_new(m_ctx, ZMQ_ROUTER);
				zsocket_set_router_handover(m_interactor, 1);//handle same identity
				//zsocket_set_probe_router(m_interactor, 1);
				if (zsocket_bind(m_interactor, "tcp://*:%u", usInteractPort_) == -1) {
					m_nErrCode = ERR_PROXY_PORT_IS_USED;
					break;
				}
				m_nRun = 1;
				if (m_pthdNetwork.p == NULL) {
					pthread_create(&m_pthdNetwork, NULL, dealNetworkThread, this);
				}
				if (m_pthdPublisher.p == NULL) {
					pthread_create(&m_pthdPublisher, NULL, dealPublishThread, this);
				}
				if (m_pthdInteractor.p == NULL) {
					pthread_create(&m_pthdInteractor, NULL, dealInteractThread, this);
				}
				if (m_pthdDevice.p == NULL) {
					pthread_create(&m_pthdDevice, NULL, dealDeviceThread, this);
				}
				m_usDataPort = usDataPort_;
				m_usPublishPort = usPublishPort_;
				m_usInteractPort = usInteractPort_;
				m_ullSrvInst = ullInstVal;

				sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d], proxy start at %u,%u,%u\r\n", 
					__FUNCTION__, __LINE__, usDataPort_, usPublishPort_, usInteractPort_);
				writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);

				if (m_usLogType != usLogType_) {
					pf_logger::LogConfig logConf;
					LOG_GetConfig(m_ullLogInst, &logConf);
					logConf.usLogType = usLogType_;
					LOG_SetConfig(m_ullLogInst, logConf);
					m_usLogType = usLogType_;
				}
				return 0;
			} while (0);
			if (m_publisher) {
				zsocket_destroy(m_ctx, m_publisher);
				m_publisher = NULL;
			}
			if (m_interactor) {
				zsocket_destroy(m_ctx, m_interactor);
				m_interactor = NULL;
			}
			TS_StopServer(ullInstVal);
			ullInstVal = 0;
		}
	}
	return -1;
}

int ccrfid_proxy::DeviceProxy::Stop()
{
	m_nErrCode = 0;
	if (m_nRun) {
		if (m_ullSrvInst) {
			TS_StopServer(m_ullSrvInst);
			m_ullSrvInst = 0;
			m_usDataPort = 0;
		}
		if (m_publisher) {
			zsocket_destroy(m_ctx, m_publisher);
			m_publisher = NULL;
		}
		if (m_interactor) {
			zsocket_destroy(m_ctx, m_interactor);
			m_interactor = NULL;
		}
		char szLog[256] = { 0 };
		sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]proxy stop at %u,%u,%u\r\n", __FUNCTION__,
			__LINE__, m_usDataPort, m_usPublishPort, m_usInteractPort);
		writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);

		m_nRun = 0;
		if (m_pthdDevice.p) {
			pthread_cond_broadcast(&m_cond4DeviceMsgQue);
			pthread_join(m_pthdDevice, NULL);
			m_pthdDevice.p = NULL;
		}
		if (m_pthdNetwork.p) {
			pthread_join(m_pthdNetwork, NULL);
			m_pthdNetwork.p = NULL;
		}
		if (m_pthdInteractor.p) {
			pthread_cond_broadcast(&m_cond4InteractMsgQue);
			pthread_join(m_pthdInteractor, NULL);
			m_pthdInteractor.p = NULL;
		}
		if (m_pthdPublisher.p) {
			pthread_cond_broadcast(&m_cond4PublishMsgQue);
			pthread_join(m_pthdPublisher, NULL);
			m_pthdPublisher.p = NULL;
		}
	}
	return 0;
}

void ccrfid_proxy::DeviceProxy::SetLbsQueryParameter(int nLbsQry_, const char * pQryKey_)
{
	m_nQryLbs = nLbsQry_;
	if (pQryKey_ && strlen(pQryKey_)) {
		strncpy_s(m_szKey, sizeof(m_szKey), pQryKey_, strlen(pQryKey_));
	}
	else {
		m_nQryLbs = 0;
	}
}

int ccrfid_proxy::DeviceProxy::GetLastError()
{
	return m_nErrCode;
}

bool ccrfid_proxy::DeviceProxy::addLog(ccrfid_proxy::LogContext * pLogCtx_)
{
	bool result = false;
	if (pLogCtx_) {
		if (pLogCtx_->pLogData && pLogCtx_->uiDataLen) {
			pthread_mutex_lock(&m_mutex4LogQue);
			m_logQue.push(pLogCtx_);
			if (m_logQue.size() == 1) {
				pthread_cond_broadcast(&m_cond4LogQue);
			}
			pthread_mutex_unlock(&m_mutex4LogQue);
			result = true;
		}
	}
	return result;
}

void ccrfid_proxy::DeviceProxy::handleLog()
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
		ccrfid_proxy::LogContext * pLogCtx = m_logQue.front();
		m_logQue.pop();
		pthread_mutex_unlock(&m_mutex4LogQue);
		if (pLogCtx) {
			if (pLogCtx->pLogData) {
				if (m_ullLogInst) {
					LOG_Log(m_ullLogInst, pLogCtx->pLogData, pLogCtx->usLogCategory, pLogCtx->usLogType);
				}
				delete[] pLogCtx->pLogData;
				pLogCtx->pLogData = NULL;
			}
			delete pLogCtx;
			pLogCtx = NULL;
		}
	} while (1);
}

void ccrfid_proxy::DeviceProxy::writeLog(const char * pLogContent_, unsigned short usLogCategory_,
	unsigned short usLogType_)
{
	if (pLogContent_ && strlen(pLogContent_)) {
		ccrfid_proxy::LogContext * pLogCtx = new ccrfid_proxy::LogContext();
		pLogCtx->uiDataLen = (unsigned int)strlen(pLogContent_);
		pLogCtx->pLogData = new char[pLogCtx->uiDataLen + 1];
		memcpy_s(pLogCtx->pLogData, pLogCtx->uiDataLen + 1, pLogContent_, pLogCtx->uiDataLen);
		pLogCtx->pLogData[pLogCtx->uiDataLen] = '\0';
		pLogCtx->usLogType = usLogType_;
		pLogCtx->usLogCategory = usLogCategory_;
		if (!addLog(pLogCtx)) {
			delete[] pLogCtx->pLogData;
			pLogCtx->pLogData = NULL;
			delete pLogCtx;
			pLogCtx = NULL;
		}
	}
}

bool ccrfid_proxy::DeviceProxy::addDeviceMessage(ccrfid_proxy::DeviceMessage * pDevMsg_)
{
	bool result = false;
	if (pDevMsg_) {
		if (pDevMsg_->pMsgData) {
			pthread_mutex_lock(&m_mutex4DeviceMsgQue);
			m_deviceMsgQue.push(pDevMsg_);
			if (m_deviceMsgQue.size() == 1) {
				pthread_cond_broadcast(&m_cond4DeviceMsgQue);
			}
			pthread_mutex_unlock(&m_mutex4DeviceMsgQue);
			result = true;
		}
	}
	return result;
}

void ccrfid_proxy::DeviceProxy::handleDeviceMessage()
{
	do {
		pthread_mutex_lock(&m_mutex4DeviceMsgQue);
		while (m_nRun && m_deviceMsgQue.empty()) {
			pthread_cond_wait(&m_cond4DeviceMsgQue, &m_mutex4DeviceMsgQue);
		}
		if (!m_nRun && m_deviceMsgQue.empty()) {
			pthread_mutex_unlock(&m_mutex4DeviceMsgQue);
			break;
		}
		DeviceMessage * pDevMsg = m_deviceMsgQue.front();
		m_deviceMsgQue.pop();
		pthread_mutex_unlock(&m_mutex4DeviceMsgQue);
		if (pDevMsg) {
			if (pDevMsg->pMsgData) {
				parseDeviceMessage(pDevMsg);
				delete[] pDevMsg->pMsgData;
				pDevMsg->pMsgData = NULL;
			}
			delete pDevMsg;
			pDevMsg = NULL;
		}
	} while (1);
}

void ccrfid_proxy::DeviceProxy::parseDeviceMessage(ccrfid_proxy::DeviceMessage * pDevMsg_)
{
	char szLog[1024] = { 0 };
	if (pDevMsg_) {
		unsigned char * pData = NULL;
		unsigned int uiDataLen = 0;
		pthread_mutex_lock(&m_mutex4EndpointLingerDataList);
		if (zhash_size(m_endpointLingerDataList)) {
			ccrfid_proxy::LingerData * pLingerData = (ccrfid_proxy::LingerData *)zhash_lookup(m_endpointLingerDataList,
				pDevMsg_->szEndpoint);
			if (pLingerData) {
				if (pLingerData->pData && pLingerData->uiDataLen) {
					uiDataLen = pLingerData->uiDataLen + pDevMsg_->uiMsgDataLen;
					pData = new unsigned char[uiDataLen + 1];
					memcpy_s(pData, uiDataLen + 1, pLingerData->pData, pLingerData->uiDataLen);
					memcpy_s(pData + pLingerData->uiDataLen, uiDataLen + 1 - pLingerData->uiDataLen, pDevMsg_->pMsgData,
						pDevMsg_->uiMsgDataLen);
					free(pLingerData->pData);
					pLingerData->pData = NULL;
					pLingerData->uiDataLen = 0;
					zhash_delete(m_endpointLingerDataList, pDevMsg_->szEndpoint);
				}
			}
		}
		pthread_mutex_unlock(&m_mutex4EndpointLingerDataList);
		if (pData == NULL) {
			uiDataLen = pDevMsg_->uiMsgDataLen;
			pData = new unsigned char[uiDataLen + 1];
			memcpy_s(pData, uiDataLen + 1, pDevMsg_->pMsgData, uiDataLen);
			pData[uiDataLen] = '\0';
		}
		if (pData && uiDataLen) {
			unsigned int uiIndex = 0;
			unsigned int uiDataCellBeginIndex = 0;
			unsigned int uiDataCellEndIndex = 0;
			unsigned int uiDataCellLen = 0;
			do {
				int rc = getWholeMessage(pData, uiDataLen, uiIndex, uiDataCellBeginIndex, uiDataCellEndIndex);
				if (rc == 0) {
					break;
				}
				else if (rc == 1) {
					unsigned int uiLeftDataLen = uiDataLen - uiDataCellBeginIndex;
					size_t nSize = sizeof(ccrfid_proxy::LingerData);
					ccrfid_proxy::LingerData * pLingerData = (ccrfid_proxy::LingerData *)zmalloc(nSize);
					pLingerData->uiDataLen = uiLeftDataLen;
					pLingerData->pData = (unsigned char *)zmalloc(uiLeftDataLen + 1);
					memcpy_s(pLingerData->pData, uiLeftDataLen, pData + uiDataCellBeginIndex, uiLeftDataLen);
					pthread_mutex_lock(&m_mutex4EndpointLingerDataList);
					zhash_update(m_endpointLingerDataList, pDevMsg_->szEndpoint, pLingerData);
					zhash_freefn(m_endpointLingerDataList, pDevMsg_->szEndpoint, freeLingerData);
					pthread_mutex_unlock(&m_mutex4EndpointLingerDataList);
					break;
				}
				else if (rc == 2) {
					uiDataCellLen = uiDataCellEndIndex - uiDataCellBeginIndex - 1;
					uiIndex = uiDataCellEndIndex + 1;
					unsigned char * pBuf = new unsigned char[uiDataCellLen + 1];
					memcpy_s(pBuf, uiDataCellLen, pData + uiDataCellBeginIndex + 1, uiDataCellLen);
					pBuf[uiDataCellLen] = '\0';
					std::vector<std::string> strList;
					std::string strCell = (char *)pBuf;
					sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]receive from=%s, data=%s\r\n", __FUNCTION__,
						__LINE__, pDevMsg_->szEndpoint, strCell.c_str());
					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
					unsigned long long ulTime = (unsigned long long)time(NULL);
					splitString(strCell, "*", strList);
					std::string strTagName;
					std::string strDeviceId;
					std::string strContentLength;
					std::string strContent;
					if (strList.size() >= 4) {
						strTagName = strList[0];
						strDeviceId = strList[1];
						char szDeviceId[16] = { 0 };
						strncpy_s(szDeviceId, sizeof(szDeviceId), strDeviceId.c_str(), strDeviceId.size());
						updateDeviceLink(pDevMsg_->szEndpoint, szDeviceId);
						strContentLength = strList[2];
						strContent = strList[3];
						int nContentLength = atoi(strContentLength.c_str());
						std::vector<std::string> strContentList;
						splitString(strContent, ",", strContentList);
						if (!strContentList.empty()) {
							if (strcmp(strContentList[0].c_str(), "LK") == 0) {
								char szReply[128] = { 0 };
								sprintf_s(szReply, sizeof(szReply), "[SG*%s*0002*LK]", strDeviceId.c_str());
								TS_SendData(m_ullSrvInst, pDevMsg_->szEndpoint, szReply, (unsigned int)strlen(szReply));
								size_t nListCount = strContentList.size();
								if (nListCount == 4) {
									ccrfid_proxy::DeviceAlive devAlive;
									sprintf_s(devAlive.szFactoryId, sizeof(devAlive.szFactoryId), "01");
									strncpy_s(devAlive.szDeviceId, sizeof(devAlive.szDeviceId), strDeviceId.c_str(),
										strDeviceId.size());
									devAlive.usBattery = (unsigned short)atoi(strContentList[3].c_str());
									handleDeviceAlive(&devAlive, ulTime);
								}
							}
							else if (strcmp(strContentList[0].c_str(), "UD") == 0) {
								size_t nListCount = strContentList.size();
								if (nListCount >= 20) {
									ccrfid_proxy::DeviceLocate devLocate;
									sprintf_s(devLocate.szFactoryId, sizeof(devLocate.szFactoryId), "01");
									strcpy_s(devLocate.szDeviceId, sizeof(devLocate.szDeviceId), strDeviceId.c_str());
									struct tm tm_time;
									std::string strDate = strContentList[1];
									std::string strTime = strContentList[2];
									sscanf_s(strDate.c_str(), "%02u%02u%02u", &tm_time.tm_mday, &tm_time.tm_mon, &tm_time.tm_year);
									tm_time.tm_year += (2000 - 1900);
									tm_time.tm_mon -= 1;
									sscanf_s(strTime.c_str(), "%02u%02u%02u", &tm_time.tm_hour, &tm_time.tm_min, &tm_time.tm_sec);
									tm_time.tm_hour += 8;
									if (tm_time.tm_hour >= 24) {
										tm_time.tm_hour -= 24;
										tm_time.tm_mday += 1;
									}
									devLocate.locateInfo.ulLocateTime = (unsigned long)(mktime(&tm_time));
									std::string strLocateFlag = strContentList[3];
									if (strLocateFlag == "A" || strLocateFlag == "a") {
										devLocate.locateInfo.nLocateFlag = 1;
									}
									else {
										devLocate.locateInfo.nLocateFlag = 0;
									}
									std::string strLatitude = strContentList[4];
									devLocate.locateInfo.dLatitude = atof(strLatitude.c_str());
									std::string strLatType = strContentList[5];
									if (strLatType == "N" || strLatType == "n") {
										devLocate.locateInfo.usLatType = 1;
									}
									else {
										devLocate.locateInfo.usLatType = 0;
									}
									std::string strLngitude = strContentList[6];
									devLocate.locateInfo.dLngitude = atof(strLngitude.c_str());
									std::string strLngType = strContentList[7];
									if (strLngType == "E" || strLngType == "e") {
										devLocate.locateInfo.usLngType = 1;
									}
									else {
										devLocate.locateInfo.usLngType = 0;
									}
									std::string strSpeed = strContentList[8];
									devLocate.locateInfo.dMoveSpeed = atof(strSpeed.c_str());
									std::string strDirection = strContentList[9];
									devLocate.locateInfo.dMoveDirection = atof(strDirection.c_str());
									std::string strHeight = strContentList[10];
									devLocate.locateInfo.nElevation = atoi(strHeight.c_str());
									std::string strSatelliteCount = strContentList[11];
									devLocate.locateInfo.nGpsStatelliteCount = atoi(strSatelliteCount.c_str());
									std::string strSignalIntensity = strContentList[12];
									devLocate.locateInfo.nSignalIntensity = atoi(strSignalIntensity.c_str());
									std::string strBattery = strContentList[13];
									devLocate.locateInfo.nBattery = atoi(strBattery.c_str());
									std::string strDeviceStatus = strContentList[16];
									sscanf_s(strDeviceStatus.c_str(), "%x", &devLocate.locateInfo.nStatus);
									std::string strBaseStationCount = strContentList[17];
									devLocate.locateInfo.nBaseStationCount = atoi(strBaseStationCount.c_str());
									std::string strGsmDelay = strContentList[18];
									devLocate.locateInfo.nGsmDelay = atoi(strGsmDelay.c_str());
									std::string strNationCode = strContentList[19];
									devLocate.locateInfo.nNationCode = atoi(strNationCode.c_str());
									std::string strNetCode = strContentList[20];
									devLocate.locateInfo.nNetCode = atoi(strNetCode.c_str());
									int nBSCount = devLocate.locateInfo.nBaseStationCount;
									if (nBSCount > 0) {
										devLocate.locateInfo.pBaseStationList = new ccrfid_device::BaseStation[nBSCount];
										for (int i = 0; i < nBSCount; i++) {
											std::string strLocationCode = strContentList[21 + i * 3];
											std::string strBaseStationId = strContentList[21 + i * 3 + 1];
											std::string strSignalIntensity = strContentList[21 + i * 3 + 2];
											devLocate.locateInfo.pBaseStationList[i].nLocateAreaCode = atoi(strLocationCode.c_str());
											devLocate.locateInfo.pBaseStationList[i].nCellId = atoi(strBaseStationId.c_str());
											devLocate.locateInfo.pBaseStationList[i].nSignalIntensity = atoi(strSignalIntensity.c_str());
										}
									}
									if (nListCount >= (size_t)(21 + nBSCount * 3)) {
										std::string strDetectedWifiCount = strContentList[21 + nBSCount * 3];
										int nWifiCount = atoi(strDetectedWifiCount.c_str());
										if (nWifiCount > 0 && nListCount >= (size_t)(21 + nBSCount * 3 + nWifiCount * 3)) {
											devLocate.locateInfo.nDetectedWifiCount = nWifiCount;
											devLocate.locateInfo.pDetectedWifiList = new ccrfid_device::WifiInformation[nWifiCount];
											for (int i = 0; i < nWifiCount; i++) {
												std::string strWifiTagName = strContentList[22 + nBSCount * 3 + (i * 3)];
												std::string strWifiMacAddress = strContentList[22 + nBSCount * 3 + (i * 3 + 1)];
												std::string strWifiSignalIntensity = strContentList[22 + nBSCount * 3 + (i * 3 + 2)];
												strncpy_s(devLocate.locateInfo.pDetectedWifiList[i].szWifiTagName,
													sizeof(devLocate.locateInfo.pDetectedWifiList[i].szWifiTagName),
													strWifiTagName.c_str(), strWifiTagName.size());
												strncpy_s(devLocate.locateInfo.pDetectedWifiList[i].szWifiMacAddress,
													sizeof(devLocate.locateInfo.pDetectedWifiList[i].szWifiMacAddress),
													strWifiMacAddress.c_str(), strWifiMacAddress.size());
												devLocate.locateInfo.pDetectedWifiList[i].nWifiSignalIntensity 
													= atoi(strWifiSignalIntensity.c_str());
											}
										}
									}
									handleDeviceLocate(&devLocate, ulTime);
									if (devLocate.locateInfo.pBaseStationList) {
										delete[] devLocate.locateInfo.pBaseStationList;
										devLocate.locateInfo.pBaseStationList = NULL;
									}
									if (devLocate.locateInfo.pDetectedWifiList) {
										delete[] devLocate.locateInfo.pDetectedWifiList;
										devLocate.locateInfo.pDetectedWifiList = NULL;
									}
								}
							}
							else if (strcmp(strContentList[0].c_str(), "UD2") == 0) {
								size_t nListCount = strContentList.size();
								if (nListCount >= 20) {
									ccrfid_proxy::DeviceLocate devLocate;
									sprintf_s(devLocate.szFactoryId, sizeof(devLocate.szFactoryId), "01");
									strcpy_s(devLocate.szDeviceId, sizeof(devLocate.szDeviceId), strDeviceId.c_str());
									struct tm tm_time;
									std::string strDate = strContentList[1];
									std::string strTime = strContentList[2];
									sscanf_s(strDate.c_str(), "%02d%02d%02d", &tm_time.tm_mday, &tm_time.tm_mon, &tm_time.tm_year);
									tm_time.tm_year += (2000 - 1900);
									tm_time.tm_mon -= 1;
									sscanf_s(strTime.c_str(), "%02d%02d%02d", &tm_time.tm_hour, &tm_time.tm_min, &tm_time.tm_sec);
									tm_time.tm_hour += 8;
									if (tm_time.tm_hour >= 24) {
										tm_time.tm_hour -= 24;
										tm_time.tm_mday += 1;
									}
									devLocate.locateInfo.ulLocateTime = (unsigned long)(mktime(&tm_time));
									std::string strLocateFlag = strContentList[3];
									if (strLocateFlag == "A" || strLocateFlag == "a") {
										devLocate.locateInfo.nLocateFlag = 1;
									}
									else {
										devLocate.locateInfo.nLocateFlag = 0;
									}
									std::string strLatitude = strContentList[4];
									devLocate.locateInfo.dLatitude = atof(strLatitude.c_str());
									std::string strLatType = strContentList[5];
									if (strLatType == "N" || strLatType == "n") {
										devLocate.locateInfo.usLatType = 1;
									}
									else {
										devLocate.locateInfo.usLatType = 0;
									}
									std::string strLngitude = strContentList[6];
									devLocate.locateInfo.dLngitude = atof(strLngitude.c_str());
									std::string strLngType = strContentList[7];
									if (strLngType == "E" || strLngType == "e") {
										devLocate.locateInfo.usLngType = 1;
									}
									else {
										devLocate.locateInfo.usLngType = 0;
									}
									std::string strSpeed = strContentList[8];
									devLocate.locateInfo.dMoveSpeed = atof(strSpeed.c_str());
									std::string strDirection = strContentList[9];
									devLocate.locateInfo.dMoveDirection = atof(strDirection.c_str());
									std::string strHeight = strContentList[10];
									devLocate.locateInfo.nElevation = atoi(strHeight.c_str());
									std::string strSatelliteCount = strContentList[11];
									devLocate.locateInfo.nGpsStatelliteCount = atoi(strSatelliteCount.c_str());
									std::string strSignalIntensity = strContentList[12];
									devLocate.locateInfo.nSignalIntensity = atoi(strSignalIntensity.c_str());
									std::string strBattery = strContentList[13];
									devLocate.locateInfo.nBattery = atoi(strBattery.c_str());
									std::string strDeviceStatus = strContentList[16];
									sscanf_s(strDeviceStatus.c_str(), "%x", &devLocate.locateInfo.nStatus);
									std::string strBaseStationCount = strContentList[17];
									devLocate.locateInfo.nBaseStationCount = atoi(strBaseStationCount.c_str());
									std::string strGsmDelay = strContentList[18];
									devLocate.locateInfo.nGsmDelay = atoi(strGsmDelay.c_str());
									std::string strNationCode = strContentList[19];
									devLocate.locateInfo.nNationCode = atoi(strNationCode.c_str());
									std::string strNetCode = strContentList[20];
									devLocate.locateInfo.nNetCode = atoi(strNetCode.c_str());
									int nBSCount = devLocate.locateInfo.nBaseStationCount;
									if (nBSCount > 0) {
										devLocate.locateInfo.pBaseStationList = new ccrfid_device::BaseStation[nBSCount];
										for (int i = 0; i < nBSCount; i++) {
											std::string strLocationCode = strContentList[21 + i * 3];
											std::string strBaseStationId = strContentList[21 + i * 3 + 1];
											std::string strSignalIntensity = strContentList[21 + i * 3 + 2];
											devLocate.locateInfo.pBaseStationList[i].nLocateAreaCode = atoi(strLocationCode.c_str());
											devLocate.locateInfo.pBaseStationList[i].nCellId = atoi(strBaseStationId.c_str());
											devLocate.locateInfo.pBaseStationList[i].nSignalIntensity = atoi(strSignalIntensity.c_str());
										}
									}
									if (nListCount >= (size_t)(21 + nBSCount * 3)) {
										std::string strDetectedWifiCount = strContentList[21 + nBSCount * 3];
										int nWifiCount = atoi(strDetectedWifiCount.c_str());
										if (nWifiCount > 0 && nListCount >= (size_t)(21 + nBSCount * 3 + nWifiCount * 3)) {
											devLocate.locateInfo.nDetectedWifiCount = nWifiCount;
											devLocate.locateInfo.pDetectedWifiList = new ccrfid_device::WifiInformation[nWifiCount];
											for (int i = 0; i < nWifiCount; i++) {
												std::string strWifiTagName = strContentList[22 + nBSCount * 3 + (i * 3)];
												std::string strWifiMacAddress = strContentList[22 + nBSCount * 3 + (i * 3 + 1)];
												std::string strWifiSignalIntensity = strContentList[22 + nBSCount * 3 + (i * 3 + 2)];
												strncpy_s(devLocate.locateInfo.pDetectedWifiList[i].szWifiTagName,
													sizeof(devLocate.locateInfo.pDetectedWifiList[i].szWifiTagName),
													strWifiTagName.c_str(), strWifiTagName.size());
												strncpy_s(devLocate.locateInfo.pDetectedWifiList[i].szWifiMacAddress,
													sizeof(devLocate.locateInfo.pDetectedWifiList[i].szWifiMacAddress),
													strWifiMacAddress.c_str(), strWifiMacAddress.size());
												devLocate.locateInfo.pDetectedWifiList[i].nWifiSignalIntensity
													= atoi(strWifiSignalIntensity.c_str());
											}
										}
									}
									handleDeviceLocate(&devLocate, ulTime);
									if (devLocate.locateInfo.pBaseStationList) {
										delete[] devLocate.locateInfo.pBaseStationList;
										devLocate.locateInfo.pBaseStationList = NULL;
									}
									if (devLocate.locateInfo.pDetectedWifiList) {
										delete[] devLocate.locateInfo.pDetectedWifiList;
										devLocate.locateInfo.pDetectedWifiList = NULL;
									}
								}
							}
							else if (strcmp(strContentList[0].c_str(), "AL") == 0) {
								char szReply[128] = { 0 };
								sprintf_s(szReply, sizeof(szReply), "[SG*%s*0002*AL]", strDeviceId.c_str());
								TS_SendData(m_ullSrvInst, pDevMsg_->szEndpoint, szReply, (unsigned int)strlen(szReply));
								size_t nListCount = strContentList.size();
								if (nListCount > 20) {
									ccrfid_proxy::DeviceLocate devLocate;
									sprintf_s(devLocate.szFactoryId, sizeof(devLocate.szFactoryId), "01");
									strcpy_s(devLocate.szDeviceId, sizeof(devLocate.szDeviceId), strDeviceId.c_str());
									struct tm tm_time;
									std::string strDate = strContentList[1];
									std::string strTime = strContentList[2];
									sscanf_s(strDate.c_str(), "%02d%02d%02d", &tm_time.tm_mday, &tm_time.tm_mon, &tm_time.tm_year);
									tm_time.tm_year += (2000 - 1900);
									tm_time.tm_mon -= 1;
									sscanf_s(strTime.c_str(), "%02d%02d%02d", &tm_time.tm_hour, &tm_time.tm_min, &tm_time.tm_sec);
									tm_time.tm_hour += 8;
									if (tm_time.tm_hour >= 24) {
										tm_time.tm_hour -= 24;
										tm_time.tm_mday += 1;
									}
									devLocate.locateInfo.ulLocateTime = (unsigned long)(mktime(&tm_time));
									std::string strLocateFlag = strContentList[3];
									if (strLocateFlag == "A" || strLocateFlag == "a") {
										devLocate.locateInfo.nLocateFlag = 1;
									}
									else {
										devLocate.locateInfo.nLocateFlag = 0;
									}
									std::string strLatitude = strContentList[4];
									devLocate.locateInfo.dLatitude = atof(strLatitude.c_str());
									std::string strLatType = strContentList[5];
									if (strLatType == "N" || strLatType == "n") {
										devLocate.locateInfo.usLatType = 1;
									}
									else {
										devLocate.locateInfo.usLatType = 0;
									}
									std::string strLngitude = strContentList[6];
									devLocate.locateInfo.dLngitude = atof(strLngitude.c_str());
									std::string strLngType = strContentList[7];
									if (strLngType == "E" || strLngType == "e") {
										devLocate.locateInfo.usLngType = 1;
									}
									else {
										devLocate.locateInfo.usLngType = 0;
									}
									std::string strSpeed = strContentList[8];
									devLocate.locateInfo.dMoveSpeed = atof(strSpeed.c_str());
									std::string strDirection = strContentList[9];
									devLocate.locateInfo.dMoveDirection = atof(strDirection.c_str());
									std::string strHeight = strContentList[10];
									devLocate.locateInfo.nElevation = atoi(strHeight.c_str());
									std::string strSatelliteCount = strContentList[11];
									devLocate.locateInfo.nGpsStatelliteCount = atoi(strSatelliteCount.c_str());
									std::string strSignalIntensity = strContentList[12];
									devLocate.locateInfo.nSignalIntensity = atoi(strSignalIntensity.c_str());
									std::string strBattery = strContentList[13];
									devLocate.locateInfo.nBattery = atoi(strBattery.c_str());
									std::string strDeviceStatus = strContentList[16];
									sscanf_s(strDeviceStatus.c_str(), "%x", &devLocate.locateInfo.nStatus);
									std::string strBaseStationCount = strContentList[17];
									devLocate.locateInfo.nBaseStationCount = atoi(strBaseStationCount.c_str());
									std::string strGsmDelay = strContentList[18];
									devLocate.locateInfo.nGsmDelay = atoi(strGsmDelay.c_str());
									std::string strNationCode = strContentList[19];
									devLocate.locateInfo.nNationCode = atoi(strNationCode.c_str());
									std::string strNetCode = strContentList[20];
									devLocate.locateInfo.nNetCode = atoi(strNetCode.c_str());
									int nBSCount = devLocate.locateInfo.nBaseStationCount;
									if (nBSCount > 0) {
										devLocate.locateInfo.pBaseStationList = new ccrfid_device::BaseStation[nBSCount];
										for (int i = 0; i < nBSCount; i++) {
											std::string strLocationCode = strContentList[21 + i * 3];
											std::string strBaseStationId = strContentList[21 + i * 3 + 1];
											std::string strSignalIntensity = strContentList[21 + i * 3 + 2];
											devLocate.locateInfo.pBaseStationList[i].nLocateAreaCode = atoi(strLocationCode.c_str());
											devLocate.locateInfo.pBaseStationList[i].nCellId = atoi(strBaseStationId.c_str());
											devLocate.locateInfo.pBaseStationList[i].nSignalIntensity = atoi(strSignalIntensity.c_str());
										}
									}
									if (nListCount >= (size_t)(21 + nBSCount * 3)) {
										std::string strDetectedWifiCount = strContentList[21 + nBSCount * 3];
										int nWifiCount = atoi(strDetectedWifiCount.c_str());
										if (nWifiCount > 0 && nListCount >= (size_t)(21 + nBSCount * 3 + nWifiCount * 3)) {
											devLocate.locateInfo.nDetectedWifiCount = nWifiCount;
											devLocate.locateInfo.pDetectedWifiList = new ccrfid_device::WifiInformation[nWifiCount];
											for (int i = 0; i < nWifiCount; i++) {
												std::string strWifiTagName = strContentList[22 + nBSCount * 3 + (i * 3)];
												std::string strWifiMacAddress = strContentList[22 + nBSCount * 3 + (i * 3 + 1)];
												std::string strWifiSignalIntensity = strContentList[22 + nBSCount * 3 + (i * 3 + 2)];
												strncpy_s(devLocate.locateInfo.pDetectedWifiList[i].szWifiTagName,
													sizeof(devLocate.locateInfo.pDetectedWifiList[i].szWifiTagName),
													strWifiTagName.c_str(), strWifiTagName.size());
												strncpy_s(devLocate.locateInfo.pDetectedWifiList[i].szWifiMacAddress,
													sizeof(devLocate.locateInfo.pDetectedWifiList[i].szWifiMacAddress),
													strWifiMacAddress.c_str(), strWifiMacAddress.size());
												devLocate.locateInfo.pDetectedWifiList[i].nWifiSignalIntensity
													= atoi(strWifiSignalIntensity.c_str());
											}
										}
									}
									handleDeviceAlarm(&devLocate, ulTime);
									if (devLocate.locateInfo.pBaseStationList) {
										delete[] devLocate.locateInfo.pBaseStationList;
										devLocate.locateInfo.pBaseStationList = NULL;
									}
									if (devLocate.locateInfo.pDetectedWifiList) {
										delete[] devLocate.locateInfo.pDetectedWifiList;
										devLocate.locateInfo.pDetectedWifiList = NULL;
									}
								}
							} 
							else if (strcmp(strContentList[0].c_str(), "TKQ") == 0) {
								char szReply[128] = { 0 };
								sprintf_s(szReply, sizeof(szReply), "[SG*%s*0003*TKQ]", strDeviceId.c_str());
								TS_SendData(m_ullSrvInst, pDevMsg_->szEndpoint, szReply, (unsigned int)strlen(szReply));
							}
							else if (strcmp(strContentList[0].c_str(), "TKQ2") == 0) {
								char szReply[128] = { 0 };
								sprintf_s(szReply, sizeof(szReply), "[SG*%s*0004*TKQ2]", strDeviceId.c_str());
								TS_SendData(m_ullSrvInst, pDevMsg_->szEndpoint, szReply, (unsigned int)strlen(szReply));
							}
							else if (strcmp(strContentList[0].c_str(), "ZJ") == 0) {
								//
							}
							else if (strcmp(strContentList[0].c_str(), "ZJSJ") == 0) {
								//
							}
							else if (strcmp(strContentList[0].c_str(), "SBLJ") == 0) {
								//
							}
							else if (strcmp(strContentList[0].c_str(), "RWZX") == 0) {
								//
							}
							else if (strcmp(strContentList[0].c_str(), "WSTF") == 0) {
								//
							}
							else if (strcmp(strContentList[0].c_str(), "UPLOAD") == 0) {
								//
							}
						}
					}
					delete[] pBuf;
					pBuf = NULL;
				}
			} while (1);
			delete[] pData;
			pData = NULL;
		}
	}
}

int ccrfid_proxy::DeviceProxy::getWholeMessage(const unsigned char * pData_, unsigned int uiDataLen_,
	unsigned int uiIndex_, unsigned int & uiBeginIndex_, unsigned int & uiEndIndex_)
{
	int result = 0;
	unsigned int i = uiIndex_;
	char bc = BEGIN_TOKEN;
	char ec = END_TOKEN;
	bool bFindHead = false;
	do {
		if (i >= uiDataLen_) {
			break;
		}
		if (!bFindHead) {
			if (pData_[i] == bc) {
				result = 1;
				bFindHead = true;
				uiBeginIndex_ = i;
			}
			i++;
		}
		else {
			if (pData_[i] == ec) {
				result = 2;
				uiEndIndex_ = i;
				break;
			}
			else {
				i++;
			}
		}
	} while (1);
	return result;
}

void ccrfid_proxy::DeviceProxy::splitString(std::string strSource_, std::string strDelimiter_,
	std::vector<std::string> & strList_)
{
	strList_.clear();
	std::string strCell = strSource_;
	if (!strCell.empty()) {
		size_t n = strCell.find_first_of(strDelimiter_);
		while (n != std::string::npos) {
			std::string strUnit = strCell.substr(0, n);
			strList_.push_back(strUnit);
			strCell = strCell.substr(n + 1);
			n = strCell.find_first_of(strDelimiter_);
		}
		if (!strCell.empty()) {
			strList_.push_back(strCell);
		}
	}
}

void ccrfid_proxy::DeviceProxy::updateDeviceLink(const char * pEndpoint_, const char * pDeviceId_)
{
	if (pEndpoint_ && strlen(pEndpoint_) && pDeviceId_ && strlen(pDeviceId_)) {
		pthread_mutex_lock(&m_mutex4DeviceList);
		std::string strDeviceId = pDeviceId_;
		if (!m_deviceList2.empty()) {
			std::map<std::string, ccrfid_proxy::DeviceInfo *>::iterator iter = m_deviceList2.find(strDeviceId);
			if (iter != m_deviceList2.end()) {
				ccrfid_proxy::DeviceInfo * pDevInfo = iter->second;
				if (pDevInfo) {
					if (strcmp(pDevInfo->szLink, pEndpoint_) != 0) {
						strncpy_s(pDevInfo->szLink, sizeof(pDevInfo->szLink), pEndpoint_, strlen(pEndpoint_));
					}
				}
			}
			else {
				size_t nDevInfoSize = sizeof(ccrfid_proxy::DeviceInfo);
				ccrfid_proxy::DeviceInfo * pDevInfo = (ccrfid_proxy::DeviceInfo *)zmalloc(nDevInfoSize);
				memset(pDevInfo, 0, nDevInfoSize);
				strncpy_s(pDevInfo->szDeviceId, sizeof(pDevInfo->szDeviceId), pDeviceId_, strlen(pDeviceId_));
				sprintf_s(pDevInfo->szFactoryId, sizeof(pDevInfo->szFactoryId), "01");
				strncpy_s(pDevInfo->szLink, sizeof(pDevInfo->szLink), pEndpoint_, strlen(pEndpoint_));
				pDevInfo->usOnline = 1;
				m_deviceList2.insert(std::make_pair(strDeviceId, pDevInfo));
			}
		}
		else {
			size_t nDevInfoSize = sizeof(ccrfid_proxy::DeviceInfo);
			ccrfid_proxy::DeviceInfo * pDevInfo = (ccrfid_proxy::DeviceInfo *)zmalloc(nDevInfoSize);
			memset(pDevInfo, 0, nDevInfoSize);
			strncpy_s(pDevInfo->szDeviceId, sizeof(pDevInfo->szDeviceId), pDeviceId_, strlen(pDeviceId_));
			sprintf_s(pDevInfo->szFactoryId, sizeof(pDevInfo->szFactoryId), "01");
			strncpy_s(pDevInfo->szLink, sizeof(pDevInfo->szLink), pEndpoint_, strlen(pEndpoint_));
			pDevInfo->usOnline = 1;
			m_deviceList2.insert(std::make_pair(strDeviceId, pDevInfo));
		}
		//if (zhash_size(m_deviceList)) {
		//	ccrfid_proxy::DeviceInfo * pDevInfo = (ccrfid_proxy::DeviceInfo *)zhash_lookup(m_deviceList, pDeviceId_);
		//	if (pDevInfo) {
		//		if (strcmp(pDevInfo->szLink, pEndpoint_) != 0) {
		//			strncpy_s(pDevInfo->szLink, sizeof(pDevInfo->szLink), pEndpoint_, strlen(pEndpoint_));
		//		}
		//	}
		//	else {
		//		size_t nDevInfoSize = sizeof(ccrfid_proxy::DeviceInfo);
		//		ccrfid_proxy::DeviceInfo * pDevInfo = (ccrfid_proxy::DeviceInfo *)zmalloc(nDevInfoSize);
		//		memset(pDevInfo, 0, nDevInfoSize);
		//		strncpy_s(pDevInfo->szDeviceId, sizeof(pDevInfo->szDeviceId), pDeviceId_, strlen(pDeviceId_));
		//		sprintf_s(pDevInfo->szFactoryId, sizeof(pDevInfo->szFactoryId), "01");
		//		strncpy_s(pDevInfo->szLink, sizeof(pDevInfo->szLink), pEndpoint_, strlen(pEndpoint_));
		//		pDevInfo->usOnline = 1;
		//		zhash_update(m_deviceList, pDeviceId_, pDevInfo);
		//		zhash_update(m_deviceList, pDeviceId_, free);
		//	}
		//}
		//else {
		//	size_t nDevInfoSize = sizeof(ccrfid_proxy::DeviceInfo);
		//	ccrfid_proxy::DeviceInfo * pDevInfo = (ccrfid_proxy::DeviceInfo *)zmalloc(nDevInfoSize);
		//	memset(pDevInfo, 0, nDevInfoSize);
		//	strncpy_s(pDevInfo->szDeviceId, sizeof(pDevInfo->szDeviceId), pDeviceId_, strlen(pDeviceId_));
		//	sprintf_s(pDevInfo->szFactoryId, sizeof(pDevInfo->szFactoryId), "01");
		//	strncpy_s(pDevInfo->szLink, sizeof(pDevInfo->szLink), pEndpoint_, strlen(pEndpoint_));
		//	pDevInfo->usOnline = 1;
		//	pDevInfo->ulLastActiveTime = 0;
		//	pDevInfo->ulLastLocateTime = 0;
		//	pDevInfo->usBattery = 0;
		//	pDevInfo->usLoose = 0;
		//	pDevInfo->dLatitude = 0.00;
		//	pDevInfo->dLngitude = 0.00;
		//	zhash_update(m_deviceList, pDeviceId_, pDevInfo);
		//	zhash_freefn(m_deviceList, pDeviceId_, free);
		//}
		pthread_mutex_unlock(&m_mutex4DeviceList);
		pthread_mutex_lock(&m_mutex4LinkDeviceList);
		if (zhash_size(m_linkDeviceList)) {
			char * pDevId = (char *)zhash_lookup(m_linkDeviceList, pEndpoint_);
			if (pDevId) {
				if (strcmp(pDevId, pDeviceId_) != 0) {
					zhash_delete(m_linkDeviceList, pEndpoint_);
					size_t nLen = strlen(pDeviceId_);
					char * pDevIdCopy = (char *)zmalloc(nLen + 1);
					memcpy_s(pDevIdCopy, nLen + 1, pDeviceId_, nLen);
					pDevIdCopy[nLen] = '\0';
					zhash_update(m_linkDeviceList, pEndpoint_, pDevIdCopy);
					zhash_freefn(m_linkDeviceList, pEndpoint_, free);
				}
			}
			else {
				size_t nLen = strlen(pDeviceId_);
				char * pDevIdCopy = (char *)zmalloc(nLen + 1);
				memcpy_s(pDevIdCopy, nLen + 1, pDeviceId_, nLen);
				pDevIdCopy[nLen] = '\0';
				zhash_update(m_linkDeviceList, pEndpoint_, pDevIdCopy);
				zhash_freefn(m_linkDeviceList, pEndpoint_, free);
			}
		}
		else {
			size_t nLen = strlen(pDeviceId_);
			char * pDevIdCopy = (char *)zmalloc(nLen + 1);
			memcpy_s(pDevIdCopy, nLen + 1, pDeviceId_, nLen);
			pDevIdCopy[nLen] = '\0';
			zhash_update(m_linkDeviceList, pEndpoint_, pDevIdCopy);
			zhash_freefn(m_linkDeviceList, pEndpoint_, free);
		}
		pthread_mutex_unlock(&m_mutex4LinkDeviceList);
	}
}

void ccrfid_proxy::DeviceProxy::handleDisconnectLink(const char * pEndpoint_)
{
	if (strlen(pEndpoint_)) {
		char szLog[256] = { 0 };
		char szDeviceId[20] = { 0 };
		char szFactoryId[4] = { 0 };
		bool bPublish = false;
		pthread_mutex_lock(&m_mutex4LinkDeviceList);
		char * pDeviceId = (char *)zhash_lookup(m_linkDeviceList, pEndpoint_);
		if (pDeviceId) {
			strncpy_s(szDeviceId, sizeof(szDeviceId), pDeviceId, strlen(pDeviceId));
			zhash_delete(m_linkDeviceList, pEndpoint_);
		}
		pthread_mutex_unlock(&m_mutex4LinkDeviceList);
		if (strlen(szDeviceId)) {
			pthread_mutex_lock(&m_mutex4DeviceList);
			//ccrfid_proxy::DeviceInfo * pDevInfo = (ccrfid_proxy::DeviceInfo *)zhash_lookup(m_deviceList, szDeviceId);
			std::string strDeviceId = szDeviceId;
			std::map<std::string, ccrfid_proxy::DeviceInfo *>::iterator iter = m_deviceList2.find(strDeviceId);
			if (iter != m_deviceList2.end()) {
				ccrfid_proxy::DeviceInfo * pDevInfo = iter->second;
				if (pDevInfo) {
					strncpy_s(szFactoryId, sizeof(szFactoryId), pDevInfo->szFactoryId, strlen(pDevInfo->szFactoryId));
					pDevInfo->szLink[0] = '\0';
					pDevInfo->usOnline = 0;
					pDevInfo->usLowpower = 0;
					pDevInfo->usLoose = 0;
					bPublish = true;
				}
			}
			pthread_mutex_unlock(&m_mutex4DeviceList);
		}
		if (bPublish) {
			char szMsgTopic[40] = { 0 };
			sprintf_s(szMsgTopic, sizeof(szMsgTopic), "%s_%s", szFactoryId, szDeviceId);
			ccrfid_device::DeviceMessage devOfflineMsg;
			memset(&devOfflineMsg, 0, sizeof(devOfflineMsg));
			devOfflineMsg.usMessageType = ccrfid_device::MT_OFFLINE;
			devOfflineMsg.usMessageTypeExtra = 0;
			devOfflineMsg.usDeviceBattery = 0;
			devOfflineMsg.ulMessageTime = (unsigned long long)time(NULL);
			strncpy_s(devOfflineMsg.szFactoryId, sizeof(devOfflineMsg.szFactoryId), szFactoryId, 
				strlen(szFactoryId));
			strncpy_s(devOfflineMsg.szDeviceId, sizeof(devOfflineMsg.szDeviceId), szDeviceId, 
				strlen(szDeviceId));
			size_t nMsgDataLen = sizeof(devOfflineMsg);
			unsigned char * pMsgData = new unsigned char[nMsgDataLen + 1];
			memcpy_s(pMsgData, nMsgDataLen + 1, &devOfflineMsg, nMsgDataLen);
			pMsgData[nMsgDataLen] = '\0';
			if (addPublishMessage(szMsgTopic, ccrfid_device::MT_OFFLINE, pMsgData, nMsgDataLen)) {
				sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish offline message for %s, "
					"link=%s disconnect\r\n", __FUNCTION__, __LINE__, szMsgTopic, pEndpoint_);
				writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
			}
			delete [] pMsgData;
			pMsgData = NULL;
		}
	}
}

void ccrfid_proxy::DeviceProxy::handleDeviceAlive(ccrfid_proxy::DeviceAlive * pDevAlive_, 
	unsigned long long ulTime_)
{
	if (pDevAlive_) {
		char szLog[512] = { 0 };
		bool bOnline = false;
		int nPublishBattery = 0;
		std::string strDeviceId = pDevAlive_->szDeviceId;
		pthread_mutex_lock(&m_mutex4DeviceList);
		if (!m_deviceList2.empty()) {
			std::map<std::string, ccrfid_proxy::DeviceInfo *>::iterator iter = m_deviceList2.find(strDeviceId);
			if (iter != m_deviceList2.end()) {
				ccrfid_proxy::DeviceInfo * pDevInfo = iter->second;
				if (pDevInfo) {
					if (pDevInfo->usOnline == 0) {
						pDevInfo->usOnline = 1;
						bOnline = true;
					}
					if (pDevInfo->ulLastActiveTime <= ulTime_) {
						pDevInfo->ulLastActiveTime = ulTime_;
						pDevInfo->usBattery = pDevAlive_->usBattery;
						if (pDevInfo->usBattery < DEFAULT_BATTERY_THRESHOLD) {
							if (pDevInfo->usLowpower == 0) {
								pDevInfo->usLowpower = 1;
								nPublishBattery = 1;
							}
						}
						else {
							if (pDevInfo->usLowpower == 1) {
								pDevInfo->usLowpower = 0;
								nPublishBattery = 2;
							}
						}
					}
				}
			}
		}
		//if (zhash_size(m_deviceList)) {
		//	ccrfid_proxy::DeviceInfo * pDevInfo = (ccrfid_proxy::DeviceInfo *)zhash_lookup(m_deviceList,
		//	pDevAlive_->szDeviceId);
		//	if (pDevInfo) {
		//		if (pDevInfo->usOnline == 0) {
		//			pDevInfo->usOnline = 1;
		//			bOnline = true;
		//		}
		//		if (pDevInfo->ulLastActiveTime <= ulTime_) {
		//			pDevInfo->ulLastActiveTime = ulTime_;
		//			pDevInfo->usBattery = pDevAlive_->usBattery;
		//			if (pDevInfo->usBattery < DEFAULT_BATTERY_THRESHOLD) {
		//				if (pDevInfo->usLowpower == 0) {
		//					pDevInfo->usLowpower = 1;
		//					nPublishBattery = 1;
		//				}
		//			}
		//			else {
		//				if (pDevInfo->usLowpower == 1) {
		//					pDevInfo->usLowpower = 0;
		//					nPublishBattery = 2;
		//				}
		//			}
		//		}
		//	}
		//}
		pthread_mutex_unlock(&m_mutex4DeviceList);
		ccrfid_device::DeviceMessage devMsg;
		memset(&devMsg, 0, sizeof(devMsg));
		char szMsgTopic[40] = { 0 };
		sprintf_s(szMsgTopic, sizeof(szMsgTopic), "%s_%s", pDevAlive_->szFactoryId, pDevAlive_->szDeviceId);
		size_t nSize = sizeof(devMsg);
		strncpy_s(devMsg.szFactoryId, sizeof(devMsg.szFactoryId), pDevAlive_->szFactoryId, 
			strlen(pDevAlive_->szFactoryId));
		strncpy_s(devMsg.szDeviceId, sizeof(devMsg.szDeviceId), pDevAlive_->szDeviceId, 
			strlen(pDevAlive_->szDeviceId));
		if (bOnline) {
			devMsg.usMessageType = ccrfid_device::MT_ONLINE;
		}
		else {
			devMsg.usMessageType = ccrfid_device::MT_ALIVE;
		}
		devMsg.usMessageTypeExtra = 0;
		devMsg.usDeviceBattery = pDevAlive_->usBattery;
		devMsg.ulMessageTime = ulTime_;
		size_t nMsgDataLen = sizeof(devMsg);
		unsigned char * pMsgData = new unsigned char[nMsgDataLen + 1];
		memcpy_s(pMsgData, nMsgDataLen + 1, &devMsg, nMsgDataLen);
		pMsgData[nMsgDataLen] = '\0';
		if (addPublishMessage(szMsgTopic, devMsg.usMessageType, pMsgData, nMsgDataLen)) {
			if (devMsg.usMessageType == ccrfid_device::MT_ONLINE) {
				sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish online message for %s, factoryId=%s"
					", deviceId=%s, battery=%u\r\n", __FUNCTION__, __LINE__, szMsgTopic, pDevAlive_->szFactoryId,
					pDevAlive_->szDeviceId, pDevAlive_->usBattery);
			}
			else {
				sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish alive message for %s, factoryId=%s"
					", deviceId=%s, battery=%u\r\n", __FUNCTION__, __LINE__, szMsgTopic, pDevAlive_->szFactoryId,
					pDevAlive_->szFactoryId, pDevAlive_->usBattery);
			}
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
		}
		delete pMsgData;
		pMsgData = NULL;
		if (nPublishBattery > 0) {
			ccrfid_device::DeviceMessage lowpowerAlarmMsg;
			memset(&lowpowerAlarmMsg, 0, sizeof(lowpowerAlarmMsg));
			strncpy_s(lowpowerAlarmMsg.szFactoryId, sizeof(lowpowerAlarmMsg.szFactoryId), pDevAlive_->szFactoryId,
				strlen(pDevAlive_->szFactoryId));
			strncpy_s(lowpowerAlarmMsg.szDeviceId, sizeof(lowpowerAlarmMsg.szDeviceId), pDevAlive_->szDeviceId,
				strlen(pDevAlive_->szDeviceId));
			lowpowerAlarmMsg.ulMessageTime = ulTime_;
			lowpowerAlarmMsg.usDeviceBattery = pDevAlive_->usBattery;
			lowpowerAlarmMsg.usMessageType = ccrfid_device::MT_ALARM_LOWPOWER;
			if (nPublishBattery == 1) {
				lowpowerAlarmMsg.usMessageTypeExtra = 1;
			}
			else if (nPublishBattery == 2) {
				lowpowerAlarmMsg.usMessageTypeExtra = 0;
			}
			unsigned int uiMsgDataLen = sizeof(lowpowerAlarmMsg);
			unsigned char * pMsgData = new unsigned char[uiMsgDataLen + 1];
			memcpy_s(pMsgData, uiMsgDataLen + 1, &lowpowerAlarmMsg, uiMsgDataLen);
			pMsgData[uiMsgDataLen] = '\0';
			if (addPublishMessage(szMsgTopic, ccrfid_device::MT_ALARM_LOWPOWER, pMsgData, uiMsgDataLen)) {
				sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish %s message for %s, factoryId=%s, "
					"deviceId=%s, battery=%u\r\n", __FUNCTION__, __LINE__, lowpowerAlarmMsg.usMessageTypeExtra == 0
					? "lowpower" : "lowpower revoke", szMsgTopic, pDevAlive_->szFactoryId,
					pDevAlive_->szDeviceId, pDevAlive_->usBattery);
				writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
			}
			delete [] pMsgData;
			pMsgData = NULL;
		}
	}
}

void ccrfid_proxy::DeviceProxy::handleDeviceLocate(ccrfid_proxy::DeviceLocate * pDevLocate_,
	unsigned long long ulTime_)
{
	if (pDevLocate_) {
		char szLog[1024] = { 0 };
		std::string strDeviceId = pDevLocate_->szDeviceId;
		pthread_mutex_lock(&m_mutex4DeviceList);
		if (!m_deviceList2.empty()) {
			std::map<std::string, ccrfid_proxy::DeviceInfo *>::iterator iter = m_deviceList2.find(strDeviceId);
			if (iter != m_deviceList2.end()) {
				ccrfid_proxy::DeviceInfo * pDevInfo = iter->second;
				if (pDevInfo) {
					char szMsgTopic[40] = { 0 };
					sprintf_s(szMsgTopic, sizeof(szMsgTopic), "%s_%s", pDevLocate_->szFactoryId, pDevLocate_->szDeviceId);
					char szDatetime[20] = { 0 };
					formatDatetime(pDevLocate_->locateInfo.ulLocateTime, szDatetime, sizeof(szDatetime));
					if (pDevInfo->ulLastActiveTime < ulTime_) {
						pDevInfo->ulLastActiveTime = ulTime_;
					}
					if (pDevInfo->ulLastLocateTime <= pDevLocate_->locateInfo.ulLocateTime) {//realtime
						pDevInfo->ulLastLocateTime = pDevLocate_->locateInfo.ulLocateTime;
						pDevInfo->usBattery = (unsigned short)pDevLocate_->locateInfo.nBattery;
						unsigned short usLooseAlarm = 0, usLooseStatus = 0;
						analyzeDeviceStatus(pDevLocate_->locateInfo.nStatus, usLooseAlarm, usLooseStatus);
						if (usLooseStatus == 1) {
							if (pDevInfo->usLoose == 0) {
								pDevInfo->usLoose = 1;
								ccrfid_device::DeviceMessage looseAlarmMsg;
								memset(&looseAlarmMsg, 0, sizeof(looseAlarmMsg));
								strncpy_s(looseAlarmMsg.szFactoryId, sizeof(looseAlarmMsg.szFactoryId), pDevLocate_->szFactoryId,
									strlen(pDevLocate_->szFactoryId));
								strncpy_s(looseAlarmMsg.szDeviceId, sizeof(looseAlarmMsg.szDeviceId), pDevLocate_->szDeviceId,
									strlen(pDevLocate_->szDeviceId));
								looseAlarmMsg.usMessageType = ccrfid_device::MT_ALARM_LOOSE;
								looseAlarmMsg.usMessageTypeExtra = 1;
								looseAlarmMsg.usDeviceBattery = pDevInfo->usBattery;
								looseAlarmMsg.ulMessageTime = pDevLocate_->locateInfo.ulLocateTime;
								size_t nLen = sizeof(looseAlarmMsg);
								unsigned char * pMsgData = new unsigned char[nLen + 1];
								memcpy_s(pMsgData, nLen + 1, &looseAlarmMsg, nLen);
								pMsgData[nLen] = '\0';
								if (addPublishMessage(szMsgTopic, ccrfid_device::MT_ALARM_LOOSE, pMsgData, (unsigned int)nLen)) {
									sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish loose message for %s, factoryId=%s,"
										" deviceId=%s, battery=%u, mode=1\r\n", __FUNCTION__, __LINE__, szMsgTopic,
										pDevLocate_->szFactoryId, pDevLocate_->szDeviceId,
										(unsigned short)pDevLocate_->locateInfo.nBattery);
									writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
								}
							}
						}
						else {
							if (pDevInfo->usLoose == 1) {
								pDevInfo->usLoose = 0;
								ccrfid_device::DeviceMessage looseAlarmMsg;
								memset(&looseAlarmMsg, 0, sizeof(looseAlarmMsg));
								strncpy_s(looseAlarmMsg.szFactoryId, sizeof(looseAlarmMsg.szFactoryId), pDevLocate_->szFactoryId,
									strlen(pDevLocate_->szFactoryId));
								strncpy_s(looseAlarmMsg.szDeviceId, sizeof(looseAlarmMsg.szDeviceId), pDevLocate_->szDeviceId,
									strlen(pDevLocate_->szDeviceId));
								looseAlarmMsg.usMessageType = ccrfid_device::MT_ALARM_LOOSE;
								looseAlarmMsg.usMessageTypeExtra = 0;
								looseAlarmMsg.usDeviceBattery = pDevInfo->usBattery;
								looseAlarmMsg.ulMessageTime = pDevLocate_->locateInfo.ulLocateTime;
								size_t nLen = sizeof(looseAlarmMsg);
								unsigned char * pMsgData = new unsigned char[nLen + 1];
								memcpy_s(pMsgData, nLen + 1, &looseAlarmMsg, nLen);
								pMsgData[nLen] = '\0';
								if (addPublishMessage(szMsgTopic, ccrfid_device::MT_ALARM_LOOSE, pMsgData, (unsigned int)nLen)) {
									sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish loose revoke message for %s, "
										"factoryId=%s, deviceId=%s, battery=%u, mode=0\r\n", __FUNCTION__, __LINE__, szMsgTopic,
										pDevLocate_->szFactoryId, pDevLocate_->szDeviceId,
										(unsigned short)pDevLocate_->locateInfo.nBattery);
									writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
								}
								delete[] pMsgData;
								pMsgData = NULL;
							}
						}
						if (pDevInfo->usBattery < DEFAULT_BATTERY_THRESHOLD) {
							if (pDevInfo->usLowpower == 0) {
								pDevInfo->usLowpower = 1;
								ccrfid_device::DeviceMessage alarmLowpowerMsg;
								memset(&alarmLowpowerMsg, 0, sizeof(alarmLowpowerMsg));
								strncpy_s(alarmLowpowerMsg.szFactoryId, sizeof(alarmLowpowerMsg.szFactoryId),
									pDevInfo->szFactoryId, strlen(pDevInfo->szFactoryId));
								strncpy_s(alarmLowpowerMsg.szDeviceId, sizeof(alarmLowpowerMsg.szDeviceId),
									pDevInfo->szDeviceId, strlen(pDevInfo->szDeviceId));
								alarmLowpowerMsg.usDeviceBattery = pDevInfo->usBattery;
								alarmLowpowerMsg.ulMessageTime = ulTime_;
								alarmLowpowerMsg.usMessageType = ccrfid_device::MT_ALARM_LOWPOWER;
								alarmLowpowerMsg.usMessageTypeExtra = 1;
								unsigned int uiMsgDataLen = sizeof(alarmLowpowerMsg);
								unsigned char * pMsgData = new unsigned char[uiMsgDataLen + 1];
								memcpy_s(pMsgData, uiMsgDataLen + 1, &alarmLowpowerMsg, uiMsgDataLen);
								pMsgData[uiMsgDataLen] = '\0';
								if (addPublishMessage(szMsgTopic, ccrfid_device::MT_ALARM_LOWPOWER, pMsgData, uiMsgDataLen)) {
									sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish lowpower message for %s, "
										"factoryId=%s, deviceId=%s, battery=%u\r\n", __FUNCTION__, __LINE__, szMsgTopic,
										pDevInfo->szFactoryId, pDevInfo->szDeviceId, pDevInfo->usBattery);
									writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
								}
								delete[] pMsgData;
								pMsgData = NULL;
							}
						}
						else {
							if (pDevInfo->usLowpower == 1) {
								pDevInfo->usLowpower = 0;
								ccrfid_device::DeviceMessage alarmLowpowerMsg;
								memset(&alarmLowpowerMsg, 0, sizeof(alarmLowpowerMsg));
								strncpy_s(alarmLowpowerMsg.szFactoryId, sizeof(alarmLowpowerMsg.szFactoryId),
									pDevInfo->szFactoryId, strlen(pDevInfo->szFactoryId));
								strncpy_s(alarmLowpowerMsg.szDeviceId, sizeof(alarmLowpowerMsg.szDeviceId),
									pDevInfo->szDeviceId, strlen(pDevInfo->szDeviceId));
								alarmLowpowerMsg.usDeviceBattery = pDevInfo->usBattery;
								alarmLowpowerMsg.ulMessageTime = ulTime_;
								alarmLowpowerMsg.usMessageType = ccrfid_device::MT_ALARM_LOWPOWER;
								alarmLowpowerMsg.usMessageTypeExtra = 0;
								unsigned int uiMsgDataLen = sizeof(alarmLowpowerMsg);
								unsigned char * pMsgData = new unsigned char[uiMsgDataLen + 1];
								memcpy_s(pMsgData, uiMsgDataLen + 1, &alarmLowpowerMsg, uiMsgDataLen);
								pMsgData[uiMsgDataLen] = '\0';
								if (addPublishMessage(szMsgTopic, ccrfid_device::MT_ALARM_LOWPOWER, pMsgData, uiMsgDataLen)) {
									sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish lowpower revoke message for %s,"
										" factoryId=%s, deviceId=%s, battery=%u\r\n", __FUNCTION__, __LINE__, szMsgTopic,
										pDevInfo->szFactoryId, pDevInfo->szDeviceId, pDevInfo->usBattery);
									writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
								}
								delete[] pMsgData;
								pMsgData = NULL;
							}
						}
						if (pDevLocate_->locateInfo.nLocateFlag == 1) {
							pDevInfo->dLatitude = pDevLocate_->locateInfo.dLatitude;
							pDevInfo->dLngitude = pDevLocate_->locateInfo.dLngitude;
						}
					}
					if (pDevLocate_->locateInfo.nLocateFlag == 1) {//gps 
						ccrfid_device::DeviceLocateGpsMessage locateGpsMsg;
						memset(&locateGpsMsg, 0, sizeof(locateGpsMsg));
						strncpy_s(locateGpsMsg.szFactoryId, sizeof(locateGpsMsg.szFactoryId), pDevLocate_->szFactoryId,
							strlen(pDevLocate_->szFactoryId));
						strncpy_s(locateGpsMsg.szDeviceId, sizeof(locateGpsMsg.szDeviceId), pDevLocate_->szDeviceId,
							strlen(pDevLocate_->szDeviceId));
						locateGpsMsg.dSpeed = pDevLocate_->locateInfo.dMoveSpeed;
						locateGpsMsg.dDirection = pDevLocate_->locateInfo.dMoveDirection;
						locateGpsMsg.usSatelliteCount = (unsigned short)pDevLocate_->locateInfo.nGpsStatelliteCount;
						locateGpsMsg.usSignalIntensity = (unsigned short)pDevLocate_->locateInfo.nSignalIntensity;
						locateGpsMsg.ulLocateTime = pDevLocate_->locateInfo.ulLocateTime;
						locateGpsMsg.dLatitude = pDevLocate_->locateInfo.dLatitude;
						locateGpsMsg.dLngitude = pDevLocate_->locateInfo.dLngitude;
						locateGpsMsg.usDeviceBattery = pDevInfo->usBattery;
						locateGpsMsg.nCoordinate = ccrfid_device::COORDINATE_WGS84;
						unsigned int uiLen = sizeof(locateGpsMsg);
						unsigned char * pMsgData = new unsigned char[uiLen + 1];
						memcpy_s(pMsgData, uiLen + 1, &locateGpsMsg, uiLen);
						pMsgData[uiLen] = '\0';
						if (addPublishMessage(szMsgTopic, ccrfid_device::MT_LOCATE_GPS, pMsgData, uiLen)) {
							sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish gps locate message for %s, factory=%s, "
								"deviceId=%s, locateTime=%s, latitude=%f, lngitude=%f, sattelite=%d, intensity=%d, battery=%u\r\n",
								__FUNCTION__, __LINE__, szMsgTopic, pDevLocate_->szFactoryId, pDevLocate_->szDeviceId, szDatetime, 
								locateGpsMsg.dLatitude, locateGpsMsg.dLngitude, locateGpsMsg.usSatelliteCount, 
								locateGpsMsg.usSignalIntensity, locateGpsMsg.usDeviceBattery);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
						}
						delete[] pMsgData;
						pMsgData = NULL;
					}
					else { //lbs
						ccrfid_device::DeviceLocateLbsMessage locateLbsMsg;
						memset(&locateLbsMsg, 0, sizeof(locateLbsMsg));
						locateLbsMsg.pBaseStationList = NULL;
						locateLbsMsg.pDetectedWifiList = NULL;
						strncpy_s(locateLbsMsg.szFactoryId, sizeof(locateLbsMsg.szFactoryId), pDevLocate_->szFactoryId,
							strlen(pDevLocate_->szFactoryId));
						strncpy_s(locateLbsMsg.szDeviceId, sizeof(locateLbsMsg.szDeviceId), pDevLocate_->szDeviceId,
							strlen(pDevLocate_->szDeviceId));
						locateLbsMsg.ulLocateTime = pDevLocate_->locateInfo.ulLocateTime;
						locateLbsMsg.usDeviceBattery = pDevInfo->usBattery;
						locateLbsMsg.nNationCode = pDevLocate_->locateInfo.nNationCode;
						locateLbsMsg.nNetCode = pDevLocate_->locateInfo.nNetCode;
						locateLbsMsg.nBaseStationCount = pDevLocate_->locateInfo.nBaseStationCount;
						locateLbsMsg.dRefLatitude = pDevLocate_->locateInfo.dLatitude;
						locateLbsMsg.dRefLngitude = pDevLocate_->locateInfo.dLngitude;
						locateLbsMsg.nCoordinate = ccrfid_device::COORDINATE_WGS84;
						unsigned int uiBSListLen = 0;
						char szBts[32] = { 0 };
						char szNearBts[256] = { 0 };
						char szWifis[256] = { 0 };
						if (locateLbsMsg.nBaseStationCount > 0) {
							uiBSListLen = sizeof(ccrfid_device::BaseStation) * locateLbsMsg.nBaseStationCount;
							locateLbsMsg.pBaseStationList = new ccrfid_device::BaseStation[locateLbsMsg.nBaseStationCount];
							memcpy_s(locateLbsMsg.pBaseStationList, uiBSListLen, pDevLocate_->locateInfo.pBaseStationList,
								uiBSListLen);
							sprintf_s(szBts, sizeof(szBts), "460,01,%d,%d,%d", 
								pDevLocate_->locateInfo.pBaseStationList[0].nLocateAreaCode,
								pDevLocate_->locateInfo.pBaseStationList[0].nCellId,
								pDevLocate_->locateInfo.pBaseStationList[0].nSignalIntensity);
							for (int i = 1; i < pDevLocate_->locateInfo.nBaseStationCount; i++) {
								char szBtsCell[32] = { 0 };
								sprintf_s(szBtsCell, sizeof(szBtsCell), "460,01,%d,%d,%d", 
									pDevLocate_->locateInfo.pBaseStationList[i].nLocateAreaCode,
									pDevLocate_->locateInfo.pBaseStationList[i].nCellId,
									pDevLocate_->locateInfo.pBaseStationList[i].nSignalIntensity);
								if (strlen(szNearBts) == 0) {
									strncpy_s(szNearBts, sizeof(szNearBts), szBtsCell, strlen(szBtsCell));
								}
								else {
									strcat_s(szNearBts, sizeof(szNearBts), "|");
									strcat_s(szNearBts, sizeof(szNearBts), szBtsCell);
								}
							}
						}
						locateLbsMsg.nDetectedWifiCount = pDevLocate_->locateInfo.nDetectedWifiCount;
						unsigned int uiWifiListLen = 0;
						if (locateLbsMsg.nDetectedWifiCount > 0) {
							uiWifiListLen = sizeof(ccrfid_device::WifiInformation) * locateLbsMsg.nDetectedWifiCount;
							locateLbsMsg.pDetectedWifiList = new ccrfid_device::WifiInformation[locateLbsMsg.nDetectedWifiCount];
							memcpy_s(locateLbsMsg.pDetectedWifiList, uiWifiListLen, pDevLocate_->locateInfo.pDetectedWifiList,
								uiWifiListLen);
							for (int i = 0; i < pDevLocate_->locateInfo.nDetectedWifiCount; i++) {
								if (pDevLocate_->locateInfo.pDetectedWifiList[i].szWifiMacAddress[0] != 0) {
									char szWifiCell[32] = { 0 };
									sprintf_s(szWifiCell, sizeof(szWifiCell), "%s,%d,%d",
										pDevLocate_->locateInfo.pDetectedWifiList[i].szWifiMacAddress,
										pDevLocate_->locateInfo.pDetectedWifiList[i].nWifiSignalIntensity, i + 1);
									if (strlen(szWifis) == 0) {
										strncpy_s(szWifis, sizeof(szWifis), szWifiCell, strlen(szWifiCell));
									}
									else {
										strcat_s(szWifis, sizeof(szWifis), "|");
										strcat_s(szWifis, sizeof(szWifis), szWifiCell);
									}
								}
							}
						}
						if (m_nQryLbs != 0 && strlen(m_szKey)) {
							char szQryUrl[1024] = { 0 };
							sprintf_s(szQryUrl, sizeof(szQryUrl), "http://apilocate.amap.com/position?accesstype=0&imei=&cdma=0"
								"&bts=%s&nearbts=%s&network=GPRS&macs=%s&output=json&key=%s", szBts, szNearBts, szWifis, m_szKey);
							LbsQueryResult lbsQry;
							if (LbsGeoQuery(szQryUrl, QRY_OBJ_AMAP, &lbsQry) == 0) {
								if (lbsQry.nRetCode == 0 && lbsQry.dLat > 0.00 && lbsQry.dLng > 0.00) {
									locateLbsMsg.dRefLatitude = lbsQry.dLat;
									locateLbsMsg.dRefLngitude = lbsQry.dLng;
									locateLbsMsg.nCoordinate = ccrfid_device::COORDINATE_GCJ02;
								}
							}
							sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]url=%s,retcode=%d,qryLat=%.6f,qryLng=%.6f\r\n",
								__FUNCTION__, __LINE__, szQryUrl, lbsQry.nRetCode, lbsQry.dLat, lbsQry.dLng);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
						}
						unsigned int uiLocateLbsMsgSize = sizeof(ccrfid_device::DeviceLocateLbsMessage);
						unsigned int uiMsgDataLen = uiLocateLbsMsgSize + uiBSListLen + uiWifiListLen;
						unsigned char * pMsgData = new unsigned char[uiMsgDataLen + 1];
						memcpy_s(pMsgData, uiMsgDataLen + 1, &locateLbsMsg, uiLocateLbsMsgSize);
						unsigned int uiOffset = uiLocateLbsMsgSize;
						if (uiBSListLen > 0) {
							memcpy_s(pMsgData + uiOffset, uiMsgDataLen + 1 - uiOffset, locateLbsMsg.pBaseStationList,
								uiBSListLen);
							uiOffset += uiBSListLen;
						}
						if (uiWifiListLen > 0) {
							memcpy_s(pMsgData + uiOffset, uiMsgDataLen + 1 - uiOffset, locateLbsMsg.pDetectedWifiList,
								uiWifiListLen);
							uiOffset += uiWifiListLen;
						}
						if (addPublishMessage(szMsgTopic, ccrfid_device::MT_LOCATE_LBS, pMsgData, uiMsgDataLen)) {
							sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish lbs locate message for %s, factoryId=%s,"
								" deviceId=%s, lat=%f, lng=%f, coordinate=%d, locateTime=%s, battery=%u\r\n", 
								__FUNCTION__, __LINE__, szMsgTopic, pDevLocate_->szFactoryId, pDevLocate_->szDeviceId, 
								locateLbsMsg.dRefLatitude, locateLbsMsg.dRefLngitude, locateLbsMsg.nCoordinate,
								szDatetime, locateLbsMsg.usDeviceBattery);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
						}
						delete[] pMsgData;
						pMsgData = NULL;
						if (locateLbsMsg.pBaseStationList) {
							delete[] locateLbsMsg.pBaseStationList;
							locateLbsMsg.pBaseStationList = NULL;
						}
						if (locateLbsMsg.pDetectedWifiList) {
							delete[] locateLbsMsg.pDetectedWifiList;
							locateLbsMsg.pDetectedWifiList = NULL;
						}
					}
				}
			}
		}
		//ccrfid_proxy::DeviceInfo * pDevInfo = (ccrfid_proxy::DeviceInfo *)zhash_lookup(m_deviceList, 
		//	pDevLocate_->szDeviceId);
		//if (pDevInfo) {
		//	char szMsgTopic[40] = { 0 };
		//	sprintf_s(szMsgTopic, sizeof(szMsgTopic), "%s_%s", pDevLocate_->szFactoryId, pDevLocate_->szDeviceId);
		//	char szDatetime[20] = { 0 };
		//	formatDatetime(pDevLocate_->locateInfo.ulLocateTime, szDatetime, sizeof(szDatetime));
		//	if (pDevInfo->ulLastActiveTime < ulTime_) {
		//		pDevInfo->ulLastActiveTime = ulTime_;
		//	}
		//	if (pDevInfo->ulLastLocateTime <= pDevLocate_->locateInfo.ulLocateTime) {//realtime
		//		pDevInfo->ulLastLocateTime = pDevLocate_->locateInfo.ulLocateTime;
		//		pDevInfo->usBattery = (unsigned short)pDevLocate_->locateInfo.nBattery;
		//		unsigned short usLooseAlarm = 0, usLooseStatus = 0;
		//		analyzeDeviceStatus(pDevLocate_->locateInfo.nStatus, usLooseAlarm, usLooseStatus);
		//		if (usLooseStatus == 1) {
		//			if (pDevInfo->usLoose == 0) {
		//				pDevInfo->usLoose = 1;
		//				ccrfid_device::DeviceMessage looseAlarmMsg;
		//				strncpy_s(looseAlarmMsg.szFactoryId, sizeof(looseAlarmMsg.szFactoryId), pDevLocate_->szFactoryId,
		//					strlen(pDevLocate_->szFactoryId));
		//				strncpy_s(looseAlarmMsg.szDeviceId, sizeof(looseAlarmMsg.szDeviceId), pDevLocate_->szDeviceId,
		//					strlen(pDevLocate_->szDeviceId));
		//				looseAlarmMsg.usMessageType = ccrfid_device::MT_ALARM_LOOSE;
		//				looseAlarmMsg.usMessageTypeExtra = 1;
		//				looseAlarmMsg.usDeviceBattery = pDevInfo->usBattery;
		//				looseAlarmMsg.ulMessageTime = pDevLocate_->locateInfo.ulLocateTime;
		//				size_t nLen = sizeof(looseAlarmMsg);
		//				unsigned char * pMsgData = new unsigned char[nLen + 1];
		//				memcpy_s(pMsgData, nLen + 1, &looseAlarmMsg, nLen);
		//				pMsgData[nLen] = '\0';
		//				if (addPublishMessage(szMsgTopic, ccrfid_device::MT_ALARM_LOOSE, pMsgData, nLen)) {
		//					sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish loose message for %s, factoryId=%s,"
		//						" deviceId=%s, battery=%u, mode=1\r\n", __FUNCTION__, __LINE__, szMsgTopic, 
		//						pDevLocate_->szFactoryId, pDevLocate_->szDeviceId, 
		//						(unsigned short)pDevLocate_->locateInfo.nBattery);
		//					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		//				}
		//			}
		//		}
		//		else {
		//			if (pDevInfo->usLoose == 1) {
		//				pDevInfo->usLoose = 0;
		//				ccrfid_device::DeviceMessage looseAlarmMsg;
		//				strncpy_s(looseAlarmMsg.szFactoryId, sizeof(looseAlarmMsg.szFactoryId), pDevLocate_->szFactoryId,
		//					strlen(pDevLocate_->szFactoryId));
		//				strncpy_s(looseAlarmMsg.szDeviceId, sizeof(looseAlarmMsg.szDeviceId), pDevLocate_->szDeviceId,
		//					strlen(pDevLocate_->szDeviceId));
		//				looseAlarmMsg.usMessageType = ccrfid_device::MT_ALARM_LOOSE;
		//				looseAlarmMsg.usMessageTypeExtra = 0;
		//				looseAlarmMsg.usDeviceBattery = pDevInfo->usBattery; 
		//				looseAlarmMsg.ulMessageTime = pDevLocate_->locateInfo.ulLocateTime;
		//				size_t nLen = sizeof(looseAlarmMsg);
		//				unsigned char * pMsgData = new unsigned char[nLen + 1];
		//				memcpy_s(pMsgData, nLen + 1, &looseAlarmMsg, nLen);
		//				pMsgData[nLen] = '\0';
		//				if (addPublishMessage(szMsgTopic, ccrfid_device::MT_ALARM_LOOSE, pMsgData, nLen)) {
		//					sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish loose revoke message for %s, "
		//						"factoryId=%s, deviceId=%s, battery=%u, mode=0\r\n", __FUNCTION__, __LINE__, szMsgTopic,
		//						pDevLocate_->szFactoryId, pDevLocate_->szDeviceId, 
		//						(unsigned short)pDevLocate_->locateInfo.nBattery);
		//					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		//				}
		//				delete[] pMsgData;
		//				pMsgData = NULL;
		//			}
		//		}
		//		if (pDevInfo->usBattery < DEFAULT_BATTERY_THRESHOLD) {
		//			if (pDevInfo->usLowpower == 0) {
		//				pDevInfo->usLowpower = 1;
		//				ccrfid_device::DeviceMessage alarmLowpowerMsg;
		//				strncpy_s(alarmLowpowerMsg.szFactoryId, sizeof(alarmLowpowerMsg.szFactoryId),
		//					pDevInfo->szFactoryId, strlen(pDevInfo->szFactoryId));
		//				strncpy_s(alarmLowpowerMsg.szDeviceId, sizeof(alarmLowpowerMsg.szDeviceId),
		//					pDevInfo->szDeviceId, strlen(pDevInfo->szDeviceId));
		//				alarmLowpowerMsg.ulMessageTime = ulTime_;
		//				alarmLowpowerMsg.usMessageType = ccrfid_device::MT_ALARM_LOWPOWER;
		//				alarmLowpowerMsg.usMessageTypeExtra = 1;
		//				unsigned int uiMsgDataLen = sizeof(alarmLowpowerMsg);
		//				unsigned char * pMsgData = new unsigned char[uiMsgDataLen + 1];
		//				memcpy_s(pMsgData, uiMsgDataLen + 1, &alarmLowpowerMsg, uiMsgDataLen);
		//				pMsgData[uiMsgDataLen] = '\0';
		//				if (addPublishMessage(szMsgTopic, ccrfid_device::MT_ALARM_LOWPOWER, pMsgData, uiMsgDataLen)) {
		//					sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish lowpower message for %s, "
		//						"factoryId=%s, deviceId=%s, battery=%u\r\n", __FUNCTION__, __LINE__, szMsgTopic,
		//						pDevInfo->szFactoryId, pDevInfo->szDeviceId, pDevInfo->usBattery);
		//					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		//				}
		//				delete[] pMsgData;
		//				pMsgData = NULL;
		//			}
		//		}
		//		else {
		//			if (pDevInfo->usLowpower == 1) {
		//				pDevInfo->usLowpower = 0;
		//				ccrfid_device::DeviceMessage alarmLowpowerMsg;
		//				strncpy_s(alarmLowpowerMsg.szFactoryId, sizeof(alarmLowpowerMsg.szFactoryId),
		//					pDevInfo->szFactoryId, strlen(pDevInfo->szFactoryId));
		//				strncpy_s(alarmLowpowerMsg.szDeviceId, sizeof(alarmLowpowerMsg.szDeviceId),
		//					pDevInfo->szDeviceId, strlen(pDevInfo->szDeviceId));
		//				alarmLowpowerMsg.ulMessageTime = ulTime_;
		//				alarmLowpowerMsg.usMessageType = ccrfid_device::MT_ALARM_LOWPOWER;
		//				alarmLowpowerMsg.usMessageTypeExtra = 0;
		//				unsigned int uiMsgDataLen = sizeof(alarmLowpowerMsg);
		//				unsigned char * pMsgData = new unsigned char[uiMsgDataLen + 1];
		//				memcpy_s(pMsgData, uiMsgDataLen + 1, &alarmLowpowerMsg, uiMsgDataLen);
		//				pMsgData[uiMsgDataLen] = '\0';
		//				if (addPublishMessage(szMsgTopic, ccrfid_device::MT_ALARM_LOWPOWER, pMsgData, uiMsgDataLen)) {
		//					sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish lowpower revoke message for %s,"
		//						" factoryId=%s, deviceId=%s, battery=%u\r\n", __FUNCTION__, __LINE__, szMsgTopic,
		//						pDevInfo->szFactoryId, pDevInfo->szDeviceId, pDevInfo->usBattery);
		//					writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		//				}
		//				delete[] pMsgData;
		//				pMsgData = NULL;
		//			}
		//		}
		//		if (pDevLocate_->locateInfo.nLocateFlag == 1) {
		//			pDevInfo->dLatitude = pDevLocate_->locateInfo.dLatitude;
		//			pDevInfo->dLngitude = pDevLocate_->locateInfo.dLngitude;
		//		}
		//	}
		//	if (pDevLocate_->locateInfo.nLocateFlag == 1) {//gps 
		//		ccrfid_device::DeviceLocateGpsMessage locateGpsMsg;
		//		strncpy_s(locateGpsMsg.szFactoryId, sizeof(locateGpsMsg.szFactoryId), pDevLocate_->szFactoryId, 
		//			strlen(pDevLocate_->szFactoryId));
		//		strncpy_s(locateGpsMsg.szDeviceId, sizeof(locateGpsMsg.szDeviceId), pDevLocate_->szDeviceId,
		//			strlen(pDevLocate_->szDeviceId));
		//		locateGpsMsg.usLatType = pDevLocate_->locateInfo.usLatType;
		//		locateGpsMsg.usLngType = pDevLocate_->locateInfo.usLngType;
		//		locateGpsMsg.dSpeed = pDevLocate_->locateInfo.dMoveSpeed;
		//		locateGpsMsg.dDirection = pDevLocate_->locateInfo.dMoveDirection;
		//		locateGpsMsg.usSatelliteCount = (unsigned short)pDevLocate_->locateInfo.nGpsStatelliteCount;
		//		locateGpsMsg.usSignalIntensity = (unsigned short)pDevLocate_->locateInfo.nSignalIntensity;
		//		locateGpsMsg.ulLocateTime = pDevLocate_->locateInfo.ulLocateTime;
		//		locateGpsMsg.dLatitude = pDevLocate_->locateInfo.dLatitude;
		//		locateGpsMsg.dLngitude = pDevLocate_->locateInfo.dLngitude;
		//		locateGpsMsg.usDeviceBattery = pDevInfo->usBattery;
		//		unsigned int uiLen = sizeof(locateGpsMsg);
		//		unsigned char * pMsgData = new unsigned char[uiLen + 1];
		//		memcpy_s(pMsgData, uiLen + 1, &locateGpsMsg, uiLen);
		//		pMsgData[uiLen] = '\0';
		//		if (addPublishMessage(szMsgTopic, ccrfid_device::MT_LOCATE_GPS, pMsgData, uiLen)) {
		//			sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish gps locate message for %s, factory=%s, "
		//				"deviceId=%s, locateTime=%s, latitude=%f, lngitude=%f, battery=%u\r\n", __FUNCTION__, __LINE__,
		//				szMsgTopic, pDevLocate_->szFactoryId, pDevLocate_->szDeviceId, szDatetime, locateGpsMsg.dLatitude,
		//				locateGpsMsg.dLngitude, locateGpsMsg.usDeviceBattery);
		//			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		//		}
		//		delete[] pMsgData;
		//		pMsgData = NULL;
		//	}
		//	else { //lbs
		//		ccrfid_device::DeviceLocateLbsMessage locateLbsMsg;
		//		strncpy_s(locateLbsMsg.szFactoryId, sizeof(locateLbsMsg.szFactoryId), pDevLocate_->szFactoryId,
		//			strlen(pDevLocate_->szFactoryId));
		//		strncpy_s(locateLbsMsg.szDeviceId, sizeof(locateLbsMsg.szDeviceId), pDevLocate_->szDeviceId,
		//			strlen(pDevLocate_->szDeviceId));
		//		locateLbsMsg.ulLocateTime = pDevLocate_->locateInfo.ulLocateTime;
		//		locateLbsMsg.usDeviceBattery = pDevInfo->usBattery;
		//		locateLbsMsg.nNationCode = pDevLocate_->locateInfo.nNationCode;
		//		locateLbsMsg.nNetCode = pDevLocate_->locateInfo.nNetCode;
		//		locateLbsMsg.nBaseStationCount = pDevLocate_->locateInfo.nBaseStationCount;
		//		unsigned int uiBSListLen = 0;
		//		if (locateLbsMsg.nBaseStationCount > 0) {
		//			uiBSListLen = sizeof(ccrfid_device::BaseStation) * locateLbsMsg.nBaseStationCount;
		//			locateLbsMsg.pBaseStationList = new ccrfid_device::BaseStation[locateLbsMsg.nBaseStationCount];
		//			memcpy_s(locateLbsMsg.pBaseStationList, uiBSListLen, pDevLocate_->locateInfo.pBaseStationList,
		//				uiBSListLen);
		//		}
		//		locateLbsMsg.nDetectedWifiCount = pDevLocate_->locateInfo.nDetectedWifiCount;
		//		unsigned int uiWifiListLen = 0;
		//		if (locateLbsMsg.nDetectedWifiCount > 0) {
		//			uiWifiListLen = sizeof(ccrfid_device::WifiInformation) * locateLbsMsg.nDetectedWifiCount;
		//			locateLbsMsg.pDetectedWifiList = new ccrfid_device::WifiInformation[locateLbsMsg.nDetectedWifiCount];
		//			memcpy_s(locateLbsMsg.pDetectedWifiList, uiWifiListLen, pDevLocate_->locateInfo.pDetectedWifiList,
		//				uiWifiListLen);
		//		}
		//		unsigned int uiLocateLbsMsgSize = sizeof(ccrfid_device::DeviceLocateLbsMessage);
		//		unsigned int uiMsgDataLen = uiLocateLbsMsgSize + uiBSListLen + uiWifiListLen;
		//		unsigned char * pMsgData = new unsigned char[uiMsgDataLen + 1];
		//		memcpy_s(pMsgData, uiMsgDataLen + 1, &locateLbsMsg, uiLocateLbsMsgSize);
		//		unsigned int uiOffset = uiLocateLbsMsgSize;
		//		if (uiBSListLen > 0) {
		//			memcpy_s(pMsgData + uiOffset, uiMsgDataLen + 1 - uiOffset, locateLbsMsg.pBaseStationList, 
		//				uiBSListLen);
		//			uiOffset += uiBSListLen;
		//		}
		//		if (uiWifiListLen > 0) {
		//			memcpy_s(pMsgData + uiOffset, uiMsgDataLen + 1 - uiOffset, locateLbsMsg.pDetectedWifiList, 
		//				uiWifiListLen);
		//			uiOffset += uiWifiListLen;
		//		}
		//		if (addPublishMessage(szMsgTopic, ccrfid_device::MT_LOCATE_LBS, pMsgData, uiMsgDataLen)) {
		//			sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish lbs locate message for %s, factoryId=%s, "
		//				"deviceId=%s, locateTime=%s, battery=%u\r\n", __FUNCTION__, __LINE__, szMsgTopic, 
		//				pDevLocate_->szFactoryId, pDevLocate_->szDeviceId, szDatetime, locateLbsMsg.usDeviceBattery);
		//			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, m_usLogType);
		//		} 
		//		delete[] pMsgData;
		//		pMsgData = NULL;
		//		if (locateLbsMsg.pBaseStationList) {
		//			delete[] locateLbsMsg.pBaseStationList;
		//			locateLbsMsg.pBaseStationList = NULL;
		//		}
		//		if (locateLbsMsg.pDetectedWifiList) {
		//			delete[] locateLbsMsg.pDetectedWifiList;
		//			locateLbsMsg.pDetectedWifiList = NULL;
		//		}
		//	}
		//}
		pthread_mutex_unlock(&m_mutex4DeviceList);
	}
}

void ccrfid_proxy::DeviceProxy::handleDeviceAlarm(ccrfid_proxy::DeviceLocate * pDevLocate_,
	unsigned long long ulTime_)
{
	if (pDevLocate_) {
		char szLog[512] = { 0 };
		pthread_mutex_lock(&m_mutex4DeviceList);
		std::string strDeviceId = pDevLocate_->szDeviceId;
		std::map<std::string, ccrfid_proxy::DeviceInfo *>::iterator iter = m_deviceList2.find(strDeviceId);
		if (iter != m_deviceList2.end()) {
			ccrfid_proxy::DeviceInfo * pDevInfo = iter->second;
			//ccrfid_proxy::DeviceInfo * pDevInfo = (ccrfid_proxy::DeviceInfo *)zhash_lookup(m_deviceList,
			//	pDevLocate_->szDeviceId);
			if (pDevInfo) {
				char szMsgTopic[40] = { 0 };
				sprintf_s(szMsgTopic, sizeof(szMsgTopic), "%s_%s", pDevLocate_->szFactoryId, pDevLocate_->szDeviceId);
				unsigned short usLooseAlarm = 0, usLooseStatus = 0;
				analyzeDeviceStatus(pDevLocate_->locateInfo.nStatus, usLooseAlarm, usLooseStatus);
				if (usLooseAlarm || usLooseStatus == 1) {
					if (pDevInfo->usLoose == 0) {
						pDevInfo->usLoose = 1;
						ccrfid_device::DeviceMessage looseAlarmMsg;
						unsigned int uiAlarmMsgSize = sizeof(looseAlarmMsg);
						memset(&looseAlarmMsg, 0, uiAlarmMsgSize);
						strncpy_s(looseAlarmMsg.szFactoryId, sizeof(looseAlarmMsg.szFactoryId), pDevLocate_->szFactoryId,
							strlen(pDevLocate_->szFactoryId));
						strncpy_s(looseAlarmMsg.szDeviceId, sizeof(looseAlarmMsg.szDeviceId), pDevLocate_->szDeviceId,
							strlen(pDevLocate_->szDeviceId));
						looseAlarmMsg.usMessageType = ccrfid_device::MT_ALARM_LOOSE;
						looseAlarmMsg.usMessageTypeExtra = 1;
						looseAlarmMsg.usDeviceBattery = pDevInfo->usBattery;
						looseAlarmMsg.ulMessageTime = pDevLocate_->locateInfo.ulLocateTime;
						unsigned char * pMsgData = new unsigned char[uiAlarmMsgSize + 1];
						memcpy_s(pMsgData, uiAlarmMsgSize + 1, &looseAlarmMsg, uiAlarmMsgSize);
						pMsgData[uiAlarmMsgSize] = '\0';
						if (addPublishMessage(szMsgTopic, ccrfid_device::MT_ALARM_LOOSE, pMsgData, uiAlarmMsgSize)) {
							sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish loose message for %s, factoryId=%s,"
								" deviceId=%s, battery=%d, mode=0\r\n", __FUNCTION__, __LINE__, szMsgTopic,
								pDevLocate_->szFactoryId, pDevLocate_->szDeviceId, pDevLocate_->locateInfo.nBattery);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
						}
						delete[] pMsgData;
						pMsgData = NULL;
					}
				}
				else if (usLooseStatus == 0) {
					if (pDevInfo->usLoose == 1) {
						pDevInfo->usLoose = 0;
						ccrfid_device::DeviceMessage looseAlarmMsg;
						memset(&looseAlarmMsg, 0, sizeof(looseAlarmMsg));
						strncpy_s(looseAlarmMsg.szFactoryId, sizeof(looseAlarmMsg.szFactoryId),
							pDevLocate_->szFactoryId, strlen(pDevLocate_->szFactoryId));
						strncpy_s(looseAlarmMsg.szDeviceId, sizeof(looseAlarmMsg.szDeviceId), pDevLocate_->szDeviceId,
							strlen(pDevLocate_->szDeviceId));
						looseAlarmMsg.usMessageType = ccrfid_device::MT_ALARM_LOOSE;
						looseAlarmMsg.usMessageTypeExtra = 0;
						looseAlarmMsg.usDeviceBattery = pDevInfo->usBattery;
						looseAlarmMsg.ulMessageTime = pDevLocate_->locateInfo.ulLocateTime;
						unsigned int uiMsgDataLen = sizeof(looseAlarmMsg);
						unsigned char * pMsgData = new unsigned char[uiMsgDataLen + 1];
						memcpy_s(pMsgData, uiMsgDataLen + 1, &looseAlarmMsg, uiMsgDataLen);
						pMsgData[uiMsgDataLen] = '\0';
						if (addPublishMessage(szMsgTopic, ccrfid_device::MT_ALARM_LOOSE, pMsgData, uiMsgDataLen)) {
							sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish loose revoke message for %s, "
								"factoryId=%s, deviceId=%s, battery=%u, mode=0\r\n", __FUNCTION__, __LINE__, szMsgTopic,
								pDevLocate_->szFactoryId, pDevLocate_->szDeviceId, pDevLocate_->locateInfo.nBattery);
							writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
						}
						delete[] pMsgData;
						pMsgData = NULL;
					}
				}
				if (pDevInfo->ulLastActiveTime < ulTime_) {
					pDevInfo->ulLastActiveTime = ulTime_;
					pDevInfo->usBattery = (unsigned short)pDevLocate_->locateInfo.nBattery;
					if (pDevInfo->ulLastLocateTime < pDevLocate_->locateInfo.ulLocateTime) {
						pDevInfo->ulLastLocateTime = pDevLocate_->locateInfo.ulLocateTime;
						char szLocateDatetime[20] = { 0 };
						formatDatetime(pDevLocate_->locateInfo.ulLocateTime, szLocateDatetime, sizeof(szLocateDatetime));
						if (pDevLocate_->locateInfo.nLocateFlag == 1) { //gps
							pDevInfo->dLatitude = pDevLocate_->locateInfo.dLatitude;
							pDevInfo->dLngitude = pDevLocate_->locateInfo.dLngitude;
							ccrfid_device::DeviceLocateGpsMessage locateGpsMsg;
							memset(&locateGpsMsg, 0, sizeof(locateGpsMsg));
							strncpy_s(locateGpsMsg.szFactoryId, sizeof(locateGpsMsg.szFactoryId), pDevLocate_->szFactoryId,
								strlen(pDevLocate_->szFactoryId));
							strncpy_s(locateGpsMsg.szDeviceId, sizeof(locateGpsMsg.szDeviceId), pDevLocate_->szDeviceId,
								strlen(pDevLocate_->szDeviceId));
							locateGpsMsg.dSpeed = pDevLocate_->locateInfo.dMoveSpeed;
							locateGpsMsg.dDirection = pDevLocate_->locateInfo.dMoveDirection;
							locateGpsMsg.usSatelliteCount = (unsigned short)pDevLocate_->locateInfo.nGpsStatelliteCount;
							locateGpsMsg.usSignalIntensity = (unsigned short)pDevLocate_->locateInfo.nSignalIntensity;
							locateGpsMsg.ulLocateTime = pDevLocate_->locateInfo.ulLocateTime;
							locateGpsMsg.dLatitude = pDevLocate_->locateInfo.dLatitude;
							locateGpsMsg.dLngitude = pDevLocate_->locateInfo.dLngitude;
							locateGpsMsg.usDeviceBattery = pDevInfo->usBattery;
							unsigned int uiLen = sizeof(locateGpsMsg);
							unsigned char * pMsgData = new unsigned char[uiLen + 1];
							memcpy_s(pMsgData, uiLen + 1, &locateGpsMsg, uiLen);
							pMsgData[uiLen] = '\0';
							if (addPublishMessage(szMsgTopic, ccrfid_device::MT_LOCATE_GPS, pMsgData, uiLen)) {
								sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish gps locate message for %s, factory=%s, "
									"deviceId=%s, locateTime=%s, latitude=%f, lngitude=%f, battery=%u\r\n", __FUNCTION__, __LINE__,
									szMsgTopic, pDevLocate_->szFactoryId, pDevLocate_->szDeviceId, szLocateDatetime,
									locateGpsMsg.dLatitude, locateGpsMsg.dLngitude, locateGpsMsg.usDeviceBattery);
								writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
							}
							delete[] pMsgData;
							pMsgData = NULL;
						}
						else { //lbs
							ccrfid_device::DeviceLocateLbsMessage locateLbsMsg;
							memset(&locateLbsMsg, 0, sizeof(locateLbsMsg));
							strncpy_s(locateLbsMsg.szFactoryId, sizeof(locateLbsMsg.szFactoryId), pDevLocate_->szFactoryId,
								strlen(pDevLocate_->szFactoryId));
							strncpy_s(locateLbsMsg.szDeviceId, sizeof(locateLbsMsg.szDeviceId), pDevLocate_->szDeviceId,
								strlen(pDevLocate_->szDeviceId));
							locateLbsMsg.ulLocateTime = pDevLocate_->locateInfo.ulLocateTime;
							locateLbsMsg.usDeviceBattery = pDevInfo->usBattery;
							locateLbsMsg.nNationCode = pDevLocate_->locateInfo.nNationCode;
							locateLbsMsg.nNetCode = pDevLocate_->locateInfo.nNetCode;
							locateLbsMsg.nBaseStationCount = pDevLocate_->locateInfo.nBaseStationCount;
							char szBts[32] = { 0 };
							char szNearBts[256] = { 0 };
							char szWifis[256] = { 0 };
							unsigned int uiBSListLen = 0;
							if (locateLbsMsg.nBaseStationCount > 0) {
								uiBSListLen = sizeof(ccrfid_device::BaseStation) * locateLbsMsg.nBaseStationCount;
								locateLbsMsg.pBaseStationList = new ccrfid_device::BaseStation[locateLbsMsg.nBaseStationCount];
								memcpy_s(locateLbsMsg.pBaseStationList, uiBSListLen, pDevLocate_->locateInfo.pBaseStationList,
									uiBSListLen);
								sprintf_s(szBts, sizeof(szBts), "460,01,%d,%d,%d",
									pDevLocate_->locateInfo.pBaseStationList[0].nLocateAreaCode,
									pDevLocate_->locateInfo.pBaseStationList[0].nCellId,
									pDevLocate_->locateInfo.pBaseStationList[0].nSignalIntensity);
								for (int i = 1; i < pDevLocate_->locateInfo.nBaseStationCount; i++) {
									char szBtsCell[32] = { 0 };
									sprintf_s(szBtsCell, sizeof(szBtsCell), "460,01,%d,%d,%d",
										pDevLocate_->locateInfo.pBaseStationList[i].nLocateAreaCode,
										pDevLocate_->locateInfo.pBaseStationList[i].nCellId,
										pDevLocate_->locateInfo.pBaseStationList[i].nSignalIntensity);
									if (strlen(szNearBts) == 0) {
										strncpy_s(szNearBts, sizeof(szNearBts), szBtsCell, strlen(szBtsCell));
									}
									else {
										strcat_s(szNearBts, sizeof(szNearBts), "|");
										strcat_s(szNearBts, sizeof(szNearBts), szBtsCell);
									}
								}
							}
							locateLbsMsg.nDetectedWifiCount = pDevLocate_->locateInfo.nDetectedWifiCount;
							unsigned int uiWifiListLen = 0;
							if (locateLbsMsg.nDetectedWifiCount > 0) {
								uiWifiListLen = sizeof(ccrfid_device::WifiInformation) * locateLbsMsg.nDetectedWifiCount;
								locateLbsMsg.pDetectedWifiList = new ccrfid_device::WifiInformation[locateLbsMsg.nDetectedWifiCount];
								memcpy_s(locateLbsMsg.pDetectedWifiList, uiWifiListLen, pDevLocate_->locateInfo.pDetectedWifiList,
									uiWifiListLen);
								for (int i = 0; i < pDevLocate_->locateInfo.nDetectedWifiCount; i++) {
									if (pDevLocate_->locateInfo.pDetectedWifiList[i].szWifiMacAddress[0] != 0) {
										char szWifiCell[32] = { 0 };
										sprintf_s(szWifiCell, sizeof(szWifiCell), "%s,%d,%d",
											pDevLocate_->locateInfo.pDetectedWifiList[i].szWifiMacAddress,
											pDevLocate_->locateInfo.pDetectedWifiList[i].nWifiSignalIntensity, i + 1);
										if (strlen(szWifis) == 0) {
											strncpy_s(szWifis, sizeof(szWifis), szWifiCell, strlen(szWifiCell));
										}
										else {
											strcat_s(szWifis, sizeof(szWifis), "|");
											strcat_s(szWifis, sizeof(szWifis), szWifiCell);
										}
									}
								}
							}
							if (m_nQryLbs != 0 && strlen(m_szKey)) {
								char szQryUrl[1024] = { 0 };
								sprintf_s(szQryUrl, sizeof(szQryUrl), "http://apilocate.amap.com/position?accesstype=0&imei=&cdma=0"
									"&bts=%s&nearbts=%s&network=GPRS&macs=%s&output=json&key=%s", szBts, szNearBts, szWifis, m_szKey);
								LbsQueryResult lbsQry;
								if (LbsGeoQuery(szQryUrl, QRY_OBJ_AMAP, &lbsQry) == 0) {
									if (lbsQry.nRetCode == 0 && lbsQry.dLat > 0.00 && lbsQry.dLng > 0.00) {
										locateLbsMsg.dRefLatitude = lbsQry.dLat;
										locateLbsMsg.dRefLngitude = lbsQry.dLng;
										locateLbsMsg.nCoordinate = ccrfid_device::COORDINATE_GCJ02;
									}
								}
								sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]url=%s,retcode=%d,qryLat=%.6f,qryLng=%.6f\r\n",
									__FUNCTION__, __LINE__, szQryUrl, lbsQry.nRetCode, lbsQry.dLat, lbsQry.dLng);
								writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
							}
							unsigned int uiLocateLbsMsgSize = sizeof(ccrfid_device::DeviceLocateLbsMessage);
							unsigned int uiMsgDataLen = uiLocateLbsMsgSize + uiBSListLen + uiWifiListLen;
							unsigned char * pMsgData = new unsigned char[uiMsgDataLen + 1];
							memcpy_s(pMsgData, uiMsgDataLen + 1, &locateLbsMsg, uiLocateLbsMsgSize);
							unsigned int uiOffset = uiLocateLbsMsgSize;
							if (uiBSListLen > 0) {
								memcpy_s(pMsgData + uiOffset, uiMsgDataLen + 1 - uiOffset, locateLbsMsg.pBaseStationList,
									uiBSListLen);
								uiOffset += uiBSListLen;
							}
							if (uiWifiListLen > 0) {
								memcpy_s(pMsgData + uiOffset, uiMsgDataLen + 1 - uiOffset, locateLbsMsg.pDetectedWifiList,
									uiWifiListLen);
								uiOffset += uiWifiListLen;
							}
							if (addPublishMessage(szMsgTopic, ccrfid_device::MT_LOCATE_LBS, pMsgData, uiMsgDataLen)) {
								sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish lbs locate message for %s, factoryId=%s,"
									" deviceId=%s, locateTime=%s, battery=%u\r\n", __FUNCTION__, __LINE__, szMsgTopic,
									pDevLocate_->szFactoryId, pDevLocate_->szDeviceId, szLocateDatetime,
									locateLbsMsg.usDeviceBattery);
								writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
							}
							delete[] pMsgData;
							pMsgData = NULL;
							if (locateLbsMsg.pBaseStationList) {
								delete[] locateLbsMsg.pBaseStationList;
								locateLbsMsg.pBaseStationList = NULL;
							}
							if (locateLbsMsg.pDetectedWifiList) {
								delete[] locateLbsMsg.pDetectedWifiList;
								locateLbsMsg.pDetectedWifiList = NULL;
							}
						}
					}
					if (pDevInfo->usBattery < DEFAULT_BATTERY_THRESHOLD) {
						if (pDevInfo->usLowpower == 0) {
							pDevInfo->usLowpower = 1;
							ccrfid_device::DeviceMessage alarmLowpowerMsg;
							memset(&alarmLowpowerMsg, 0, sizeof(alarmLowpowerMsg));
							strncpy_s(alarmLowpowerMsg.szFactoryId, sizeof(alarmLowpowerMsg.szFactoryId),
								pDevInfo->szFactoryId, strlen(pDevInfo->szFactoryId));
							strncpy_s(alarmLowpowerMsg.szDeviceId, sizeof(alarmLowpowerMsg.szDeviceId),
								pDevInfo->szDeviceId, strlen(pDevInfo->szDeviceId));
							alarmLowpowerMsg.usDeviceBattery = pDevInfo->usBattery;
							alarmLowpowerMsg.ulMessageTime = ulTime_;
							alarmLowpowerMsg.usMessageType = ccrfid_device::MT_ALARM_LOWPOWER;
							alarmLowpowerMsg.usMessageTypeExtra = 1;
							unsigned int uiMsgDataLen = sizeof(alarmLowpowerMsg);
							unsigned char * pMsgData = new unsigned char[uiMsgDataLen + 1];
							memcpy_s(pMsgData, uiMsgDataLen + 1, &alarmLowpowerMsg, uiMsgDataLen);
							pMsgData[uiMsgDataLen] = '\0';
							if (addPublishMessage(szMsgTopic, ccrfid_device::MT_ALARM_LOWPOWER, pMsgData, uiMsgDataLen)) {
								sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish lowpower message for %s, "
									"factoryId=%s, deviceId=%s, battery=%u\r\n", __FUNCTION__, __LINE__, szMsgTopic,
									pDevInfo->szFactoryId, pDevInfo->szDeviceId, pDevInfo->usBattery);
								writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
							}
							delete[] pMsgData;
							pMsgData = NULL;
						}
					}
					else {
						if (pDevInfo->usLowpower == 1) {
							pDevInfo->usLowpower = 0;
							ccrfid_device::DeviceMessage alarmLowpowerMsg;
							memset(&alarmLowpowerMsg, 0, sizeof(alarmLowpowerMsg));
							strncpy_s(alarmLowpowerMsg.szFactoryId, sizeof(alarmLowpowerMsg.szFactoryId),
								pDevInfo->szFactoryId, strlen(pDevInfo->szFactoryId));
							strncpy_s(alarmLowpowerMsg.szDeviceId, sizeof(alarmLowpowerMsg.szDeviceId),
								pDevInfo->szDeviceId, strlen(pDevInfo->szDeviceId));
							alarmLowpowerMsg.usDeviceBattery = pDevInfo->usBattery;
							alarmLowpowerMsg.ulMessageTime = ulTime_;
							alarmLowpowerMsg.usMessageType = ccrfid_device::MT_ALARM_LOWPOWER;
							alarmLowpowerMsg.usMessageTypeExtra = 0;
							unsigned int uiMsgDataLen = sizeof(alarmLowpowerMsg);
							unsigned char * pMsgData = new unsigned char[uiMsgDataLen + 1];
							memcpy_s(pMsgData, uiMsgDataLen + 1, &alarmLowpowerMsg, uiMsgDataLen);
							pMsgData[uiMsgDataLen] = '\0';
							if (addPublishMessage(szMsgTopic, ccrfid_device::MT_ALARM_LOWPOWER, pMsgData, uiMsgDataLen)) {
								sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish lowpower revoke message for %s,"
									" factoryId=%s, deviceId=%s, battery=%u\r\n", __FUNCTION__, __LINE__, szMsgTopic,
									pDevInfo->szFactoryId, pDevInfo->szDeviceId, pDevInfo->usBattery);
								writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
							}
							delete[] pMsgData;
							pMsgData = NULL;
						}
					}
				}
			}
		}
		pthread_mutex_unlock(&m_mutex4DeviceList);
	}
}

void ccrfid_proxy::DeviceProxy::analyzeDeviceStatus(int nDeviceStatus_, unsigned short & usLooseAlarm_,
	unsigned short & usLooseStatus_)
{
	usLooseAlarm_ = 0;
	usLooseStatus_ = 0;
	if (nDeviceStatus_ > 0) {
		usLooseAlarm_ = (unsigned short)((nDeviceStatus_ >> 20) & 1);
		usLooseStatus_ = (unsigned short)((nDeviceStatus_ >> 3) & 1);
	}
}

void ccrfid_proxy::DeviceProxy::handleNetWork()
{
	zmq_pollitem_t items[] = { {m_interactor, 0, ZMQ_POLLIN, 0} };
	while (m_nRun) {
		int rc = zmq_poll(items, 1, 1000 * ZMQ_POLL_MSEC);
		if (rc == -1 && errno == ETERM) {
			break;
		}
		if (items[0].revents & ZMQ_POLLIN) {
			zmsg_t * msg_interact = zmsg_recv(items[0].socket);
			if (msg_interact) {
				size_t nFrameCount = zmsg_size(msg_interact);
				if (nFrameCount >= 4) {
					zframe_t * frame_interact_identity = zmsg_pop(msg_interact);
					zframe_t * frame_interact_sequence = zmsg_pop(msg_interact);
					zframe_t * frame_interact_datetime = zmsg_pop(msg_interact);
					zframe_t * frame_interact_type = zmsg_pop(msg_interact);
					zframe_t * frame_interact_data = zmsg_pop(msg_interact);
					char szMsgIdentity[64] = { 0 };
					size_t nIdLen = zframe_size(frame_interact_identity);
					memcpy_s(szMsgIdentity, sizeof(szMsgIdentity), zframe_data(frame_interact_identity), nIdLen);
					char szMsgSequence[20] = { 0 };
					size_t nSeqLen = zframe_size(frame_interact_sequence);
					memcpy_s(szMsgSequence, sizeof(szMsgSequence), zframe_data(frame_interact_sequence), nSeqLen);
					char szMsgDatetime[20] = { 0 };
					memcpy_s(szMsgDatetime, sizeof(szMsgDatetime), zframe_data(frame_interact_datetime),
						zframe_size(frame_interact_datetime));
					char szMsgType[16] = { 0 };
					memcpy_s(szMsgType, sizeof(szMsgType), zframe_data(frame_interact_type),
						zframe_size(frame_interact_type));
					size_t nMsgDataLen = zframe_size(frame_interact_data);
					unsigned char * pMsgData = NULL;
					if (nMsgDataLen) {
						pMsgData = zframe_data(frame_interact_data);
					}
					ccrfid_proxy::InteractMessage * pInteractMsg = new ccrfid_proxy::InteractMessage();
					strncpy_s(pInteractMsg->szMsgIdentity, sizeof(pInteractMsg->szMsgIdentity), szMsgIdentity,
						strlen(szMsgIdentity));
					pInteractMsg->uiMsgSeq = (unsigned int)atoi(szMsgSequence);
					makeDatetime(szMsgDatetime, &pInteractMsg->ulMsgTime);
					pInteractMsg->uiMsgType = (unsigned int)atoi(szMsgType);
					pInteractMsg->uiMsgDataLen = (unsigned int)nMsgDataLen;
					pInteractMsg->pMsgData = NULL;
					if (nMsgDataLen && pMsgData) {
						pInteractMsg->pMsgData = new unsigned char[nMsgDataLen + 1];
						memcpy_s(pInteractMsg->pMsgData, nMsgDataLen + 1, pMsgData, nMsgDataLen);
					}
					if (!addInteractMessage(pInteractMsg)) {
						if (pInteractMsg->pMsgData && pInteractMsg->uiMsgDataLen) {
							delete[] pInteractMsg->pMsgData;
							pInteractMsg->pMsgData = NULL;
							pInteractMsg->uiMsgDataLen = 0;
							delete pInteractMsg;
							pInteractMsg = NULL;
						}
					}
					zframe_destroy(&frame_interact_identity);
					zframe_destroy(&frame_interact_sequence);
					zframe_destroy(&frame_interact_datetime);
					zframe_destroy(&frame_interact_type);
					zframe_destroy(&frame_interact_data);
				}
				zmsg_destroy(&msg_interact);
			}
		}
	}
}

bool ccrfid_proxy::DeviceProxy::addPublishMessage(const char * pMsgTopic_, unsigned int uiMsgType_, 
	unsigned char * pMsgData_, size_t nMsgDataLen_)
{
	bool result = false;
	if (pMsgTopic_ && pMsgData_) {
		ccrfid_proxy::PublishMessage * pPubMsg = new ccrfid_proxy::PublishMessage();
		memset(pPubMsg, 0, sizeof(ccrfid_proxy::PublishMessage));
		pPubMsg->uiMsgDataLen = (unsigned int)nMsgDataLen_;
		pPubMsg->pMsgData = new unsigned char[nMsgDataLen_ + 1];
		memset(pPubMsg->pMsgData, 0, nMsgDataLen_ + 1);
		memcpy_s(pPubMsg->pMsgData, nMsgDataLen_ + 1, pMsgData_, nMsgDataLen_);
		encryptMessage(pPubMsg->pMsgData, 0, (unsigned int)nMsgDataLen_);
		pPubMsg->pMsgData[nMsgDataLen_] = '\0';
		strncpy_s(pPubMsg->szMsgTopic, sizeof(pPubMsg->szMsgTopic), pMsgTopic_, strlen(pMsgTopic_));
		pPubMsg->ulMsgTime = (unsigned long long)time(NULL);
		pPubMsg->uiMsgSeq = getPublishMessageSequence();
		pPubMsg->uiMsgType = uiMsgType_;
		pthread_mutex_lock(&m_mutex4PublishMsgQue);
		m_publishMsgQue.push(pPubMsg);
		if (m_publishMsgQue.size() == 1) {
			pthread_cond_broadcast(&m_cond4PublishMsgQue);
		}
		pthread_mutex_unlock(&m_mutex4PublishMsgQue);
		result = true;
	}
	return result;
}

void ccrfid_proxy::DeviceProxy::handlePublishMessage()
{
	do {
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
			zmsg_t * msg_pub = zmsg_new();
			zframe_t * frame_pub_topic = zframe_from(pPubMsg->szMsgTopic);
			char szSeq[16] = { 0 };
			sprintf_s(szSeq, sizeof(szSeq), "%u", pPubMsg->uiMsgSeq);
			zframe_t * frame_pub_sequence = zframe_from(szSeq);
			char szPubTime[20] = { 0 };
			formatDatetime(pPubMsg->ulMsgTime, szPubTime, sizeof(szPubTime));
			zframe_t * frame_pub_time = zframe_from(szPubTime);
			char szType[16] = { 0 };
			sprintf_s(szType, sizeof(szType), "%u", pPubMsg->uiMsgType);
			zframe_t * frame_pub_type = zframe_from(szType);
			zframe_t * frame_pub_data = zframe_new(pPubMsg->pMsgData, pPubMsg->uiMsgDataLen);
			zmsg_append(msg_pub, &frame_pub_topic);
			zmsg_append(msg_pub, &frame_pub_sequence);
			zmsg_append(msg_pub, &frame_pub_time);
			zmsg_append(msg_pub, &frame_pub_type);
			zmsg_append(msg_pub, &frame_pub_data);
			zmsg_send(&msg_pub, m_publisher);
			char szLog[256] = { 0 };
			sprintf_s(szLog, sizeof(szLog), "[DeviceProxy]%s[%d]publish message: topic=%s, seq=%s, time=%s, type=%s\r\n", 
				__FUNCTION__, __LINE__, pPubMsg->szMsgTopic, szSeq, szPubTime, szType);
			writeLog(szLog, pf_logger::eLOGCATEGORY_INFO, pf_logger::eLOGTYPE_FILE);
			printf("%s\n", szLog);
		}
	} while (1);
}

bool ccrfid_proxy::DeviceProxy::addInteractMessage(ccrfid_proxy::InteractMessage * pInteractMsg_)
{
	bool result = false;
	if (pInteractMsg_) {
		pthread_mutex_lock(&m_mutex4InteractMsgQue);
		m_interactMsgQue.push(pInteractMsg_);
		if (m_interactMsgQue.size() == 1) {
			pthread_cond_broadcast(&m_cond4InteractMsgQue);
		}
		pthread_mutex_unlock(&m_mutex4InteractMsgQue);
		result = true;
	}
	return result;
}

void ccrfid_proxy::DeviceProxy::handleInteractMessage()
{
	do {
		pthread_mutex_lock(&m_mutex4InteractMsgQue);
		while (m_nRun && m_interactMsgQue.empty()) {
			pthread_cond_wait(&m_cond4InteractMsgQue, &m_mutex4InteractMsgQue);
		}
		if (!m_nRun && m_interactMsgQue.empty()) {
			pthread_mutex_unlock(&m_mutex4InteractMsgQue);
			break;
		}
		ccrfid_proxy::InteractMessage * pInteractMsg = m_interactMsgQue.front();
		m_interactMsgQue.pop();
		pthread_mutex_unlock(&m_mutex4InteractMsgQue);
		if (pInteractMsg) {
			switch (pInteractMsg->uiMsgType) {
				case INTERACTOR_KEEPALIVE: {
					zframe_t * frame_interact_reply_identity = zframe_from(pInteractMsg->szMsgIdentity);
					char szSequence[16] = { 0 };
					sprintf_s(szSequence, sizeof(szSequence), "%u", pInteractMsg->uiMsgSeq);
					zframe_t * frame_interact_reply_sequence = zframe_from(szSequence);
					char szDatetime[20] = { 0 };
					//formatDatetime(pInteractMsg_->ulMsgTime, szDatetime, sizeof(szDatetime));
					formatDatetime((unsigned long long)time(NULL), szDatetime, sizeof(szDatetime)); //reply time
					zframe_t * frame_interact_reply_datetime = zframe_from(szDatetime);
					char szType[16] = { 0 };
					sprintf_s(szType, sizeof(szType), "%u", pInteractMsg->uiMsgType);
					zframe_t * frame_interact_reply_type = zframe_from(szType);
					zframe_t * frame_interact_reply_data = zframe_new(NULL, 0);
					zmsg_t * msg_interact_reply = zmsg_new();
					zmsg_append(msg_interact_reply, &frame_interact_reply_identity);
					zmsg_append(msg_interact_reply, &frame_interact_reply_sequence);
					zmsg_append(msg_interact_reply, &frame_interact_reply_datetime);
					zmsg_append(msg_interact_reply, &frame_interact_reply_type);
					zmsg_append(msg_interact_reply, &frame_interact_reply_data);
					zmsg_send(&msg_interact_reply, m_interactor);
					break;
				}
				case INTERACTOR_SNAPSHOT: {

					break;
				}
				case INTERACTOR_CONTROL: {
					if (pInteractMsg->pMsgData && pInteractMsg->uiMsgDataLen) {
						int nRetVal = -1;
						ccrfid_device::DeviceCommandInfo devCmdInfo;
						unsigned int uiCmdInfoLen = sizeof(devCmdInfo);
						if (pInteractMsg->uiMsgDataLen >= uiCmdInfoLen) {
							memcpy_s(&devCmdInfo, uiCmdInfoLen, pInteractMsg->pMsgData, uiCmdInfoLen);
							pthread_mutex_lock(&m_mutex4DeviceList);
							char szEndpoint[32] = { 0 };
							//if (zhash_size(m_deviceList)) {
							//	ccrfid_proxy::DeviceInfo * pDevInfo = (ccrfid_proxy::DeviceInfo *)zhash_lookup(m_deviceList,
							//		devCmdInfo.szDeviceId);
							//	if (pDevInfo) {
							//		strncpy_s(szEndpoint, sizeof(szEndpoint), pDevInfo->szLink, strlen(pDevInfo->szLink));
							//	}
							//}
							if (!m_deviceList2.empty()) {
								std::string strDeviceId = devCmdInfo.szDeviceId;
								std::map<std::string, ccrfid_proxy::DeviceInfo *>::iterator iter = m_deviceList2.find(strDeviceId);
								if (iter != m_deviceList2.end()) {
									ccrfid_proxy::DeviceInfo * pDevInfo = iter->second;
									if (pDevInfo) {
										strncpy_s(szEndpoint, sizeof(szEndpoint), pDevInfo->szLink, strlen(pDevInfo->szLink));
									}
								}
							}
							pthread_mutex_unlock(&m_mutex4DeviceList);
							if (strlen(szEndpoint)) {
								switch (devCmdInfo.nCommand) {
									case ccrfid_device::CMD_BIND: {
										char szCmd[128] = { 0 };
										sprintf_s(szCmd, sizeof(szCmd), "[SG*%s*0004*SBLJ]", devCmdInfo.szDeviceId);
										nRetVal = TS_SendData(m_ullSrvInst, szEndpoint, szCmd, (unsigned int)strlen(szCmd));
										break;
									}
									case ccrfid_device::CMD_TASK: {
										char szCmd[128] = { 0 };
										if (devCmdInfo.nParam1 == 1) {
											sprintf_s(szCmd, sizeof(szCmd), "[SG*%s*0002*CR][SG*%s*0006*RWZX,1]",
												devCmdInfo.szDeviceId, devCmdInfo.szDeviceId);
										}
										else {
											sprintf_s(szCmd, sizeof(szCmd), "[SG*%s*0006*RWZX,0]", devCmdInfo.szDeviceId);
										}
										nRetVal = TS_SendData(m_ullSrvInst, szEndpoint, szCmd, (unsigned int)strlen(szCmd));
										break;
									}
									case ccrfid_device::CMD_FLEE: {
										char szCmd[128] = { 0 };
										sprintf_s(szCmd, sizeof(szCmd), "[SG*%s*0006*WSTF,%hu]", devCmdInfo.szDeviceId,
											devCmdInfo.nParam1);
										nRetVal = TS_SendData(m_ullSrvInst, szEndpoint, szCmd, (unsigned int)strlen(szCmd));
										break;
									}
									case ccrfid_device::CMD_RESET: {
										char szCmd[128] = { 0 };
										sprintf_s(szCmd, sizeof(szCmd), "[SG*%s*0005*RESET]", devCmdInfo.szDeviceId);
										nRetVal = TS_SendData(m_ullSrvInst, szEndpoint, szCmd, (unsigned int)strlen(szCmd));
										break;
									}
									case ccrfid_device::CMD_SET_INTERVAL: {
										int nInterval = devCmdInfo.nParam1;
										if (nInterval < 10) {
											nInterval = 10;
										}
										else if (nInterval > 300) {
											nInterval = 300;
										}
										char szInterval[6] = { 0 };
										sprintf_s(szInterval, 6, "%d", nInterval);
										int nLen = (int)strlen(szInterval) + 7;
										char szLen[5] = { 0 };
										sprintf_s(szLen, 5, "%04x", nLen);
										char szCmd[128] = { 0 };
										sprintf_s(szCmd, sizeof(szCmd), "[SG*%s*%s*UPLOAD,%d]", devCmdInfo.szDeviceId, 
											szLen, nInterval);
										nRetVal = TS_SendData(m_ullSrvInst, szEndpoint, szCmd, (unsigned int)strlen(szCmd));
									}
								}
							}
							devCmdInfo.nParam2 = nRetVal;
							zframe_t * frame_reply_identity = zframe_from(pInteractMsg->szMsgIdentity);
							char szMsgSeq[16] = { 0 };
							sprintf_s(szMsgSeq, 16, "%u", pInteractMsg->uiMsgSeq);
							zframe_t * frame_reply_sequence = zframe_from(szMsgSeq);
							char szDatetime[20] = { 0 };
							formatDatetime((unsigned long long)time(NULL), szDatetime, sizeof(szDatetime));
							zframe_t * frame_reply_datetime = zframe_from(szDatetime);
							char szMsgType[16] = { 0 };
							sprintf_s(szMsgType, sizeof(szMsgType), "%u", pInteractMsg->uiMsgType);
							zframe_t * frame_reply_type = zframe_from(szMsgType);
							zframe_t * frame_reply_data = zframe_new(&devCmdInfo, uiCmdInfoLen);
							zmsg_t * msg_interact = zmsg_new();
							zmsg_append(msg_interact, &frame_reply_identity);
							zmsg_append(msg_interact, &frame_reply_sequence);
							zmsg_append(msg_interact, &frame_reply_datetime);
							zmsg_append(msg_interact, &frame_reply_type);
							zmsg_append(msg_interact, &frame_reply_data);
							zmsg_send(&msg_interact, m_interactor);
						}
					}
					break;
				}
				default: {
					break;
				}
			}
			if (pInteractMsg->pMsgData && pInteractMsg->uiMsgDataLen) {
				delete[] pInteractMsg->pMsgData;
				pInteractMsg->pMsgData = NULL;
			}
			delete pInteractMsg;
			pInteractMsg = NULL;
		}
	} while (1);
}

unsigned int ccrfid_proxy::DeviceProxy::getPublishMessageSequence()
{
	unsigned int result = 0;
	pthread_mutex_lock(&g_mutex4PubSequence);
	g_uiPubSequence++;
	if (g_uiPubSequence == 0) {
		g_uiPubSequence = 1;
	}
	result = g_uiPubSequence;
	pthread_mutex_unlock(&g_mutex4PubSequence);
	return result;
}

void ccrfid_proxy::DeviceProxy::encryptMessage(unsigned char * pData_, unsigned int uiBeginIndex_, 
	unsigned int uiEndIndex_)
{
	char secret = '8';
	if (uiEndIndex_ > uiBeginIndex_ && uiBeginIndex_ >= 0) {
		for (unsigned int i = uiBeginIndex_; i < uiEndIndex_; i++) {
			pData_[i] += 1;
			pData_[i] = pData_[i] ^ secret;
		}
	}
}

void ccrfid_proxy::DeviceProxy::decryptMessage(unsigned char * pData_, unsigned int uiBeginIndex_, 
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

void ccrfid_proxy::DeviceProxy::formatDatetime(unsigned long long ulDateTime_, char * pDatetime_, size_t nLen_)
{
	time_t datetime = (time_t)ulDateTime_;
	struct tm tm_datetime;
	localtime_s(&tm_datetime, &datetime);
	tm_datetime.tm_year += 1900;
	tm_datetime.tm_mon += 1;
	if (pDatetime_ && nLen_ >= 16) {
		sprintf_s(pDatetime_, nLen_, "%04u%02u%02u%02u%02u%02u", tm_datetime.tm_year, tm_datetime.tm_mon,
			tm_datetime.tm_mday, tm_datetime.tm_hour, tm_datetime.tm_min, tm_datetime.tm_sec);
	}
}

void ccrfid_proxy::DeviceProxy::makeDatetime(const char * pDatetime_, unsigned long long * pUlTime_)
{
	struct tm tm_time;
	sscanf_s(pDatetime_, "%04d%02d%02d%02d%02d%02d", &tm_time.tm_year, &tm_time.tm_mon,
		&tm_time.tm_mday, &tm_time.tm_hour, &tm_time.tm_min, &tm_time.tm_sec);
	tm_time.tm_year -= 1900;
	tm_time.tm_mon -= 1;
	time_t this_time = mktime(&tm_time);
	if (pUlTime_) {
		*pUlTime_ = (unsigned long long)this_time;
	}
}

void __stdcall ccrfid_proxy::fMsgCb(int nType_, void * pMsg_, void * pUserData_)
{
	ccrfid_proxy::DeviceProxy * pProxy = (ccrfid_proxy::DeviceProxy *)pUserData_;
	if (pProxy) {
		switch (nType_) {
			case MSG_LINK_CONNECT: {
				break;
			}
			case MSG_LINK_DISCONNECT: {
				const char * pEndpoint = (char *)pMsg_;
				pProxy->handleDisconnectLink(pEndpoint);
				break;
			}
			case MSG_DATA: {
				MessageContent * pMsgContent = (MessageContent *)pMsg_;
				DeviceMessage * pDevMsg = new DeviceMessage();
				strncpy_s(pDevMsg->szEndpoint, sizeof(pDevMsg->szEndpoint), pMsgContent->szEndPoint,
					strlen(pMsgContent->szEndPoint));
				pDevMsg->ulMsgTime = pMsgContent->ulMsgTime;
				pDevMsg->uiMsgDataLen = pMsgContent->uiMsgDataLen;
				if (pDevMsg->ulMsgTime > 0) {
					pDevMsg->pMsgData = new unsigned char[pDevMsg->uiMsgDataLen + 1];
					memcpy_s(pDevMsg->pMsgData, pDevMsg->uiMsgDataLen + 1, pMsgContent->pMsgData, pDevMsg->uiMsgDataLen);
					pDevMsg->pMsgData[pDevMsg->uiMsgDataLen] = '\0';
				}
				if (!pProxy->addDeviceMessage(pDevMsg)) {
					if (pDevMsg->pMsgData) {
						delete[] pDevMsg->pMsgData;
						pDevMsg->pMsgData = NULL;
					}
					delete pDevMsg;
					pDevMsg = NULL;
				}
				break;
			}
		}
	}
}

void * ccrfid_proxy::dealLogThread(void * param_)
{
	ccrfid_proxy::DeviceProxy * pProxy = (ccrfid_proxy::DeviceProxy *)param_;
	if (pProxy) {
		pProxy->handleLog();
	}
	pthread_exit(NULL);
	return NULL;
}

void * ccrfid_proxy::dealDeviceThread(void * param_)
{
	ccrfid_proxy::DeviceProxy * pProxy = (ccrfid_proxy::DeviceProxy *)param_;
	if (pProxy) {
		pProxy->handleDeviceMessage();
	}
	pthread_exit(NULL);
	return NULL;
}

void * ccrfid_proxy::dealInteractThread(void * param_)
{
	ccrfid_proxy::DeviceProxy * pProxy = (ccrfid_proxy::DeviceProxy *)param_;
	if (pProxy) {
		pProxy->handleInteractMessage();
	}
	pthread_exit(NULL);
	return NULL;
}

void * ccrfid_proxy::dealPublishThread(void * param_)
{
	ccrfid_proxy::DeviceProxy * pProxy = (ccrfid_proxy::DeviceProxy *)param_;
	if (pProxy) {
		pProxy->handlePublishMessage();
	}
	pthread_exit(NULL);
	return NULL;
}

void * ccrfid_proxy::dealNetworkThread(void * param_)
{
	ccrfid_proxy::DeviceProxy * pProxy = (ccrfid_proxy::DeviceProxy *)param_;
	if (pProxy) {
		pProxy->handleNetWork();
	}
	pthread_exit(NULL);
	return NULL;
}

void ccrfid_proxy::freeLingerData(void * pData_)
{
	ccrfid_proxy::LingerData * pLingerData = (ccrfid_proxy::LingerData *)pData_;
	if (pLingerData) {
		if (pLingerData->pData && pLingerData->uiDataLen) {
			free(pLingerData->pData);
			pLingerData->pData = NULL;
			pLingerData->uiDataLen = NULL;
		}
		free(pLingerData);
		pLingerData = NULL;
	}
	pData_ = NULL;
}