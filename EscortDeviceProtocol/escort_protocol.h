#ifndef ESCORT_PROTOCOL_A2F92347328F4755939CFBB03156B8F5_H
#define ESCORT_PROTOCOL_A2F92347328F4755939CFBB03156B8F5_H

#include <string>

namespace device_protocol
{
	enum eCommandType
	{
		CMD_CONNECTION_INITIALIZE_REQUEST = 1,
		CMD_CONNECTION_KEEP_ALIVE_REQUEST = 2,
		CMD_CONNECTION_SET_PARAMETER_REQUEST = 3,
		CMD_CONNECTION_GET_PARAMETER_REQUEST = 4,
		CMD_CONNECTION_DEVICE_CONTROL_REQUEST = 5,
		CMD_CONNECTION_DEVICE_SET_FENCE_REQUEST = 6,
		CMD_CONNECTION_DEVICE_GET_FENCE_REQUEST = 7,
		CMD_CONNECTION_DEVICE_REMOVE_FENCE_REQUEST = 8,
		CMD_CONNECTION_SUBSCRIBE_DEVICE_REQUEST = 9,
		CMD_CONNECTION_UNINITIALIZE_REQUEST = 10,

		CMD_DEVICE_GPS_LOCATION_NOTIFY = 100,
		CND_DEVICE_LBS_LOCATION_NOTIFY = 101,
		CMD_DEVICE_HEARTBEAT_NOTIFY = 102,
		CMD_DEVICE_ONLINE_NOTIFY = 103,
		CMD_DEVICE_OFFLINE_NOTIFY = 104,
		CMD_DEVICE_LOOSE_ALARM_NOTIFY = 105,
		CMD_DEVICE_LOWPOWER_ALARM_NOTIFY = 106,
		CMD_DEVICE_FENCE_ALARM_NOTIFY = 107,

		CMD_DEFAULT_REPLY = 200,
		CMD_CONNECTION_INITIALIZE_REPLY = 201,
		CMD_CONNECTION_KEEP_ALIVE_REPLY = 202,
		CMD_CONNECTION_SET_PARAMETER_REPLY = 203,
		CMD_CONNECTION_GET_PARAMETER_REPLY = 204,
		CMD_CONNECTION_DEVICE_CONTROL_REPLY = 205,
		CMD_CONNECTION_DEVICE_SET_FENCE_REPLY = 206,
		CMD_CONNECTION_DEVICE_GET_FENCE_REPLY = 207,
		CMD_CONNECTION_DEVICE_REMOVE_FENCE_REPLY = 208,
		CMD_CONNECTION_SUBSCRIBE_DEVICE_REPLY = 209,
		CMD_CONNECTION_UNINITIALIZE_REPLY = 210,
	};

	enum eProtocolType
	{
		PROTOCOL_PRIVATE = 0,
		PROTOCOL_MQTT = 1,
	};

	enum eSecurityPolicy
	{
		POLICY_EMPTY = 0,
		POLICY_SIMPLE_PRIVATE = 1,
		POLICY_RSA = 2,
		POLICY_BASE64 = 3,
	};

	enum eDeviceCommandType
	{
		DEV_CMD_DEVICE_BIND = 1,
		DEV_CMD_DEVICE_TASK = 2,
		DEV_CMD_DEVICE_ALARM = 3,
		DEV_CMD_DEVICE_SET_LOCATE_INTERVAL = 4,
		DEV_CMD_DEVICE_REBOOT = 5,
	};

	enum eCoordinateType
	{
		COORDINATE_WGS84 = 0,
		COORDINATE_BD09 = 1,
		COORDINATE_GCJ02 = 2,
	};

	enum eFenceType
	{
		FENCE_POLYGON = 0,
		FENCE_RECT = 1,
		FENCE_CIRCLE = 2,
	};

	enum eConnectionParameter
	{
		CONN_PARAM_REPLY_WAIT_TIMEOUT = 1,
		CONN_PARAM_RESEND_COUNT = 2,
		CONN_PARAM_KEEP_ALIVE_INTERVAL = 3,
		CONN_PARAM_ALIVE_MISS_TOLERANCE_COUNT = 4,
	};

	enum eProtocolErrorCode
	{
		ERROR_UNKNOW = -1,
		ERROR_NO = 0,
		ERROR_CONNECTION_REJECT = 1,
		ERROR_ACCOUNT_NOT_EXISTS = 2,
		ERROR_PASSWD_INCORRECT = 3,
		ERROR_ACCOUNT_LOGIN_ALREADY = 4,
		ERROR_ACCOUNT_REACH_PARALLEL_UPPER_LIMIT = 5,
		ERROR_SESSION_INVALID = 6,
		ERROR_BROKER_IS_RUNNING = 7,
		ERROR_BROKER_PORT_IS_USED = 8,
		ERROR_BROKER_CONNECT_PROXY_FAILED = 9,
		ERROR_CONNECTION_PARAMETER_TYPE_NOT_SUPPORT = 10,
		ERROR_CONNECTION_PARAMETER_VALUE_INCORECT = 11,

		ERROR_DEVICE_NOT_FOUND = 20,
		ERROR_DEVICE_OFFLINE = 21,
		ERROR_DEVICE_COMMAND_TYPE_NOT_SUPPORT = 22,
		ERROR_DEVICE_COMMAND_FAILED = 23,
		ERROR_DEVICE_FENCE_ALREADY_EXISTS = 24,
		ERROR_DEVICE_FENCE_INVALID = 25,
		ERROR_DEVICE_FENCE_NOT_EXISTS = 26,
		

		ERROR_REQUEST_IGNORED = 97,
		ERROR_PROTOCOL_NOT_SUPPORTED = 98,
		ERROR_PARSE_REQUEST_FAILED = 99,

	};

	typedef struct tagProtocolMessageHead
	{
		unsigned char mark[2];
		int8_t protocol_type;
		int8_t security_policy;
		unsigned short security_extra;
		unsigned short seq_num;
		unsigned int payload_length;
		tagProtocolMessageHead()
		{
			mark[0] = 0x45;
			mark[1] = 0x43;
			seq_num = 0;
			protocol_type = 0;
			security_policy = 0;
			payload_length = 0;
			security_extra = 0;
		}
	} ProtocolMessageHead;

	typedef struct tagLinkInitializeRequest
	{
		char szAccount[32];
		char szPasswd[64];
		unsigned int uiReqSeq;
		unsigned long ulReqTime;
		char szSession[20];
		tagLinkInitializeRequest()
		{
			szAccount[0] = '\0';
			szPasswd[0] = '\0';
			uiReqSeq = 0;
			ulReqTime = 0;
			szSession[0] = '\0';
		}
	} LinkInitializeRequest;

	typedef struct tagLinkInitializeReply
	{
		char szAccount[32];
		unsigned int uiRepSeq;
		unsigned long ulRepTime;
		char szSession[20];
		int nRepCode;
		tagLinkInitializeReply()
		{
			szAccount[0] = '\0';
			uiRepSeq = 0;
			ulRepTime = 0;
			szSession[0] = '\0';
			nRepCode = 0;
		}
	} LinkInitializeReply;

	typedef struct tagLinkUninitializeRequest
	{
		char szSession[20];
		unsigned int uiReqSeq;
		unsigned long ulReqTime;
		tagLinkUninitializeRequest()
		{
			szSession[0] = '\0';
			uiReqSeq = 0;
			ulReqTime = 0;
		}
	} LinkUninitializeRequest;

	typedef struct tagLinkUnitializeReply
	{
		char szSession[20];
		unsigned int uiReqSeq;
		unsigned long ulReqTime;
		int nRepCode;
		tagLinkUnitializeReply()
		{
			szSession[0] = '\0';
			uiReqSeq = 0;
			ulReqTime = 0;
			nRepCode = 0;
		}
	} LinkUnitializeReply;

	typedef struct tagLinkHeartBeatRequest
	{
		char szSession[20];
		unsigned int uiHeartBeatSeq;
		unsigned long ulHeartBeatTime;
		tagLinkHeartBeatRequest()
		{
			szSession[0] = '\0';
			uiHeartBeatSeq = 0;
			ulHeartBeatTime = 0;
		}
	} LinkHeartBeatRequest;

	typedef struct tagLinkHeartBeatReply
	{
		char szSession[20];
		unsigned int uiHeartBeatSeq;
		unsigned long ulHeartBeatTime;
		int nRepCode;
		tagLinkHeartBeatReply()
		{
			szSession[0] = '\0';
			uiHeartBeatSeq = 0;
			ulHeartBeatTime = 0;
			nRepCode = 0;
		}
	} LinkHeartBeatReply;

	typedef struct tagLinkSetParameterRequest
	{
		char szSession[20];
		int nParameterKey;
		char szParameterValue[32];
		unsigned int uiReqSeq;
		unsigned long ulReqTime;
		tagLinkSetParameterRequest()
		{
			szSession[0] = '\0';
			nParameterKey = 0;
			szParameterValue[0] = '\0';
			uiReqSeq = 0;
			ulReqTime = 0;
		}
	} LinkSetParameterRequest;

	typedef struct tagLinkSetParameterReply
	{
		char szSession[20];
		int nParameterKey;
		unsigned int uiRepSeq;
		unsigned long ulRepTime;
		int nRepCode;
		tagLinkSetParameterReply()
		{
			szSession[0] = '\0';
			nParameterKey = 0;
			uiRepSeq = 0;
			ulRepTime = 0;
			nRepCode = 0;
		}
	} LinkSetParameterReply;

	typedef struct tagLinkGetParameterRequest
	{
		char szSession[20];
		int nParameterKey;
		unsigned int uiReqSeq;
		unsigned long ulReqTime;
		tagLinkGetParameterRequest()
		{
			szSession[0] = '\0';
			nParameterKey = 0;
			uiReqSeq = 0;
			ulReqTime = 0;
		}
	} LinkGetParameterRequest;

	typedef struct tagLinkGetParameterReply
	{
		char szSession[20];
		int nParameterKey;
		char szParameterValue[32];
		unsigned int uiRepSeq;
		unsigned long ulRepTime;
		int nRepCode;
		tagLinkGetParameterReply()
		{
			szSession[0] = '\0';
			nParameterKey = 0;
			szParameterValue[0] = '\0';
			uiRepSeq = 0;
			ulRepTime = 0;
			nRepCode = 0;
		}
	} LinkGetParameterReply;

	typedef struct tagLinkDeviceControlRequest
	{
		char szSession[20];
		char szDeviceId[20];
		int nSubType;
		int nParameter;
		unsigned int uiReqSeq;
		unsigned long ulReqDatetime;
	} LinkDeviceControlRequest;

	typedef struct tagLinkDeviceControlReply
	{
		char szSession[20];
		char szDeviceId[20];
		int nSubType;
		unsigned int uiReqSeq;
		unsigned long ulRepDatetime;
		int nRepCode;
	} LinkDeviceControlReply;

	typedef struct tagFenceInfo
	{
		char szFenceId[20];
		int nFenceType : 8; //0,1,2
		int nCoordinate : 8;//0,1,2
		int nPolicy : 8; //0,1
		int nState : 8; //0,1
		char szFenceContent[256];
		unsigned long ulStartTime;
		unsigned long ulStopTime;
		std::string toString()
		{
			char szOut[512] = { 0 };
			sprintf_s(szOut, sizeof(szOut), "%d|%d|%d|%s|%lu|%lu", nFenceType, nCoordinate, nPolicy,
				szFenceContent, ulStartTime, ulStopTime);
			return (std::string)(szOut);
		}
		tagFenceInfo()
		{
			szFenceId[0] = '\0';
			szFenceContent[0] = '\0';
			ulStartTime = ulStopTime = 0;
			nCoordinate = nFenceType = -1;
			nState = nPolicy = 0;
		}
	} FenceInfo;

	typedef struct tagLinkSetFenceRequest
	{
		char szSession[20];
		char szDeviceId[20];
		unsigned int uiReqSeq;
		unsigned long ulReqTime;
		FenceInfo fenceInfo;
	} LinkSetFenceRequest;
	
	typedef struct tagLinkSetFenceReply
	{
		char szSession[20];
		char szDeviceId[20];
		unsigned int uiRepSeq;
		unsigned long ulRepTime;
		char szFenceId[20];
		int nRetCode;
	} LinkSetFenceReply;

	typedef struct tagLinkGetFenceRequest
	{
		char szSession[20];
		char szDeviceId[20];
		unsigned int uiReqSeq;
		unsigned long ulReqTime;
	} LinkGetFenceRequest;

	typedef struct tagLinkGetFenceReply
	{
		char szSession[20];
		char szDeviceId[20];
		unsigned int uiRepSeq;
		unsigned long ulRepTime;
		unsigned int uiFenceCount;
		FenceInfo * pFenceList;
		int nRepCode;
	} LinkGetFenceReply;

	typedef struct tagLinkRemoveFenceRequest
	{
		char szSession[20];
		char szDeviceId[20];
		char szFenceId[20];
		unsigned int uiReqSeq;
		unsigned long ulReqTime;
	} LinkRemoveFenceRequest;

	typedef struct tagLinkRemoveFenceReply
	{
		char szSession[20];
		char szDeviceId[20];
		char szFenceId[20];
		unsigned int uiRepSeq;
		unsigned long ulReqTime;
		int nRepCode;
	} LinkRemoveFenceReply;

	typedef struct tagLinkSubscribeDeviceRequest
	{
		char szSession[20];
		char szDeviceId[20];
		int nAct;//0: subscribe, 1: unsubscribe
		unsigned int uiReqSeq;
		unsigned long ulReqTime;
		tagLinkSubscribeDeviceRequest()
		{
			szSession[0] = '\0';
			szDeviceId[0] = '\0';
			nAct = 0;
			uiReqSeq = 0;
			ulReqTime = 0;
		}
	} LinkSubscribeDeviceRequest;

	typedef struct tagLinkSubscribeDeviceReply
	{
		char szSession[20];
		char szDeviceId[20];
		int nAct;
		unsigned int uiRepSeq;
		unsigned long ulRepTime;
		int nRepCode;
		tagLinkSubscribeDeviceReply()
		{
			szSession[0] = '\0';
			szDeviceId[0] = '\0';
			nAct = 0;
			uiRepSeq = 0;
			ulRepTime = 0;
			nRepCode = 0;
		}
	} LinkSubscribeDeviceReply;

	typedef struct tagPushDeviceOnlineMessage
	{
		char szDeviceId[20];

	} PushDeviceOnlineMessage;

	typedef struct tagPushDeviceOfflineMessage
	{

	} PushDeviceOfflineMessage;

	typedef struct tagPushDeviceAliveMessage
	{

	} PushDeviceAliveMessage;

	typedef struct tagPushDeviceLowpowerAlarm
	{

	} PushDeviceLowpowerAlarm;

	typedef struct tagPushDeviceLooseAlarm
	{

	} PushDeviceLooseAlarm;

	typedef struct tagPushDeviceFenceAlarm
	{

	} PushDeviceFenceAlarm;


}

#endif
