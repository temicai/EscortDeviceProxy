#ifndef HTTPQUERY_H_5D4C6E0C_DAF9_4433_ABF6_6587F1DF9C27
#define HTTPQUERY_H_5D4C6E0C_DAF9_4433_ABF6_6587F1DF9C27

typedef struct _tagQueryResult
{
	int nRetCode: 16; //output
	int nCoordinate : 16; //output
	int nRadius : 16; //output
	int nObjType : 16; //input, 
	double dLat; //output
	double dLng; //output
} LbsQueryResult;

#define QRY_OBJ_DATA_WAREHOUSE 0
#define QRY_OBJ_AMAP 1

extern "C"
{
#ifndef QRY_API
#define QRY_API extern "C" __declspec(dllexport)
#endif
	QRY_API int __stdcall LbsGeoQuery(const char * pUrl, int nQryObjType, LbsQueryResult * pResult);
}
#endif 
