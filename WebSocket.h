#pragma once
#include "glog/logging.h"
#include <windows.h>
#include <string>
#include <sstream>
#include <iostream>
#include "base64.h"
#include "sha1.h"
#include "unzip.h"
#include <UrlMon.h>
#include <vector>
#include <process.h>
#include <iterator>
#include "curl\curl.h"
#include "StateReport.h"
#include "dist\json\json.h"
#include "dist\json\json-forwards.h"
using namespace google;
#pragma comment(lib, "glog.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "lib_json.lib")
#pragma comment(lib, "zlibwapi.lib")
#pragma comment(lib, "libcurl.lib")
using namespace std;


//The log function
//int WriteToLog(char* str, int c);
void InitGLog();

//The thread function
unsigned __stdcall WorkThread(LPVOID lpParam);
//void WorkThread(SOCKET sockClient);

//Function implementation function
void UpdateConfigFile(Json::Value &root, char *zipdlpathname, SOCKET sockClient);
void RestoreConfigFile(Json::Value &root, char *zipdlpathname, SOCKET sockClient);
string GetStats(string path);

//File manipulation function
int UnCompressing(char *Unzfilepath, vector<string> &zipfilelist);
char *GetFileSHA1(char *FileNameInPut, char *outSHA1, char *outError);
void GetFileName(char* lpPath,vector<string> &fileList);
void FindFile(char* filename, char *filepath, vector<string> &filepathList);

//Configuration processing function
string ConfigFileRead(string &path);
string ConfigVersion(string &path);
void CreateDir(string &dir);
void DeleteFile(char* lpPath);

class WebSocket
{
public:
	WebSocket(void);
	~WebSocket(void);
	void respondInfo(SOCKET sockClient, char * request);
	void getKey(char *request, string clientkey);
	void respondClient(SOCKET sockClient, byte charb[],int length, boolean finalFragment);
	void initsocket();
	void requestInfo(SOCKET sockClient, char * request);
	char *parsedata(char *inClientData, char *outClientData, SOCKET sockClient);
};

