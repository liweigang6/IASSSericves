#pragma once
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
#include <curl/curl.h>
#include "StateReport.h"
#include "dist\json\json.h"
#include "dist\json\json-forwards.h"
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "lib_json.lib")
#pragma comment(lib, "zlibwapi.lib")
#pragma comment(lib, "libcurl.lib")
using namespace std;
//#define FILE_PATH "C:\\Program Files (x86)\\socket\\log.txt" //信息输出文件

//The log function
int WriteToLog(char* str);

//The thread function
unsigned __stdcall WorkThread(LPVOID lpParam);
//void WorkThread(SOCKET sockClient);

//Function implementation function
void UpdateConfigFile(Json::Value &root, char *zipdlpathname, SOCKET sockClient);
void RestoreConfigFile(Json::Value &root, char *zipdlpathname, SOCKET sockClient);
string GetStats();

//File manipulation function
int UnCompressing(char *Unzfilepath, vector<string> &zipfilelist);
char *GetFileSHA1(char *FileNameInPut, char *outSHA1, char *outError);
void GetFileName(char* lpPath,vector<string> &fileList);
void FindFile(char* filename, char *filepath, vector<string> &filepathList);

//Configuration processing function
string ConfigFileRead(string &path);
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

