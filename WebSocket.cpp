#pragma once
#include "StdAfx.h"
#include "WebSocket.h"
#include <time.h>
#include <fstream>
#include <io.h>
#include <direct.h>
#define SHA1LEN 60

typedef struct  _STRUCT_DATA_  
{  
	SOCKET sfd;
}_DATA,*_pDATA;

WebSocket::WebSocket(void)
{

}


WebSocket::~WebSocket(void)
{

}

/*解压缩函数，内部如果还有压缩包，保存压缩包的据对路径
*Unzfilepath：要解压缩的压缩包
*zipfilelist：放置内部压缩包绝对路径的容器
*/
int UnCompressing(char *Unzfilepath, vector<string> &zipfilelist)
{
	//获取新要建立的文件夹的名字
	char *dev = strstr(Unzfilepath, ".zip");
	char dirpathname[1024]={0};
	int dlength = (int)(strlen(Unzfilepath)-strlen(dev));
	strncpy(dirpathname, Unzfilepath, dlength);
	//创建目录
	if(_access(dirpathname, 0) == -1)
	{
		int error = CreateDirectory(dirpathname, NULL);
		if(error == 0)
		{
			WriteToLog("DEBUG:创建目录失败");
			WriteToLog("DEBUG:目录已经存在");
		}
	}
	unzFile zFile;  
	zFile = unzOpen64(Unzfilepath);  
	if (zFile == NULL)  
	{  
		WriteToLog("ERROR;文件打开失败");  
		return -1;  
	}  
	unz_global_info64 zGlobalInfo;
	if (UNZ_OK != unzGetGlobalInfo64(zFile, &zGlobalInfo))  
	{  
	    // 错误处理  
	    WriteToLog("ERROR:得到全局信息出错");  
	    return -1;  
	} 
	unz_file_info64 *pfileinfo = new unz_file_info64[zGlobalInfo.number_entry];  
	unsigned int num = 512;  
	char *fileName = new char[num];
	memset(fileName,0, num);
	
	vector<string> vecfilename;
	for (int i = 0; i < zGlobalInfo.number_entry; i++)  
	{ 
	    // 遍历所有文件  该取函数的功能，是获取压缩包内当前读的文件信息
	    if (UNZ_OK != unzGetCurrentFileInfo64(zFile, &pfileinfo[i], fileName, num, NULL, 0, NULL, 0))  
	    {  
	        //错误处理信息  
	        WriteToLog("ERROR:得到当前文件信息出错！");
			return -1;
	    }
		vecfilename.push_back(fileName);
 		unzGoToNextFile(zFile);
	}

	vector<string>::iterator it=vecfilename.begin();
	int index = 0 ;
	for(;it!=vecfilename.end();it++,index++)
	{
		std::string file = *it;

		if (file.rfind('/')==file.length()-1)
		{
			continue;
		}
		//打开当前文件
		if (UNZ_OK != unzLocateFile(zFile, file.c_str(), 0))
		{
			//错误处理信息  
			WriteToLog("ERROR:unzLocateFile文件失败！");
			return -1;
		}

		if (UNZ_OK != unzOpenCurrentFile(zFile))  
		{  
			//错误处理信息  
			WriteToLog("ERROR:unzOpenCurrentFile失败");
			return -1;
		}  

		int fileLength = (int)(pfileinfo[index].uncompressed_size);
		if(fileLength == 0)
		{	
			unzCloseCurrentFile(zFile);
			continue;
		}
		char *fileData = new char[fileLength];
		memset(fileData, 0, fileLength); 
		int len = 1 ;  
	
		//解压缩文件 读取当前文件信息 
		len = unzReadCurrentFile(zFile, fileData, fileLength);
		if(len == 0)
		{
			break;
		}

		string path= dirpathname;
		std::size_t p = file.find('/');
		if(p!=std::string::npos)
		{
			std::cout << dev << std::endl;
			char des[1024]= {0};
			strncpy(des, file.c_str(), p);
			string s;
			s.assign(path).append("\\").append(des);
			if(_access(s.c_str(), 0) == -1)
			{
				int flag= CreateDirectory(s.c_str(), NULL);
				if(flag == 0)
				{
					WriteToLog("DEBUG:创建目录失败");
				}
			}
		}
		path.append("\\").append(file);
		path.replace(path.find('/'),1,"\\");
		if(strstr(path.c_str(), ".zip") != NULL)
		{
			zipfilelist.push_back(path);
		}
		FILE *f= fopen(path.c_str(),"wb");
		if(f == NULL)
		{
			WriteToLog("ERROR:文件打开失败");
			unzCloseCurrentFile(zFile);
			return 0;
		}
		fwrite(fileData, len, 1, f);
		unzCloseCurrentFile(zFile);
		fclose(f);
		if(fileData)
		{
			delete[] fileData;
			fileData = NULL;
		}

	}
	if(fileName)
	{
		delete[] fileName;
		fileName = NULL;
	}
	unzClose(zFile);
	return 0;
}

/*拼接获得状态的JSON字符串
*
*/
string GetStats()
{
   Json::Value root;
   root["code"] = Json::Value(0);
   root["message"] = Json::Value(0);
   root["result"] = Json::Value("0");

   string out = root.toStyledString();
   return out;
}


/*获取文件的SHA1值，如果发生错误则将错误信息写入outError
* FileNameInPut:文件路径
* outSHA1:SHA1输出变量
* outError:错误信息输出变量
* returns:outSHA1
*/
char *GetFileSHA1(char *FileNameInPut, char *outSHA1, char *outError)
{
	BYTE rgbFile[MAX_PATH];
	DWORD cbRead = 0;
	BOOL bResult = FALSE;
	BYTE rgbHash[SHA1LEN];
	DWORD cbHash = 0;
	HCRYPTHASH hHash = 0;
	HCRYPTPROV hProv = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	if(FileNameInPut==NULL) 
	{
		if (outError != NULL)
		{
			sprintf(outError, "%s", "FileNameInPut Is NULL");
		}
		return outError;
	}

	HANDLE hFile = CreateFile(FileNameInPut,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN,
		NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		sprintf(outError, "%s", "CreateFile Error");
		return outError;
	}
	//Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv,
		NULL,
		NULL,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		sprintf(outError, "%s", "CryptAcquireContext Error");
		CloseHandle(hFile);
		return outError;
	}
	if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
	{
		sprintf(outError, "%s", "CryptCreateHash Error");
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return outError;
	}
	while (bResult = ReadFile(hFile, rgbFile, MAX_PATH, 
		&cbRead, NULL))
	{
		if (0 == cbRead)
		{
			break;
		}

		if (!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			sprintf(outError, "%s", "CryptHashData Error");
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return outError;
		}
	}
	if (!bResult)
	{
		sprintf(outError, "%s", "Read File Error"); 
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);
		return outError;
	}

	cbHash = SHA1LEN;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{


		for (DWORD i = 0; i < cbHash; i++)
		{
			sprintf(outSHA1+(2*i), "%c%c", rgbDigits[rgbHash[i] >> 4],
				rgbDigits[rgbHash[i] & 0xf]);
		}

	}
	else
	{
		sprintf(outError, "%s", "CryptGetHashParam Error");
		return outError;
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);

	return outSHA1; 
}

/*遍历制定路径下的所有文件，如果发生错误直接返回
*lpPath：指定文件路径
*filelist：存放文件名称的链表
*/
void GetFileName(char* lpPath,vector<string> &fileList)  
{  
	  
	WIN32_FIND_DATA FindFileData;  
	string path;
	

	HANDLE hFind=::FindFirstFile(path.assign(lpPath).append("\\*").c_str() ,&FindFileData);  
   if(INVALID_HANDLE_VALUE == hFind)    return;  
  
   while(true)  
   {  
        if(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)  
        {  
            if(FindFileData.cFileName[0]!='.')  
            {  
                char szFile[MAX_PATH];  
                strcpy(szFile,lpPath);  
                strcat(szFile,"\\");  
                strcat(szFile,(char* )(FindFileData.cFileName));  
                GetFileName(szFile,fileList);  
            }  
        }  
        else  
        {  

            fileList.push_back(path.assign(lpPath).append("\\").append(FindFileData.cFileName));

        }  
        if(!FindNextFile(hFind,&FindFileData))    break;  
   }  
   FindClose(hFind);  
} 

/*遍历制定路径下的所有文件，查找相同文件名，返回绝对路径，发生错误直接返回
*filename：需要查找的文件名
*filepath：需要查找的文件路径
*filepathList：存放文件名称的链表
*/
void FindFile(char* filename, char *filepath, vector<string> &filepathList)  
{  

	WIN32_FIND_DATA FindFileData;  
	string path;


	HANDLE hFind=::FindFirstFile(path.assign(filepath).append("\\*").c_str(), &FindFileData);  
	if(INVALID_HANDLE_VALUE == hFind)    return;  

	while(true)  
	{  
		if(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)  
		{  
			if(FindFileData.cFileName[0]!='.')  
			{  
				char szFile[MAX_PATH];  
				strcpy(szFile,filepath);  
				strcat(szFile,"\\");  
				strcat(szFile,(char* )(FindFileData.cFileName));  
				FindFile(filename, szFile, filepathList);  
			}  
		}  
		else  
		{  
			if(strcmp(filename, FindFileData.cFileName) == 0)
			{
				filepathList.push_back(path.assign(filepath).append("\\").append(FindFileData.cFileName));
			}
		}  
		if(!FindNextFile(hFind,&FindFileData))    break;  
	}  
	FindClose(hFind);
	return;
}
/*回复链接请求
*sockClient：端口号
*request：回复的握手包信息
*/
void WebSocket::respondInfo(SOCKET sockClient, char * request){
	send(sockClient, request, (int)(strlen(request)), 0);
}


/*初始化端口和建立线程连接
*
*/
void WebSocket::initsocket(){
	WORD imgrequest;
	WSADATA wsadata;
	imgrequest = MAKEWORD(1, 1);
	int err;
	err = WSAStartup(imgrequest, &wsadata);
	if (!err)
	{
		WriteToLog("DEBUG:服务已经启动");
	}
	else
	{
		WriteToLog("ERROR:服务未启动");
		return;
	}
	SOCKET sersocket = socket(AF_INET, SOCK_STREAM, 0);

	SOCKADDR_IN addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);      //ip地址
	addr.sin_port = htons(8899);                        //绑定端口
	if(bind(sersocket, (SOCKADDR*)&addr, sizeof(SOCKADDR)) != 0)//绑定完成
	{
		WriteToLog("ERROR:绑定失败");
		return;
	}
	listen(sersocket, 10);                              //其中第二个参数代表能够接收的最多的连接数

	SOCKADDR_IN clientsocket;
	int len = sizeof(SOCKADDR);

	_DATA socketclient;

	while (true){
		SOCKET serConn = accept(sersocket, (SOCKADDR*)&clientsocket, &len);
		WriteToLog("DEBUG:客户端连接");
		unsigned threadid={0};
		socketclient.sfd = serConn;
		//我这里起了一个线程来处理协议
		HANDLE hThread1 = (HANDLE)_beginthreadex(NULL,0,WorkThread, &socketclient,0,&threadid);
		//HANDLE hThread1 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkThread, (LPVOID)serConn, 0, 0);
		if (hThread1 != NULL)
		{
			CloseHandle(hThread1);
		}

	}
}

/*获取key和协议
*sockClient：端口号
*request：拼接的握手包
*/
void WebSocket::requestInfo(SOCKET sockClient, char * request){
	char recev[1024] = {0};
	recv(sockClient, recev, 2048, 0);
	string s = recev;
	int i = (int)(s.find("Sec-WebSocket-Key"));
	s = s.substr(i + 19, 24);
	//以上是为了得到客户端请求信息的key，关于key的作用可以去了解握手协议
	//以下是服务器拼接协议返回给客户端
	getKey(request,s);
}

/*协议
这个过程就是拿到客户端的key然后经过sha加密，再拼接返回的协议发给客户端
*request：拼接的握手包
*clientkey：客户端的key
*/
void WebSocket::getKey(char *request, string clientkey){
	strcat(request, "HTTP/1.1 101 Switching Protocols\r\n");
	strcat(request, "Connection: upgrade\r\n");
	strcat(request, "Sec-WebSocket-Accept: ");
	string server_key = clientkey;
	server_key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	SHA1  sha;
	unsigned int message_digest[5];
	
	sha.Reset();
	sha << server_key.c_str();
	sha.Result(message_digest);
	for (int i = 0; i < 5; i++) {
		message_digest[i] = htonl(message_digest[i]);
	}
	server_key = base64_encode(reinterpret_cast<const unsigned char*>(message_digest), 20);
	server_key += "\r\n";
	strcat(request, server_key.c_str());
	strcat(request, "Upgrade: websocket\r\n\r\n");
}

/*解析JS反馈的数据
*inClientData:接受到的数据
*outClientData:解析后的数据
*sockClient:端口号
*/
char * WebSocket::parsedata(char *inClientData, char *outClientData, SOCKET sockClient)
{
	int point = 0;            //字节指针位置
	int tmppoint = 0;         //临时指针变量
	/*这里b字节数组是客户端的请求信息，需要注意point这个指针的变化，具体需要去理解它的协议，协议中每段字节里面包含了什么信息需要把    它解析出来*/
	byte b[4096] = "";
	//转为字节来处理
	memcpy(b, inClientData, 2048);
	//取第一个字节
	int first = b[point] & 0xFF;
	
	byte opCode = (byte)(first & 0x0F);             //0000 1111 后四位为opCode 00001111
	if (opCode == 8){
		closesocket(sockClient);
	}
	//取第二个字节
	first = b[++point];
	//负载长度
	int payloadLength = first & 0x7F;
	
	if (payloadLength == 126) {
		byte extended[2] = "";
		extended[0] = b[++point];
		extended[1] = b[++point];
		int shift = 0;
		payloadLength = 0;
		for (int i = 2- 1; i >= 0; i--) {
			payloadLength = payloadLength + ((extended[i] & 0xFF) << shift);
			shift += 8;
		}
	}else if (payloadLength == 127) {
		byte extended[8] = "";
		tmppoint = ++point;     //保存临时指针
		point = --point;
		for (int i = 0; i < 8;i++){
			extended[i] = b[tmppoint + i];
			point++;
		}
		int shift = 0;
		payloadLength = 0;
		for (int i = 8 - 1; i >= 0; i--) {
			payloadLength = payloadLength + ((extended[i] & 0xFF) << shift);
			shift += 8;
		}
	}

	//非126和127置回来
	else if ((payloadLength != 126) || (payloadLength != 127)){
		point = 1;              
	}

	
	//第三个字节，掩码
	byte mask[4] = "";
	tmppoint = ++point;
	//因为自增了一次，这里需要减掉
	point = --point; 
	//取掩码值
	for (int i = 0; i < 4; i++){
		mask[i] = b[tmppoint + i];
		point++;
		
	}
	byte changeb[4096] = {0};

	//内容的长度保留，循环里面已经被改变
	int length = payloadLength;
	int readThisFragment = 1;

	//通过掩码计算真实的数据
	while (payloadLength > 0){
		int maskbyte = b[++point];
		int index = (readThisFragment - 1) % 4;
		maskbyte = maskbyte ^ (mask[index] & 0xFF);
		changeb[readThisFragment-1] = (byte)maskbyte;
		payloadLength--;
		readThisFragment++;
	}
	memcpy(outClientData, changeb, length);
	return outClientData;
}

/*线程连接
*lpParam:指向存储端口的结构体
*/
unsigned __stdcall WorkThread(LPVOID lpParam)
{
	_pDATA sockclient = (_pDATA)lpParam;
	SOCKET sockClient= sockclient->sfd;
	char request[1024] = {0};  //请求信息
	char clieninfo[2048]= {0}; //握手后响应信息
	int len = 0;              //返回的长度

	WebSocket web;
	//握手协议
	web.requestInfo(sockClient, request);
	web.respondInfo(sockClient, request);
	//以上是握手协议
	//握手协议结束后，也就是服务返回给客户端后，客户端再一次返回
	//数据给服务器，下面就是解析客户端的返回数据
	//将数据全部读取出来

	len=recv(sockClient, clieninfo, 2048, 0);
	//接受错误
	if(len < 0)
	{
		WriteToLog("ERROR:链接异常断开");
		closesocket(sockClient);
		_endthreadex(0);
		return -1;
	}
	//接受数据
	if (len>0)
	{
		//处理接受的客户端的数据
		char charb[4096] = {0};
		web.parsedata(clieninfo, charb, sockClient);
		string s = charb;

		//json报文处理
		Json::Reader reader;
		Json::Value root;
		if(reader.parse(s, root))
		{
			char zipfilepath[MAX_PATH]={0};
			string buf;
			char s[1024]={0};
			GetModuleFileName(NULL, s, 1024);
			char *p = strrchr(s, '\\');
			char b[1024]={0};
			strncpy(b, s, strlen(s)-strlen(p+1));
			string path;
			path.assign(b).append("config.ini");
			buf = ConfigFileRead(path);
			if(buf.empty())
			{
				closesocket(sockClient);
				_endthreadex(0);
				return -1;
			}
			strcpy(zipfilepath, buf.c_str());
			CreateDir(buf);
			string cmd=root["cmd"].asString();
			if(strcmp(cmd.c_str(), "UpdateConfigFile") == 0)
			{
				UpdateConfigFile(root, zipfilepath, sockClient);
			}
			else if(strcmp(cmd.c_str(), "RestoreConfigFile") == 0)
			{
				RestoreConfigFile(root, zipfilepath, sockClient);
			}
			else if(strcmp(cmd.c_str(), "GetStatus") == 0)
			{
				string s=GetStats();
				char a[4096]= {0};
				strcpy(a, s.c_str());
				byte test[2048] = {0};
				memcpy(test, a, strlen(a));
				web.respondClient(sockClient, test, (int)strlen(a), true);
			}
			else
			{
				WriteToLog("ERROR:未匹配到的操作");
			}
		}
	}
	closesocket(sockClient);
	_endthreadex(0);
	return 0;
}

/*回复客户端信息
*sockClient:连接端口号
*charb：要恢复的信息
*length：信息长度
*finalFragment：标记位
*/
void WebSocket::respondClient(SOCKET sockClient, byte charb[],int length, boolean finalFragment){
	byte buf[1024] = {0};
	int first = 0x00;
	int tmp = 0;
	if (finalFragment) {
		first = first + 0x80;
		first = first + 0x1;
	}
	buf[0] = first;
	tmp = 1;
	//cout <<"数组长度:\n"<< length << endl;
	unsigned int nuNum = (unsigned)length;
	if (length < 126) {
		buf[1] = length;
		tmp = 2;
	}else if (length < 65536) {
		buf[1] = 126;
		buf[2] = nuNum >> 8;
		buf[3] = length & 0xFF;
		tmp = 4;
	}else {
		//数据长度超过65536
		buf[1] = 127;
		buf[2] = 0;
		buf[3] = 0;
		buf[4] = 0;
		buf[5] = 0;
		buf[6] = nuNum >> 24;
		buf[7] = nuNum >> 16;
		buf[8] = nuNum >> 8;
		buf[9] = nuNum & 0xFF;
		tmp = 10;
	}
	for (int i = 0; i < length;i++){
		buf[tmp+i]= charb[i];
	}
	char charbuf[1024] = {0};
	memcpy(charbuf, buf, length + tmp);
	send(sockClient, charbuf, 1024, 0);
}

/*分析按钮实现
*root：JS反馈的报文信息
*zipdlpathname：下载路径
*/
void UpdateConfigFile(Json::Value &root, char *zipdlpathname, SOCKET sockClient)
{
	WriteToLog("DEBUG:文件分析开始");
	//初始化上报函数
	string username=root["username"].asString();
	string dcpuuid=root["dcpuuid"].asString();
	string yun_addr=root["yun_addr"].asString();
	string url;
	url.assign(yun_addr).append("/slice/asreport/analyseNotice.shtml");
	cout <<  url << endl;
	string asreportId= root["asreportid"].asString();
	string result;
	CStateReport sr(url);
	string downloadurl= root["downloadurl"].asString();	

	//先匹配盘符
	int DSLength = GetLogicalDriveStrings(0,NULL);  
    //通过GetLogicalDriveStrings()函数获取所有驱动器字符串信息长度。  
    char* DStr = new char[DSLength];//用获取的长度在堆区创建一个c风格的字符串数组  
    GetLogicalDriveStrings(DSLength,(LPTSTR)DStr);  
    //通过GetLogicalDriveStrings将字符串信息复制到堆区数组中,其中保存了所有驱动器的信息。  
    int si=0; 
	vector<string> drivename;
    for(int i=0;i<DSLength/4;++i)  
        //为了显示每个驱动器的状态，则通过循环输出实现，由于DStr内部保存的数据是A:\NULLB:\NULLC:\NULL，这样的信息，所以DSLength/4可以获得具体大循环范围  
    {  
        char dir[4]={DStr[si],':','\\',0};    
        si+=4; 
		drivename.push_back(dir);
    }
	if(DStr)
	{
		delete[] DStr;
		DStr = NULL;
	}
	string dcppath=root["dcppath"].asString();
	WebSocket web;
	for(int i=(int)(drivename.size()-1);;i--)
	{
		if(i == 0)
		{
			WriteToLog("ERROR:未匹配到指定盘符");
			Json::Value root;
			root["code"] = Json::Value(1001);
			string s=root.toStyledString();
			char a[4096]= {0};
			strcpy(a, s.c_str());
			byte test[2048] = {0};
			memcpy(test, a, strlen(a));
			web.respondClient(sockClient, test, (int)strlen(a), true);
			return;
		}
		if(_stricmp(drivename[i].c_str(), zipdlpathname) == 0 ||_stricmp(drivename[i].c_str(), "C:\\") == 0)
		{
			continue;
		}
		string s;
		s.assign(drivename[i].append(dcppath));
		WIN32_FIND_DATA FindFileData; 
		HANDLE hFind=::FindFirstFile(s.append("\\*").c_str() ,&FindFileData);  
		if(INVALID_HANDLE_VALUE != hFind)
		{
			dcppath.assign(drivename[i]);
			FindClose(hFind);
			break;
		}
	}
	
	//正常匹配到盘符，返回给前端code:1000
	Json::Value root;
	root["code"] = Json::Value(1000);
	string s=root.toStyledString();
	char a[4096]= {0};
	strcpy(a, s.c_str());
	byte test[2048] = {0};
	memcpy(test, a, strlen(a));
	web.respondClient(sockClient, test, (int)strlen(a), true);

	//得到下载路径，并按照UUID给下载包命名
	string dirdcpuuid;
	dirdcpuuid.assign(zipdlpathname).append(dcpuuid).append(".zip");
	char zipfilepath[MAX_PATH] = {0};
	strcpy(zipfilepath, dirdcpuuid.c_str());
	char download[MAX_PATH]={0};
	strcpy(download, downloadurl.c_str());
	HRESULT hr = URLDownloadToFile(0, download, zipfilepath, 0, NULL);
	if(hr == S_OK)
	{
		WriteToLog("DEBUG:下载完成");
	}
	else
	{
			WriteToLog("ERROR:下载失败");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:分析失败");
			}
			else
			{
				WriteToLog("DEBUG:分析成功");
			}
			return;
	}
	//开始解压压缩包
	vector<string> zipfilelist;
	if(UnCompressing(zipfilepath, zipfilelist) != 0)
	{
		WriteToLog("ERROR:解压失败");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:分析失败");
		}
		else
		{
			WriteToLog("DEBUG:分析成功");
		}
		return;
	}
	else
	{
		WriteToLog("DEBUG:解压开始");
	}
	vector<string> dirzipfilelist;
	for(int i=0;i<(int)zipfilelist.size();i++)
	{
		char zippath[1024]={0};
		strcpy(zippath, zipfilelist[i].c_str());
		if(UnCompressing(zippath, dirzipfilelist) != 0)
		{
			WriteToLog("ERROR:解压失败");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:分析失败");
			}
			else
			{
				WriteToLog("DEBUG:分析成功");
			}
			return;
		}
	}
	if(dirzipfilelist.size() == 0)
	{
		WriteToLog("DEBUG:解压成功");
	}
	//按照文件名称开始匹配，进行分析操作
	vector<string> orifileList;//定义一个存放结果文件名称的链表
	vector<string> newfilelist;	
	vector<string> checkfilepath;
	vector<string> searceshlist;
	char checkfilename[MAX_PATH] = {0};
	char newpath[MAX_PATH] = {0};  //解压缩的新文件目录
	if(zipfilelist.size() == 0)
	{
		WriteToLog("ERROR:解压目录文件为空");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:分析失败");
		}
		else
		{
			WriteToLog("DEBUG:分析成功");
		}
		return;
	}
	for(int i=0; i<(int)zipfilelist.size(); i++)
	{
		if(zipfilelist[i].find("new.zip", 0) != string::npos)
		{
			strncpy(newpath, zipfilelist[0].c_str(), strlen(zipfilelist[i].c_str())-strlen(".zip"));
			break;
		}
	}

	char oripath[MAX_PATH] = {0};  //解压缩的旧文件目录
	for(int i=0; i<(int)zipfilelist.size(); i++)
	{
		if(zipfilelist[i].find("old.zip", 0) != string::npos)
		{
			strncpy(oripath, zipfilelist[i].c_str(), strlen(zipfilelist[i].c_str())-strlen(".zip"));
			break;
		}
	}

	char checkpath[MAX_PATH] = {0};
	char outSHA1[MAX_PATH] = {0};
	char outSHA2[MAX_PATH] = {0};
	char Error[MAX_PATH] = {0};
	char newPath[MAX_PATH] = {0};
	char filename[MAX_PATH] = {0};
	//得到新下载目录下文件名称
	GetFileName(oripath, orifileList);
	GetFileName(newpath, newfilelist);

	strcpy(filename, orifileList[0].c_str());
	char *d = strrchr(filename, '\\');
	sprintf(checkfilename, "%s", d+1);
	char filesha1[MAX_PATH]={0};
	strcpy(filesha1, orifileList[0].c_str());
	//得到其中一个文件的hash值
	GetFileSHA1(filesha1, outSHA1, Error);
	if(strlen(Error) != 0)
	{
		WriteToLog("ERROR:GetFileHash1 error");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:分析失败");
		}
		else
		{
			WriteToLog("DEBUG:分析成功");
		}
		return;
	}

	
	strcpy(newPath, dcppath.c_str());
	//按照名字查找指定路径下的同名文件
	for(int j=0;j<(int)orifileList.size();j++)
	{
		char filename[MAX_PATH]={0};
		char filepathname[MAX_PATH]={0};
		strcpy(filepathname, orifileList[j].c_str());
		char *d = strrchr(filepathname, '\\');
		sprintf(filename, "%s", d+1);
		FindFile(filename, newPath, searceshlist);
	}
	if(searceshlist.size() == 0)
	{
		WriteToLog("ERROR:匹配查找的文件夹为空");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:分析失败");
		}
		else
		{
			WriteToLog("DEBUG:分析成功");
		}
		return;
	}
	for(int i=0;i < (int)orifileList.size();i++)
	{
		char outSHA3[MAX_PATH] = {0};
		char outSHA4[MAX_PATH] = {0};
		char filepathname[MAX_PATH]={0};
		strcpy(filepathname, orifileList[i].c_str());
		GetFileSHA1(filepathname, outSHA3, Error);
		if(strlen(Error) != 0)
		{
			WriteToLog("ERROR:GetFileHash3 error");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:分析失败");
			}
			else
			{
				WriteToLog("DEBUG:分析成功");
			}
			return;
		}
		char searech[MAX_PATH]={0};
		strcpy(searech, searceshlist[i].c_str());
		GetFileSHA1(searech, outSHA4, Error);
		if(strlen(Error) != 0)
		{
			WriteToLog("ERROR:GetFileHash4 error");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:分析失败");
			}
			else
			{
				WriteToLog("DEBUG:分析成功");
			}
			return;
		}
		if(strcmp(outSHA3, outSHA4) != 0)
		{
			WriteToLog("ERROR:文件hash值匹配失败");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:分析失败");
			}
			else
			{
				WriteToLog("DEBUG:分析成功");
			}
			return;
		}
		else
		{
			WriteToLog("DEBUG:文件hash值匹配成功");
		}
	}
	for(int i=0;i < (int)newfilelist.size();i++)
	{
		char l[MAX_PATH]= {0};
		strcpy(l, newfilelist[i].c_str());
		char searech[MAX_PATH]={0};
		strcpy(searech, searceshlist[i].c_str());
		if(CopyFile(l, searech, FALSE) == 0)
		{
			WriteToLog("ERROR:文件覆盖失败");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:分析失败");
			}
			else
			{
				WriteToLog("DEBUG:分析成功");
			}
			return;
		}
		else
		{
			WriteToLog("DEBUG:文件覆盖成功");
		}
	}
	
	int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateOK",asreportId,result);
	if(code != 0)
	{
		WriteToLog("ERROR:分析失败");
	}
	else
	{
		WriteToLog("DEBUG:分析成功");
	}
	WriteToLog("DEBUG:文件分析完成");		
	return;
}

/*上报按钮功能实现
*root：JS反馈的报文信息
*zipdlpathname：下载路径
*/
void RestoreConfigFile(Json::Value &root, char *zipdlpathname, SOCKET sockClient)
{
	WriteToLog("DEBUG:上报按钮开始");
	//初始化上报状态函数
	string username=root["username"].asString();
	string dcpuuid=root["dcpuuid"].asString();
	string yun_addr=root["yun_addr"].asString();
	string url;
	url.assign(yun_addr).append("/slice/asreport/reportNotice.shtml");
	cout <<  url << endl;
	string asreportId= root["asreportid"].asString();
	string result;
	CStateReport sr(url);
	

	//自动匹配盘符
	int DSLength = GetLogicalDriveStrings(0,NULL);  
    //通过GetLogicalDriveStrings()函数获取所有驱动器字符串信息长度。  
    char* DStr = new char[DSLength];//用获取的长度在堆区创建一个c风格的字符串数组  
    GetLogicalDriveStrings(DSLength,(LPTSTR)DStr);  
    //通过GetLogicalDriveStrings将字符串信息复制到堆区数组中,其中保存了所有驱动器的信息。  
    int si=0; 
	vector<string> drivename;
    for(int i=0;i<DSLength/4;++i)  
        //为了显示每个驱动器的状态，则通过循环输出实现，由于DStr内部保存的数据是A:\NULLB:\NULLC:\NULL，这样的信息，所以DSLength/4可以获得具体大循环范围  
    {  
        char dir[4]={DStr[si],':','\\',0};    
        si+=4; 
		drivename.push_back(dir);
    }
	if(DStr)
	{
		delete[] DStr;
		DStr = NULL;
	}
	string dcppath=root["dcppath"].asString();
	WebSocket web;
	for(int i=(int)(drivename.size()-1);;i--)
	{
		if(i == 0)
		{
			WriteToLog("ERROR:未匹配到指定盘符");
			Json::Value root;
			root["code"] = Json::Value(1001);
			string s=root.toStyledString();
			char a[4096]= {0};
			strcpy(a, s.c_str());
			byte test[2048] = {0};
			memcpy(test, a, strlen(a));
			web.respondClient(sockClient, test, (int)strlen(a), true);
			return;
		}
		if(_stricmp(drivename[i].c_str(), zipdlpathname) == 0 ||_stricmp(drivename[i].c_str(), "C:\\") == 0)
		{
			continue;
		}
		string s;
		s.assign(drivename[i].append(dcppath));
		WIN32_FIND_DATA FindFileData; 
		HANDLE hFind=::FindFirstFile(s.append("\\*").c_str() ,&FindFileData);  
		if(INVALID_HANDLE_VALUE != hFind)
		{
			dcppath.assign(drivename[i]);
			FindClose(hFind);
			break;
		}
	}


	Json::Value root;
	root["code"] = Json::Value(1000);
	string s=root.toStyledString();
	char a[4096]= {0};
	strcpy(a, s.c_str());
	byte test[2048] = {0};
	memcpy(test, a, strlen(a));
	web.respondClient(sockClient, test, (int)strlen(a), true);

	
	//按照文件名称开始匹配，进行分析操作
	vector<string> orifileList;  //定义一个存放结果文件名称的链表
	vector<string> newfilelist;	
	vector<string> checkfilepath;
	vector<string> searceshlist;
	char checkfilename[MAX_PATH] = {0};
	char newpath[MAX_PATH] = {0};  //解压缩的新文件目录
	string NewPath;
	NewPath.assign(zipdlpathname).append(dcpuuid);
	char zippath[MAX_PATH]={0};
	strcpy(zippath, NewPath.c_str());
	vector<string> zipfilelist;
	GetFileName(zippath, zipfilelist);
	if(zipfilelist.size() == 0)
	{
		WriteToLog("ERROR:解压目录文件为空");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:上报失败");
		}
		else
		{
			WriteToLog("DEBUG:上报成功");
		}
		return;
	}
	for(int i=0;i<(int)zipfilelist.size();i++)
	{
		if(zipfilelist[i].find("new.zip", 0) != string::npos)
		{
			NewPath.assign(zipfilelist[i]);
			break;
		}
	}
	strncpy(newpath, NewPath.c_str(), strlen(NewPath.c_str())-strlen(".zip"));
	char oripath[MAX_PATH] = {0};  //解压缩的旧文件目录
	string OldPath;
	for(int i=0;i<(int)zipfilelist.size();i++)
	{
		if(zipfilelist[i].find("old.zip", 0) != string::npos)
		{
			OldPath.assign(zipfilelist[i]);
			break;
		}
	}
	strncpy(oripath, OldPath.c_str(), strlen(OldPath.c_str())-strlen(".zip"));
	char checkpath[MAX_PATH] = {0};
	char outSHA1[MAX_PATH] = {0};
	char outSHA2[MAX_PATH] = {0};
	char Error[MAX_PATH] = {0};
	char newPath[MAX_PATH] = {0};
	char filename[MAX_PATH] = {0};

	//得到新下载目录下文件名称
	GetFileName(oripath, orifileList);
	GetFileName(newpath, newfilelist);
	strcpy(filename, newfilelist[0].c_str());
	char *d = strrchr(filename, '\\');
	sprintf(checkfilename, "%s", d+1);
	char filesha1[MAX_PATH]={0};
	strcpy(filesha1, orifileList[0].c_str());
	//得到其中一个文件的hash值
	GetFileSHA1(filesha1, outSHA1, Error);
	if(strlen(Error) != 0)
	{
		WriteToLog("ERROR:GET outSHA1 error");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:上报失败");
		}
		else
		{
			WriteToLog("DEBUG:上报成功");
		}
		return;
	}

	
	strcpy(newPath, dcppath.c_str());


	for(int j=0;j<(int)newfilelist.size();j++)
	{
		char filename[MAX_PATH]={0};
		char filepathname[MAX_PATH]={0};
		strcpy(filepathname, newfilelist[j].c_str());
		char *d = strrchr(filepathname, '\\');
		sprintf(filename, "%s", d+1);
		FindFile(filename, newPath, searceshlist);
	}
	if(searceshlist.size() == 0)
	{
		WriteToLog("ERROR:搜索文件搜索失败");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:上报失败");
		}
		else
		{
			WriteToLog("DEBUG:上报成功");
		}
		return;
	}
	for(int i=0;i < (int)newfilelist.size();i++)
	{
		char outSHA3[MAX_PATH] = {0};
		char outSHA4[MAX_PATH] = {0};
		char filepathname[MAX_PATH]={0};
		strcpy(filepathname, newfilelist[i].c_str());
		GetFileSHA1(filepathname, outSHA3, Error);
		if(strlen(Error) != 0)
		{
			WriteToLog("ERROR:GetFileHash3 error");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:上报失败");
			}
			else
			{
				WriteToLog("DEBUG:上报成功");
			}
			return;
		}
		char searech[MAX_PATH]={0};
		strcpy(searech, searceshlist[i].c_str());
		GetFileSHA1(searech, outSHA4, Error);
		if(strlen(Error) != 0)
		{
			WriteToLog("ERROR:GetFileHash4 error");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:上报失败");
			}
			else
			{
				WriteToLog("DEBUG:上报成功");
			}
			return;
		}
		if(strcmp(outSHA3, outSHA4) != 0)
		{
			WriteToLog("ERROR:文件hash值匹配失败");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:上报失败");
			}
			else
			{
				WriteToLog("DEBUG:上报成功");
			}
			return;
		}
		else
		{
			WriteToLog("DEBUG:文件hash值匹配成功");
		}
	}
	for(int i=0;i < (int)orifileList.size();i++)
	{
		char l[MAX_PATH]= {0};
		strcpy(l, orifileList[i].c_str());
		char searech[MAX_PATH]={0};
		strcpy(searech, searceshlist[i].c_str());
		if(CopyFile(l, searech, FALSE) == 0)
		{
			WriteToLog("ERROR:覆盖失败");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:上报失败");
			}
			else
			{
				WriteToLog("DEBUG:上报成功");
			}
			return;
		}
		else
		{
			WriteToLog("DEBUG:覆盖成功");
		}
	}
	int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreOK",asreportId,result);
	if(code != 0)
	{
		WriteToLog("ERROR:上报失败");
	}
	else
	{
		WriteToLog("DEBUG:上报成功");
		DeleteFile(zippath);
	}


	WriteToLog("DEBUG:上报按钮结束");
	return;
}

/*LOG日志，附带时间
*str:写入LOG日志的信息
*/
int WriteToLog(char* str)  
{
	char s[1024]={0};
	GetModuleFileName(NULL, s, 1024);
	char *p = strrchr(s, '\\');
	char b[1024]={0};
	strncpy(b, s, strlen(s)-strlen(p+1));
	strcat(b, "log.txt");
	FILE* pfile;  
	fopen_s(&pfile, b, "a+");  
	if (pfile==NULL)  
	{  
		return -1;  
	}
	time_t t; 
	time(&t);
	fprintf_s(pfile,"%s %s\n",str, ctime(&t));
	fclose(pfile);  
	return 0;  
}

/*读取配置信息
*path:配置文件指定路径
*/
string ConfigFileRead(string &path) 
{
    ifstream configFile;
    configFile.open(path.c_str());
	if(!configFile)
	{
		WriteToLog("ERROR;配置文件读取失败");
		return NULL;
	}
    string strLine;
    string filepath;
    if(configFile.is_open())
    {
        while (!configFile.eof())
        {
            getline(configFile, strLine);
			if(strLine[0] == '#')
			{
				continue;
			}
            size_t pos = strLine.find('=');
            string key = strLine.substr(0, pos);
                    
            if(key == "filepath")
            {
                filepath = strLine.substr(pos + 1);            
            }            
        }
    }
	configFile.close();
    return filepath;
}

/*循环创建目录
*dir:指定目录
*/
void CreateDir(string &dir)
{
	if(_access(dir.c_str(),0) != -1)
	{
		WriteToLog("目录已经存在");
		return;
	}
    int m = 0, n;
    string str1, str2;
    
    str1 = dir;
    str2 = str1.substr( 0, 2 );
    str1 = str1.substr( 3, str1.size() );
    
    while( m >= 0 )
    {
        m = (int)str1.find('\\');
    
        str2 += '\\' + str1.substr( 0, m );    
        n = _access( str2.c_str(), 0 ); //判断该目录是否存在
        if( n == -1 )
        {
            _mkdir( str2.c_str() );     //创建目录
        }
        str1 = str1.substr( m+1, str1.size() );
    }
	return;
}

/*遍历删除文件
*lpPath:要删除的文件路径
*/
void DeleteFile(char* lpPath)  
{  
	  
	WIN32_FIND_DATA FindFileData;  
	string path;
	

	HANDLE hFind=::FindFirstFile(path.assign(lpPath).append("\\*").c_str() ,&FindFileData);  
   if(INVALID_HANDLE_VALUE == hFind)    return;  
   while(true)  
   {  
        if(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)  
        {  
            if(FindFileData.cFileName[0]!='.')  
            {  
                char szFile[MAX_PATH];  
                strcpy(szFile,lpPath);  
                strcat(szFile,"\\");  
                strcat(szFile,(char* )(FindFileData.cFileName));
                DeleteFile(szFile);
				_rmdir(szFile);
            }  
        }  
        else  
        {  
			string s;
			s.assign(lpPath).append("\\").append(FindFileData.cFileName);
			remove(s.c_str());
        }  
        if(!FindNextFile(hFind,&FindFileData))    break;  
   }  
   FindClose(hFind);
   char zipdelpath[1024]={0};
   strcpy(zipdelpath, lpPath);
   strcat(lpPath, "\\");
   _rmdir(lpPath);
   strcat(zipdelpath, ".zip");
   remove(zipdelpath);
   return;
}
