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

/*��ѹ���������ڲ��������ѹ����������ѹ�����ľݶ�·��
*Unzfilepath��Ҫ��ѹ����ѹ����
*zipfilelist�������ڲ�ѹ��������·��������
*/
int UnCompressing(char *Unzfilepath, vector<string> &zipfilelist)
{
	//��ȡ��Ҫ�������ļ��е�����
	char *dev = strstr(Unzfilepath, ".zip");
	char dirpathname[1024]={0};
	int dlength = (int)(strlen(Unzfilepath)-strlen(dev));
	strncpy(dirpathname, Unzfilepath, dlength);
	//����Ŀ¼
	if(_access(dirpathname, 0) == -1)
	{
		int error = CreateDirectory(dirpathname, NULL);
		if(error == 0)
		{
			WriteToLog("DEBUG:����Ŀ¼ʧ��");
			WriteToLog("DEBUG:Ŀ¼�Ѿ�����");
		}
	}
	unzFile zFile;  
	zFile = unzOpen64(Unzfilepath);  
	if (zFile == NULL)  
	{  
		WriteToLog("ERROR;�ļ���ʧ��");  
		return -1;  
	}  
	unz_global_info64 zGlobalInfo;
	if (UNZ_OK != unzGetGlobalInfo64(zFile, &zGlobalInfo))  
	{  
	    // ������  
	    WriteToLog("ERROR:�õ�ȫ����Ϣ����");  
	    return -1;  
	} 
	unz_file_info64 *pfileinfo = new unz_file_info64[zGlobalInfo.number_entry];  
	unsigned int num = 512;  
	char *fileName = new char[num];
	memset(fileName,0, num);
	
	vector<string> vecfilename;
	for (int i = 0; i < zGlobalInfo.number_entry; i++)  
	{ 
	    // ���������ļ�  ��ȡ�����Ĺ��ܣ��ǻ�ȡѹ�����ڵ�ǰ�����ļ���Ϣ
	    if (UNZ_OK != unzGetCurrentFileInfo64(zFile, &pfileinfo[i], fileName, num, NULL, 0, NULL, 0))  
	    {  
	        //��������Ϣ  
	        WriteToLog("ERROR:�õ���ǰ�ļ���Ϣ����");
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
		//�򿪵�ǰ�ļ�
		if (UNZ_OK != unzLocateFile(zFile, file.c_str(), 0))
		{
			//��������Ϣ  
			WriteToLog("ERROR:unzLocateFile�ļ�ʧ�ܣ�");
			return -1;
		}

		if (UNZ_OK != unzOpenCurrentFile(zFile))  
		{  
			//��������Ϣ  
			WriteToLog("ERROR:unzOpenCurrentFileʧ��");
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
	
		//��ѹ���ļ� ��ȡ��ǰ�ļ���Ϣ 
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
					WriteToLog("DEBUG:����Ŀ¼ʧ��");
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
			WriteToLog("ERROR:�ļ���ʧ��");
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

/*ƴ�ӻ��״̬��JSON�ַ���
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


/*��ȡ�ļ���SHA1ֵ��������������򽫴�����Ϣд��outError
* FileNameInPut:�ļ�·��
* outSHA1:SHA1�������
* outError:������Ϣ�������
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

/*�����ƶ�·���µ������ļ��������������ֱ�ӷ���
*lpPath��ָ���ļ�·��
*filelist������ļ����Ƶ�����
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

/*�����ƶ�·���µ������ļ���������ͬ�ļ��������ؾ���·������������ֱ�ӷ���
*filename����Ҫ���ҵ��ļ���
*filepath����Ҫ���ҵ��ļ�·��
*filepathList������ļ����Ƶ�����
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
/*�ظ���������
*sockClient���˿ں�
*request���ظ������ְ���Ϣ
*/
void WebSocket::respondInfo(SOCKET sockClient, char * request){
	send(sockClient, request, (int)(strlen(request)), 0);
}


/*��ʼ���˿ںͽ����߳�����
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
		WriteToLog("DEBUG:�����Ѿ�����");
	}
	else
	{
		WriteToLog("ERROR:����δ����");
		return;
	}
	SOCKET sersocket = socket(AF_INET, SOCK_STREAM, 0);

	SOCKADDR_IN addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);      //ip��ַ
	addr.sin_port = htons(8899);                        //�󶨶˿�
	if(bind(sersocket, (SOCKADDR*)&addr, sizeof(SOCKADDR)) != 0)//�����
	{
		WriteToLog("ERROR:��ʧ��");
		return;
	}
	listen(sersocket, 10);                              //���еڶ������������ܹ����յ�����������

	SOCKADDR_IN clientsocket;
	int len = sizeof(SOCKADDR);

	_DATA socketclient;

	while (true){
		SOCKET serConn = accept(sersocket, (SOCKADDR*)&clientsocket, &len);
		WriteToLog("DEBUG:�ͻ�������");
		unsigned threadid={0};
		socketclient.sfd = serConn;
		//����������һ���߳�������Э��
		HANDLE hThread1 = (HANDLE)_beginthreadex(NULL,0,WorkThread, &socketclient,0,&threadid);
		//HANDLE hThread1 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkThread, (LPVOID)serConn, 0, 0);
		if (hThread1 != NULL)
		{
			CloseHandle(hThread1);
		}

	}
}

/*��ȡkey��Э��
*sockClient���˿ں�
*request��ƴ�ӵ����ְ�
*/
void WebSocket::requestInfo(SOCKET sockClient, char * request){
	char recev[1024] = {0};
	recv(sockClient, recev, 2048, 0);
	string s = recev;
	int i = (int)(s.find("Sec-WebSocket-Key"));
	s = s.substr(i + 19, 24);
	//������Ϊ�˵õ��ͻ���������Ϣ��key������key�����ÿ���ȥ�˽�����Э��
	//�����Ƿ�����ƴ��Э�鷵�ظ��ͻ���
	getKey(request,s);
}

/*Э��
������̾����õ��ͻ��˵�keyȻ�󾭹�sha���ܣ���ƴ�ӷ��ص�Э�鷢���ͻ���
*request��ƴ�ӵ����ְ�
*clientkey���ͻ��˵�key
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

/*����JS����������
*inClientData:���ܵ�������
*outClientData:�����������
*sockClient:�˿ں�
*/
char * WebSocket::parsedata(char *inClientData, char *outClientData, SOCKET sockClient)
{
	int point = 0;            //�ֽ�ָ��λ��
	int tmppoint = 0;         //��ʱָ�����
	/*����b�ֽ������ǿͻ��˵�������Ϣ����Ҫע��point���ָ��ı仯��������Ҫȥ�������Э�飬Э����ÿ���ֽ����������ʲô��Ϣ��Ҫ��    ����������*/
	byte b[4096] = "";
	//תΪ�ֽ�������
	memcpy(b, inClientData, 2048);
	//ȡ��һ���ֽ�
	int first = b[point] & 0xFF;
	
	byte opCode = (byte)(first & 0x0F);             //0000 1111 ����λΪopCode 00001111
	if (opCode == 8){
		closesocket(sockClient);
	}
	//ȡ�ڶ����ֽ�
	first = b[++point];
	//���س���
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
		tmppoint = ++point;     //������ʱָ��
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

	//��126��127�û���
	else if ((payloadLength != 126) || (payloadLength != 127)){
		point = 1;              
	}

	
	//�������ֽڣ�����
	byte mask[4] = "";
	tmppoint = ++point;
	//��Ϊ������һ�Σ�������Ҫ����
	point = --point; 
	//ȡ����ֵ
	for (int i = 0; i < 4; i++){
		mask[i] = b[tmppoint + i];
		point++;
		
	}
	byte changeb[4096] = {0};

	//���ݵĳ��ȱ�����ѭ�������Ѿ����ı�
	int length = payloadLength;
	int readThisFragment = 1;

	//ͨ�����������ʵ������
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

/*�߳�����
*lpParam:ָ��洢�˿ڵĽṹ��
*/
unsigned __stdcall WorkThread(LPVOID lpParam)
{
	_pDATA sockclient = (_pDATA)lpParam;
	SOCKET sockClient= sockclient->sfd;
	char request[1024] = {0};  //������Ϣ
	char clieninfo[2048]= {0}; //���ֺ���Ӧ��Ϣ
	int len = 0;              //���صĳ���

	WebSocket web;
	//����Э��
	web.requestInfo(sockClient, request);
	web.respondInfo(sockClient, request);
	//����������Э��
	//����Э�������Ҳ���Ƿ��񷵻ظ��ͻ��˺󣬿ͻ�����һ�η���
	//���ݸ���������������ǽ����ͻ��˵ķ�������
	//������ȫ����ȡ����

	len=recv(sockClient, clieninfo, 2048, 0);
	//���ܴ���
	if(len < 0)
	{
		WriteToLog("ERROR:�����쳣�Ͽ�");
		closesocket(sockClient);
		_endthreadex(0);
		return -1;
	}
	//��������
	if (len>0)
	{
		//������ܵĿͻ��˵�����
		char charb[4096] = {0};
		web.parsedata(clieninfo, charb, sockClient);
		string s = charb;

		//json���Ĵ���
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
				WriteToLog("ERROR:δƥ�䵽�Ĳ���");
			}
		}
	}
	closesocket(sockClient);
	_endthreadex(0);
	return 0;
}

/*�ظ��ͻ�����Ϣ
*sockClient:���Ӷ˿ں�
*charb��Ҫ�ָ�����Ϣ
*length����Ϣ����
*finalFragment�����λ
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
	//cout <<"���鳤��:\n"<< length << endl;
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
		//���ݳ��ȳ���65536
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

/*������ťʵ��
*root��JS�����ı�����Ϣ
*zipdlpathname������·��
*/
void UpdateConfigFile(Json::Value &root, char *zipdlpathname, SOCKET sockClient)
{
	WriteToLog("DEBUG:�ļ�������ʼ");
	//��ʼ���ϱ�����
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

	//��ƥ���̷�
	int DSLength = GetLogicalDriveStrings(0,NULL);  
    //ͨ��GetLogicalDriveStrings()������ȡ�����������ַ�����Ϣ���ȡ�  
    char* DStr = new char[DSLength];//�û�ȡ�ĳ����ڶ�������һ��c�����ַ�������  
    GetLogicalDriveStrings(DSLength,(LPTSTR)DStr);  
    //ͨ��GetLogicalDriveStrings���ַ�����Ϣ���Ƶ�����������,���б�������������������Ϣ��  
    int si=0; 
	vector<string> drivename;
    for(int i=0;i<DSLength/4;++i)  
        //Ϊ����ʾÿ����������״̬����ͨ��ѭ�����ʵ�֣�����DStr�ڲ������������A:\NULLB:\NULLC:\NULL����������Ϣ������DSLength/4���Ի�þ����ѭ����Χ  
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
			WriteToLog("ERROR:δƥ�䵽ָ���̷�");
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
	
	//����ƥ�䵽�̷������ظ�ǰ��code:1000
	Json::Value root;
	root["code"] = Json::Value(1000);
	string s=root.toStyledString();
	char a[4096]= {0};
	strcpy(a, s.c_str());
	byte test[2048] = {0};
	memcpy(test, a, strlen(a));
	web.respondClient(sockClient, test, (int)strlen(a), true);

	//�õ�����·����������UUID�����ذ�����
	string dirdcpuuid;
	dirdcpuuid.assign(zipdlpathname).append(dcpuuid).append(".zip");
	char zipfilepath[MAX_PATH] = {0};
	strcpy(zipfilepath, dirdcpuuid.c_str());
	char download[MAX_PATH]={0};
	strcpy(download, downloadurl.c_str());
	HRESULT hr = URLDownloadToFile(0, download, zipfilepath, 0, NULL);
	if(hr == S_OK)
	{
		WriteToLog("DEBUG:�������");
	}
	else
	{
			WriteToLog("ERROR:����ʧ��");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:����ʧ��");
			}
			else
			{
				WriteToLog("DEBUG:�����ɹ�");
			}
			return;
	}
	//��ʼ��ѹѹ����
	vector<string> zipfilelist;
	if(UnCompressing(zipfilepath, zipfilelist) != 0)
	{
		WriteToLog("ERROR:��ѹʧ��");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:����ʧ��");
		}
		else
		{
			WriteToLog("DEBUG:�����ɹ�");
		}
		return;
	}
	else
	{
		WriteToLog("DEBUG:��ѹ��ʼ");
	}
	vector<string> dirzipfilelist;
	for(int i=0;i<(int)zipfilelist.size();i++)
	{
		char zippath[1024]={0};
		strcpy(zippath, zipfilelist[i].c_str());
		if(UnCompressing(zippath, dirzipfilelist) != 0)
		{
			WriteToLog("ERROR:��ѹʧ��");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:����ʧ��");
			}
			else
			{
				WriteToLog("DEBUG:�����ɹ�");
			}
			return;
		}
	}
	if(dirzipfilelist.size() == 0)
	{
		WriteToLog("DEBUG:��ѹ�ɹ�");
	}
	//�����ļ����ƿ�ʼƥ�䣬���з�������
	vector<string> orifileList;//����һ����Ž���ļ����Ƶ�����
	vector<string> newfilelist;	
	vector<string> checkfilepath;
	vector<string> searceshlist;
	char checkfilename[MAX_PATH] = {0};
	char newpath[MAX_PATH] = {0};  //��ѹ�������ļ�Ŀ¼
	if(zipfilelist.size() == 0)
	{
		WriteToLog("ERROR:��ѹĿ¼�ļ�Ϊ��");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:����ʧ��");
		}
		else
		{
			WriteToLog("DEBUG:�����ɹ�");
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

	char oripath[MAX_PATH] = {0};  //��ѹ���ľ��ļ�Ŀ¼
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
	//�õ�������Ŀ¼���ļ�����
	GetFileName(oripath, orifileList);
	GetFileName(newpath, newfilelist);

	strcpy(filename, orifileList[0].c_str());
	char *d = strrchr(filename, '\\');
	sprintf(checkfilename, "%s", d+1);
	char filesha1[MAX_PATH]={0};
	strcpy(filesha1, orifileList[0].c_str());
	//�õ�����һ���ļ���hashֵ
	GetFileSHA1(filesha1, outSHA1, Error);
	if(strlen(Error) != 0)
	{
		WriteToLog("ERROR:GetFileHash1 error");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:����ʧ��");
		}
		else
		{
			WriteToLog("DEBUG:�����ɹ�");
		}
		return;
	}

	
	strcpy(newPath, dcppath.c_str());
	//�������ֲ���ָ��·���µ�ͬ���ļ�
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
		WriteToLog("ERROR:ƥ����ҵ��ļ���Ϊ��");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:����ʧ��");
		}
		else
		{
			WriteToLog("DEBUG:�����ɹ�");
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
				WriteToLog("ERROR:����ʧ��");
			}
			else
			{
				WriteToLog("DEBUG:�����ɹ�");
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
				WriteToLog("ERROR:����ʧ��");
			}
			else
			{
				WriteToLog("DEBUG:�����ɹ�");
			}
			return;
		}
		if(strcmp(outSHA3, outSHA4) != 0)
		{
			WriteToLog("ERROR:�ļ�hashֵƥ��ʧ��");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:����ʧ��");
			}
			else
			{
				WriteToLog("DEBUG:�����ɹ�");
			}
			return;
		}
		else
		{
			WriteToLog("DEBUG:�ļ�hashֵƥ��ɹ�");
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
			WriteToLog("ERROR:�ļ�����ʧ��");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:����ʧ��");
			}
			else
			{
				WriteToLog("DEBUG:�����ɹ�");
			}
			return;
		}
		else
		{
			WriteToLog("DEBUG:�ļ����ǳɹ�");
		}
	}
	
	int code = sr.report_status_to_server(username,dcpuuid,"Report-UpdateOK",asreportId,result);
	if(code != 0)
	{
		WriteToLog("ERROR:����ʧ��");
	}
	else
	{
		WriteToLog("DEBUG:�����ɹ�");
	}
	WriteToLog("DEBUG:�ļ��������");		
	return;
}

/*�ϱ���ť����ʵ��
*root��JS�����ı�����Ϣ
*zipdlpathname������·��
*/
void RestoreConfigFile(Json::Value &root, char *zipdlpathname, SOCKET sockClient)
{
	WriteToLog("DEBUG:�ϱ���ť��ʼ");
	//��ʼ���ϱ�״̬����
	string username=root["username"].asString();
	string dcpuuid=root["dcpuuid"].asString();
	string yun_addr=root["yun_addr"].asString();
	string url;
	url.assign(yun_addr).append("/slice/asreport/reportNotice.shtml");
	cout <<  url << endl;
	string asreportId= root["asreportid"].asString();
	string result;
	CStateReport sr(url);
	

	//�Զ�ƥ���̷�
	int DSLength = GetLogicalDriveStrings(0,NULL);  
    //ͨ��GetLogicalDriveStrings()������ȡ�����������ַ�����Ϣ���ȡ�  
    char* DStr = new char[DSLength];//�û�ȡ�ĳ����ڶ�������һ��c�����ַ�������  
    GetLogicalDriveStrings(DSLength,(LPTSTR)DStr);  
    //ͨ��GetLogicalDriveStrings���ַ�����Ϣ���Ƶ�����������,���б�������������������Ϣ��  
    int si=0; 
	vector<string> drivename;
    for(int i=0;i<DSLength/4;++i)  
        //Ϊ����ʾÿ����������״̬����ͨ��ѭ�����ʵ�֣�����DStr�ڲ������������A:\NULLB:\NULLC:\NULL����������Ϣ������DSLength/4���Ի�þ����ѭ����Χ  
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
			WriteToLog("ERROR:δƥ�䵽ָ���̷�");
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

	
	//�����ļ����ƿ�ʼƥ�䣬���з�������
	vector<string> orifileList;  //����һ����Ž���ļ����Ƶ�����
	vector<string> newfilelist;	
	vector<string> checkfilepath;
	vector<string> searceshlist;
	char checkfilename[MAX_PATH] = {0};
	char newpath[MAX_PATH] = {0};  //��ѹ�������ļ�Ŀ¼
	string NewPath;
	NewPath.assign(zipdlpathname).append(dcpuuid);
	char zippath[MAX_PATH]={0};
	strcpy(zippath, NewPath.c_str());
	vector<string> zipfilelist;
	GetFileName(zippath, zipfilelist);
	if(zipfilelist.size() == 0)
	{
		WriteToLog("ERROR:��ѹĿ¼�ļ�Ϊ��");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:�ϱ�ʧ��");
		}
		else
		{
			WriteToLog("DEBUG:�ϱ��ɹ�");
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
	char oripath[MAX_PATH] = {0};  //��ѹ���ľ��ļ�Ŀ¼
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

	//�õ�������Ŀ¼���ļ�����
	GetFileName(oripath, orifileList);
	GetFileName(newpath, newfilelist);
	strcpy(filename, newfilelist[0].c_str());
	char *d = strrchr(filename, '\\');
	sprintf(checkfilename, "%s", d+1);
	char filesha1[MAX_PATH]={0};
	strcpy(filesha1, orifileList[0].c_str());
	//�õ�����һ���ļ���hashֵ
	GetFileSHA1(filesha1, outSHA1, Error);
	if(strlen(Error) != 0)
	{
		WriteToLog("ERROR:GET outSHA1 error");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:�ϱ�ʧ��");
		}
		else
		{
			WriteToLog("DEBUG:�ϱ��ɹ�");
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
		WriteToLog("ERROR:�����ļ�����ʧ��");
		int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreFailed",asreportId,result);
		if(code != 0)
		{
			WriteToLog("ERROR:�ϱ�ʧ��");
		}
		else
		{
			WriteToLog("DEBUG:�ϱ��ɹ�");
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
				WriteToLog("ERROR:�ϱ�ʧ��");
			}
			else
			{
				WriteToLog("DEBUG:�ϱ��ɹ�");
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
				WriteToLog("ERROR:�ϱ�ʧ��");
			}
			else
			{
				WriteToLog("DEBUG:�ϱ��ɹ�");
			}
			return;
		}
		if(strcmp(outSHA3, outSHA4) != 0)
		{
			WriteToLog("ERROR:�ļ�hashֵƥ��ʧ��");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:�ϱ�ʧ��");
			}
			else
			{
				WriteToLog("DEBUG:�ϱ��ɹ�");
			}
			return;
		}
		else
		{
			WriteToLog("DEBUG:�ļ�hashֵƥ��ɹ�");
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
			WriteToLog("ERROR:����ʧ��");
			int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreFailed",asreportId,result);
			if(code != 0)
			{
				WriteToLog("ERROR:�ϱ�ʧ��");
			}
			else
			{
				WriteToLog("DEBUG:�ϱ��ɹ�");
			}
			return;
		}
		else
		{
			WriteToLog("DEBUG:���ǳɹ�");
		}
	}
	int code = sr.report_status_to_server(username,dcpuuid,"Report-RestoreOK",asreportId,result);
	if(code != 0)
	{
		WriteToLog("ERROR:�ϱ�ʧ��");
	}
	else
	{
		WriteToLog("DEBUG:�ϱ��ɹ�");
		DeleteFile(zippath);
	}


	WriteToLog("DEBUG:�ϱ���ť����");
	return;
}

/*LOG��־������ʱ��
*str:д��LOG��־����Ϣ
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

/*��ȡ������Ϣ
*path:�����ļ�ָ��·��
*/
string ConfigFileRead(string &path) 
{
    ifstream configFile;
    configFile.open(path.c_str());
	if(!configFile)
	{
		WriteToLog("ERROR;�����ļ���ȡʧ��");
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

/*ѭ������Ŀ¼
*dir:ָ��Ŀ¼
*/
void CreateDir(string &dir)
{
	if(_access(dir.c_str(),0) != -1)
	{
		WriteToLog("Ŀ¼�Ѿ�����");
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
        n = _access( str2.c_str(), 0 ); //�жϸ�Ŀ¼�Ƿ����
        if( n == -1 )
        {
            _mkdir( str2.c_str() );     //����Ŀ¼
        }
        str1 = str1.substr( m+1, str1.size() );
    }
	return;
}

/*����ɾ���ļ�
*lpPath:Ҫɾ�����ļ�·��
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
