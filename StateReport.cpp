#include "stdafx.h"
#include <curl/curl.h>
#include "dist\json\json.h"
#include <time.h>
#include "StateReport.h"

size_t CStateReport::downloadCallback(void *buffer, size_t sz, size_t nmemb, void *writer) 
{  
	std::string* psResponse = (std::string*) writer;  
	size_t size = sz * nmemb;  
	psResponse->append((char*) buffer, size);  

	return sz * nmemb;  
} 

CStateReport::CStateReport(std::string &server_url)
{
	m_server_url = server_url;
	fp = NULL;
}

CStateReport::~CStateReport()
{

}

//   -------------------------------------------------------
//   ��������stat2json :��״̬ת����json��ʽ
//   --------------------------------------------------------
//   ����ֵ��json
//   ������
//   @dcpuuid:����dcp��uuid
//   @username:�û���
//   @stat:״̬��,�ο�Э��
//   --------------------------------------------------------
//   ������                   �޸ģ�             ������
//   --------------------------------------------------------
std::string CStateReport::stat2json(std::string dcpuuid,std::string username,
	std::string stat,std::string asreportid)
{
	Json::FastWriter writeinfo;
	Json::Value writevalueinfo;

	time_t tm;
	time(&tm);
	char tmbuf[32]={'\0'};
	strftime(tmbuf,32,"%Y-%m-%d %H:%M:%S",localtime(&tm));

	writevalueinfo["version"] = 1;
	writevalueinfo["dateTime"] = tmbuf;
	writevalueinfo["username"] = username;
	writevalueinfo["dcpuuid"] = dcpuuid;
	writevalueinfo["status"] = stat;
	writevalueinfo["asreportid"] = asreportid;

	std::string json_txt = writeinfo.write(writevalueinfo);
	return json_txt;
}

//   -------------------------------------------------------
//   ��������report_status_to_server :����������ϱ���״̬
//   --------------------------------------------------------
//   ����ֵ������״̬ 0���ɹ���-1���쳣
//   ������
//   @server_url:��ƽ̨��url
//   @username:ӰԺ�û���
//   @dcpuuid:����dcp��uuid
//   @status:״̬��,�ο�Э��
//   @result���쳣����
//   --------------------------------------------------------
//   ������                   �޸ģ�             ������
//   --------------------------------------------------------
int CStateReport::report_status_to_server(std::string username,std::string dcpuuid,
	std::string stat,std::string asreportid,std::string &result)
{
	CURL *curl=NULL;
	CURLcode res;
	int code = -1;

	curl = curl_easy_init();
	std::string respones;
	
	if (curl )
	{
		std::string stat_str;
		struct curl_slist *header = NULL;
		stat_str = stat2json(dcpuuid,username,stat,asreportid);
		header = curl_slist_append(header,"Content-Type:application/json");
		
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, stat_str.c_str()); // ָ��post����
		curl_easy_setopt(curl, CURLOPT_URL, m_server_url.c_str());    // ָ��url
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CStateReport::downloadCallback); 
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &respones);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER,header);

		
	
		res = curl_easy_perform(curl);
		printf("res:%s\n",respones.c_str());
		Json::Reader reader;
		Json::Value root;
		// reader��Json�ַ���������root��root������Json��������Ԫ��  
		int len = respones.length();
		if (!reader.parse(respones.c_str(), respones.c_str() + len, root))
		{
			return -1;
		}

		code = atoi(root["code"].asString().c_str());
		result = root["result"].asString();
		std::string msg = root["message"].asString();
		/*std::size_t txt_len_pos = respones.find("Context-Length:");
		std::size_t pos = respones.find("\n\n");
		if(pos != std::string::npos && txt_len_pos != std::string::npos)
		{
			int length_end_pos = respones.find('\n',txt_len_pos);
			int content_length_txt_len = strlen("Context-Length:");
			int size = length_end_pos -  txt_len_pos - content_length_txt_len;
			int content_len = atoi(respones.substr(txt_len_pos + content_length_txt_len,size).c_str());
			std::string content = respones.substr(pos + 2,content_len);
			//printf("response content:%s\n",content.c_str());

			Json::Reader reader;
			Json::Value root;
			// reader��Json�ַ���������root��root������Json��������Ԫ��  
			int len = content.length();
			if (!reader.parse(content.c_str(), content.c_str() + len, root))
			{
				return false;
			}

			code = root["code"].asInt();
			result = root["result"].asString();
			std::string msg = root["message"].asString();

		}
		*/

		curl_slist_free_all(header); /* free the list again */
		curl_easy_cleanup(curl);
	}

	return code;
}