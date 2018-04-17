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
//   函数名：stat2json :将状态转换成json格式
//   --------------------------------------------------------
//   返回值：json
//   参数：
//   @dcpuuid:处理dcp的uuid
//   @username:用户名
//   @stat:状态字,参考协议
//   --------------------------------------------------------
//   创建：                   修改：             姓名：
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
//   函数名：report_status_to_server :报告分析和上报的状态
//   --------------------------------------------------------
//   返回值：返回状态 0：成功，-1：异常
//   参数：
//   @server_url:云平台的url
//   @username:影院用户名
//   @dcpuuid:处理dcp的uuid
//   @status:状态字,参考协议
//   @result：异常描述
//   --------------------------------------------------------
//   创建：                   修改：             姓名：
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
		
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, stat_str.c_str()); // 指定post内容
		curl_easy_setopt(curl, CURLOPT_URL, m_server_url.c_str());    // 指定url
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CStateReport::downloadCallback); 
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &respones);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER,header);

		
	
		res = curl_easy_perform(curl);
		printf("res:%s\n",respones.c_str());
		Json::Reader reader;
		Json::Value root;
		// reader将Json字符串解析到root，root将包含Json里所有子元素  
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
			// reader将Json字符串解析到root，root将包含Json里所有子元素  
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