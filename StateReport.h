#pragma once
#include <string>
#include <stdio.h>

class CStateReport
{
public:

	CStateReport(std::string &server_url);
	~CStateReport();

public:
	int report_status_to_server(std::string username,std::string dcpuuid,
		std::string stat,std::string asreportid,std::string &result );
	static size_t downloadCallback(void *buffer, size_t sz, size_t nmemb, void *writer) ;
private:
	std::string stat2json(std::string dcpuuid,std::string username,std::string stat,std::string asreportid);

	std::string  m_server_url;

	FILE *fp;
};
