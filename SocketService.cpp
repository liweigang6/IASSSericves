// SocketService.cpp : �������̨Ӧ�ó������ڵ㡣
//
#pragma once
#include "stdafx.h"
#include "WebSocket.h"

 
SERVICE_STATUS servicestatus;  
SERVICE_STATUS_HANDLE hstatus; 
void WINAPI CtrlHandler(DWORD request); 

void WINAPI ServiceMain(int argc, char** argv)  
{  
    servicestatus.dwServiceType = SERVICE_WIN32;  
    servicestatus.dwCurrentState = SERVICE_START_PENDING;  
    servicestatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN|SERVICE_ACCEPT_STOP;//�ڱ�����ֻ����ϵͳ�ػ���ֹͣ�������ֿ�������  
    servicestatus.dwWin32ExitCode = 0;  
    servicestatus.dwServiceSpecificExitCode = 0;  
    servicestatus.dwCheckPoint = 0;  
    servicestatus.dwWaitHint = 0;  
	
    hstatus = ::RegisterServiceCtrlHandler("testservice", CtrlHandler);  
  
    if (hstatus==0)  
    {  
        WriteToLog("ERROR;RegisterServiceCtrlHandler failed");  
        return;  
    }  
  
    WriteToLog("DEBUG:RegisterServiceCtrlHandler success");  
  
    //��SCM ��������״̬  
  
    servicestatus.dwCurrentState = SERVICE_RUNNING;  
  
    SetServiceStatus (hstatus, &servicestatus);  
	
    //����Ϳ�ʼ����ѭ���ˣ������������Լ�ϣ���������Ĺ���  
  
	curl_global_init(CURL_GLOBAL_WIN32);
    WebSocket web;
	web.initsocket();
	curl_global_cleanup();
} 
void WINAPI CtrlHandler(DWORD request)  
{  
	switch (request)  
	{  
	case SERVICE_CONTROL_STOP:   
		servicestatus.dwCurrentState = SERVICE_STOPPED;  
		break;  

	case SERVICE_CONTROL_SHUTDOWN:  
		servicestatus.dwCurrentState = SERVICE_STOPPED;  
		break;  

	default:  
		break;  
	}  

	SetServiceStatus (hstatus, &servicestatus);  
}

int _tmain(int argc, _TCHAR* argv[])
{
	//��ʼ������
	SERVICE_TABLE_ENTRY entrytable[2];   
	entrytable[0].lpServiceName= "testservice";   
	entrytable[0].lpServiceProc=(LPSERVICE_MAIN_FUNCTION)ServiceMain;   
	entrytable[1].lpServiceName=NULL;   
	entrytable[1].lpServiceProc=NULL;  
	//����ϵͳ���Ʒ�����
	StartServiceCtrlDispatcher(entrytable);  

	return 0;
}

