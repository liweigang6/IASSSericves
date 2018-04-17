// SocketService.cpp : 定义控制台应用程序的入口点。
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
    servicestatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN|SERVICE_ACCEPT_STOP;//在本例中只接受系统关机和停止服务两种控制命令  
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
  
    //向SCM 报告运行状态  
  
    servicestatus.dwCurrentState = SERVICE_RUNNING;  
  
    SetServiceStatus (hstatus, &servicestatus);  
	
    //下面就开始任务循环了，你可以添加你自己希望服务做的工作  
  
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
	//初始化数组
	SERVICE_TABLE_ENTRY entrytable[2];   
	entrytable[0].lpServiceName= "testservice";   
	entrytable[0].lpServiceProc=(LPSERVICE_MAIN_FUNCTION)ServiceMain;   
	entrytable[1].lpServiceName=NULL;   
	entrytable[1].lpServiceProc=NULL;  
	//调用系统控制分派器
	StartServiceCtrlDispatcher(entrytable);  

	return 0;
}

