// WonderWallDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"


#include "WonderWallDll.h"
extern "C"
_declspec(dllexport)BOOL EnumProcess(PROCESSENTRY32* ProcessEntry)
{

	int ProcessCount = 0;
	//创建快照句柄，CreateToolhelp32Snapshot（）函数返回当前运行的进程快照句柄
	HANDLE ToolHelpHandle = NULL;

	//PROCESSENTRY32结构体记录当前进程的一些信息，其中dwSize必须指定大小，大小为当前结构体大小
	PROCESSENTRY32 ProcessEntry32 = { 0 };
	ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);

	ToolHelpHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (ToolHelpHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	BOOL bOk = Process32First(ToolHelpHandle, &ProcessEntry32);
	while (bOk)
	{
		ProcessEntry[ProcessCount].th32ProcessID = ProcessEntry32.th32ProcessID;
		memcpy(ProcessEntry[ProcessCount].szExeFile, ProcessEntry32.szExeFile, sizeof(ProcessEntry32.szExeFile));
		ProcessCount++;
		bOk = Process32Next(ToolHelpHandle, &ProcessEntry32);
	}

	CloseHandle(ToolHelpHandle);
	ToolHelpHandle = INVALID_HANDLE_VALUE;
	return TRUE;

}


