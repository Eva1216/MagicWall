// WonderWallDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"

#include "Common.h"
#include "WonderWallDll.h"
#include <cstdlib>
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



extern "C"
_declspec(dllexport)BOOL EnumProcess2(PROCESSENTRY32* ProcessEntry)
{
	int ProcessCount = 0;
	PWTS_PROCESS_INFO ppi;
	DWORD dwCounts;
	BOOL bRet = WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, 0, 1, &ppi, &dwCounts);
	if (!bRet)
		return FALSE;
	//这里先把ppi存起来，方便以后释放，当然如果用数组下标的形式访问的话就不用这样繁琐了
	PWTS_PROCESS_INFO ppiTemp = ppi;
	for (int i = 0; i< dwCounts; i++)
	{
		ProcessEntry[ProcessCount].th32ProcessID = ppi->ProcessId;
		memcpy(ProcessEntry[ProcessCount].szExeFile, ppi->pProcessName, wcslen(ppi->pProcessName)*2);
		ProcessCount++;
		//printf("%S \t %d \n", ppi->pProcessName, ppi->ProcessId);//ppi[i].pProcessName
		ppi++;
	}
	//内存泄漏就是从这里来的，好多人要忘记这里
	WTSFreeMemory(ppiTemp);
	//getchar();

	

	return TRUE;

}
extern "C" 
_declspec(dllexport)BOOL EnumProcess1(PROCESSENTRY32* ProcessEntry)
{

	int ProcessCount = 0;
	DWORD Processes[MAXPROCESSES], Size, ProcessesNumber;

	if (!EnumProcesses(Processes, sizeof(Processes), &Size))
	{
		return FALSE;
	}


	//计算进程总数

	ProcessesNumber = Size / sizeof(DWORD);

	//打印各个进程

	for (int i = 0; i < ProcessesNumber; i++)
	{
		if (Processes[i] != 0)
		{
			WCHAR ProcessName[MAX_PATH] = L"<unknown>";

			//获得进程句柄
			HANDLE ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION |
				PROCESS_VM_READ,
				FALSE, Processes[i]);

			//获得进程名称
			if (NULL != ProcessHandle)
			{
				HMODULE hMod;
				DWORD ReturnLength;

				if (EnumProcessModules(ProcessHandle, &hMod, sizeof(hMod),
					&ReturnLength))
				{
					GetModuleBaseName(ProcessHandle, hMod, ProcessName,
						sizeof(ProcessName) / sizeof(WCHAR));
				}
			}

			ProcessEntry[ProcessCount].th32ProcessID = Processes[i];
			memcpy(ProcessEntry[ProcessCount].szExeFile, ProcessName, sizeof(ProcessName)*2);
			ProcessCount++;

			//关闭进程句柄
			CloseHandle(ProcessHandle);

		}
	}
	return 0;
}


BOOL  WcharToChar(CHAR** szDestString, WCHAR* wzSourString)
{
	SIZE_T StringLength = 0;
	if (wzSourString == NULL)
	{
		return FALSE;
	}

	StringLength = (wcslen(wzSourString) + 1) * sizeof(CHAR);

	*szDestString = (CHAR*)malloc(StringLength);

	if (*szDestString == NULL)
	{
		return FALSE;
	}

	memset(*szDestString, 0, StringLength);
	wcstombs(*szDestString, wzSourString, StringLength);


	return TRUE;
}