#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include "..\WonderWallDll\WonderWallDll.h"
using namespace std;
typedef BOOL(*pfnEnumProcess)(PROCESSENTRY32* ProcessEntry,ULONG32 Index);

typedef VOID(*pfnInstallDriver)(WCHAR* InDriverPath, WCHAR* InDriverName);	//加载驱动

BOOL EnableDebugPrivilege();
VOID Test();
int main()
{
	EnableDebugPrivilege();
	Test();
}


VOID Test()
{
	HMODULE DllModuleHandle = LoadLibrary(L"WonderWallDll.dll");

	if (DllModuleHandle != NULL)
	{
		//获取Dll中导出的函数的地址
		pfnEnumProcess   RhEnumProcess = NULL;
		RhEnumProcess = (pfnEnumProcess)GetProcAddress(DllModuleHandle, "EnumProcess");
		if (RhEnumProcess == NULL)
		{
			cout << "Failed to Find Func" << endl;
			return;
		}
		//int a = GetLastError();
		PROCESSENTRY32 ProcessEntry[1000];
		memset(ProcessEntry, 0, sizeof(ProcessEntry));
		BOOL bRet = RhEnumProcess(ProcessEntry, 4);
		if (bRet)
		{
			int i = 0;
			while (ProcessEntry[i].th32ProcessID != 0 || i == 0)
			{
				printf("PID:\t0x%X,", ProcessEntry[i].th32ProcessID);
				printf("\tName:\t%S\r\n", ProcessEntry[i].szExeFile);
				i++;
			}
		}

		getchar();
		getchar();
		pfnInstallDriver   RhInstallDriver = NULL;
		RhInstallDriver = (pfnInstallDriver)GetProcAddress(DllModuleHandle, "RhInstallDriver");

		if (RhInstallDriver != NULL)
		{
			//RhInstallDriver(L"DPC.sys", L"DPC.sys");
		}


	}
}



BOOL EnableDebugPrivilege()
{

	HANDLE hToken;
	TOKEN_PRIVILEGES TokenPrivilege;
	LUID uID;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &uID))
	{
		CloseHandle(hToken);

		return FALSE;
	}

	TokenPrivilege.PrivilegeCount = 1;
	TokenPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	TokenPrivilege.Privileges[0].Luid = uID;

	if (!AdjustTokenPrivileges(hToken, false, &TokenPrivilege, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		CloseHandle(hToken);

		return  FALSE;
	}

	CloseHandle(hToken);

	return TRUE;

}
