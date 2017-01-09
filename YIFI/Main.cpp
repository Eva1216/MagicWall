#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include "..\WonderWallDll\WonderWallDll.h"
using namespace std;
typedef BOOL(*pfnEnumProcess)(PROCESSENTRY32* ProcessEntry,ULONG32 Index);

VOID Test();
int main()
{
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
		BOOL bRet = RhEnumProcess(ProcessEntry, 0);
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
	}
}

