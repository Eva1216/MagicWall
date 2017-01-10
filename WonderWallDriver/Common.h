#pragma once
#include <ntifs.h>
#define MAX_PATH 260


#define DEVICE_NAME   L"\\Device\\WonderWallDriverDeviceName"    

#define LINK_NAME     L"\\DosDevices\\WonderWallDriverLinkName"

#define PROCESS_QUERY_INFORMATION (0x0400)  

typedef struct _PROCESS_INFORMATION_
{
	ULONG EProcessAddress;
	ULONG ProcessNameLength;
	CHAR  szProcessName[MAX_PATH];
	ULONG ProcessFullPathLength;
	WCHAR wzProcessFullPath[MAX_PATH];
}PROCESS_INFORMATION, *PPROCESS_INFORMATION;

typedef struct tagPROCESSENTRY32W
{
	ULONG   dwSize;
	ULONG   cntUsage;
	ULONG   th32ProcessID;          // this process
	ULONG_PTR th32DefaultHeapID;
	ULONG   th32ModuleID;           // associated exe
	ULONG   cntThreads;
	ULONG   th32ParentProcessID;    // this process's parent process
	LONG    pcPriClassBase;         // Base priority of process's threads
	ULONG   dwFlags;
	WCHAR   szExeFile[MAX_PATH];    // Path
} PROCESSENTRY32W;
typedef PROCESSENTRY32W *  PPROCESSENTRY32;

BOOLEAN  GetProcessImageNameByProcessID(ULONG32 ulProcessID, char* szProcessImageName, ULONG32* ulProcessImageNameLength);
BOOLEAN	 GetProcessFullPathByProcessID(ULONG32	ulProcessID, WCHAR* wzProcessFullPath, ULONG32* ulProcessFullPathLength);
extern
char* PsGetProcessImageFileName(PEPROCESS EProcess);
extern
	NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,PVOID ProcessInformation,ULONG ProcessInformationLength,
	PULONG ReturnLength);