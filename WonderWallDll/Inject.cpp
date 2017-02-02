#include "Common.h"
#include "stdafx.h"
#include "WonderWallDll.h"
#include <windows.h>
#include <iostream>
#include <exception>
#include <string>


using namespace std;

BOOL IatInject(CHAR* ProcessName, CHAR* DllName,CHAR* FunctionName)
{
	BOOL bRet = FALSE;
	try
	{
		bRet = AddNewSection(ProcessName);
		if (!bRet)
		{
			ERROR_MESSAGE("AddImportTable:AddNewSection failed.");
			return FALSE;
		}
		bRet = AddNewImportDescriptor(ProcessName, DllName, FunctionName);
		if (!bRet)
		{
			ERROR_MESSAGE("AddImportTable:AddNewImportDescriptor failed.");
			return FALSE;
		}
	}
	catch (exception* e)
	{
		return FALSE;
	}
	return TRUE;
}



BOOL AddNewImportDescriptor(CHAR* ProcessName,CHAR* DllName,CHAR*	FunctionName)
{
	BOOL bRet = TRUE;
	HANDLE TargetFileHandle = NULL;
	HANDLE MappingHandle = NULL;
	PVOID FileData = NULL;
	PIMAGE_IMPORT_DESCRIPTOR ImportTable = NULL;

	try
	{
		// 打开文件
		TargetFileHandle = CreateFileA(ProcessName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (TargetFileHandle == INVALID_HANDLE_VALUE)
		{
			ERROR_MESSAGE(string("AddNewImportDescriptor:CreateFileA error with error code:" + GetLastError()).c_str());
			bRet = FALSE;
			goto EXIT;
		}

		ULONG ulFileSize = GetFileSize(TargetFileHandle, NULL);

		// 映射文件
		MappingHandle = CreateFileMappingA(TargetFileHandle, NULL, PAGE_READWRITE, 0, ulFileSize, NULL);
		if (MappingHandle == NULL)
		{
			cout << "AddNewImportDescriptor:CreateFileMapping error with error code:" << std::to_string(GetLastError()).c_str();
			bRet = FALSE;
			goto EXIT;
		}

		// 得到缓存头
		FileData = MapViewOfFile(MappingHandle, FILE_MAP_ALL_ACCESS, 0, 0, ulFileSize);
		if (FileData == NULL)
		{
			ERROR_MESSAGE(string("AddNewImportDescriptor:MapViewOfFile error with error code:" + GetLastError()).c_str());
			bRet = FALSE;
			goto EXIT;
		}

		// 判断是否是PE文件
		if (((PIMAGE_DOS_HEADER)FileData)->e_magic != IMAGE_DOS_SIGNATURE)
		{
			ERROR_MESSAGE("AddNewImportDescriptor:Target File is not a vaild file");
			bRet = FALSE;
			goto EXIT;
		}

		PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)FileData + ((PIMAGE_DOS_HEADER)FileData)->e_lfanew);
		if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			ERROR_MESSAGE("AddNewImportDescriptor:Target File is not a vaild file");
			bRet = FALSE;
			goto EXIT;
		}

		// 得到原导入表
		ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)FileData + RVAToFOA(NtHeaders, NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
		// 判断是否使用了绑定导入表
		BOOL bBoundImport = FALSE;
		if (ImportTable->Characteristics == 0 && ImportTable->FirstThunk != 0)
		{
			// 桥一为0 桥二不是0 说明使用了绑定导入表
			bBoundImport = TRUE;
			NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;	// 关闭绑定导入
			NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
		}

		// 找到自己添加的新节
		PIMAGE_SECTION_HEADER NewSectionHeader = (PIMAGE_SECTION_HEADER)(NtHeaders + 1) + NtHeaders->FileHeader.NumberOfSections - 1;
		PBYTE NewSectionData = NewSectionHeader->PointerToRawData + (PBYTE)FileData;
		PBYTE NewImportDescriptor = NewSectionData;
		// 往新节中拷贝原导入表内容
		int i = 0;
		while (ImportTable->FirstThunk != 0 || ImportTable->Characteristics != 0)
		{
			memcpy(NewSectionData + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), ImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR));
			ImportTable++;
			NewImportDescriptor += sizeof(IMAGE_IMPORT_DESCRIPTOR);
			i++;
		}
		// 复制最后一个描述符
		memcpy(NewImportDescriptor, NewImportDescriptor - sizeof(IMAGE_IMPORT_DESCRIPTOR), sizeof(IMAGE_IMPORT_DESCRIPTOR));

		// 计算修正值
		DWORD dwDelt = NewSectionHeader->VirtualAddress - NewSectionHeader->PointerToRawData;

		// pNewImportDescriptor 当前指向要构造的新描述符 再空出一个空描述符作为导入表的结束符 所以是 2 * 
		PIMAGE_THUNK_DATA pNewThunkData = PIMAGE_THUNK_DATA(NewImportDescriptor + 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR));
		PBYTE pszDllName = (PBYTE)(pNewThunkData +2);
		memcpy(pszDllName, DllName, strlen(DllName) + 1 );
		// 确定 DllName 的位置
		//pszDllName[strlen(DllName) + 1] = 0;
		// 确定 IMAGE_IMPORT_BY_NAM 的位置 
		PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pszDllName + strlen(DllName) + 1 );
		// 初始化 IMAGE_THUNK_DATA
		pNewThunkData->u1.Ordinal = (DWORD_PTR)pImportByName - (DWORD_PTR)FileData + /*加上修正值 - 这里应该填充在内存中的地址*/dwDelt;
		// 初始化 IMAGE_IMPORT_BY_NAME
		pImportByName->Hint = 1;
		memcpy(pImportByName->Name, FunctionName, strlen(FunctionName) + 1);
		//pImportByName->Name[strlen(FunctionName) + 1] = 0;
		// 初始化 PIMAGE_IMPORT_DESCRIPTOR
		if (bBoundImport)
		{
			((PIMAGE_IMPORT_DESCRIPTOR)NewImportDescriptor)->OriginalFirstThunk = 0;
		}
		else
		{
			((PIMAGE_IMPORT_DESCRIPTOR)NewImportDescriptor)->OriginalFirstThunk = dwDelt + (DWORD_PTR)pNewThunkData - (DWORD_PTR)FileData;
		}
		((PIMAGE_IMPORT_DESCRIPTOR)NewImportDescriptor)->FirstThunk = dwDelt + (DWORD_PTR)pNewThunkData - (DWORD_PTR)FileData;
		((PIMAGE_IMPORT_DESCRIPTOR)NewImportDescriptor)->Name = dwDelt + (DWORD_PTR)pszDllName - (DWORD_PTR)FileData;
		// 修改导入表入口
		NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = NewSectionHeader->VirtualAddress;
		NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (i + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	catch (exception* e)
	{
		ERROR_MESSAGE((string("AddNewImportDescriptor:") + e->what()).c_str());
		bRet = FALSE;
	}

EXIT:
	{
		if (TargetFileHandle != NULL)
		{
			CloseHandle(TargetFileHandle);
			TargetFileHandle = NULL;
		}

		if (FileData != NULL)
		{
			UnmapViewOfFile(FileData);
			FileData = NULL;
		}

		if (MappingHandle != NULL)
		{
			CloseHandle(MappingHandle);
			MappingHandle = NULL;
		}
	}

	return bRet;
}

PIMAGE_SECTION_HEADER GetOwnerSection(PIMAGE_NT_HEADERS pNTHeaders, DWORD dwRVA)
{
	int i;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(pNTHeaders + 1);
	for (i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++)
	{
		if ((dwRVA >= (pSectionHeader + i)->VirtualAddress) && (dwRVA <= ((pSectionHeader + i)->VirtualAddress + (pSectionHeader + i)->SizeOfRawData)))
		{
			return ((PIMAGE_SECTION_HEADER)(pSectionHeader + i));
		}
	}
	return PIMAGE_SECTION_HEADER(NULL);
}
DWORD RVAToFOA(PIMAGE_NT_HEADERS pNTHeaders, DWORD dwRVA)
{
	DWORD _offset;
	PIMAGE_SECTION_HEADER section;
	// 找到偏移所在节
	section = GetOwnerSection(pNTHeaders, dwRVA);
	if (section == NULL)
	{
		return(0);
	}
	// 修正偏移
	_offset = dwRVA + section->PointerToRawData - section->VirtualAddress;
	return(_offset);
}
BOOL AddNewSection(CHAR* ProcessName)

{
	BOOL	bRet				= TRUE;
	HANDLE	TargetFileHandle	= NULL;
	HANDLE	MappingHandle		= NULL;
	PVOID	FileData			= NULL;

	try
	{
		// 打开文件
		TargetFileHandle = CreateFileA(ProcessName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (TargetFileHandle == INVALID_HANDLE_VALUE)
		{
			ERROR_MESSAGE(string("AddNewSection:CreateFileA error with error code:" + GetLastError()).c_str());
			bRet = FALSE;
			goto EXIT;
		}

		ULONG ulFileSize = GetFileSize(TargetFileHandle, NULL);

		// 映射文件
		MappingHandle = CreateFileMappingA(TargetFileHandle, NULL, PAGE_READWRITE, 0, ulFileSize, NULL);
		if (MappingHandle == NULL)
		{
			ERROR_MESSAGE(string("AddNewSection:CreateFileMapping error with error code:" + GetLastError()).c_str());
			bRet = FALSE;
			goto EXIT;
		}

		// 得到缓存头
		FileData = MapViewOfFile(MappingHandle, FILE_MAP_ALL_ACCESS, 0, 0, ulFileSize);
		if (FileData == NULL)
		{
			ERROR_MESSAGE(string("AddNewSection:MapViewOfFile error with error code:" + GetLastError()).c_str());
			bRet = FALSE;
			goto EXIT;
		}

		// 判断是否是PE文件
		if (((PIMAGE_DOS_HEADER)FileData)->e_magic != IMAGE_DOS_SIGNATURE)
		{
			ERROR_MESSAGE("AddNewSection:Target File is not a vaild file");
			bRet = FALSE;
			goto EXIT;
		}

		PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)FileData + ((PIMAGE_DOS_HEADER)FileData)->e_lfanew);
		if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			ERROR_MESSAGE("AddNewSection:Target File is not a vaild file");
			bRet = FALSE;
			goto EXIT;
		}

		// 判断是否可以增加一个新节
		if ((NtHeaders->FileHeader.NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER) > NtHeaders->OptionalHeader.SizeOfHeaders)
		{
			ERROR_MESSAGE("AddNewSection:There is not enough space to add a new section.");
			bRet = FALSE;
			goto EXIT;
		}

		// 得到新节的起始地址， 最后的起始地址
		PIMAGE_SECTION_HEADER NewSectionHeader = (PIMAGE_SECTION_HEADER)(NtHeaders + 1) + NtHeaders->FileHeader.NumberOfSections;
		PIMAGE_SECTION_HEADER LastSectionHeader = NewSectionHeader - 1;

		// 对齐RVA和偏移
		DWORD FileSize      =	PEAlign(256, NtHeaders->OptionalHeader.FileAlignment);
		DWORD FileOffset    =	PEAlign(LastSectionHeader->PointerToRawData + LastSectionHeader->SizeOfRawData, NtHeaders->OptionalHeader.FileAlignment);
		DWORD VirtualSize   =	PEAlign(256, NtHeaders->OptionalHeader.SectionAlignment);
		DWORD VirtualOffset =	PEAlign(LastSectionHeader->VirtualAddress + LastSectionHeader->Misc.VirtualSize, NtHeaders->OptionalHeader.SectionAlignment);

		// 填充新节表
		memcpy(NewSectionHeader->Name, "Inject", strlen("Inject"));
		NewSectionHeader->VirtualAddress = VirtualOffset;
		NewSectionHeader->Misc.VirtualSize = VirtualSize;
		NewSectionHeader->PointerToRawData = FileOffset;
		NewSectionHeader->SizeOfRawData = FileSize;
		NewSectionHeader->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

		// 修改IMAGE_NT_HEADERS
		NtHeaders->FileHeader.NumberOfSections++;
		NtHeaders->OptionalHeader.SizeOfImage += VirtualSize;
		NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;			// 关闭绑定导入
		NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;

		// 添加新节到文件尾部
		SetFilePointer(TargetFileHandle, 0, 0, FILE_END);
		PCHAR	NewSectionContent = new CHAR[FileSize];
		RtlZeroMemory(NewSectionContent, FileSize);
		DWORD WrittenLength = 0;
		bRet = WriteFile(TargetFileHandle, NewSectionContent, FileSize, &WrittenLength, NULL);
		if (bRet == FALSE)
		{
			ERROR_MESSAGE(string("AddNewSection:WriteFile error with error code:" + GetLastError()).c_str());
			bRet = FALSE;
			goto EXIT;
		}
	}
	catch (exception* e)
	{
		ERROR_MESSAGE((string("AddNewSection:") + e->what()).c_str());
		bRet = FALSE;
	}
EXIT:
	if (TargetFileHandle != NULL)
	{
		CloseHandle(TargetFileHandle);
		TargetFileHandle = nullptr;
	}
	if (FileData != NULL)
	{
		UnmapViewOfFile(FileData);
		FileData = nullptr;
	}
	if (MappingHandle != NULL)
	{
		CloseHandle(MappingHandle);
		MappingHandle = nullptr;
	}

	return bRet;
}


ULONG32 PEAlign(ULONG32 dwNumber, ULONG32 dwAlign)
{
	return(((dwNumber + dwAlign - 1) / dwAlign) * dwAlign);		//  想 dwAlign 对齐，加上 dwAlign - 1，这样就可以保证对齐后的值 >= dwNumber
}