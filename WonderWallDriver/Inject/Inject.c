#include "Inject.h"
/*1.判断当前LoadImageNotify加载的dll名字是System32(SysWOW64)\\ntdll.dll
2.ObOpenObjectByPointer打开一个ProcessHandle
3.KeStackAttachProcess切到被注入的进程的地址空间去，
4.遍历导出表取ntdll!ZwTestAlert的地址（win10取ntdll!LdrGetProcedureAddressForCaller）
5.取ntdll!NtProtectVirtualMemory的地址
6.KeUnstackDetachProcess切回来
6.在ntdll附近分配注入shellcode需要的内存7.调用ntoskrnl!ZwReadVirtualMemory获取ntdll!ZwTestAlert处头5字节的数据保存起来
8.配置好shellcode及shellcode的需要的数据（如注入的dll路径、ntdll!NtProtectVirtualMemory地址等）
9.调用ntoskrnl!ZwWriteVirtualMemory往刚才分配的内存区域里复制配置好的shellcode及shellcode需要的数据。
10.调用ntoskrnl!ZwProtectVirtualMemory+ZwWriteVirtualMemory+ZwProtectVirtualMemory把{0xE9, ??, ??, ??, ??}（其实是jmp到shellcode处）复制到ntdll!ZwTestAlert处，覆盖5个字节
11.做一些收尾工作，如关闭ProcessHandle句柄，解除Process对象引用

Q：为什么分配shellcode不随便挑个地址分配，非要在ntdll附近分配呢？

A：因为我们要用最方便的手段跳转到shellcode。而0xE9的jmp跳转指令只能用4字节的offset，也就是说跳转的目的地址相对当前指令结束位置的偏移必须在当前地址的前后2GB范围内。
简单的说，就是int offset = (ULONGLONG)shellcode - ((ULONGLONG)pfnZwTestAlert + 5)不溢出。因此选择在ntdll附近分配内存是一定可以用5字节的jmp跳转过去的。

Q：为什么非要ZwRead，ZwWrite？多麻烦，直接KeStackAttachProcess上去然后读写内存不行吗？

A：不行，KeStackAttachProcess之后强制读写可能会绕过进程的VAD，导致的结果就是COPY-ON-WRITE机制失效，你的所有进程的ntdll都被你篡改了，包括正在运行的那些。

以上是整个注入过程在内核中的部分。这个过程发生在PspUserThreadStartup->DbgkCreateThread->PsCallImageNotifyRoutines->你注册的ImageNotify中。

那么那段shellcode在ring3又做了什么呢？
一波断点之后，拿到了shellcode的位置，跟进去就可以看出大致思路（应该是手写的汇编，这里就不放代码了）
1.调用ntdll!NtProtectVirtualMemory修改ntdll!ZwTestAlert（这个地址是刚才第7步就预置好的，不是动态获取的）的保护页成PAGE_EXECUTE_READWRITE
2.memcpy恢复ntdll!ZwTestAlert头部的5字节（这5个字节也是第7步预置好的）
3.调用NtProtectVirtualMemory恢复ntdll!ZwTestAlert保护页
4.调用ntdll!LdrLoadDll完成工作
5.跳回ntdll!ZwTestAlert处
*/ 
ULONG_PTR GetDllFunctionAddress(PCCHAR lpFunctionName, PVOID BaseAddress)
{
	HANDLE hSection = NULL, hFile = NULL;
	SIZE_T size = 0;
	NTSTATUS status;


	////转换DLL名称
	//UNICODE_STRING strDllName;
	//RtlInitUnicodeString(&strDllName, pDllName);

	//OBJECT_ATTRIBUTES  objectAttributes = { 0 };


	//IO_STATUS_BLOCK iosb = { 0 };

	////初始化 objectAttributes
	//InitializeObjectAttributes(&objectAttributes, &strDllName, OBJ_KERNEL_HANDLE, NULL, NULL);

	//__try
	//{
	//	//打开文件
	//	status = ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &objectAttributes, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	//	if (!NT_SUCCESS(status))
	//	{
	//		__leave;
	//	}
	//	objectAttributes.ObjectName = 0;

	//	//创建内存块
	//	status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &objectAttributes, 0, PAGE_READONLY, SEC_IMAGE, hFile); //PAGE_READONLY页面保护属性，必须结合SEC_IMAGE属性
	//	if (!NT_SUCCESS(status))
	//	{
	//		__leave;
	//	}

	//	//内存映射文件
	//	status = ZwMapViewOfSection(hSection,
	//		OpenProcess(ProcessId),
	//		&BaseAddress,
	//		0,
	//		1024,
	//		0,
	//		&size,
	//		ViewUnmap,
	//		MEM_LARGE_PAGES,		//针对DLL文件较小是可以用MEM_TOP_DOWN 文件较大比如USER32.DLL时需要用MEM_LARGE_PAGES
	//		PAGE_READWRITE);
	//}
	//__finally
	//{
	//	DPRINT("map dest process success!\r\n");
	//	if (hFile != NULL)
	//	{
	//		//关闭文件句柄
	//		ZwClose(hFile);
	//	}
	//	if (!NT_SUCCESS(status) && hSection != NULL)
	//	{
	//		//关闭内存块
	//		ZwClose(hSection);
	//	}
	//}
	////如果失败 直接返回
	//if (!NT_SUCCESS(status))
	//{
	//	return 0;
	//}




	//HANDLE hSection, hFile;
	//UNICODE_STRING dllName;
	//PVOID BaseAddress = NULL;
	//SIZE_T size = 0;
	//NTSTATUS stat;
	//OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &dllName, OBJ_CASE_INSENSITIVE };
	//IO_STATUS_BLOCK iosb;

	//RtlInitUnicodeString(&dllName, pDllName);


	////_asm int 3;
	//stat = ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &oa, &iosb,
	//	FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	//if (!NT_SUCCESS(stat)) {
	//	DPRINT("ZwOpenFile : errorcoede:0x%X\n", stat);
	//	return 0;
	//}

	//oa.ObjectName = 0;

	//stat = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0, PAGE_EXECUTE,
	//	SEC_IMAGE, hFile);

	//if (!NT_SUCCESS(stat)) {
	//	return 0;
	//}

	//stat = ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0,
	//	1000, 0, &size, (SECTION_INHERIT)1, MEM_TOP_DOWN, PAGE_READWRITE);

	//if (!NT_SUCCESS(stat)) {
	//	return 0;
	//}



	////读取PE头信息
	//IMAGE_DOS_HEADER* dosheader;
	////IMAGE_OPTIONAL_HEADER* opthdr;
	//PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
	//PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
	//IMAGE_EXPORT_DIRECTORY* pExportTable;
	//PULONG arrayOfFunctionAddresses, arrayOfFunctionNames;
	//PUSHORT arrayOfFunctionOrdinals;
	//ULONG_PTR functionOrdinal, functionAddress = 0;
	//PSTR functionName;
	//ANSI_STRING anFunName;
	//UNICODE_STRING unFunctionName, unFunctionNameSearch;
	////模块句柄
	//HANDLE hMod = BaseAddress;

	//ASSERT(BaseAddress != NULL);
	//if (BaseAddress == NULL)
	//	return NULL;

	////得到DOS头
	//dosheader = (PIMAGE_DOS_HEADER)hMod;

	///// Not a PE file
	//if (dosheader->e_magic != IMAGE_DOS_SIGNATURE)
	//	return NULL;
	//pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)BaseAddress + dosheader->e_lfanew);
	//pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)BaseAddress + dosheader->e_lfanew);

	//// Not a PE file
	//if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
	//	return NULL;


	//// 64 bit image
	//if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	//{
	//	pExportTable = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)BaseAddress);

	//}
	//// 32 bit image
	//else
	//{
	//	pExportTable = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)BaseAddress);

	//}

	//arrayOfFunctionOrdinals = (PUSHORT)(pExportTable->AddressOfNameOrdinals + (ULONG_PTR)BaseAddress);
	//arrayOfFunctionNames = (PULONG)(pExportTable->AddressOfNames + (ULONG_PTR)BaseAddress);
	//arrayOfFunctionAddresses = (PULONG)(pExportTable->AddressOfFunctions + (ULONG_PTR)BaseAddress);
	//DWORD Base = pExportTable->Base;
	//////得到PE选项头
	////opthdr = (PIMAGE_OPTIONAL_HEADER)((BYTE *)hMod + dosheader->e_lfanew + 24);
	//////得到导出表
	////pExportTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hMod + opthdr->DataDirectory[0].VirtualAddress);
	////得到函数地址列表
	////arrayOfFunctionAddresses = (PDWORD)((BYTE *)hMod + pExportTable->AddressOfFunctions);
	//////得到函数名称列表
	////arrayOfFunctionNames = (PDWORD)((BYTE *)hMod + pExportTable->AddressOfNames);
	//////得到函数序号
	////arrayOfFunctionOrdinals = (WORD *)((BYTE *)hMod + pExportTable->AddressOfNameOrdinals);
	//////导出表基地址


	////转换函数名
	//RtlInitUnicodeString(&unFunctionNameSearch, lpFunctionName);
	////循环导出表
	//for (DWORD x = 0; x < pExportTable->NumberOfFunctions; x++)			//导出函数有名称 编号之分，导出函数总数=名称导出+编号导出，这里是循环导出名称的函数
	//{
	//	//得到函数名 
	//	functionName = (PSTR)((BYTE *)hMod + arrayOfFunctionNames[x]);

	//	//转化为ANSI_STRING
	//	RtlInitAnsiString(&anFunName, functionName);
	//	//转化为UNICODE_STRING
	//	RtlAnsiStringToUnicodeString(&unFunctionName, &anFunName, TRUE);
	//	//打印调试信息
	//	DPRINT("%d/%d,FunName:%wZ\n", x + 1, pExportTable->NumberOfNames, &unFunctionName);
	//	//比较函数名称
	//	if (RtlCompareUnicodeString(&unFunctionName, &unFunctionNameSearch, TRUE) == 0)
	//	{
	//		//得到该函数地址
	//		functionOrdinal = arrayOfFunctionOrdinals[x] + Base - 1;
	//		functionAddress = (ULONG_PTR)((BYTE *)hMod + arrayOfFunctionAddresses[functionOrdinal]);//
	//		break;
	//	}
	//}
	////这里释放资源返回的地址将无效 所以先存放起来
	////ZwUnmapViewOfSection (NtCurrentProcess(), BaseAddress);


	////ZwClose(hSection);

	//return functionAddress;







	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG expSize = 0;
	ULONG_PTR pAddress = 0;
	PUSHORT pAddressOfOrds;
	PULONG  pAddressOfNames;
	PULONG  pAddressOfFuncs;
	ULONG i;

	ASSERT(BaseAddress != NULL);
	if (BaseAddress == NULL)
		return NULL;

	/// Not a PE file
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)BaseAddress + pDosHdr->e_lfanew);
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)BaseAddress + pDosHdr->e_lfanew);

	// Not a PE file
	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// 64 bit image
	if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)BaseAddress);
		expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	// 32 bit image
	else
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)BaseAddress);
		expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)BaseAddress);
	pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)BaseAddress);
	pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)BaseAddress);

	for (i = 0; i < pExport->NumberOfFunctions; ++i)
	{
		USHORT OrdIndex = 0xFFFF;
		PCHAR  pName = NULL;

		// Find by index
		if ((ULONG_PTR)lpFunctionName <= 0xFFFF)
		{
			OrdIndex = (USHORT)i;
		}
		// Find by name
		else if ((ULONG_PTR)lpFunctionName > 0xFFFF && i < pExport->NumberOfNames)
		{
			pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)BaseAddress);
			OrdIndex = pAddressOfOrds[i];
		}
		// Weird params
		else
			return NULL;

		if (((ULONG_PTR)lpFunctionName <= 0xFFFF && (USHORT)((ULONG_PTR)lpFunctionName) == OrdIndex + pExport->Base) ||
			((ULONG_PTR)lpFunctionName > 0xFFFF && strcmp(pName, (PTSTR)(PCTSTR)lpFunctionName) == 0))
		{
			pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)BaseAddress;

			// Check forwarded export
			if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize)
			{
				return NULL;
			}

			break;
		}
	}

	return (ULONG_PTR)pAddress;





}
HANDLE KLoadLibrary(const wchar_t *full_dll_path)
{
	HANDLE hSection, hFile;
	UNICODE_STRING dllName;
	PVOID BaseAddress = NULL;
	SIZE_T size = 0;
	NTSTATUS stat;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &dllName, OBJ_CASE_INSENSITIVE };
	IO_STATUS_BLOCK iosb;

	RtlInitUnicodeString(&dllName, full_dll_path);


	//_asm int 3;
	stat = ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &oa, &iosb,
		FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	if (!NT_SUCCESS(stat)) {
		return 0;
	}

	oa.ObjectName = 0;

	stat = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0, PAGE_EXECUTE,
		SEC_IMAGE, hFile);

	if (!NT_SUCCESS(stat)) {
		return 0;
	}

	stat = ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0,
		1000, 0, &size, (SECTION_INHERIT)1, MEM_TOP_DOWN, PAGE_READWRITE);

	if (!NT_SUCCESS(stat)) {
		return 0;
	}

	ZwClose(hSection);
	ZwClose(hFile);

	return BaseAddress;
}
DWORD_PTR SearchModuleAndFindFuncAddrInTarget64(PEPROCESS Process, PCCHAR lpFunctionName)
{
	KAPC_STATE                      KAPC = { 0 };
	ULONG PebOffset = 0;
	ULONG PebLdrOffset = 0;
	DWORD64 Peb;
	ULONG ProcessParametersOffset = 0;

	PPEB_LDR_DATA64 PebLdr;
	PLDR_DATA_TABLE_ENTRY64 LdrTableEntry;
	PLIST_ENTRY pListHead, pListNext;
	int i = 0;
	DWORD_PTR funcAddr = 0;
	WCHAR ExeModule[260];
	WCHAR ExeDirectory[260];

	BOOL BIsAttached;
	//__debugbreak();
	if (!MmIsAddressValid(Process))
	{
		DPRINT("Process is invalid!\r\n");
		return funcAddr;
	}
	__try
	{
		KeStackAttachProcess(Process, &KAPC);
		BIsAttached = TRUE;
		HANDLE ntdll = KLoadLibrary(L"\\SystemRoot\\SysWOW64\\ntdll.dll");
		funcAddr = GetDllFunctionAddress(lpFunctionName, ntdll);
		//
		//	PebOffset = 0x338;
		//	PebLdrOffset = 0x18;
		//	ProcessParametersOffset = 0x20;
		//	
		//
		//if (PebOffset == 0 ||
		//	PebLdrOffset == 0 ||
		//	ProcessParametersOffset == 0)
		//{
		//	
		//	__leave;
		//}
		//DPRINT("PEProcess:0x%llx\r\n", Process);
		//KeStackAttachProcess(Process, &KAPC);
		//BIsAttached = TRUE;
		//Peb = *(DWORD64*)((DWORD64)Process + PebOffset);

		//ProbeForRead((PVOID)Peb, 8, 1);//PEB是用户空间的，可能会不能访问

		//if (Peb == 0 || !MmIsAddressValid((PVOID)Peb))//
		//{
		//	
		//		DPRINT("Peb is null\n");
		//	
		//	__leave;
		//}
		//
		//////////////////////////////

		//PebLdr = (PPEB_LDR_DATA64)*(DWORD64*)(Peb + PebLdrOffset);

		//ProbeForRead((PVOID)PebLdr, 8, 1);

		//if (!MmIsAddressValid(PebLdr))
		//{
		//	
		//		DPRINT("PebLdr offset is null\n");
		//	
		//	__leave;
		//}
		//pListHead = &PebLdr->InLoadOrderModuleList;
		//pListNext = pListHead->Flink;
		//while (pListHead != pListNext)
		//{
		//	LdrTableEntry = (PLDR_DATA_TABLE_ENTRY64)pListNext;
		//	if (!MmIsAddressValid(LdrTableEntry))
		//	{
		//		break;
		//	}
		//	if (MmIsAddressValid(&LdrTableEntry->FullDllName) &&
		//		LdrTableEntry->FullDllName.Buffer != NULL &&
		//		LdrTableEntry->FullDllName.Length > 0)
		//	{
		//		memset(ExeModule, 0, sizeof(ExeModule));
		//		memset(ExeDirectory, 0, sizeof(ExeDirectory));
		//		memcpy(
		//			
		//			ExeModule, LdrTableEntry->FullDllName.Buffer,
		//			LdrTableEntry->FullDllName.Length
		//			);
		//		
		//		DPRINT("search module:%ws+++++++++++++++++\r\n", ExeModule);
		//		if (_wcsnicmp(ExeModule, L"C:\\Windows\\System32\\ntdll.dll", sizeof("C:\\Windows\\System32\\ntdll.dll")*2) == 0)
		//			{
		//				//hide~
		//				DPRINT("HideDLL:%ws+++++++++++++++++\r\n", ExeModule);
		//				funcAddr =  GetDllFunctionAddress(lpFunctionName, LdrTableEntry->DllBase);
		//				break;
		//			}
		//		
		//	}
		//	pListNext = pListNext->Flink;

		//}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

	}
	if (BIsAttached != FALSE)
	{
		KeUnstackDetachProcess(&KAPC);
	}
	return funcAddr;
}

DWORD_PTR SearchModuleAndFindFuncAddrInTarget32(PEPROCESS Process, PCCHAR lpFunctionName)
{
	KAPC_STATE                      KAPC = { 0 };
	ULONG PebOffset = 0;
	ULONG PebLdrOffset = 0;
	DWORD64 Peb;
	ULONG ProcessParametersOffset = 0;

	PPEB_LDR_DATA64 PebLdr;
	PLDR_DATA_TABLE_ENTRY64 LdrTableEntry;
	PLIST_ENTRY pListHead, pListNext;
	int i = 0;
	DWORD funcAddr = 0;
	WCHAR ExeModule[260];
	WCHAR ExeDirectory[260];

	BOOL BIsAttached;
	//__debugbreak();
	if (!MmIsAddressValid(Process))
	{
		DPRINT("Process is invalid!\r\n");
		return funcAddr;
	}
	__try
	{
		KeStackAttachProcess(Process, &KAPC);
		BIsAttached = TRUE;
		HANDLE ntdll = KLoadLibrary(L"\\SystemRoot\\SysWOW64\\ntdll.dll");
		funcAddr = (DWORD)GetDllFunctionAddress(lpFunctionName, ntdll);

		//PebOffset = 0x338;
		//PebLdrOffset = 0x18;
		//ProcessParametersOffset = 0x20;


		//if (PebOffset == 0 ||
		//	PebLdrOffset == 0 ||
		//	ProcessParametersOffset == 0)
		//{

		//	__leave;
		//}
		//DPRINT("PEProcess:0x%llx\r\n", Process);
		//
		//Peb = *(DWORD64*)((DWORD64)Process + PebOffset);
		//KeStackAttachProcess(Process, &KAPC);
		//BIsAttached = TRUE;
		//ProbeForRead((PVOID)Peb, 8, 1);//PEB是用户空间的，可能会不能访问

		//if (Peb == 0 || !MmIsAddressValid((PVOID)Peb))//
		//{

		//	DPRINT("Peb is null\n");

		//	__leave;
		//}

		//////////////////////////////

		//PebLdr = (PPEB_LDR_DATA64)*(DWORD64*)(Peb + PebLdrOffset);

		//ProbeForRead((PVOID64)PebLdr, 8, 1);

		//if (!MmIsAddressValid(PebLdr))
		//{

		//	DPRINT("PebLdr offset is null\n");

		//	__leave;
		//}
		//pListHead = (PLIST_ENTRY)&PebLdr->InLoadOrderModuleList;
		//pListNext = (PLIST_ENTRY)pListHead->Flink;
		//while (pListHead != pListNext)
		//{
		//	LdrTableEntry = (PLDR_DATA_TABLE_ENTRY64)pListNext;
		//	if (!MmIsAddressValid(LdrTableEntry))
		//	{
		//		break;
		//	}
		//	if (MmIsAddressValid(&LdrTableEntry->FullDllName) &&
		//		LdrTableEntry->FullDllName.Buffer != NULL &&
		//		LdrTableEntry->FullDllName.Length > 0)
		//	{
		//		memset(ExeModule, 0, sizeof(ExeModule));
		//		memset(ExeDirectory, 0, sizeof(ExeDirectory));
		//		memcpy(

		//			ExeModule, LdrTableEntry->FullDllName.Buffer,
		//			LdrTableEntry->FullDllName.Length
		//			);

		//		DPRINT("search module:%ws+++++++++++++++++\r\n", ExeModule);
		//		if (_wcsnicmp(ExeModule, L"C:\\Windows\\SysWoW64\\ntdll.dll", sizeof("C:\\Windows\\SysWoW64\\ntdll.dll")*2) == 0)
		//		{
		//			//hide~
		//			DPRINT("HideDLL:%ws+++++++++++++++++\r\n", ExeModule);
		//			funcAddr = (ULONG)GetDllFunctionAddress(lpFunctionName, LdrTableEntry->DllBase);
		//			break;
		//		}

		//	}
		//	pListNext = (PLIST_ENTRY)pListNext->Flink;

		//}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

	}
	if (BIsAttached != FALSE)
	{
		KeUnstackDetachProcess(&KAPC);
	}
	return funcAddr;
}
////////////////////////////////
//功    能：根据进程ID获取进程句柄
//参    数: 进程ID  x64 x86通用
//返 回 值：进程句柄
////////////////////////////////
HANDLE OpenProcess(
	HANDLE  Processid
)
{
	//NTSTATUS status;
	//PEPROCESS Process = NULL;
	//HANDLE hProcess = NULL;
	//UNICODE_STRING Unicode;
	//status = PsLookupProcessByProcessId(Processid, &Process);
	//if (NT_SUCCESS(status))//判断进程号是否存在
	//{
	//	RtlInitUnicodeString(&Unicode, L"PsProcessType");
	//	//得到系统导出函数的地址和用户态的GetProcessAddress雷同

	//	PsProcessType = (POBJECT_TYPE *)MmGetSystemRoutineAddress(&Unicode);
	//	if (PsProcessType)
	//	{
	//		status = ObOpenObjectByPointer(
	//			Process,
	//			0,
	//			NULL,
	//			PROCESS_ALL_ACCESS,
	//			(POBJECT_TYPE)*PsProcessType,
	//			KernelMode,
	//			&hProcess
	//			);

	//		if (NT_SUCCESS(status))
	//		{
	//			//减少指针计数
	//			ObfDereferenceObject(Process);
	//			return hProcess;
	//		}
	//	}
	//	ObfDereferenceObject(Process);
	//}
	//return 0;
	//__debugbreak();
	PEPROCESS Process;
	NTSTATUS nStatus;
	HANDLE hProcess = NULL;

	nStatus = PsLookupProcessByProcessId((HANDLE)Processid, &Process);
	if (!NT_SUCCESS(nStatus))
	{
		DPRINT(("the id is not eist!"));
		return hProcess;
	}
	nStatus = ObOpenObjectByPointer(Process, 0, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &hProcess);
	ObDereferenceObject(Process);
	if (!NT_SUCCESS(nStatus)) DPRINT(("ObOpenObjectByPointer open failed!")); else DPRINT(("ObOpenObjectByPointer open success!"));
	return hProcess;
}



PVOID AllocateInjectMemory(IN HANDLE ProcessHandle, IN PVOID DesiredAddress, IN SIZE_T DesiredSize)
{
	//__debugbreak();
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T AllocateSize = DesiredSize; UNICODE_STRING uniFunctionName;
	if ((ULONG_PTR)DesiredAddress >= 0x70000000 && (ULONG_PTR)DesiredAddress < 0x80000000)
		DesiredAddress = (PVOID)0x70000000;
	NTSTATUS status = STATUS_SUCCESS;

	while (1)
	{
		status = (pfnZwQueryVirtualMemory(ProcessHandle, DesiredAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL));
		DPRINT("status:0x%llx", status);
		if (!NT_SUCCESS(status))
			return NULL;

		if (DesiredAddress != mbi.AllocationBase)
		{
			DesiredAddress = mbi.AllocationBase;
		}
		else
		{
			DesiredAddress = (PVOID)((ULONG_PTR)mbi.AllocationBase - 0x10000);
		}

		if (mbi.State == MEM_FREE)
		{
			if (NT_SUCCESS(ZwAllocateVirtualMemory(ProcessHandle, &mbi.BaseAddress, 0, &AllocateSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
			{
				if (NT_SUCCESS(ZwAllocateVirtualMemory(ProcessHandle, &mbi.BaseAddress, 0, &AllocateSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
				{
					return mbi.BaseAddress;
				}
			}
		}
	}
	return NULL;
}


PINJECT_BUFFER GetInlineHookCode64(IN HANDLE ProcessHandle, IN PUNICODE_STRING pDllPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PINJECT_BUFFER pBuffer = NULL;
	INJECT_BUFFER Buffer = { 0 };



	//Try to allocate before ntdll.dll
	pBuffer = (PINJECT_BUFFER)AllocateInjectMemory(ProcessHandle, (PVOID)PsNtDllBase64, PAGE_SIZE);
	if (pBuffer != NULL)
	{
		status = pfnZwReadVirtualMemory(ProcessHandle, fnHookFunc64, Buffer.original_code, sizeof(Buffer.original_code), NULL);
		if (NT_SUCCESS(status))
		{
			// Fill data
			Buffer.path.Length = min(pDllPath->Length, sizeof(Buffer.buffer));
			Buffer.path.MaximumLength = min(pDllPath->MaximumLength, sizeof(Buffer.buffer));
			Buffer.path.Buffer = (PWCH)pBuffer->buffer;
			Buffer.hook_func = fnHookFunc64;
			memcpy(Buffer.buffer, pDllPath->Buffer, Buffer.path.Length);
			memcpy(Buffer.code, HookCode64, sizeof(HookCode64));

			// Fill code
			*(ULONG*)((PUCHAR)Buffer.code + 16) = (ULONG)((ULONGLONG)&pBuffer->hook_func - ((ULONGLONG)pBuffer + 20));
			*(ULONG*)((PUCHAR)Buffer.code + 65) = (ULONG)((ULONGLONG)fnProtectVirtualMemory64 - ((ULONGLONG)pBuffer + 69));
			*(ULONG*)((PUCHAR)Buffer.code + 71) = (ULONG)((ULONGLONG)pBuffer->original_code - ((ULONGLONG)pBuffer + 75));
			*(ULONG*)((PUCHAR)Buffer.code + 83) = (ULONG)((ULONGLONG)&pBuffer->hook_func - ((ULONGLONG)pBuffer + 87));
			*(ULONG*)((PUCHAR)Buffer.code + 96) = (ULONG)((ULONGLONG)(pBuffer->original_code + 4) - ((ULONGLONG)pBuffer + 100));
			*(ULONG*)((PUCHAR)Buffer.code + 124) = (ULONG)((ULONGLONG)fnProtectVirtualMemory64 - ((ULONGLONG)pBuffer + 128));
			*(ULONG*)((PUCHAR)Buffer.code + 131) = (ULONG)((ULONGLONG)&pBuffer->module - ((ULONGLONG)pBuffer + 135));
			*(ULONG*)((PUCHAR)Buffer.code + 140) = (ULONG)((ULONGLONG)&pBuffer->path - ((ULONGLONG)pBuffer + 144));
			*(ULONG*)((PUCHAR)Buffer.code + 147) = (ULONG)((ULONGLONG)fnLdrLoadDll64 - ((ULONGLONG)pBuffer + 151));
			*(ULONG*)((PUCHAR)Buffer.code + 165) = (ULONG)((ULONGLONG)fnHookFunc64 - ((ULONGLONG)pBuffer + 169));

			//Write all
			pfnZwWriteVirtualMemory(ProcessHandle, pBuffer, &Buffer, sizeof(Buffer), NULL);

			return pBuffer;
		}
		else
		{
			DPRINT("%s: Failed to read original code %X\n", __FUNCTION__, status);
		}
	}
	else
	{
		DPRINT("%s: Failed to allocate memory\n", __FUNCTION__);
	}
	return NULL;
}
PINJECT_BUFFER GetInlineHookCode32(IN HANDLE ProcessHandle, IN PUNICODE_STRING pDllPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PINJECT_BUFFER pBuffer = NULL;
	INJECT_BUFFER Buffer = { 0 };
	//__debugbreak();

	//Try to allocate before ntdll.dll
	pBuffer = (PINJECT_BUFFER)AllocateInjectMemory(ProcessHandle, (PVOID)PsNtDllBase32, PAGE_SIZE);
	DPRINT("(pBuffer.0x%x\r\n", pBuffer);
	if (pBuffer != NULL)
	{
		//KPROCESSOR_MODE PreMode;
		//PETHREAD eThread;
		////获取当前的MODE
		//PreMode = ExGetPreviousMode();
		//if (PreMode != KernelMode) //如果非内核模式,就要开始检查IN的这些参数都否可读</span>
		//{
		//	PsLookupThreadByThreadId(PsGetCurrentThread(), &eThread); //KeGetCurrentThread();
		//	*((BYTE *)eThread + 0x1f6) = 0;
		//}
		//__debugbreak();
		ULONG OldProtect = 0;
		PVOID ProtectAddress = fnHookFunc32;
		SIZE_T ProtectSize = sizeof(Buffer.original_code);
		status = pfnZwProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, PAGE_EXECUTE_READWRITE, &OldProtect);
		if (NT_SUCCESS(status))
		{
			status = pfnZwReadVirtualMemory(ProcessHandle, fnHookFunc32, Buffer.original_code, sizeof(Buffer.original_code), NULL);
			DPRINT("original_code:%s\r\n", Buffer.original_code);
			pfnZwProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, OldProtect, &OldProtect);
		}

		if (NT_SUCCESS(status))
		{
			// Fill data
			Buffer.path32.Length = min(pDllPath->Length, sizeof(Buffer.buffer));
			Buffer.path32.MaximumLength = min(pDllPath->MaximumLength, sizeof(Buffer.buffer));
			Buffer.path32.Buffer = (ULONG)pBuffer->buffer;
			Buffer.hook_func = fnHookFunc32;
			memcpy(Buffer.buffer, pDllPath->Buffer, Buffer.path32.Length);
			memcpy(Buffer.code, HookCode32, sizeof(HookCode32));
			/*Buffer.path.Length = min(pDllPath->Length, sizeof(Buffer.buffer));
			DPRINT("Length:%d\r\n", Buffer.path.Length);
			Buffer.path.MaximumLength = min(pDllPath->MaximumLength, sizeof(Buffer.buffer));
			DPRINT("MaximumLength:%d\r\n", Buffer.path.MaximumLength);
			Buffer.path.Buffer = (PWCH)pBuffer->buffer;
			DPRINT("Buffer.path.Buffer:%s\r\n", pBuffer->buffer);
			Buffer.hook_func = fnHookFunc32;
			DPRINT("Buffer.hook_func:0x%x\r\n", Buffer.hook_func);
			memcpy(Buffer.buffer, pDllPath->Buffer, Buffer.path.Length);
			DPRINT("(Buffer.buffer:%s\r\n", Buffer.buffer);
			memcpy(Buffer.code, HookCode32, sizeof(HookCode32));
			DPRINT("(Buffer.code:%s\r\n", Buffer.code);*/
			//// Fill code
			//*(ULONG*)((PUCHAR)Buffer.code + 7) = (ULONG)((ULONG)&pBuffer->hook_func - ((ULONG)pBuffer + 11));

			//*(ULONG*)((PUCHAR)Buffer.code + 24) = (ULONG)((ULONG)fnProtectVirtualMemory32 - ((ULONG)pBuffer + 28));

			//*(ULONG*)((PUCHAR)Buffer.code + 31) = (ULONG)((ULONG)fnLdrLoadDll32 - ((ULONG)pBuffer + 34));

			//

			//*(ULONG*)((PUCHAR)Buffer.code + 59) = (ULONG)((ULONG)pBuffer->original_code - ((ULONG)pBuffer + 63));

			//*(ULONG*)((PUCHAR)Buffer.code + 95) = (ULONG)((ULONG)&pBuffer->module - ((ULONG)pBuffer + 99));

			//*(ULONG*)((PUCHAR)Buffer.code + 100) = (ULONG)((ULONG)&pBuffer->path - ((ULONG)pBuffer + 104));

			//*(ULONG*)((PUCHAR)Buffer.code + 115) = (ULONG)((ULONG)fnHookFunc32 - ((ULONG)pBuffer + 119));






			// Fill code
			*(DWORD*)((PUCHAR)Buffer.code + 7) = (DWORD)&pBuffer->hook_func;
			*(DWORD*)((PUCHAR)Buffer.code + 38) = (DWORD)((DWORD)fnProtectVirtualMemory32 - ((DWORD)pBuffer + 42));
			*(DWORD*)((PUCHAR)Buffer.code + 44) = (DWORD)&pBuffer->hook_func;
			*(DWORD*)((PUCHAR)Buffer.code + 49) = (DWORD)pBuffer->original_code;
			*(DWORD*)((PUCHAR)Buffer.code + 56) = (DWORD)pBuffer->original_code + 4;
			*(DWORD*)((PUCHAR)Buffer.code + 81) = (DWORD)((DWORD)fnProtectVirtualMemory32 - ((DWORD)pBuffer + 85));
			*(DWORD*)((PUCHAR)Buffer.code + 86) = (DWORD)&pBuffer->module;
			*(DWORD*)((PUCHAR)Buffer.code + 91) = (DWORD)(&pBuffer->path32);
			*(DWORD*)((PUCHAR)Buffer.code + 100) = (DWORD)((DWORD)fnLdrLoadDll32 - ((DWORD)pBuffer + 104));
			*(DWORD*)((PUCHAR)Buffer.code + 108) = (DWORD)((DWORD)fnHookFunc32 - ((DWORD)pBuffer + 112));
			DPRINT("(Buffer.code:%s\r\n", Buffer.code);

			//Write all
			pfnZwWriteVirtualMemory(ProcessHandle, pBuffer, &Buffer, sizeof(Buffer), NULL);

			return pBuffer;
		}
		else
		{
			DPRINT("%s: Failed to read original code %X\n", __FUNCTION__, status);
		}
	}
	else
	{
		DPRINT("%s: Failed to allocate memory\n", __FUNCTION__);
	}
	return NULL;
}




NTSTATUS InjectByHook64(HANDLE ProcessId, PVOID ImageBase, PUNICODE_STRING pDllPath)
{
	ULONG ReturnLength;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS Process = NULL;
	HANDLE ProcessHandle = NULL;

	if (!PsNtDllBase64)
		PsNtDllBase64 = ImageBase;


	status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(status))
	{
		//Do not inject WOW64 process
		status = STATUS_UNSUCCESSFUL;
		if (pfnPsGetProcessWoW64Process(Process) == NULL)
		{
			status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);
			if (NT_SUCCESS(status))
			{
				KAPC_STATE kApc;

				if (!fnLdrLoadDll64 || !fnHookFunc64 || !fnProtectVirtualMemory64)
				{
					//KeStackAttachProcess(Process, &kApc);
					fnProtectVirtualMemory64 = (PVOID)GetDllFunctionAddress("ZwProtectVirtualMemory", PsNtDllBase64);//SearchModuleAndFindFuncAddrInTarget64(Process,"ZwProtectVirtualMemory");
					fnLdrLoadDll64 = (PVOID)GetDllFunctionAddress("LdrLoadDll", PsNtDllBase64);//SearchModuleAndFindFuncAddrInTarget64(Process,"LdrLoadDll");
					fnHookFunc64 = (PVOID)GetDllFunctionAddress("ZwTestAlert", PsNtDllBase64);//SearchModuleAndFindFuncAddrInTarget64(Process,"ZwTestAlert");
																							  //KeUnstackDetachProcess(&kApc);
					DPRINT("ZwProtectVirtualMemory addr:0x%x LdrLoadDll:0x%x ZwTestAlert:0x%x\r\n", fnProtectVirtualMemory64, fnLdrLoadDll64, fnHookFunc64);
				}

				status = STATUS_UNSUCCESSFUL;

				if (fnLdrLoadDll64 && fnHookFunc64 && fnProtectVirtualMemory64)
				{
					PINJECT_BUFFER pBuffer = GetInlineHookCode64(ProcessHandle, pDllPath);
					if (pBuffer)
					{
						UCHAR trampo[] = { 0xE9, 0, 0, 0, 0 };
						ULONG OldProtect = 0;
						PVOID ProtectAddress = fnHookFunc64;
						SIZE_T ProtectSize = sizeof(trampo);

						*(DWORD *)(trampo + 1) = (DWORD)((ULONG_PTR)pBuffer->code - ((ULONG_PTR)fnHookFunc64 + 5));

						status = pfnZwProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, PAGE_EXECUTE_READWRITE, &OldProtect);
						if (NT_SUCCESS(status))
						{
							pfnZwWriteVirtualMemory(ProcessHandle, fnHookFunc64, trampo, sizeof(trampo), &ReturnLength);
							pfnZwProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, OldProtect, &OldProtect);
						}
					}
				}

				ZwClose(ProcessHandle);
			}
		}
		ObDereferenceObject(Process);
	}

	return status;
}
NTSTATUS InjectByHook32(HANDLE ProcessId, PVOID ImageBase, PUNICODE_STRING pDllPath)
{
	ULONG ReturnLength;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS Process = NULL;
	HANDLE ProcessHandle = NULL;
	//__debugbreak();
	if (!PsNtDllBase32)
		PsNtDllBase32 = ImageBase;


	status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(status))
	{
		//Do not inject WOW64 process
		status = STATUS_UNSUCCESSFUL;
		if (pfnPsGetProcessWoW64Process(Process) != NULL)
		{
			DPRINT("32 bit Process\r\n");
			status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);
			if (NT_SUCCESS(status))
			{
				KAPC_STATE kApc;

				if (!fnLdrLoadDll32 || !fnHookFunc32 || !fnProtectVirtualMemory32)
				{
					//KeStackAttachProcess(Process, &kApc);
					fnProtectVirtualMemory32 = (PVOID)GetDllFunctionAddress("ZwProtectVirtualMemory", PsNtDllBase32);//SearchModuleAndFindFuncAddrInTarget32(Process,L"ZwProtectVirtualMemory");
					fnLdrLoadDll32 = (PVOID)GetDllFunctionAddress("LdrLoadDll", PsNtDllBase32);//SearchModuleAndFindFuncAddrInTarget32(Process, L"LdrLoadDll");
					fnHookFunc32 = (PVOID)GetDllFunctionAddress("ZwTestAlert", PsNtDllBase32);//SearchModuleAndFindFuncAddrInTarget32(Process, L"ZwTestAlert");
					DPRINT("ZwProtectVirtualMemory addr:0x%x LdrLoadDll:0x%x ZwTestAlert:0x%x\r\n", fnProtectVirtualMemory32, fnLdrLoadDll32, fnHookFunc32);
					//KeUnstackDetachProcess(&kApc);
				}

				status = STATUS_UNSUCCESSFUL;

				if (fnLdrLoadDll32 && fnHookFunc32 && fnProtectVirtualMemory32)
				{
					PINJECT_BUFFER pBuffer = GetInlineHookCode32(ProcessHandle, pDllPath);
					if (pBuffer)
					{
						UCHAR trampo[] = { 0xE9, 0, 0, 0, 0 };
						ULONG OldProtect = 0;
						PVOID ProtectAddress = fnHookFunc32;
						SIZE_T ProtectSize = sizeof(trampo);

						*(DWORD *)(trampo + 1) = (DWORD)((ULONG_PTR)pBuffer->code - ((ULONG_PTR)fnHookFunc32 + 5));

						status = pfnZwProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, PAGE_EXECUTE_READWRITE, &OldProtect);
						if (NT_SUCCESS(status))
						{
							pfnZwWriteVirtualMemory(ProcessHandle, fnHookFunc32, trampo, sizeof(trampo), &ReturnLength);
							pfnZwProtectVirtualMemory(ProcessHandle, &ProtectAddress, &ProtectSize, OldProtect, &OldProtect);
						}
					}
				}

				ZwClose(ProcessHandle);
			}
		}
		ObDereferenceObject(Process);
	}

	return status;
}
VOID LoadConfig()
{
	HANDLE				hFile;
	FILE_STANDARD_INFORMATION   fbi;
	ULONG				FileLength;
	OBJECT_ATTRIBUTES	ObjectAttributes;
	UNICODE_STRING		ustrFileName;
	NTSTATUS			status;
	IO_STATUS_BLOCK		IoStatusBlock = { 0 };
	RtlInitUnicodeString(&ustrFileName, L"\\??\\C:\\gpoc.cfg");
	//初始化ObjectAttributes
	InitializeObjectAttributes(&ObjectAttributes,
		&ustrFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	//打开配置文件
	status = ZwCreateFile(&hFile,
		GENERIC_READ,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);


	//打开失败
	if (!NT_SUCCESS(status))
	{
		return;
	}

	//获得配置文件大小
	status = ZwQueryInformationFile(hFile,
		&IoStatusBlock,
		&fbi,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	FileLength = fbi.EndOfFile.LowPart;

	status = ZwReadFile(hFile,
		NULL,
		NULL,
		NULL,
		&IoStatusBlock,
		g_Read_Buffer.buffer,
		FileLength,
		NULL, NULL);
	g_Read_Buffer.buffer[FileLength] = '\0';


	ZwClose(hFile);
}
//判断进程是否在配置文件中
BOOLEAN FileGoFind(CHAR *curProc)
{
	ULONG Count;
	BOOLEAN ret = FALSE;

	if (!curProc)
	{
		DPRINT("FileGoFind curprocess == 0\n");
		return ret;
	}


	if (!strncmp(g_Read_Buffer.buffer,
		(PCHAR)curProc,
		strlen((PCHAR)curProc)))
	{

		return TRUE;

	}



	return ret;
}
VOID LoadImageNotifyCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO pImageInfo)
{
	PEPROCESS Process;
	UNICODE_STRING		ustrFileName;
	DPRINT("NTDLL addr is0x%llx\r\n", pImageInfo->ImageBase);

	if (ProcessId == (HANDLE)0 || ProcessId == (HANDLE)4)
		return;

	if (!FullImageName || !FullImageName->Length)
		return;

	if (pImageInfo->SystemModeImage)
		return;

	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
	{

		PCHAR ProcessName = (PCHAR)PsGetProcessImageFileName(Process);

		if (ProcessName && FileGoFind(ProcessName))
		{
			//ntdll.dll
			if (0 == _wcsnicmp(FullImageName->Buffer, L"\\SystemRoot\\System32\\ntdll.dll", sizeof("\\SystemRoot\\System32\\ntdll.dll") * 2))
			{

				if (m_GlobalInjectDllPath64.Length != 0)
					InjectByHook64(ProcessId, pImageInfo->ImageBase, &m_GlobalInjectDllPath64);

				/*if (m_GlobalInjectDllPath32.Length != 0)
				InjectByHook64(ProcessId, pImageInfo->ImageBase, &m_GlobalInjectDllPath32);*/

				return;
			}


			if (0 == _wcsnicmp(FullImageName->Buffer, L"\\SystemRoot\\SysWOW64\\ntdll.dll", sizeof("\\SystemRoot\\SysWOW64\\ntdll.dll") * 2))
			{
				if (m_GlobalInjectDllPath32.Length != 0)
					InjectByHook32(ProcessId, pImageInfo->ImageBase, &m_GlobalInjectDllPath32);
				return;
			}

		}
	}
	ObDereferenceObject(Process);
}
//卸载驱动
VOID ExitInjectProcess(PDRIVER_OBJECT pDriverObject)
{
	DPRINT("DriverUnload");
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);


}
PSERVICE_DESCRIPTOR_TABLE GetSsdtExTable(unsigned char *ZwCloseProcBase, BOOLEAN SsdtType)
{

	LDE Ldex64 = NULL;
	int nIndex;
	DWORD64 OpcodeLength;
	BOOLEAN IsFound;
	LONG ImmTemp;
	DWORD_PTR UsignedImmTemp;
	unsigned char * KiServiceInternal;
	DWORD_PTR KeServiceDescriptorTableShadow;

	if (ZwCloseProcBase == NULL)
	{
		return NULL;
	}
	Ldex64 = (LDE)ExAllocatePool(NonPagedPool, sizeof(LdeCode));
	if (Ldex64 == NULL)
	{
		return FALSE;
	}
	RtlCopyMemory(Ldex64, LdeCode, sizeof(LdeCode));

	IsFound = FALSE;
	for (nIndex = 0; nIndex<30; nIndex++)
	{
		if (MmIsAddressValid(ZwCloseProcBase))
		{
			OpcodeLength = Ldex64((DWORD64)ZwCloseProcBase, 64);
			if (OpcodeLength == 5)
			{
				if (ZwCloseProcBase[0] == 0xe9)
				{
					IsFound = TRUE;
					break;

				}
			}
			ZwCloseProcBase += OpcodeLength;
		}
	}
	if (!IsFound)
	{
		DPRINT("get ZwCloseProcBase call failed\n");
		return NULL;
	}
	ImmTemp = *(LONG*)(&ZwCloseProcBase[1]);

	UsignedImmTemp = (DWORD_PTR)ImmTemp;
	KiServiceInternal = (unsigned char *)((DWORD_PTR)ZwCloseProcBase + 5 + UsignedImmTemp);

	DPRINT("KiServiceInternal:%p\n", KiServiceInternal);

	/*
	fffff800`03c8ffea 83e720          and     edi,20h
	fffff800`03c8ffed 25ff0f0000      and     eax,0FFFh
	nt!KiSystemServiceRepeat:
	fffff800`03c8fff2 4c8d1547782300  lea     r10,[nt!KeServiceDescriptorTable (fffff800`03ec7840)]
	fffff800`03c8fff9 4c8d1d80782300  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff800`03ec7880)]
	*/
	IsFound = FALSE;
	for (nIndex = 0; nIndex<150; nIndex++)
	{
		if (MmIsAddressValid(KiServiceInternal))
		{
			OpcodeLength = Ldex64((DWORD64)KiServiceInternal, 64);
			if (OpcodeLength == 5)
			{
				if (KiServiceInternal[0] == 0x25 &&
					KiServiceInternal[1] == 0xff &&
					KiServiceInternal[2] == 0x0f &&
					KiServiceInternal[3] == 0x00 &&
					KiServiceInternal[4] == 0x00)
				{
					KiServiceInternal += OpcodeLength;

					OpcodeLength = Ldex64((DWORD64)KiServiceInternal, 64);
					if (OpcodeLength == 7)
					{
						//4c 8d 15
						if (KiServiceInternal[0] == 0x4c &&
							KiServiceInternal[1] == 0x8d &&
							KiServiceInternal[2] == 0x15)
						{
							//get ssdt
							if (SsdtType)
							{
								IsFound = TRUE;
								break;
							}
							KiServiceInternal += OpcodeLength;

							OpcodeLength = Ldex64((DWORD64)KiServiceInternal, 64);
							if (OpcodeLength == 7)
							{
								//4c 8d 1d
								if (KiServiceInternal[0] == 0x4c &&
									KiServiceInternal[1] == 0x8d &&
									KiServiceInternal[2] == 0x1d)
								{
									//__debugbreak();
									IsFound = TRUE;
									break;
								}
							}
						}

					}

				}
			}
			KiServiceInternal += OpcodeLength;
		}

	}
	if (!IsFound)
	{
		return NULL;
	}
	ImmTemp = *(LONG*)(&KiServiceInternal[3]);
	UsignedImmTemp = (DWORD_PTR)ImmTemp;

	KeServiceDescriptorTableShadow = (DWORD_PTR)KiServiceInternal + 7 + UsignedImmTemp;

	DPRINT("SSDTEx Table:%p\n", KeServiceDescriptorTableShadow);

	return (PSERVICE_DESCRIPTOR_TABLE)KeServiceDescriptorTableShadow;
}

PVOID GetProc(HANDLE hMod, char *lpFunctionName)
{
	IMAGE_DOS_HEADER* dosheader;
	IMAGE_OPTIONAL_HEADER* opthdr;
	IMAGE_EXPORT_DIRECTORY* pExportTable;
	DWORD* arrayOfFunctionAddresses;
	DWORD* arrayOfFunctionNames;
	WORD* arrayOfFunctionOrdinals;
	DWORD_PTR functionOrdinal;
	DWORD_PTR Base, x;
	PVOID functionAddress;
	char* functionName;
	STRING ntFunctionName, ntFunctionNameSearch;
	PVOID BaseAddress = NULL;
	SIZE_T size = 0;

	dosheader = (IMAGE_DOS_HEADER *)hMod;

	opthdr = (IMAGE_OPTIONAL_HEADER *)((BYTE*)hMod + dosheader->e_lfanew + 24);

	if (strcmp(lpFunctionName, "__ImageBaseAddress") == 0) {
		return (PVOID)opthdr->ImageBase;
	}

	pExportTable = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hMod + opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// now we can get the exported functions, but note we convert from RVA to address
	arrayOfFunctionAddresses = (DWORD*)((BYTE*)hMod + pExportTable->AddressOfFunctions);

	arrayOfFunctionNames = (DWORD*)((BYTE*)hMod + pExportTable->AddressOfNames);

	arrayOfFunctionOrdinals = (WORD*)((BYTE*)hMod + pExportTable->AddressOfNameOrdinals);

	Base = pExportTable->Base;

	RtlInitString(&ntFunctionNameSearch, lpFunctionName);

	for (x = 0; x < pExportTable->NumberOfFunctions; x++)
	{
		functionName = (char*)((BYTE*)hMod + arrayOfFunctionNames[x]);

		RtlInitString(&ntFunctionName, functionName);

		functionOrdinal = arrayOfFunctionOrdinals[x] + Base - 1; // always need to add base, -1 as array counts from 0
																 // this is the funny bit.  you would expect the function pointer to simply be arrayOfFunctionAddresses[x]...
																 // oh no... thats too simple.  it is actually arrayOfFunctionAddresses[functionOrdinal]!!
		functionAddress = (PVOID)((BYTE*)hMod + arrayOfFunctionAddresses[functionOrdinal]);
		if (RtlCompareString(&ntFunctionName, &ntFunctionNameSearch, TRUE) == 0)
		{
			DPRINT("%s functionAddress :0x%llx\r\n", lpFunctionName, functionAddress);
			return (PVOID)functionAddress;
		}
	}

	return 0;

}


ULONG GetSyscallIndex(HANDLE dll, char *syscall)
{
	//__debugbreak();
	ULONG     uIndex = 0;
	ULONG_PTR functionAddress = (ULONG_PTR)GetProc(dll, syscall);

	if (!functionAddress) {
		return 0;
	}


#ifdef _AMD64_  
	uIndex = *(PULONG)((PUCHAR)functionAddress + 4);
#else  
	uIndex = *(PULONG)((PUCHAR)functionAddress + 1);
#endif  
	return uIndex;
}
ULONG64 GetSSDTFuncCurAddr(PULONG FixKiServiceTable, PULONG Index)
{
	//__debugbreak();
	ULONG64 RoutineBase;

	LONG Temp;
	ULONG64 HookRoutine;

	RoutineBase = (ULONG64)FixKiServiceTable;
	Temp = (LONG)FixKiServiceTable[*Index];
	Temp = Temp >> 4;
	HookRoutine = RoutineBase + (LONG64)Temp;
	return HookRoutine;
}
BOOL GetFuncAddr()
{
	//获取SSDT表
	KeServiceDescriptorTable = NULL;

	UNICODE_STRING FunctionName;
	unsigned char *ZwCloseProc;
	HANDLE ntdll;
	LONG scale = 0;
	RtlInitUnicodeString(&FunctionName, L"ZwClose");
	ULONG ZwReadVirtualMemoryId, ZwWriteVirtualMemoryId, ZwProtectVirtualMemoryId, ZwReadFileId, ZwCreateFileId, ZwQueryVirtualMemoryId;
	ZwCloseProc = (unsigned char *)MmGetSystemRoutineAddress(&FunctionName);
	if (ZwCloseProc == NULL)
	{
		return FALSE;
	}
	KeServiceDescriptorTable = GetSsdtExTable(ZwCloseProc, TRUE);
	if (!KeServiceDescriptorTable)
	{
		DPRINT("get KeServiceDescriptorTable failed\n");
		return FALSE;
	}
#ifdef _WIN64
	ntdll = KLoadLibrary(L"\\SystemRoot\\System32\\ntdll.dll");
#else
	ntdll = KLoadLibrary(L"\\SystemRoot\\SysWOW64\\ntdll.dll");
#endif
	if (!ntdll)
	{
		DPRINT("Load Ntdll failed!\r\n");
		return FALSE;
	}
	//__debugbreak();
	ZwQueryVirtualMemoryId = GetSyscallIndex(ntdll, "ZwQueryVirtualMemory");
	ZwReadFileId = GetSyscallIndex(ntdll, "ZwReadFile");
	ZwCreateFileId = GetSyscallIndex(ntdll, "ZwCreateFile");
	ZwReadVirtualMemoryId = GetSyscallIndex(ntdll, "ZwReadVirtualMemory");
	ZwWriteVirtualMemoryId = GetSyscallIndex(ntdll, "ZwWriteVirtualMemory");
	ZwProtectVirtualMemoryId = GetSyscallIndex(ntdll, "ZwProtectVirtualMemory");
	DPRINT("ZwReadVirtualMemoryId:%d ZwWriteVirtualMemoryId:%d ZwProtectVirtualMemoryId:%d ZwReadFileId:%d ZwCreateFileId:%d ZwQueryVirtualMemoryId:%d\r\n", ZwReadVirtualMemoryId, ZwWriteVirtualMemoryId, ZwProtectVirtualMemoryId, ZwReadFileId, ZwCreateFileId, ZwQueryVirtualMemoryId);

	RtlInitUnicodeString(&FunctionName, L"ZwReadFile");
	pfnZwReadFile = (ZWREADFILE)(SIZE_T)MmGetSystemRoutineAddress(&FunctionName);

	RtlInitUnicodeString(&FunctionName, L"ZwCreateFile");
	pfnZwCreateFile = (ZWCREATEFILE)(SIZE_T)MmGetSystemRoutineAddress(&FunctionName);

	scale = (LONG)(((LONG)((DWORD_PTR)pfnZwCreateFile - (DWORD_PTR)pfnZwReadFile)) / (ZwCreateFileId - ZwReadFileId));
	if (scale)
	{
		pfnZwReadVirtualMemory = (ZWREADVIRTUALMEMORY)(DWORD_PTR)((ZwReadVirtualMemoryId - ZwReadFileId)*scale + (DWORD_PTR)pfnZwReadFile);
		pfnZwWriteVirtualMemory = (ZWWRITEVIRTUALMEMORY)(DWORD_PTR)((ZwWriteVirtualMemoryId - ZwReadFileId)*scale + (DWORD_PTR)pfnZwReadFile);
		pfnZwProtectVirtualMemory = (ZWPROTECTVIRTUALMEMORY)(DWORD_PTR)((ZwProtectVirtualMemoryId - ZwReadFileId)*scale + (DWORD_PTR)pfnZwReadFile);
		pfnZwQueryVirtualMemory = (ZWQUERYVIRTUALMEMORY)(DWORD_PTR)((ZwQueryVirtualMemoryId - ZwReadFileId)*scale + (DWORD_PTR)pfnZwReadFile);
	}
	else
		DPRINT("scale is zero!\r\n");
	/*pfnZwReadVirtualMemory = (NTREADVIRTUALMEMORY)GetSSDTFuncCurAddr((PULONG)KeServiceDescriptorTable->ServiceTable, &ZwReadVirtualMemoryId);
	pfnZwWriteVirtualMemory = (NTWRITEVIRTUALMEMORY)GetSSDTFuncCurAddr((PULONG)KeServiceDescriptorTable->ServiceTable, &ZwWriteVirtualMemoryId);
	pfnZwProtectVirtualMemory = (NTPROTECTVIRTUALMEMORY)GetSSDTFuncCurAddr((PULONG)KeServiceDescriptorTable->ServiceTable, &ZwProtectVirtualMemoryId);
	return TRUE;*/
	return TRUE;
}
void  Test()
{
	static UCHAR fnOriCode[5];
	static UNICODE_STRING ModuleName;
	static HANDLE ModuleHandle;


	ULONG OldProtect;
	PVOID Base = fnHookFunc32;
	SIZE_T Len = 5;

	NTPROTECTVIRTUALMEMORY fnProtectVirtualMemory32 = 0;
	LDRLOADDLL fnLdrLoadDll = 0;
	fnProtectVirtualMemory32((HANDLE)-1, &Base, &Len, PAGE_EXECUTE_READWRITE, &OldProtect);

	memcpy(Base, fnOriCode, 5);

	fnProtectVirtualMemory32((HANDLE)-1, &Base, &Len, OldProtect, &OldProtect);

	fnLdrLoadDll(0, 0, &ModuleName, &ModuleHandle);
}
NTSTATUS InjectProcess()
{
	NTSTATUS status = STATUS_SUCCESS;
	PKTIMER	Timer;
	PEPROCESS curProc;
	UNICODE_STRING uniFunctionName;
	RtlInitUnicodeString(&uniFunctionName, L"PsGetProcessWow64Process");
	//__debugbreak();
	pfnPsGetProcessWoW64Process = (PSGETPROCESSWOW64PROCESS)(SIZE_T)MmGetSystemRoutineAddress(&uniFunctionName);

	if (!GetFuncAddr() || !pfnPsGetProcessWoW64Process || !pfnZwReadVirtualMemory || !pfnZwWriteVirtualMemory || !pfnZwProtectVirtualMemory)
	{
		DPRINT("DriverEntry:Get Func addr is Failed!pfnPsGetProcessWoW64Process:0x%llx pfnNtReadVirtualMemory:0x%llx pfnNtWriteVirtualMemory:0x%llx pfnNtProtectVirtualMemory:0x%llx pfnZwQueryVirtualMemory:0x%llx\r\n", pfnPsGetProcessWoW64Process, pfnZwReadVirtualMemory, pfnZwWriteVirtualMemory, pfnZwProtectVirtualMemory, pfnZwQueryVirtualMemory);
		return status;
	}
	DPRINT("DriverEntry:Get Func addr is Success!pfnPsGetProcessWoW64Process:0x%llx pfnNtReadVirtualMemory:0x%llx pfnNtWriteVirtualMemory:0x%llx pfnNtProtectVirtualMemory:0x%llx pfnZwQueryVirtualMemory:0x%llx\r\n", pfnPsGetProcessWoW64Process, pfnZwReadVirtualMemory, pfnZwWriteVirtualMemory, pfnZwProtectVirtualMemory, pfnZwQueryVirtualMemory);
	DPRINT("Enter Driver\r\n");
	LoadConfig();

	RtlInitUnicodeString(&m_GlobalInjectDllPath32, L"C:\\Windows\\SysWoW64\\COMMHLP32.dll"); //SysWOW64
	RtlInitUnicodeString(&m_GlobalInjectDllPath64, L"C:\\InjectDll.dll");




	//原本想采用进程回调来实现，但写到一半发现
	//进程回调函数调用时机太早了,Peb竟然都没初始化
	//所以就改用加载模块回调来实现

	//由于SetLoadImageNotifyRoutine回调时机的问题。
	status = PsSetLoadImageNotifyRoutine(LoadImageNotifyCallback);


	DPRINT("PsSetLoadImageNotifyRoutine ok!\r\n");

	return status;
}