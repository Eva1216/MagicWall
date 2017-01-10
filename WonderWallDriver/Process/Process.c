#include "Process.h"

BOOLEAN  GetProcessImageNameByProcessID(ULONG32 ulProcessID, CHAR* szProcessImageName, ULONG32* ulProcessImageNameLength)
{

	NTSTATUS  Status;
	PEPROCESS  EProcess = NULL;
	Status = PsLookupProcessByProcessId((HANDLE)ulProcessID, &EProcess);

	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}


	if (EProcess == NULL)
	{
		return FALSE;
	}

	ObDereferenceObject(EProcess);




	if (strlen(PsGetProcessImageFileName(EProcess))>MAX_PATH)
	{
		*ulProcessImageNameLength = MAX_PATH - 1;
	}

	else
	{
		*ulProcessImageNameLength = strlen(PsGetProcessImageFileName(EProcess));
	}


	memcpy(szProcessImageName, PsGetProcessImageFileName(EProcess), *ulProcessImageNameLength);


	return TRUE;

}


BOOLEAN GetProcessFullPathByProcessID(ULONG32	ulProcessID, WCHAR* wzProcessFullPath, ULONG32* ulProcessFullPathLength)
{

	//进程的名称存储在进程的EProcess当前
	NTSTATUS  Status;
	PEPROCESS EProcess = NULL;
	HANDLE    hProcess = NULL;
	PVOID     ProcessInformation = NULL;
	ULONG32   ulReturnLength = 0;
	OBJECT_ATTRIBUTES oa;
	HANDLE    hFile = NULL;
	IO_STATUS_BLOCK Iosb;
	PVOID  FileObject = NULL;
	POBJECT_NAME_INFORMATION    ObjectNameInformation = NULL;


	Status = PsLookupProcessByProcessId((HANDLE)ulProcessID, &EProcess);

	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	ObDereferenceObject(EProcess);
	//判断是否有效
	if (EProcess != NULL)
	{


		Status = ObOpenObjectByPointer(EProcess, OBJ_KERNEL_HANDLE,
			NULL, PROCESS_QUERY_INFORMATION, *PsProcessType, KernelMode, &hProcess);
		//将EProcess 转换成进程句柄
		if (!NT_SUCCESS(Status))
		{
			return FALSE;
		}
		else
		{
			if (ZwQueryInformationProcess(hProcess, ProcessImageFileName,
				ProcessInformation, ulReturnLength, (PULONG)&ulReturnLength) == STATUS_INFO_LENGTH_MISMATCH)
			{
				ProcessInformation = ExAllocatePool(PagedPool, ulReturnLength);
				if (ProcessInformation == NULL)
				{
					ZwClose(hProcess);
					return FALSE;
				}
				else
				{
					if (!NT_SUCCESS(ZwQueryInformationProcess(hProcess,
						ProcessImageFileName, ProcessInformation, ulReturnLength, (PULONG)&ulReturnLength)))
					{
						ExFreePool(ProcessInformation);
						ProcessInformation = NULL;
						ZwClose(hProcess);
						return FALSE;
					}
					else
					{
						 			
						InitializeObjectAttributes(&oa, (PUNICODE_STRING)ProcessInformation,
							OBJ_CASE_INSENSITIVE | KernelMode, NULL, NULL);

						if (!NT_SUCCESS(ZwOpenFile(&hFile, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa,
							&Iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT)))
						{
							ExFreePool(ProcessInformation);
							ProcessInformation = NULL;
							ZwClose(hProcess);
							return FALSE;
						}

						else
						{

							//文件句柄得到文件对象
							if (NT_SUCCESS(ObReferenceObjectByHandle(hFile,
								FILE_READ_ATTRIBUTES, *IoFileObjectType,
								KernelMode, (PVOID*)&FileObject, NULL)))
							{
								if (NT_SUCCESS(IoQueryFileDosDeviceName((PFILE_OBJECT)FileObject,
									&ObjectNameInformation)))
								{

									if (((PUNICODE_STRING)ObjectNameInformation)->Length >= MAX_PATH)
									{
										*ulProcessFullPathLength = MAX_PATH - 1;
									}

									else
									{
										*ulProcessFullPathLength = ((PUNICODE_STRING)ObjectNameInformation)->Length;
									}

									memcpy(wzProcessFullPath,
										((PUNICODE_STRING)ObjectNameInformation)->Buffer,
										(*ulProcessFullPathLength) * sizeof(WCHAR));


									DbgPrint("%S\r\n", wzProcessFullPath);

									ExFreePool(ProcessInformation);
									ProcessInformation = NULL;
									ExFreePool(ObjectNameInformation);
									ObjectNameInformation = NULL;
									ZwClose(hProcess);
									ObDereferenceObject(FileObject);
									ZwClose(hFile);
									hFile = NULL;

									return TRUE;

								}
								else
								{
									ObDereferenceObject(FileObject);
									ZwClose(hFile);
									hFile = NULL;
									ExFreePool(ProcessInformation);
									ProcessInformation = NULL;
									ZwClose(hProcess);
									return FALSE;
								}
							}
							else
							{

								ZwClose(hFile);
								hFile = NULL;
								ExFreePool(ProcessInformation);
								ProcessInformation = NULL;
								ZwClose(hProcess);
								return FALSE;
							}
						}
					}
				}
			}
		}
	}

	return FALSE;

}

