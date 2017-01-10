#include "Driver.h"




WONDERWALL_NT_EXPORT RhInstallDriver(
	WCHAR* InDriverPath,
	WCHAR* InDriverName)
{
	WCHAR				DriverPath[MAX_PATH + 1];
	SC_HANDLE			SCManagerHandle = NULL;
	SC_HANDLE			ServiceHandle = NULL;
	NTSTATUS			NtStatus;

	GetFullPathNameW(InDriverPath, MAX_PATH, DriverPath, NULL);

	if (!RtlFileExists(DriverPath))
		THROW(STATUS_NOT_FOUND, L"The EasyHook driver file does not exist.");

	if ((SCManagerHandle = OpenSCManagerW(
		NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS)) == NULL)
		THROW(STATUS_ACCESS_DENIED, L"Unable to open service control manager. Are you running as administrator?");

	// 检查服务是否存在
	if ((ServiceHandle = OpenService(
		SCManagerHandle,
		InDriverName,
		SERVICE_ALL_ACCESS)) == NULL)
	{
		if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST)
			THROW(STATUS_INTERNAL_ERROR, L"An unknown error has occurred during driver installation.");

		// 创建服务
		if ((ServiceHandle = CreateServiceW(
			SCManagerHandle,
			InDriverName,
			InDriverName,
			SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_NORMAL,
			DriverPath,
			NULL, NULL, NULL, NULL, NULL)) == NULL)
			THROW(STATUS_INTERNAL_ERROR, L"Unable to install driver.");
	}

	// 开始并连接服务
	if (!StartServiceW(ServiceHandle, 0, NULL) && (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
		&& (GetLastError() != ERROR_SERVICE_DISABLED))
		THROW(STATUS_INTERNAL_ERROR, L"Unable to start driver!");

	RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
	{
		if (ServiceHandle != NULL)
		{
			DeleteService(ServiceHandle);

			CloseServiceHandle(ServiceHandle);
		}

		if (SCManagerHandle != NULL)
			CloseServiceHandle(SCManagerHandle);

		return NtStatus;
	}

	 
}