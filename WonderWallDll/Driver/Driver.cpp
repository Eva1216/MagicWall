#include "Driver.h"
#include "..\stdafx.h"
#include "..\DriverShared\rtl.h"
#include "..\WonderWallDll.h"
WONDERWALL_NT_EXPORT RhInstallDriver(
	WCHAR* InDriverPath,
	WCHAR* InDriverName)
{
	WCHAR				DriverPath[MAX_PATH + 1];
	SC_HANDLE			hSCManager = NULL;
	SC_HANDLE			hService = NULL;
	NTSTATUS			NtStatus;

	GetFullPathNameW(InDriverPath, MAX_PATH, DriverPath, NULL);

	if (!RtlFileExists(DriverPath))
		THROW(STATUS_NOT_FOUND, L"The EasyHook driver file does not exist.");

	if ((hSCManager = OpenSCManagerW(
		NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS)) == NULL)
		THROW(STATUS_ACCESS_DENIED, L"Unable to open service control manager. Are you running as administrator?");

	// does service exist?
	if ((hService = OpenService(
		hSCManager,
		InDriverName,
		SERVICE_ALL_ACCESS)) == NULL)
	{
		if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST)
			THROW(STATUS_INTERNAL_ERROR, L"An unknown error has occurred during driver installation.");

		// Create the service
		if ((hService = CreateServiceW(
			hSCManager,
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

	// start and connect service...
	if (!StartServiceW(hService, 0, NULL) && (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
		&& (GetLastError() != ERROR_SERVICE_DISABLED))
		THROW(STATUS_INTERNAL_ERROR, L"Unable to start driver!");

	RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
	{
		if (hService != NULL)
		{
			DeleteService(hService);

			CloseServiceHandle(hService);
		}

		if (hSCManager != NULL)
			CloseServiceHandle(hSCManager);

		return NtStatus;
	}

	 
}