#include "WonderWallDriver.h"
#include "Common.h"
#include "Trace.h"
NTSTATUS  DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
	NTSTATUS        Status;
	UNICODE_STRING  uniDeviceName;
	UNICODE_STRING  uniLinkName;
	PDEVICE_OBJECT  DeviceObject = NULL;
	int             i = 0;
	RtlInitUnicodeString(&uniDeviceName, DEVICE_NAME);

	DbgPrint("Wonder	Wall\r\n");


	Status = IoCreateDevice(DriverObject, 0, &uniDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	if (!NT_SUCCESS(Status))
	{
		return STATUS_UNSUCCESSFUL;
	}


	//创建一个LinkName
	RtlInitUnicodeString(&uniLinkName, LINK_NAME);


	Status = IoCreateSymbolicLink(&uniLinkName, &uniDeviceName);

	if (!NT_SUCCESS(Status))
	{

		IoDeleteDevice(DeviceObject);
		DeviceObject = NULL;
		return STATUS_UNSUCCESSFUL;
	}


	DriverObject->DriverUnload = UnloadDriver;
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = DefaultPassDispatch;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ControlPassDispatch;
	return STATUS_SUCCESS;
}

NTSTATUS ControlPassDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{

	PIO_STACK_LOCATION     IrpSp = NULL;
	ULONG_PTR ulIoControlCode = 0;
	PVOID     InputData = NULL;
	PVOID     OutputData = NULL;
	ULONG_PTR ulInputSize = 0;
	ULONG_PTR ulOutputSize = 0;
	CHAR      szProcessImageName[MAX_PATH] = { 0 };
	WCHAR     wzProcessFullName[MAX_PATH] = { 0 };
	ULONG32   ulProcessImageNameLength = 0;
	ULONG32   ulProcessFullNameLength = 0;
	ULONG32   ulProcessID = 0;
	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	InputData = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
	OutputData = Irp->UserBuffer;
	ulInputSize = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
	ulOutputSize = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
	ulIoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

	switch (ulIoControlCode)
	{
	case CTL_GETPROCESSIMAGNAMEBYID:
	{
		if (InputData != NULL&&ulInputSize == sizeof(ULONG32))
		{
			memcpy(&ulProcessID, InputData, sizeof(ULONG32));

			if (GetProcessFullPathByProcessID(ulProcessID, wzProcessFullName, &ulProcessFullNameLength) == TRUE)
			{
				memcpy(((PPROCESSENTRY32)OutputData)->szExeFile, wzProcessFullName, ulProcessFullNameLength);
			}
			//if (GetProcessImageNameByProcessID(ulProcessID, szProcessImageName, &ulProcessImageNameLength) == TRUE)
			{
				//memcpy(((PPROCESS_INFORMATION)OutputData)->szProcessName, szProcessImageName, ulProcessImageNameLength);
				//((PPROCESS_INFORMATION)OutputData)->ProcessNameLength = ulProcessImageNameLength;

			}
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = ulProcessFullNameLength;

			IoCompleteRequest(Irp, IO_NO_INCREMENT);

			return STATUS_SUCCESS;
		}
		break;
	}
	case	CTL_INJECTPROCESS:
	{
		InjectProcess();
		break;
	}
	}

	Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;

}




NTSTATUS DefaultPassDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{


	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


VOID  UnloadDriver(PDRIVER_OBJECT DriverObject)
{


	//销毁链接名称
	UNICODE_STRING  uniLinkName;



	//销毁所有DriverObject中的DeviceObject

	PDEVICE_OBJECT  CurrentDeviceObject = NULL;
	PDEVICE_OBJECT  NextDeviceObject = NULL;


	//InjectProcess	退出处理
	ExitInjectProcess();

	RtlInitUnicodeString(&uniLinkName, LINK_NAME);
	IoDeleteSymbolicLink(&uniLinkName);
	if (DriverObject->DeviceObject != NULL)
	{
		CurrentDeviceObject = DriverObject->DeviceObject;
		while (CurrentDeviceObject != NULL)
		{
			NextDeviceObject = CurrentDeviceObject->NextDevice;
			IoDeleteDevice(CurrentDeviceObject);

			CurrentDeviceObject = NextDeviceObject;
		}
	}

	CurrentDeviceObject = NULL;
	NextDeviceObject = NULL;
}

