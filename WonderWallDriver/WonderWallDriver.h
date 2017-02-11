#include <ntifs.h>

#include <Ntstrsafe.h>
#include <ntimage.h>


VOID UnloadDriver(PDRIVER_OBJECT DriverObject);

NTSTATUS DefaultPassDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS ControlPassDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);


/*INJECTPROCESS*/
NTSTATUS InjectProcess();
VOID	ExitInjectProcess();
