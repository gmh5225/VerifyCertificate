#include "main.h"
#include "ci.h"


void ProcessCreateProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    if (CreateInfo == nullptr) return; //process died

    if (CreateInfo->FileObject == nullptr) return;
    if (nullptr == CreateInfo->ImageFileName) return;

    validateFileUsingCiValidateFileObject(CreateInfo->FileObject);
    validateFileUsingCiCheckSignedFile(CreateInfo->ImageFileName);
}


void registerProcessCallback()
{
    NTSTATUS Status = PsSetCreateProcessNotifyRoutineEx(ProcessCreateProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("failed to register callback with status %d\n", Status));
    }
}


void unregisterProcessCallback()
{
    NTSTATUS Status = PsSetCreateProcessNotifyRoutineEx(ProcessCreateProcessNotifyRoutineEx, TRUE);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("failed to unregister callback\n"));
    }
}


VOID MyDriverUnload(_In_ struct _DRIVER_OBJECT * DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    unregisterProcessCallback();
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    if (!KD_DEBUGGER_NOT_PRESENT) {
        KdBreakPoint();//__debugbreak();
    }

    DriverObject->DriverUnload = MyDriverUnload;

    GetCiApiAddress();

    UNICODE_STRING TestFileName = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\smss.exe");//嵌入式签名。
    ValidateFileObjectByFileName(&TestFileName);

    UNICODE_STRING TestFileName2 = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\notepad.exe");//cat签名。
    ValidateFileObjectByFileName(&TestFileName2);

    registerProcessCallback();

    return STATUS_SUCCESS;
}
