/*
在驱动中获取数字签名，是多么美好和惬意的事。

开始的时候是在驱动使用openssl，但是这个太复制和庞大，毕竟不少的代码，各种的算法。

后来发现了ci.dll.
无奈的自己的IDA水平太菜，不高，那个结构没有逆向出来，而且函数的参数的个数也没弄好。
毕竟这个文件太大，且符号文件的信息也少。

直到后来的某天，一个同事发现了下面的这个仓库。
本工程修改自：https://github.com/Ido-Moshe-Github/CiDllDemo.git
反过来，结合本工程，windbg，ida可以更深入的了解ci.dll.
*/


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
