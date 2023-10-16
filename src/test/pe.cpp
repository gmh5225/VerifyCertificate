#include "pe.h"


#pragma warning(disable:4996)


PVOID MiFindExportedRoutineByName(_In_ PVOID DllBase, _In_ PANSI_STRING AnsiImageRoutineName)
/*++
Routine Description:
    This function searches the argument module looking for the requested exported function name.
Arguments:
    DllBase - Supplies the base address of the requested module.
    AnsiImageRoutineName - Supplies the ANSI routine name being searched for.
Return Value:
    The virtual address of the requested routine or NULL if not found.
--*/

/*
写作目的：
MmGetSystemRoutineAddress这个函数有如下的限制：
It can only be used for routines exported by the kernel or HAL, not for any driver-defined routine.

FltGetRoutineAddress这个函数有如下的限制：
1.调用的函数。
2.那个模块必须已经加载。

NdisGetRoutineAddress有类似的限制。

有时候获取别的内核模块的函数的地址是一个解决问题的办法，如：WINHV.sys。
有人为此还专门写了函数，当然是解析PE32/PE32+了。

其实系统已经提供了一些函数，只不过导出而没有公开而已。

看WRK知道:MmGetSystemRoutineAddress是通过MiFindExportedRoutineByName实现的。
可是：MiFindExportedRoutineByName没有导出，定位又没有好的稳定的办法。
所以自己实现，还好RtlImageDirectoryEntryToData（RtlImageNtHeader）已经导出。

本文的一些信息摘自：WRK。
不过这也是源码，加入驱动也是可以使用的。

注意：
如果是获取应用层的地址，需要附加到进程。

made by correy
made at 2014.08.18
*/
{
    USHORT OrdinalNumber;
    PULONG NameTableBase;
    PUSHORT NameOrdinalTableBase;
    PULONG Addr;
    LONG High;
    LONG Low;
    LONG Middle;
    LONG Result;
    ULONG ExportSize;
    PVOID FunctionAddress = 0;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;

    PAGED_CODE();

    __try {
        FunctionAddress = *(PVOID *)DllBase;
        FunctionAddress = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FunctionAddress;
    }

    //确保DllBase可以访问。否则蓝屏。
    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(DllBase,
                                                                            TRUE,
                                                                            IMAGE_DIRECTORY_ENTRY_EXPORT,
                                                                            &ExportSize);
    if (ExportDirectory == NULL) {
        return NULL;
    }

    // Initialize the pointer to the array of RVA-based ansi export strings. 
    NameTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNames);

    // Initialize the pointer to the array of USHORT ordinal numbers. 
    NameOrdinalTableBase = (PUSHORT)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);

    Low = 0;
    Middle = 0;
    High = ExportDirectory->NumberOfNames - 1;

    while (High >= Low) // Lookup the desired name in the name table using a binary search.
    {
        // Compute the next probe index and compare the import name with the export name entry.
        Middle = (Low + High) >> 1;
        Result = strcmp(AnsiImageRoutineName->Buffer, (PCHAR)DllBase + NameTableBase[Middle]);
        if (Result < 0) {
            High = Middle - 1;
        } else if (Result > 0) {
            Low = Middle + 1;
        } else {
            break;
        }
    }

    // If the high index is less than the low index, then a matching table entry was not found.
    // Otherwise, get the ordinal number from the ordinal table.
    if (High < Low) {
        return NULL;
    }

    OrdinalNumber = NameOrdinalTableBase[Middle];

    // If the OrdinalNumber is not within the Export Address Table,then this image does not implement the function.
    // Return not found.
    if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
        return NULL;
    }

    // Index into the array of RVA export addresses by ordinal number.
    Addr = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);
    FunctionAddress = (PVOID)((PCHAR)DllBase + Addr[OrdinalNumber]);

    // Forwarders are not used by the kernel and HAL to each other.
    ASSERT((FunctionAddress <= (PVOID)ExportDirectory) ||
           (FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));

    return FunctionAddress;
}


#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSTATUS EnumKernelModule(_In_ HandleKernelModule CallBack, _In_opt_ PVOID Context)
/*
功能：通用的处理每个内核模块的函数。

其实有一个更简单的办法，只有知道NT里的一个地址，然后调用一个函数即可获得，这个API便是RtlPcToFileHeader。

运行环境，说是NTDDI_VISTA，其实2003都有了，但是有的WDK里不包含相应的lib（Aux_klib.lib）。

其实只要包含Aux_klib.lib，在XP和2003上也可以用，因为这个是静态连接的。
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PAUX_MODULE_EXTENDED_INFO modules;

    Status = AuxKlibInitialize();
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return Status;
    }

    // Get the required array size.
    ULONG  modulesSize = 0;
    Status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (!NT_SUCCESS(Status) || modulesSize == 0) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return Status;
    }

    ULONG numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);// Calculate the number of modules.

    // Allocate memory to receive data.
    modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(PagedPool, modulesSize, TAG);
    if (modules == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return Status;
    }
    RtlZeroMemory(modules, modulesSize);

    // Obtain the module information.
    Status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        ExFreePoolWithTag(modules, TAG);
        return Status;
    }

    if (CallBack) {
        CallBack(numberOfModules, modules, Context);
    }

    ExFreePoolWithTag(modules, TAG);

    return Status;
}
#endif


NTSTATUS CALLBACK GetRoutineAddressCallBack(ULONG  numberOfModules,
                                            PAUX_MODULE_EXTENDED_INFO modules,
                                            _In_opt_ PVOID Context
)
/*
枚举内核模块（EnumAllKernelModule）的回调函数。

注释：此回调函数注册一次，调用一次。
*/
{
    PAUX_MODULE_EXTENDED_INFO ModuleInfo = (PAUX_MODULE_EXTENDED_INFO)Context;
    if (!ModuleInfo) {
        return STATUS_UNSUCCESSFUL;
    }

    for (ULONG i = 0; i < numberOfModules; i++) {
        PUCHAR ModuleName = modules[i].FullPathName + modules[i].FileNameOffset;
        PVOID ImageBase = modules[i].BasicInfo.ImageBase;

        if (_strnicmp((char const *)ModuleInfo->FullPathName,
                      (char const *)ModuleName,
                      AUX_KLIB_MODULE_PATH_LEN) == 0) {
            ModuleInfo->BasicInfo.ImageBase = ImageBase;
            break;
        }
    }

    return STATUS_SUCCESS;
}


_Must_inspect_result_
_IRQL_requires_max_(PASSIVE_LEVEL)
PVOID NTAPI GetRoutineAddress(_In_ PCSTR ModuleName, _In_ PCSTR RoutineName)
/*
功能：获取一些内核模块的导出的函数的地址。

原因：
1.一些导出，lib里没有导出信息的函数。
2.一些函数的导出序数有变动，导致驱动加载失败。
3.一些导出，但没有文档和头文件的函数。

排除场景：
1.nt函数，建议使用MmGetSystemRoutineAddress。
2.Fltmgr.sys的建议使用FltGetRoutineAddress。
3.Ndis.sys的建议使用NdisGetRoutineAddress。
*/
{
    PVOID RoutineAddress = nullptr;
    NTSTATUS Status = STATUS_SUCCESS;
    AUX_MODULE_EXTENDED_INFO ModuleInfo{};//临时借用，不再自己定义结构了。最好是自己定义，里面可以是指针。

    strcpy_s((char *)ModuleInfo.FullPathName, AUX_KLIB_MODULE_PATH_LEN, ModuleName);
    Status = EnumKernelModule(GetRoutineAddressCallBack, &ModuleInfo);
    if (!NT_SUCCESS(Status) || !ModuleInfo.BasicInfo.ImageBase) {
        return RoutineAddress;
    }

    ANSI_STRING FunctionName = {0};
    RtlInitAnsiString(&FunctionName, RoutineName);

    RoutineAddress = MiFindExportedRoutineByName(ModuleInfo.BasicInfo.ImageBase, &FunctionName);

    return RoutineAddress;
}
