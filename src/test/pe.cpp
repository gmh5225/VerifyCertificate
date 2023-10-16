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
д��Ŀ�ģ�
MmGetSystemRoutineAddress������������µ����ƣ�
It can only be used for routines exported by the kernel or HAL, not for any driver-defined routine.

FltGetRoutineAddress������������µ����ƣ�
1.���õĺ�����
2.�Ǹ�ģ������Ѿ����ء�

NdisGetRoutineAddress�����Ƶ����ơ�

��ʱ���ȡ����ں�ģ��ĺ����ĵ�ַ��һ���������İ취���磺WINHV.sys��
����Ϊ�˻�ר��д�˺�������Ȼ�ǽ���PE32/PE32+�ˡ�

��ʵϵͳ�Ѿ��ṩ��һЩ������ֻ����������û�й������ѡ�

��WRK֪��:MmGetSystemRoutineAddress��ͨ��MiFindExportedRoutineByNameʵ�ֵġ�
���ǣ�MiFindExportedRoutineByNameû�е�������λ��û�кõ��ȶ��İ취��
�����Լ�ʵ�֣�����RtlImageDirectoryEntryToData��RtlImageNtHeader���Ѿ�������

���ĵ�һЩ��Ϣժ�ԣ�WRK��
������Ҳ��Դ�룬��������Ҳ�ǿ���ʹ�õġ�

ע�⣺
����ǻ�ȡӦ�ò�ĵ�ַ����Ҫ���ӵ����̡�

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

    //ȷ��DllBase���Է��ʡ�����������
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
���ܣ�ͨ�õĴ���ÿ���ں�ģ��ĺ�����

��ʵ��һ�����򵥵İ취��ֻ��֪��NT���һ����ַ��Ȼ�����һ���������ɻ�ã����API����RtlPcToFileHeader��

���л�����˵��NTDDI_VISTA����ʵ2003�����ˣ������е�WDK�ﲻ������Ӧ��lib��Aux_klib.lib����

��ʵֻҪ����Aux_klib.lib����XP��2003��Ҳ�����ã���Ϊ����Ǿ�̬���ӵġ�
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
ö���ں�ģ�飨EnumAllKernelModule���Ļص�������

ע�ͣ��˻ص�����ע��һ�Σ�����һ�Ρ�
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
���ܣ���ȡһЩ�ں�ģ��ĵ����ĺ����ĵ�ַ��

ԭ��
1.һЩ������lib��û�е�����Ϣ�ĺ�����
2.һЩ�����ĵ��������б䶯��������������ʧ�ܡ�
3.һЩ��������û���ĵ���ͷ�ļ��ĺ�����

�ų�������
1.nt����������ʹ��MmGetSystemRoutineAddress��
2.Fltmgr.sys�Ľ���ʹ��FltGetRoutineAddress��
3.Ndis.sys�Ľ���ʹ��NdisGetRoutineAddress��
*/
{
    PVOID RoutineAddress = nullptr;
    NTSTATUS Status = STATUS_SUCCESS;
    AUX_MODULE_EXTENDED_INFO ModuleInfo{};//��ʱ���ã������Լ�����ṹ�ˡ�������Լ����壬���������ָ�롣

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
