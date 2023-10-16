#pragma once

#include "main.h"

EXTERN_C PVOID RtlImageDirectoryEntryToData(IN PVOID Base,
                                            IN BOOLEAN MappedAsImage,
                                            IN USHORT DirectoryEntry,
                                            OUT PULONG Size);

typedef NTSTATUS(WINAPI * HandleKernelModule)(_In_ ULONG numberOfModules,
                                              _In_ PAUX_MODULE_EXTENDED_INFO ModuleInfo,
                                              _In_opt_ PVOID Context);

_Must_inspect_result_
_IRQL_requires_max_(PASSIVE_LEVEL)
PVOID NTAPI GetRoutineAddress(_In_ PCSTR ModuleName, _In_ PCSTR RoutineName);
