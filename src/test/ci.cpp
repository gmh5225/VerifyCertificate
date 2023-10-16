#include "ci.h"
#include "pe.h"


CiCheckSignedFile_Fn CiCheckSignedFile;
CiFreePolicyInfo_Fn CiFreePolicyInfo;
CiValidateFileObject_Fn CiValidateFileObject;


//////////////////////////////////////////////////////////////////////////////////////////////////


bool inRange(const BYTE * rangeStartAddr, const BYTE * rangeEndAddr, const BYTE * addrToCheck)
{
    if (addrToCheck > rangeEndAddr || addrToCheck < rangeStartAddr) {
        return false;
    }

    return true;
}


void parsePolicyInfo(const pPolicyInfo policyInfo)
{
    if (policyInfo == nullptr) {
        KdPrint(("parsePolicyInfo - paramter is null\n"));
        return;
    }

    if (policyInfo->structSize == 0) {
        KdPrint(("policy info is empty\n"));
        return;
    }

    if (policyInfo->certChainInfo == nullptr) {
        KdPrint(("certChainInfo is null\n"));
        return;
    }

    const pCertChainInfoHeader chainInfoHeader = policyInfo->certChainInfo;
    const BYTE * startOfCertChainInfo = (BYTE *)(chainInfoHeader);
    const BYTE * endOfCertChainInfo = (BYTE *)(policyInfo->certChainInfo) + chainInfoHeader->bufferSize;

    if (!inRange(startOfCertChainInfo, endOfCertChainInfo, (BYTE *)chainInfoHeader->ptrToCertChainMembers)) {
        KdPrint(("chain members out of range\n"));
        return;
    }

    // need to make sure we have enough room to accomodate the chain member struct
    if (!inRange(startOfCertChainInfo,
                 endOfCertChainInfo,
                 (BYTE *)chainInfoHeader->ptrToCertChainMembers + sizeof(CertChainMember))) {
        KdPrint(("chain member out of range\n"));
        return;
    }

    // we are interested in the first certificate in the chain - the signer itself
    pCertChainMember signerChainMember = chainInfoHeader->ptrToCertChainMembers;

    KdPrint(("Signer certificate:\n  digest algorithm - 0x%x\n  size - %zu\n  subject - %.*s\n  issuer - %.*s\n", \
             signerChainMember->digestIdetifier, \
             signerChainMember->certificate.size, \
             signerChainMember->subjectName.nameLen, \
             static_cast<char *>(signerChainMember->subjectName.pointerToName), \
             signerChainMember->issuerName.nameLen, \
             static_cast<char *>(signerChainMember->issuerName.pointerToName))                                            \
    );
}


void validateFileUsingCiValidateFileObject(PFILE_OBJECT fileObject)
/*
函数名叫ValidateFileObject，岂不更好。

*/
{
    NT_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    PolicyInfo signerPolicyInfo{};
    PolicyInfo timestampingAuthorityPolicyInfo{};
    LARGE_INTEGER signingTime = {};
    int digestSize = 64;
    int digestIdentifier = 0;
    BYTE digestBuffer[64] = {};

    if (!CiValidateFileObject || !CiFreePolicyInfo) {
        return;
    }

    NTSTATUS status = CiValidateFileObject(
        fileObject,
        0,
        0,
        &signerPolicyInfo,
        &timestampingAuthorityPolicyInfo,
        &signingTime,
        digestBuffer,
        &digestSize,
        &digestIdentifier);
    if (NT_SUCCESS(status)) {
        parsePolicyInfo(&signerPolicyInfo);

        CiFreePolicyInfo(&signerPolicyInfo);
        CiFreePolicyInfo(&timestampingAuthorityPolicyInfo);
        return;
    }
}


void ValidateFileObjectByFileName(_In_ PUNICODE_STRING FileName)
{
    HANDLE File = NULL;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatus;
    PFILE_OBJECT FileObject = NULL;

    do {
        InitializeObjectAttributes(&ObjectAttributes, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        Status = ZwOpenFile(&File, SYNCHRONIZE | FILE_READ_DATA, &ObjectAttributes, &IoStatus, FILE_SHARE_READ, 0);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            break;
        }

        Status = ObReferenceObjectByHandle(File, FILE_READ_ACCESS, *IoFileObjectType, KernelMode, (PVOID *)&FileObject, 0);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            break;
        }

        validateFileUsingCiValidateFileObject(FileObject);
    } while (FALSE);

    if (FileObject) {
        ObDereferenceObject(FileObject);
    }

    if (File) {
        ZwClose(File);
    }
}


bool ciCheckSignedFileWrapper(const LPWIN_CERTIFICATE win_cert, ULONG sizeOfSecurityDirectory)
{
    // prepare the parameters required for calling CiCheckSignedFile
    PolicyInfo signerPolicyInfo{};
    PolicyInfo timestampingAuthorityPolicyInfo{};
    LARGE_INTEGER signingTime = {};
    const int digestSize = 20; // sha1 len, 0x14
    const int digestIdentifier = 0x8004; // sha1
    const BYTE digestBuffer[] = // digest of notepad++.exe  这个数据从何而来？在PE的资源里，解析asn1可得到。
    {0x83, 0xF6, 0x68, 0x3E, 0x64, 0x9C, 0x70, 0xB9, 0x8D, 0x0B, 
        0x5A, 0x8D, 0xBF, 0x9B, 0xD4, 0x70, 0xE6, 0x05, 0xE6, 0xA7};

    // CiCheckSignedFile() allocates memory from the paged pool, so make sure we're at IRQL < 2,
    // where access to paged memory is allowed
    NT_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    const NTSTATUS status = CiCheckSignedFile(
        (PVOID)digestBuffer,
        digestSize,
        digestIdentifier,
        win_cert,
        (int)sizeOfSecurityDirectory,
        &signerPolicyInfo,
        &signingTime,
        &timestampingAuthorityPolicyInfo);
    if (NT_SUCCESS(status)) {
        parsePolicyInfo(&signerPolicyInfo);
        CiFreePolicyInfo(&signerPolicyInfo);
        CiFreePolicyInfo(&timestampingAuthorityPolicyInfo);
        return true;
    }

    return false;
}


void validateFileUsingCiCheckSignedFile(PCUNICODE_STRING imageFileName)
/*
函数名叫CheckSignedFile，岂不更好。


*/
{
    if (!CiCheckSignedFile || !CiFreePolicyInfo) {
        return;
    }

    HANDLE FileHandle{};
    HANDLE SectionHandle{};
    PVOID _object{};
    PVOID _baseAddrOfView{};

    __try {        
        IO_STATUS_BLOCK ioStatusBlock = {0};
        OBJECT_ATTRIBUTES  objAttr = {0};
        InitializeObjectAttributes(
            &objAttr,
            const_cast<PUNICODE_STRING>(imageFileName),
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            nullptr,
            nullptr);
        NTSTATUS status = ZwOpenFile(
            &FileHandle,
            SYNCHRONIZE | FILE_READ_DATA, // ACCESS_MASK, we use SYNCHRONIZE because we might need to wait on the handle in order to wait for the file to be read
            &objAttr,
            &ioStatusBlock,
            FILE_SHARE_READ,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT // FILE_SYNCHRONOUS_IO_NONALERT so that zwReadfile will pend for us until reading is done
        );
        if (!NT_SUCCESS(status)) {

            __leave;
        }
        
        OBJECT_ATTRIBUTES objectAttributes = {0};
        InitializeObjectAttributes(&objectAttributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
        status = ZwCreateSection(
            &SectionHandle,
            SECTION_MAP_READ,
            &objectAttributes,
            nullptr, // maximum size - use the file size, in order to map the entire file
            PAGE_READONLY,
            SEC_COMMIT, // map as commit and not as SEC_IMAGE, because SEC_IMAGE will not map things which are not needed for the PE - such as resources and certificates
            FileHandle);
        if (!NT_SUCCESS(status)) {

            __leave;
        }
        
        status = ObReferenceObjectByHandle(SectionHandle, SECTION_MAP_READ, nullptr, KernelMode, &_object, nullptr);
        if (!NT_SUCCESS(status)) {

            __leave;
        }
        
        SIZE_T _viewSize{};
        status = MmMapViewInSystemSpace(_object, &_baseAddrOfView, &_viewSize);
        if (!NT_SUCCESS(status)) {

            __leave;
        }

        // fetch the security directory
        PVOID securityDirectoryEntry = nullptr;
        ULONG securityDirectoryEntrySize = 0;
        securityDirectoryEntry = RtlImageDirectoryEntryToData(
            _baseAddrOfView,
            TRUE, // we tell RtlImageDirectoryEntryToData it's mapped as image because then it will treat the RVA as offset from the beginning of the view, which is what we want. See https://doxygen.reactos.org/dc/d30/dll_2win32_2dbghelp_2compat_8c_source.html#l00102
            IMAGE_DIRECTORY_ENTRY_SECURITY,
            &securityDirectoryEntrySize);
        if (securityDirectoryEntry == nullptr) {
            KdPrint(("no security directory\n"));
            __leave;
        }

        // Make sure the security directory is contained in the file view
        const BYTE * endOfFileAddr = static_cast<BYTE *>(_baseAddrOfView) + _viewSize;
        const BYTE * endOfSecurityDir = static_cast<BYTE *>(securityDirectoryEntry) + securityDirectoryEntrySize;
        if (endOfSecurityDir > endOfFileAddr || securityDirectoryEntry < _baseAddrOfView) {
            KdPrint(("security directory is not contained in file view!\n"));
            __leave;
        }

        // technically, there can be several WIN_CERTIFICATE in a file.
        // This not common, and, for simplicity, we'll assume there's only one
        LPWIN_CERTIFICATE winCert = static_cast<LPWIN_CERTIFICATE>(securityDirectoryEntry);
        KdPrint(("WIN_CERTIFICATE at: %p, revision = %x, type = %x, length = %xd, bCertificate = %p\n",
                 securityDirectoryEntry,
                 winCert->wRevision,
                 winCert->wCertificateType,
                 winCert->dwLength,
                 static_cast<PVOID>(winCert->bCertificate)));

        ciCheckSignedFileWrapper(winCert, securityDirectoryEntrySize);
    } __finally {
        if (_baseAddrOfView) {
            MmUnmapViewInSystemSpace(_baseAddrOfView);
        }

        if (_object) {
            ObfDereferenceObject(_object);
        }

        if (SectionHandle) {
            ZwClose(SectionHandle);
        }

        if (FileHandle) {
            ZwClose(FileHandle);
        }
    }
}


void GetCiApiAddress()
{
    CiCheckSignedFile = (CiCheckSignedFile_Fn)GetRoutineAddress("ci.dll", "CiCheckSignedFile");
    CiFreePolicyInfo = (CiFreePolicyInfo_Fn)GetRoutineAddress("ci.dll", "CiFreePolicyInfo");
    CiValidateFileObject = (CiValidateFileObject_Fn)GetRoutineAddress("ci.dll", "CiValidateFileObject");
}
