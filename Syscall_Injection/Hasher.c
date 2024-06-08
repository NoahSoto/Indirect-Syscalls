// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>

// reference: https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringDjb2.cpp


#define INITIAL_HASH	3731		// added to randomize 
#define INITIAL_SEED	7			// recommended to be 0 < INITIAL_SEED < 10

// generate Djb2 hashes from Ascii input string
DWORD HashStringDjb2A(_In_ PCHAR String)
{
	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}

// generate Djb2 hashes from wide-character input string
DWORD HashStringDjb2W(_In_ PWCHAR String)
{
	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}


int main() {
	//VxTable.Read.wRCXVal = 0;
	//VxTable.Write.wRCXVal = 1;
	//VxTable.Allocate.wRCXVal = 2;
	//VxTable.Protect.wRCXVal = 3;
	//VxTable.Protect.wRCXVal = 4;
	//VxTable.Protect.wRCXVal = 5;


	//CHAR* cTest = "A_SHAFinal";
	CHAR* cTest = "NtReadVirtualMemory";
	WCHAR* wTest2 = L"NtAllocateVirtualMemory";
	WCHAR* wTest3 = L"NtProtectVirtualMemory";
	WCHAR* wTest4 = L"NtResumeThread";
	WCHAR* wTest5 = L"NtQueryInformationProcess";

	WCHAR* wTest6 = L"NtReadVirtualMemory";


	printf("[+] Hash Of \"%s\" Is : 0x%0.8X \n", cTest, HashStringDjb2A(cTest));
	wprintf(L"[+] Hash Of \"%s\" Is : 0x%0.8X \n", wTest2, HashStringDjb2W(wTest2));
	wprintf(L"[+] Hash Of \"%s\" Is : 0x%0.8X \n", wTest3, HashStringDjb2W(wTest3));
	wprintf(L"[+] Hash Of \"%s\" Is : 0x%0.8X \n", wTest4, HashStringDjb2W(wTest4));
	wprintf(L"[+] Hash Of \"%s\" Is : 0x%0.8X \n", wTest5, HashStringDjb2W(wTest5));
	wprintf(L"[+] Hash Of \"%s\" Is : 0x%0.8X \n", wTest6, HashStringDjb2W(wTest6));


	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}

/*
	OUTPUT:

[+] Hash Of "MaldevAcademy" Is : 0xB4FEAFA0
[+] Hash Of "MaldevAcademy" Is : 0xB4FEAFA0
*/