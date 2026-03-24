#include <stdio.h>
#include <Windows.h>

DWORD HashStringDjb2W(IN LPCSTR String)
{
	ULONG Hash = 5381;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}
int main() {


    wprintf(L"#define HASH_CreateProcessA 0x%0.8X \n", HashStringDjb2W("CreateProcessA"));

    wprintf(L"#define HASH_VirtualAllocEx 0x%0.8X \n", HashStringDjb2W("VirtualAllocEx"));

    wprintf(L"#define HASH_WriteProcessMemory 0x%0.8X \n", HashStringDjb2W("WriteProcessMemory"));

    wprintf(L"#define HASH_VirtualProtectEx 0x%0.8X \n", HashStringDjb2W("VirtualProtectEx"));

    wprintf(L"#define HASH_GetThreadContext 0x%0.8X \n", HashStringDjb2W("GetThreadContext"));

    wprintf(L"#define HASH_SetThreadContext 0x%0.8X \n", HashStringDjb2W("SetThreadContext"));

    wprintf(L"#define HASH_KERNEL32_DLL 0x%0.8X \n", HashStringDjb2W("KERNEL32.DLL"));

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
