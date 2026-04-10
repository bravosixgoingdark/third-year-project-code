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

	printf("#define NtAllocateVirtualMemory_Djb2W 0x%0.8X \n", HashStringDjb2W("NtAllocateVirtualMemory"));
	printf("#define NtProtectVirtualMemory_Djb2W 0x%0.8X \n", HashStringDjb2W("NtProtectVirtualMemory"));
	printf("#define NtWriteVirtualMemory_Djb2W 0x%0.8X \n", HashStringDjb2W("NtWriteVirtualMemory"));
	printf("#define NtCreateThreadEx_Djb2W 0x%0.8X \n", HashStringDjb2W("NtCreateThreadEx"));
	printf("#define NtWaitForSingleObject_Djb2W 0x%0.8X \n", HashStringDjb2W("NtWaitForSingleObject"));


	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
