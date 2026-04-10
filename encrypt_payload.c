#include <stdio.h>
#include <Windows.h>
#include "aes.h"


// Encrypt the payload with AES
// tiny-AES - https://github.com/kokke/tiny-AES-c

// set the size of the AES key as 32 and the size of the IV (Initialization Vector) as 16
#define KEYSIZE 32
#define IVSIZE 16

#define INPUT_FILE "adaptix.bin"
#define OUTPUT_FILE "encrypted_shellcode.bin"

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
BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData) {


	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD FileSize = NULL;
	DWORD lpNumberOfBytesRead = NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	FileSize = GetFileSize(hFile, NULL);

	unsigned char* Payload = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, FileSize);

	ZeroMemory(Payload, FileSize);

	if (!ReadFile(hFile, Payload, FileSize, &lpNumberOfBytesRead, NULL)) {
		return FALSE;
	}


	*pPayloadData = Payload;
	*sPayloadSize = lpNumberOfBytesRead;

	CloseHandle(hFile);

	if (*pPayloadData == NULL || *sPayloadSize == NULL)
		return FALSE;

	return TRUE;
}


BOOL WritePayloadFile(const char* FileInput, DWORD sPayloadSize, unsigned char* pPayloadData) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	DWORD	lpNumberOfBytesWritten = 0;

	hFile = CreateFileA(FileInput, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
	    return FALSE;
	}


	if (!WriteFile(hFile, pPayloadData, sPayloadSize, &lpNumberOfBytesWritten, NULL) || sPayloadSize != lpNumberOfBytesWritten) {
	    return FALSE;
	}

	CloseHandle(hFile);

	return TRUE;
}

VOID RandBytes(PBYTE pByte, SIZE_T sSize) {
    for(int i = 0; i < sSize; i++) {
        pByte[i] = (BYTE)rand() % 0xFF;
    }
}

BOOL EncryptAES(IN PBYTE pRawDataBuffer, IN SIZE_T sRawBufferSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* pEncryptedBuffer, OUT SIZE_T* pEncryptedBufferSize) {

	if (!pRawDataBuffer || !sRawBufferSize || !pAesKey || !pAesIv || !pRawDataBuffer|| !sRawBufferSize)
		return FALSE;

	PBYTE	pNewBuffer		= pRawDataBuffer;
	SIZE_T	sNewBufferSize	= sRawBufferSize;
	// Init the AEX_ctx struct for tiny-AES
	struct	AES_ctx AesCtx	= { 0x00 };

	// Padding for the tiny-AES library as they only supports chunks of 16 bytes
	if (sRawBufferSize % 16 != 0x00) {

		sNewBufferSize		= sRawBufferSize + 16 - (sRawBufferSize % 16);
		pNewBuffer			= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewBufferSize);

		if (!pNewBuffer) {
			printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		memcpy(pNewBuffer, pRawDataBuffer, sRawBufferSize);
	}
	// Encrypts the buffer
	RtlSecureZeroMemory(&AesCtx, sizeof(AesCtx));
	AES_init_ctx_iv(&AesCtx, pAesKey, pAesIv);
	AES_CBC_encrypt_buffer(&AesCtx, pNewBuffer, sNewBufferSize);

	//  returning the encrypted buffer
	*pEncryptedBufferSize= sNewBufferSize;
	*pEncryptedBuffer = pNewBuffer;

	return TRUE;
}

int main() {
    PBYTE pRawShellcode = NULL;
    DWORD dwRawShellcodeSize = 0;
    BYTE pAesKey[KEYSIZE];
    BYTE pAesIv[IVSIZE];
    PBYTE pEncryptedShellcode = NULL;
    SIZE_T sEncryptedShellcodeSize = 0;

    srand(time(NULL)); // set the seed
    RandBytes(pAesKey, KEYSIZE); // create random bytes

    srand (time(NULL) ^ pAesKey[0]); // create the seed from the first byte of the AES key
    RandBytes(pAesIv, IVSIZE); // generate IV

    if (!ReadPayloadFile(INPUT_FILE, &dwRawShellcodeSize, &pRawShellcode)) {
        printf("[!] Failed to read file to %s with error: %d", INPUT_FILE, GetLastError());
        return -1;
    }

    printf("// [+] Size of payload: %d \n", dwRawShellcodeSize);

    PrintHexData("raw_payload", pRawShellcode, dwRawShellcodeSize);
    if (!EncryptAES(pRawShellcode, dwRawShellcodeSize, pAesKey, pAesIv, &pEncryptedShellcode, &sEncryptedShellcodeSize)) {
        printf("[!] Shellcode Encryption failed with error: %d", GetLastError());
        return -1;
    }

    PrintHexData("encrypted_payload", pEncryptedShellcode , sEncryptedShellcodeSize);
    PrintHexData("AesKey", pAesKey, KEYSIZE);
    PrintHexData("AesIv", pAesIv, IVSIZE);

    if (!WritePayloadFile(OUTPUT_FILE, sEncryptedShellcodeSize, pEncryptedShellcode)) {
        printf("[!] Failed to write file to %s with error: %d", OUTPUT_FILE, GetLastError());
        return -1;
    }

    return 0;
}
