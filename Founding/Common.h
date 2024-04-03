#pragma once


#include <Windows.h>

#ifndef COMMON_H
#define COMMON_H




// to help identifying user input
#define UUIDFUSCATION		0x444
#define AESENCRYPTION		0x555
#define RC4ENCRYPTION		0x666
#define IPV6FUSCATION		0x111
#define IPV4FUSCATION		0x222
#define MACFUSCATION		0x333
#define XORENCRYPTION		0x777


//// to help identifying user input INJECTION

#define CREATETHREAD			0x888
#define PROCESS_INJECTION		0x999
#define FUNCTIONPOINTER			0x1000
#define APC						0x1100
#define EB_APC_DP				0x1200
#define EB_APC_SP				0x1300
#define CALLBACK_ENUM			0x1400
#define LOCAL_MAPPING			0x1500




// to help working with encryption algorithms
#define RC4KEYSIZE				16

#define AESKEYSIZE				32
#define AESIVSIZE				16

#define XORKEYSIZE				16

//----------------------------------------------------------
//------------


//-------------------------------------------------------------------------------------------------------------------------------
// 
// from IO.c
// read file from disk 
BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData);
// write file to disk
BOOL WritePayloadFile(const char* FileInput, DWORD sPayloadSize, unsigned char* pPayloadData);

void compile(int argc, char* argv[]);

//-------------------------------------------------------------------------------------------------------------------------------

//-------------------------------------------------------------------------------------------------------------------------------

//XOR
BOOL XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize);
//-------------------------------------------------------------------------------------------------------------------------------


//-------------------------------------------------------------------------------------------------------------------------------
// 
// from StringFunctions.c
// print the decryption / deobfuscation function (as a string) to the screen
VOID PrintDecodeFunctionality(IN INT TYPE);

VOID PrintInjectionFunctionality(IN INT TYPE);

//-------------------------------------------------------------------------------------------------------------------------------

//Write to a file
void RedirectStdoutToFile(const char* filename);
//
BOOL AppendInputPayload(IN INT MultipleOf, IN PBYTE pPayload, IN DWORD dwPayloadSize, OUT PBYTE* ppAppendedPayload, OUT DWORD* pAppendedPayloadSize);

//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Encryption.c
// generate random bytes of size "sSize"
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize);
// print the input buffer as a hex char array (c syntax)
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Encryption.c
// wrapper function for InstallAesEncryption that make things easier
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize);
// do the rc4 encryption
BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);
//-------------------------------------------------------------------------------------------------------------------------------




//-------------------------------------------------------------------------------------------------------------------------------
// 
// from Obfuscation.c
// generate the UUid output representation of the shellcode
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);
// generate the Mac output representation of the shellcode
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);
// generate the ipv6 output representation of the shellcode
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);
// generate the ipv4 output representation of the shellcode
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize);
//-------------------------------------------------------------------------------------------------------------------------------




#endif // !COMMON_H
