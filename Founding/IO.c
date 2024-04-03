#include <windows.h>
#include <stdio.h>
#include "Common.h"
#include <string.h>

BOOL ReportError(const char* ApiName) {
	printf("[!] \"%s\" [ FAILED ] \t%d \n", ApiName, GetLastError());
	return FALSE;
}

// read file from disk Firrst
BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData) {


	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD FileSize = NULL;
	DWORD lpNumberOfBytesRead = NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return ReportError("CreateFileA");
	}

	FileSize = GetFileSize(hFile, NULL);

	unsigned char* Payload = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, FileSize);

	ZeroMemory(Payload, FileSize);

	if (!ReadFile(hFile, Payload, FileSize, &lpNumberOfBytesRead, NULL)) {
		return ReportError("ReadFile");
	}


	*pPayloadData = Payload;
	*sPayloadSize = lpNumberOfBytesRead;

	CloseHandle(hFile);

	if (*pPayloadData == NULL || *sPayloadSize == NULL)
		return FALSE;

	return TRUE;
}

//Read file  froom disk second



// write file to disk
BOOL WritePayloadFile(const char* FileInput, DWORD sPayloadSize, unsigned char* pPayloadData) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	DWORD	lpNumberOfBytesWritten = NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return ReportError("CreateFileA");


	if (!WriteFile(hFile, pPayloadData, sPayloadSize, &lpNumberOfBytesWritten, NULL) || sPayloadSize != lpNumberOfBytesWritten)
		return ReportError("WriteFile");

	CloseHandle(hFile);

	return TRUE;
}

void RedirectStdoutToFile(const char* filename) {
	freopen(filename, "w", stdout);
}





void compile(int argc, char* argv[]) {
	// Buffer to hold the current working directory
	char exePath[MAX_PATH];

	// Get the path of the current executable
	DWORD pathLength = GetFullPathName(argv[0], MAX_PATH, exePath, NULL);
	if (pathLength == 0 || pathLength >= MAX_PATH) {
		printf("Failed to get the full path of the executable.\n");
		return;
	}

	// Build the command to set the PATH
	char setPathCmd[1024];
	sprintf(setPathCmd, "set PATH=%s\\mingw64\\bin;%%PATH%%", exePath);

	// Build the command to compile Founding.c using gcc
	char gccCmd[1024];
	sprintf(gccCmd, "%s && mingw64\\bin\\gcc.exe Founding.c -lbcrypt -municode -w  -o Erwin.exe", setPathCmd);


	printf("Compilation successful.\n");
	printf("Shinzo wo Sasageyo! Erwin.exe Created.\n");

	// Execute the command
	int result = system(gccCmd);


}



void Headers(const char* header) 
{
	if (strcmp(header, "mac") == 0) 
	{
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include <stdio.h>\n\n\n");
	}
	else if (strcmp(header, "uuid") == 0) {
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include <stdio.h>\n\n\n");
	}
	else if (strcmp(header, "ipv4") == 0) {
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include <stdio.h>\n\n\n");
	}
	else if (strcmp(header, "ipv6") == 0) {
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include <stdio.h>\n\n\n");
	}
	else if (strcmp(header, "aes") == 0) {
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include <stdio.h>\n");
		printf("#include <bcrypt.h>\n");
		printf("#pragma comment(lib, \"Bcrypt.lib\")\n\n\n");
	}
	else if (strcmp(header, "rc4") == 0) {
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include <stdio.h>\n\n\n");
	}
	else if (strcmp(header, "xor") == 0) {
		printf("#define _CRT_SECURE_NO_WARNINGS\n");
		printf("#include <windows.h>\n");
		printf("#include <stdio.h>\n\n\n");
	}
}


