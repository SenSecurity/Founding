#include <Windows.h>
#include <stdio.h>

#include "Common.h"


char* GenerateUUid(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	char Output0[32], Output1[32], Output2[32], Output3[32];
	char result[128]; // 32 * 4

	// generating output0 from the first 4 bytes
	sprintf(Output0, "%0.2X%0.2X%0.2X%0.2X", d, c, b, a);

	// generating output1 from the second 4 bytes
	sprintf(Output1, "%0.2X%0.2X-%0.2X%0.2X", f, e, h, g);

	// generating output2 from the third 4 bytes
	sprintf(Output2, "%0.2X%0.2X-%0.2X%0.2X", i, j, k, l);

	// generating output3 from the last 4 bytes
	sprintf(Output3, "%0.2X%0.2X%0.2X%0.2X", m, n, o, p);

	// combining Output0,1,2,3 all together to generate our output to return
	sprintf(result, "%s-%s-%s%s", Output0, Output1, Output2, Output3);

	//printf("[i] result: %s\n", (char*)result);
	return (char*)result;
}




// generate the UUid output representation of the shellcode
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0) {
		return FALSE;
	}

	printf("char* UuidArray[] = { \n\t");
	// c is 16 so that we start at the first 16 bytes (check later comments to understand)
	int c = 16, C = 0;
	char* IP = NULL;
	for (int i = 0; i < ShellcodeSize; i++) {
		// tracking the bytes read, at each 16 bytes (when c is 16), we enter this if statement, to generate our ipv6 address
		if (c == 16) {
			C++;
			// generating our uuid address, from 16 bytes that starts at i and count 15 bytes more ... 
			IP = GenerateUUid(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);

			if (i == ShellcodeSize - 16) {
				// printing the last uuid address
				printf("\"%s\"", IP);
				break;
			}
			else {
				// printing the uuid address
				printf("\"%s\", ", IP);
			}
			c = 1;
			// just to track how many uuid addresses we printed, so that we print \n\t and make the output more clean
			if (C % 3 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");

	printf("#define NumberOfElements %d\n\n\n", (int)(ShellcodeSize / 16));


	return TRUE;
}



// taking input raw bytes and returning them in mac string format
char* GenerateMAC(int a, int b, int c, int d, int e, int f) {
	char Output[64];
	sprintf(Output, "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X", a, b, c, d, e, f);
	//	printf("[i] Output: %s\n", Output);
	return (char*)Output;
}

// generate the Mac output representation of the shellcode
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	// if null or the size is not multiple of 6
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 6 != 0) {
		return FALSE;
	}

	printf("char* MacArray [] = {\n\t");
	// c is 6 so that we start at the first 6 bytes (check later comments to understand)
	int c = 6, C = 0;
	char* Mac = NULL;
	for (int i = 0; i < ShellcodeSize; i++) {
		// tracking the bytes read, at each 6 bytes (when c is 46, we enter this if statement, to generate our Mac address
		if (c == 6) {
			C++;
			// generating our Mac address, from a 6 bytes that starts at i and count 5 bytes more ...
			Mac = GenerateMAC(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3], pShellcode[i + 4], pShellcode[i + 5]);
			if (i == ShellcodeSize - 6) {
				// printing the last Mac address
				printf("\"%s\"", Mac);
				break;
			}
			else {
				// printing the Mac address
				printf("\"%s\", ", Mac);
			}
			c = 1;
			// just to track how many ipv4 addresses we printed, so that we print \n\t and make the output more clean
			if (C % 6 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	printf("#define NumberOfElements %d\n\n\n", (int)(ShellcodeSize / 6));

	return TRUE;
}




// taking input raw bytes and returning them in ipv6 string format
char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	char Output0[32], Output1[32], Output2[32], Output3[32];

	char result[128]; // 32 * 4
	// generating output0 from the first 4 bytes
	sprintf(Output0, "%0.2X%0.2X:%0.2X%0.2X", a, b, c, d);

	// generating output1 from the second 4 bytes
	sprintf(Output1, "%0.2X%0.2X:%0.2X%0.2X", e, f, g, h);

	// generating output2 from the third 4 bytes
	sprintf(Output2, "%0.2X%0.2X:%0.2X%0.2X", i, j, k, l);

	// generating output3 from the last 4 bytes
	sprintf(Output3, "%0.2X%0.2X:%0.2X%0.2X", m, n, o, p);

	// combining Output0,1,2,3 all together to generate our output to return
	sprintf(result, "%s:%s:%s:%s", Output0, Output1, Output2, Output3);

	//printf("[i] result: %s\n", (char*)result);

	return (char*)result;

}


// generate the ipv6 output representation of the shellcode
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0) {
		return FALSE;
	}

	printf("char* Ipv6Array [] = { \n\t");
	// c is 16 so that we start at the first 16 bytes (check later comments to understand)
	int c = 16, C = 0;
	char* IP = NULL;
	for (int i = 0; i < ShellcodeSize; i++) {
		// tracking the bytes read, at each 16 bytes (when c is 16), we enter this if statement, to generate our ipv6 address
		if (c == 16) {
			C++;
			// generating our ipv6 address, from 16 bytes that starts at i and count 15 bytes more ... 
			IP = GenerateIpv6(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);

			if (i == ShellcodeSize - 16) {
				// printing the last ipv6 address
				printf("\"%s\"", IP);
				break;
			}
			else {
				// printing the ipv6 address
				printf("\"%s\", ", IP);
			}
			c = 1;
			// just to track how many ipv6 addresses we printed, so that we print \n\t and make the output more clean
			if (C % 3 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	printf("#define NumberOfElements %d\n\n\n", (int)(ShellcodeSize / 16));
	return TRUE;
}




// taking input raw bytes and returning them in ipv4 string format
char* GenerateIpv4(int a, int b, int c, int d) {

	unsigned char Output[32];
	// combining all to *Output* to return 
	sprintf(Output, "%d.%d.%d.%d", a, b, c, d);
	//printf("[i] Output: %s\n", Output);

	return (char*)Output;
}


// generate the ipv4 output representation of the shellcode
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	// if null or the size is not multiple of 4
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 4 != 0) {
		return FALSE;
	}

	printf("char* Ipv4Array[] = { \n\t");
	// c is 4 so that we start at the first 4 bytes (check later comments to understand)
	int c = 4, C = 0;
	char* IP = NULL;
	for (int i = 0; i < ShellcodeSize; i++) {
		// tracking the bytes read, at each 4 bytes (when c is 4), we enter this if statement, to generate our ipv4 address
		if (c == 4) {
			C++;
			// generating our ipv4 address, from a 4 bytes that starts at i and count 3 bytes more ... 
			IP = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);
			if (i == ShellcodeSize - 4) {
				// printing the last ipv4 address
				printf("\"%s\"", IP);
				break;
			}
			else {
				// printing the ipv4 address
				printf("\"%s\", ", IP);
			}
			c = 1;
			// just to track how many ipv4 addresses we printed, so that we print \n\t and make the output more clean
			if (C % 8 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	printf("#define NumberOfElements %d\n\n\n", (int)C);
	return TRUE;
}


