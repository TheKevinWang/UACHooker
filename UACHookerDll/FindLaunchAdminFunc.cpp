/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2019
*
*  TITLE:       AIC.C
*
*  VERSION:     3.20
*
*  DATE:        22 Oct 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "FindLaunchAdminFunc.h"
#include <cassert>
#include <iomanip>
#include <iostream>
#include <vector>
#define SHELL32_DLL                 L"shell32.dll"
#define WINDOWS_STORAGE_DLL         L"windows.storage.dll"
HINSTANCE hNtdll = GetModuleHandleA("ntdll.dll");

typedef PIMAGE_NT_HEADERS(NTAPI* RTLIMAGENTHEADER)(PVOID);
RTLIMAGENTHEADER RtlImageNtHeader = (RTLIMAGENTHEADER)GetProcAddress(hNtdll, "RtlImageNtHeader");

typedef NTSTATUS(NTAPI* RTLGETVERSION)(PRTL_OSVERSIONINFOW);
RTLGETVERSION RtlGetVersion = (RTLGETVERSION)GetProcAddress(hNtdll, "RtlGetVersion");

//RTLIMAGENTHEADER RtlImageNtHeader = (RTLIMAGENTHEADER)GetProcAddress(hNtdll, "RtlImageNtHeader");
//
// AicLaunchAdminProcess prologue signature.
//

unsigned char LaunchAdminProcessSignature760x[] = {
	0xFF, 0xF3, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81,
	0xEC, 0x30, 0x04, 0x00, 0x00
};

unsigned char LaunchAdminProcessSignature9200[] = {
	0x44, 0x89, 0x44, 0x24, 0x18, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
	0x41, 0x57, 0x48, 0x81, 0xEC, 0xF0, 0x03, 0x00, 0x00
};

unsigned char LaunchAdminProcessSignature9600[] = {
	0x44, 0x89, 0x4C, 0x24, 0x20, 0x44, 0x89, 0x44, 0x24, 0x18, 0x53, 0x56, 0x57, 0x41,
	0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x00, 0x04, 0x00, 0x00
};

unsigned char LaunchAdminProcessSignature10240_10586[] = {
	0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81,
	0xEC, 0x30, 0x04, 0x00, 0x00
};

unsigned char LaunchAdminProcessSignature14393[] = {
	0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81,
	0xEC, 0x20, 0x04, 0x00, 0x00
};

unsigned char LaunchAdminProcessSignature_15063_18362[] = {
	0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81,
	0xEC, 0x20, 0x04, 0x00, 0x00
};
//40 53 56 57 41 54 41 55 41 56 41 57 48 81 EC 30 04 00 00
unsigned char LaunchAdminProcessSignature_18363_xxxxx[] = {
	0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81,
	0xEC, 0x30, 0x04, 0x00, 0x00
};


/*
* supFindPattern
*
* Purpose:
*
* Lookup pattern in buffer.
*
*/
PVOID supFindPattern(
	CONST PBYTE Buffer,
	SIZE_T BufferSize,
	CONST PBYTE Pattern,
	SIZE_T PatternSize
)
{
	PBYTE	p = Buffer;

	if (PatternSize == 0)
		return NULL;
	if (BufferSize < PatternSize)
		return NULL;
	BufferSize -= PatternSize;

	do {
		p = (PBYTE)memchr(p, Pattern[0], BufferSize - (p - Buffer));
		if (p == NULL)
			break;

		if (memcmp(p, Pattern, PatternSize) == 0)
			return p;

		p++;
	} while (BufferSize - (p - Buffer) > 0); //-V555

	return NULL;
}

/*
* AicFindLaunchAdminProcess
*
* Purpose:
*
* Locate unexported AppInfo routine in memory by signature.
*
*/
ULONG_PTR AicFindLaunchAdminProcess(
	_Out_ PNTSTATUS StatusCode)
{
	ULONG_PTR Address = 0;
	PBYTE Pattern = NULL, ScanBase = NULL;
	DWORD PatternSize = 0, ScanSize = 0;
	IMAGE_NT_HEADERS* NtHeaders;
	LPWSTR ScanModule = NULL;
	RTL_OSVERSIONINFOW g_ctx;
	RtlSecureZeroMemory(&g_ctx, sizeof(g_ctx));
	g_ctx.dwOSVersionInfoSize = sizeof(g_ctx);
	RtlGetVersion((PRTL_OSVERSIONINFOW)&g_ctx);
	DWORD dwBuildNumber = g_ctx.dwBuildNumber;
	if (g_ctx.dwBuildNumber < 10240)
		ScanModule = SHELL32_DLL;
	else
		ScanModule = WINDOWS_STORAGE_DLL;

	switch (g_ctx.dwBuildNumber) {

	case 7600:
	case 7601:
		Pattern = LaunchAdminProcessSignature760x;
		PatternSize = sizeof(LaunchAdminProcessSignature760x);
		break;
	case 9200:
		Pattern = LaunchAdminProcessSignature9200;
		PatternSize = sizeof(LaunchAdminProcessSignature9200);
		break;
	case 9600:
		Pattern = LaunchAdminProcessSignature9600;
		PatternSize = sizeof(LaunchAdminProcessSignature9600);
		break;
	case 10240:
	case 10586:
		Pattern = LaunchAdminProcessSignature10240_10586;
		PatternSize = sizeof(LaunchAdminProcessSignature10240_10586);
		break;
	case 14393:
		Pattern = LaunchAdminProcessSignature14393;
		PatternSize = sizeof(LaunchAdminProcessSignature14393);
		break;
	case 15063:
	case 16299:
	case 17134:
	case 17763:
	case 18362:
		Pattern = LaunchAdminProcessSignature_15063_18362;
		PatternSize = sizeof(LaunchAdminProcessSignature_15063_18362);
		break;
	case 18363:
	default:
		Pattern = LaunchAdminProcessSignature_18363_xxxxx;
		PatternSize = sizeof(LaunchAdminProcessSignature_18363_xxxxx);
		break;
	}

	ScanBase = (PBYTE)GetModuleHandleW(ScanModule);
	if (ScanBase == NULL) {
		ScanBase = (PBYTE)LoadLibraryExW(ScanModule, NULL, 0); //is in \KnownDlls
	}

	if (ScanBase == NULL) {
		*StatusCode = STATUS_INTERNAL_ERROR;
		return 0;
	}

	NtHeaders = RtlImageNtHeader(ScanBase);
	if (NtHeaders->OptionalHeader.SizeOfImage <= PatternSize) {
		*StatusCode = STATUS_INTERNAL_ERROR;
		return 0;
	}

	ScanSize = NtHeaders->OptionalHeader.SizeOfImage - PatternSize;
	Address = (ULONG_PTR)supFindPattern(ScanBase, (SIZE_T)ScanSize, Pattern, (SIZE_T)PatternSize);
	if (Address == 0) {
		*StatusCode = STATUS_PROCEDURE_NOT_FOUND;
		return 0;
	}

	*StatusCode = STATUS_SUCCESS;

	return Address;
}