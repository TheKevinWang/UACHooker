#pragma once


//disable nonmeaningful warnings.
#pragma warning(push)
//#pragma warning(disable: 4005) // macro redefinition
//#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
//#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
//#pragma comment(lib, "ntdll.lib")
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union

#include <windows.h>
#include <ntstatus.h>
#include <bcrypt.h>
//typedef PIMAGE_NT_HEADERS(NTAPI* RTLIMAGENTHEADER)(PVOID);
//HINSTANCE hNtdll = GetModuleHandleA("ntdll.dll");
//RTLIMAGENTHEADER RtlImageNtHeader = (RTLIMAGENTHEADER)GetProcAddress(hNtdll, "RtlImageNtHeader");
//
//typedef NTSTATUS(NTAPI* RTLGETVERSION)(PRTL_OSVERSIONINFOW);
//RTLGETVERSION RtlGetVersion = (RTLGETVERSION)GetProcAddress(hNtdll, "RtlGetVersion");


#define _NTDEF_
//#include <ntsecapi.h>
#undef _NTDEF_

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000ull
#endif

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)


typedef ULONG ELEVATION_REASON;

#define ALIGN_UP_BY(Address, Align) (((ULONG_PTR)(Address) + (Align) - 1) & ~((Align) - 1))

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
ULONG_PTR AicFindLaunchAdminProcess(
	_Out_ PNTSTATUS StatusCode);

#define SUCCESS                     0L
#define FAILURE_NULL_ARGUMENT       1L
#define FAILURE_API_CALL            2L
#define FAILURE_INSUFFICIENT_BUFFER 3L
#define MAX_PATH_LEN 260
#define MAX_ARGS_LEN 32768
#define UNICODE