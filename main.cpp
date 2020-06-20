#include <stdio.h>
#include <iostream>
#include <Windows.h>
#include <Shlwapi.h>
#include <string>
#include <TlHelp32.h>
using namespace std;

#pragma comment(lib, "Shlwapi.lib")

int main(void) {
	char DllPath[] = "\\.\\InjectDLL.dll"; // Dll File Path
	if (!PathFileExists(DllPath)) {
		cout << "Invalid DLL File Path\n";
		exit(-1);
	}

	size_t len = strlen(DllPath) + 1;
	DWORD pid, nWrite;
	HWND hwnd = FindWindow(NULL, "Window of Target Application");
	if (NULL == hwnd) {
		cout << "FindWindow Failure!\n";
		exit(-1);
	}

	GetWindowThreadProcessId(hwnd, &pid);

	HANDLE hOpen = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hOpen == NULL) {
		cout << "OpenProcess Failure!\n";
		exit(-1);
	}

	LPVOID vAlloc = VirtualAllocEx(hOpen, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (vAlloc == NULL) {
		cout << "VirtualAllocEx Failure!\n";
		exit(-1);
	}

	BOOL bOk = WriteProcessMemory(hOpen, vAlloc, DllPath, len, &nWrite);
	if (bOk == 0) {
		cout << "WriteProcessMemory Failure!\n";
		exit(-1);
	}

	FARPROC farAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	HANDLE cThread = CreateRemoteThread(hOpen, NULL, 0, (PTHREAD_START_ROUTINE)farAddr, vAlloc, 0, NULL);
	if (cThread == NULL) {
		cout << "CreateRemoteThread Failure!\n";
		exit(-1);
	}

	cout << "DLL Injected Successfully\n";
	VirtualFreeEx(hOpen, vAlloc, len, MEM_DECOMMIT | MEM_RELEASE);
	CloseHandle(hOpen);

	return 0;
}
