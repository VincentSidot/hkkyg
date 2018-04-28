#include <iostream>
#include <windows.h>
#include <strsafe.h>
#include "debuger.h"

//DWORD addr = 0x34b2f20;

typedef int (WINAPI* MsgBoxParam)(HWND, LPCSTR, LPCSTR, UINT);

struct PARAMETERS
{
	DWORD MessageBoxInj;
	char text[50];
	char caption[25];
	int buttons;
};

DWORD myFunc(PARAMETERS* param);
DWORD useless(); // find size of my func;

DWORD myFunc(PARAMETERS* param)
{
	MsgBoxParam MsgBox = (MsgBoxParam)param->MessageBoxInj;
	DWORD result = MsgBox(0, param->text, param->caption, param->buttons);
	/*
	switch (result)
	{
	case IDOK:
		//do nothings
		break;
	case IDCANCEL:
		exit(0);
		break;
	}
	*/
	return 0;
}
DWORD useless()
{
	return 0;
}


int main(int argc, char** argv)
{
	DWORD pid = utils::getPid(L"notepad.exe");
	utils::privileges();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (hProcess == NULL)
		utils::ErrorExit("OpenProcess");

	char text[] = "You have been hijacked";
	char caption[] = "Hello :)";

	PARAMETERS data;

	data.MessageBoxInj = (DWORD)GetProcAddress(GetModuleHandle("User32.dll"), "MessageBoxA");
	strcpy_s(data.text, strlen(text)+1, text);
	strcpy_s(data.caption, strlen(caption)+1, caption);
	data.buttons = MB_OKCANCEL | MB_ICONWARNING;

	DWORD size_function = (DWORD)useless - (DWORD)myFunc;
	
	PVOID myFuncAddr = VirtualAllocEx(hProcess, NULL, size_function, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, myFuncAddr, (void*)myFunc, size_function, NULL);

	PVOID myParamAddr = VirtualAllocEx(hProcess, NULL, sizeof(PARAMETERS), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, myParamAddr, &data, sizeof(PARAMETERS), NULL);

	HANDLE thread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)myFuncAddr, myParamAddr, 0, NULL);
	if (thread != 0)
	{
		WaitForSingleObject(thread, INFINITE);
		VirtualFreeEx(hProcess, myFuncAddr, size_function, MEM_RELEASE);
		VirtualFreeEx(hProcess, myParamAddr, sizeof(PARAMETERS), MEM_RELEASE);
		CloseHandle(thread);
		CloseHandle(hProcess);
		std::cout << "Injection completed" << std::endl;
		std::cin.ignore().get();
	}
	else
	{
		utils::ErrorExit("CreateThreadRemote", false);
		std::cout << "Error creating thread" << std::endl;
		std::cin.ignore().get();
	}


	return 0;
}
