#include "debuger.h"

PROCESSENTRY32W utils::getProcess(LPCWSTR name)
{
	PROCESSENTRY32W process;
	process.dwSize = sizeof(process);
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32FirstW(snap, &process))
	{
		do
		{
			if (lstrcmpiW(process.szExeFile, name) == 0)
			{
				CloseHandle(snap);
				return process;
			}
		} while (Process32NextW(snap, &process));
	}
	CloseHandle(snap);
}

std::vector<PROCESSENTRY32W> utils::getAllProcess()
{
	std::vector<PROCESSENTRY32W> rep;
	PROCESSENTRY32W process;
	process.dwSize = sizeof(process);
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32FirstW(snap, &process))
	{
		do 
		{
			rep.push_back(process);
		} while (Process32NextW(snap,&process));
	}
	CloseHandle(snap);
	return rep;
}

DWORD utils::getPid(LPCWSTR name)
{
	return getProcess(name).th32ProcessID;
}

void utils::ErrorExit(LPCTSTR lpszFunction, bool exit)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	if(exit)
		ExitProcess(dw);
}

size_t utils::rawDataToHex(LPCVOID rawdata, size_t datalen, char ** str)
{
	size_t len = datalen * 5 -1 ; // "0xab" with a space so 5char for one data byte, except for the last.
	*str = (char*)malloc(len+1);
	sprintf_s(*str, len, "0x%x", *((PBYTE)rawdata));
	for (size_t i = 1; i < datalen; i++)
	{
		sprintf_s(*str, len+1, "%s 0x%x", *str,*((PBYTE)rawdata + i));
	}
	return len;
}

bool utils::Debuguer::attach(LPCWSTR name)
{
	pid = utils::getPid(name);
	if (pid == 0)
		return false;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (hProcess == NULL)
	{
#ifdef	DEBUG
		ErrorExit("utils::Debuger::attach::OpenProcess");
#endif
		return false;
	}
	return true;
}

bool utils::Debuguer::attach(DWORD pid)
{
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (hProcess == NULL)
	{
#ifdef	DEBUG
		ErrorExit("utils::Debuger::attach::OpenProcess");
#endif
		return false;
	}
	return true;
}

utils::Debuguer::~Debuguer()
{
	CloseHandle(hProcess);
}

HANDLE utils::Debuguer::getProcess() const
{
	return hProcess;
}

DWORD utils::Debuguer::read(DWORD addr, PBYTE buffer, DWORD buffsize)
{
	DWORD oldProtect,trash;
	if (VirtualProtectEx(hProcess, (PVOID)addr, buffsize, PAGE_READWRITE, &oldProtect) == 0)
	{
#ifdef	DEBUG
		ErrorExit("utils::Debuger::read::VirtualProtectEx");
#endif
		return 0;
	}
	if (ReadProcessMemory(hProcess, (PVOID)addr, (PVOID)buffer, buffsize, NULL) == 0)
	{
#ifdef	DEBUG
		ErrorExit("utils::Debuger::read::ReadProcessMemory");
#endif
		return 0;
	}
	if (VirtualProtectEx(hProcess, (PVOID)addr, buffsize, oldProtect, &trash) == 0)
	{
#ifdef	DEBUG
		ErrorExit("utils::Debuger::read::VirtualProtectEx");
#endif
		return 0;
	}
}

DWORD utils::Debuguer::write(DWORD addr, PBYTE const buffer, DWORD buffsize)
{
	DWORD oldProtect, trash;
	if (VirtualProtectEx(hProcess, (PVOID)addr, buffsize, PAGE_READWRITE, &oldProtect) == 0)
	{
#ifdef	DEBUG
		ErrorExit("utils::Debuger::write::VirtualProtectEx");
#endif
		return 0;
	}
	if (WriteProcessMemory(hProcess, (PVOID)addr, (PVOID)buffer, buffsize, NULL) == 0)
	{
#ifdef	DEBUG
		ErrorExit("utils::Debuger::write::WriteProcessMemory");
#endif
		return 0;
	}
	if (VirtualProtectEx(hProcess, (PVOID)addr, buffsize, oldProtect, &trash) == 0)
	{
#ifdef	DEBUG
		ErrorExit("utils::Debuger::write::VirtualProtectEx");
#endif
		return 0;
	}
}

DWORD utils::Debuguer::write(DWORD addr, char * const buffer, DWORD buffsize)
{
	DWORD oldProtect, trash;
	if (VirtualProtectEx(hProcess, (PVOID)addr, buffsize, PAGE_READWRITE, &oldProtect) == 0)
	{
#ifdef	DEBUG
		ErrorExit("utils::Debuger::write::VirtualProtectEx");
#endif
		return 0;
	}
	if (WriteProcessMemory(hProcess, (PVOID)addr, (PVOID)buffer, buffsize, NULL) == 0)
	{
#ifdef	DEBUG
		ErrorExit("utils::Debuger::write::WriteProcessMemory");
#endif
		return 0;
	}
	if (VirtualProtectEx(hProcess, (PVOID)addr, buffsize, oldProtect, &trash) == 0)
	{
#ifdef	DEBUG
		ErrorExit("utils::Debuger::write::VirtualProtectEx");
#endif
		return 0;
	}
}

DWORD utils::Debuguer::getPid() const
{
	return pid;
}

int utils::privileges() {
	HANDLE Token;
	TOKEN_PRIVILEGES tp;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
	{
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (AdjustTokenPrivileges(Token, 0, &tp, sizeof(tp), NULL, NULL) == 0) {
			return 1; //FAIL
		}
		else {
			return 0; //SUCCESS
		}
	}
	return 1;
}

bool utils::inject(DWORD PID, std::string dllPath)
{
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, NULL, PID);
	if (hProcess == INVALID_HANDLE_VALUE || hProcess == NULL)
	{
#ifdef DEBUG
		utils::ErrorExit("utils::inject::OpenProcess");
#endif // DEBUG
		return false;
	}
	LPVOID kernel32addr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	LPVOID alloc = VirtualAllocEx(hProcess, NULL, dllPath.length() + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (alloc == NULL)
	{
#ifdef DEBUG
		utils::ErrorExit("utils::inject::VirtualAllocEx");
#endif // DEBUG
		return false;
	}
	if (WriteProcessMemory(hProcess, alloc, dllPath.c_str(), dllPath.length() + 1, NULL) == 0)
	{
#ifdef DEBUG
		utils::ErrorExit("utils::inject::WriteProcessMemory");
#endif // DEBUG
		return false;
	}
	DWORD threadId;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)kernel32addr, alloc, 0, &threadId);
	if (hThread == NULL)
	{
#ifdef DEBUG
		utils::ErrorExit("utils::inject::CreateRemoteThread");
#endif // DEBUG
		return false;
	}
	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hProcess, alloc, dllPath.length() + 1, MEM_RELEASE);
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return true;
}

DWORD utils::manual_inject(DWORD PID, std::string dllPath)
{

}

