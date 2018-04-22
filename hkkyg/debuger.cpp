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

utils::Debuguer::~Debuguer()
{
	CloseHandle(hProcess);
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
