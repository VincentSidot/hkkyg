#include "debuger.h"

PROCESSENTRY32W utils::getProcess(WCHAR * const name)
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

DWORD utils::getPid(WCHAR * const name)
{
	return getProcess(name).th32ProcessID;
}

bool utils::Debuguer::attach(LPWSTR name)
{
	pid = getPid(name);
	if(pid == 0)
		return false;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (hProcess == NULL)
		return false;
	return true;
}

utils::Debuguer::~Debuguer()
{
	CloseHandle(hProcess);
}

void utils::Debuguer::read(DWORD addr, PBYTE buffer, DWORD buffsize)
{
	ReadProcessMemory(hProcess, (PVOID)addr, (PVOID)buffer, buffsize, NULL);
}

void utils::Debuguer::write(DWORD addr, PBYTE const buffer, DWORD buffsize)
{
	WriteProcessMemory(hProcess, (PVOID)addr, (PVOID)buffer, buffsize, NULL);
}

void utils::Debuguer::write(DWORD addr, char * const buffer, DWORD buffsize)
{
	WriteProcessMemory(hProcess, (PVOID)addr, (PVOID)buffer, buffsize, NULL);
}
