#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

namespace utils {

	PROCESSENTRY32W getProcess(WCHAR* const name);
	std::vector<PROCESSENTRY32W> getAllProcess();
	DWORD getPid(WCHAR* const name);
	
	class Debuguer
	{
	public:
		bool attach(LPWSTR name);
		~Debuguer();

		template<typename T>
		T read(DWORD addr)
		{
			T rep;
			ReadProcessMemory(hProcess, (PVOID)addr, &rep, sizeof(T), NULL);
			return rep;
		}

		template<typename T>
		void write(DWORD addr, T val)
		{
			WriteProcessMemory(hProcess, (PVOID)addr, &val, sizof(T), NULL)
		}

		void read(DWORD addr, PBYTE buffer, DWORD buffsize);
		void write(DWORD addr, PBYTE const buffer, DWORD buffsize);
		void write(DWORD addr, char* const buffer, DWORD buffsize);

	private:
		DWORD pid;
		HANDLE hProcess;
	};

}