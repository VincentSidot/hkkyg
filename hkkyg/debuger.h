#pragma once
#include <Windows.h>
#include <strsafe.h>
#include <TlHelp32.h>
#include <vector>

#define DEBUG

namespace utils {

	PROCESSENTRY32W getProcess(LPCWSTR name);
	std::vector<PROCESSENTRY32W> getAllProcess();
	DWORD getPid(LPCWSTR name);
	void ErrorExit(LPCTSTR lpszFunction, bool exit = true);
	
	class Debuguer
	{
	public:
		bool attach(const LPCWSTR name);
		~Debuguer();

		template<typename T>
		T read(DWORD addr,DWORD* ret = NULL) //ret = 0 if not okay
		{
			T rep;
			DWORD _ret = this->read(addr, (PBYTE)&rep, sizeof(rep));
			if (ret != NULL)
			{
				*ret = _ret;
			}
			return rep;
		}

		template<typename T>
		DWORD write(DWORD addr, T val) //return 0 if not okay
		{
			return this->write(addr, (PBYTE)&val, sizeof(val));
		}

		DWORD read(DWORD addr, PBYTE buffer, DWORD buffsize); //return 0 if not okay
		DWORD write(DWORD addr, PBYTE const buffer, DWORD buffsize); //return 0 if not okay
		DWORD write(DWORD addr, char* const buffer, DWORD buffsize); //return 0 if not okay

		DWORD getPid() const;

	private:
		DWORD pid;
		HANDLE hProcess;
	};

}