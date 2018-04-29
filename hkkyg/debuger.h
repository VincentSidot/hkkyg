#pragma once
#include <Windows.h>
#include <strsafe.h>
#include <TlHelp32.h>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <vector>

#define DEBUG

namespace utils {

	PROCESSENTRY32W getProcess(LPCWSTR name);
	std::vector<PROCESSENTRY32W> getAllProcess();
	DWORD getPid(LPCWSTR name);
	void ErrorExit(LPCTSTR lpszFunction, bool exit = true);
	size_t rawDataToHex(LPCVOID rawdata, size_t datalen, char** str); // return size of str, auto allocate str you must free it after use.
	int privileges();
	bool inject(DWORD PID, std::string dllPath);
	DWORD manual_inject(DWORD PID, std::string dllPath);
	class Debuguer
	{
	public:
		bool attach(const LPCWSTR name);
		bool attach(DWORD pid);
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

		HANDLE getProcess() const;
		DWORD read(DWORD addr, PBYTE buffer, DWORD buffsize); //return 0 if not okay
		DWORD write(DWORD addr, PBYTE const buffer, DWORD buffsize); //return 0 if not okay
		DWORD write(DWORD addr, char* const buffer, DWORD buffsize); //return 0 if not okay

		DWORD getPid() const;

	private:
		DWORD pid;
		HANDLE hProcess;
	};

}