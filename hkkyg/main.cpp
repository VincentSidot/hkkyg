#include <iostream>
#include <windows.h>
#include <strsafe.h>
#include "debuger.h"


DWORD addr = 0x2f56fe0;


int main(int argc, char** argv)
{
	utils::Debuguer debug;
	if (!debug.attach(L"test_apps.exe"))
	{
		return -1;
	}
	int readedVal = debug.read<int>(addr);
	std::cout << "Readed val : " << readedVal << std::endl;
	int newVal;
	std::cout << "Enter new val : ";
	std::cin >> newVal;
	debug.write<int>(addr, newVal);

	return 0;
}
