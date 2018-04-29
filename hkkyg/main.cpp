#include <iostream>
#include <windows.h>
#include <strsafe.h>
#include "debuger.h"

//DWORD addr = 0x34b2f20;



int main(int argc, char** argv)
{
	DWORD pid = utils::getPid(L"test_apps.exe");
	utils::privileges();

	if (utils::inject(pid, "dll_test.dll"))
	{
		std::cout << "Successful injection" << std::endl;
	}
	else
	{
		std::cout << "Error" << std::endl;
	}
	
	std::cin.ignore().get();

	return 0;
}
