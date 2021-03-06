// dllmain.cpp : Définit le point d'entrée pour l'application DLL.
#include "stdafx.h"

void inject();

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH:
		inject();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void inject()
{
	switch (MessageBoxA(NULL, "You have been hijacked", "Hello :)", MB_OKCANCEL | MB_ICONWARNING))
	{
	case IDOK:
		printf("\nHello from dll :)\n");
		break;
	case IDCANCEL:
		ExitProcess(1);
		break;
	};
	
}
