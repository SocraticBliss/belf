
#ifndef DLLMAIN_CPP
#define DLLMAIN_CPP

#include <string.h>
#include <Shlwapi.h>
#include <Windows.h>

#include <loader.hpp>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);

		return TRUE;
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		return TRUE;
	}

	return FALSE;
}

#endif // DLLMAIN_CPP
