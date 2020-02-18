#include <Windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	return TRUE;
}

// Return TRUE because this is the real DLL

extern "C" __declspec(dllexport) BOOL Static()
{
	return TRUE;
};

extern "C" __declspec(dllexport) BOOL Dynamic()
{
	return TRUE;
};