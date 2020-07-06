#include <Windows.h>

extern "C" BOOL Static();
typedef BOOL (WINAPI *DynExport)();

int main() {

	// Static Sink
	if (Static()) {
		MessageBox(0, L"[+] Static Sink: GOOD", L"Harness", 0);
	}
	else {
		MessageBox(0, L"[!] Static Sink: BAD", L"Harness", 0);
	}

	// Dynamic Sink
	HMODULE module = LoadLibrary(L"Theif.dll");
	if (!module) return 1;

	DynExport Dynamic = (DynExport)GetProcAddress(module, "Dynamic");
	if (!Dynamic) return 1;

	if (Dynamic()) {
		MessageBox(0, L"[+] Dynamic Sink: GOOD", L"Harness", 0);
	}
	else {
		MessageBox(0, L"[!] Dynamic Sink: BAD", L"Harness", 0);
	}

	return 0;
}