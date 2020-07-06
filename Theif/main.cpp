#include <Windows.h>
#include <winternl.h>
#include <map>
#include <string>

#ifdef _REBUILD
BOOL RebuildExportTable(PBYTE ourBase, PBYTE targetBase);
#endif

#ifdef _FORWARD

#pragma comment(linker,"/export:Static=Functions.Static")
#pragma comment(linker,"/export:Dynamic=Functions.Dynamic")

#else

// Return FALSE because this is the Theif DLL
// (we shouldn't hit these)

extern "C" __declspec(dllexport) BOOL Static()
{
	return FALSE;
};

extern "C" __declspec(dllexport) BOOL Dynamic()
{
	return FALSE;
};
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason != DLL_PROCESS_ATTACH)
		return TRUE;

#ifdef _REBUILD
	HMODULE real_dll = LoadLibrary(L"Functions.dll");
	RebuildExportTable((PBYTE)hinstDLL, (PBYTE)real_dll);
#endif

	return (TRUE);
}


#ifdef _REBUILD

PBYTE AllocateUsableMemory(PBYTE baseAddress, DWORD size, DWORD protection = PAGE_READWRITE) {

#ifdef _WIN64
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)dosHeader + dosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER optionalHeader = &ntHeaders->OptionalHeader;

	// Create some breathing room
	baseAddress = baseAddress + optionalHeader->SizeOfImage;

	for (PBYTE offset = baseAddress; offset < baseAddress + MAXDWORD; offset += 1024 * 8) {
		PBYTE usuable = (PBYTE)VirtualAlloc(
			offset,
			size,
			MEM_RESERVE | MEM_COMMIT,
			protection);

		if (usuable) {
			ZeroMemory(usuable, size); // Not sure if this is required
			return usuable;
		}
	}
#else
	// In x86 it doesn't matter where we allocate

	PBYTE usuable = (PBYTE)VirtualAlloc(
		NULL,
		size,
		MEM_RESERVE | MEM_COMMIT,
		protection);

	if (usuable) {
		ZeroMemory(usuable, size);
		return usuable;
	}
#endif
	return 0;
}

typedef struct _UNICODE_STR
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

BOOL RebuildExportTable(PBYTE ourBase, PBYTE targetBase)
{
#ifdef _WIN64
	BYTE jmpPrefix[] = { 0x48, 0xb8 };
	BYTE jmpRax[] = { 0xff, 0xe0 };
#else
	BYTE jmpPrefix[] = { 0x68 };
	BYTE jmpRax[] = { 0xc3 };
#endif

	std::map<std::string, PBYTE> exports;

	///
	// 1 - Get export directories for both DLLs. Perform sanity checks.
	///

	auto targetHeaders = (PIMAGE_NT_HEADERS)(targetBase + PIMAGE_DOS_HEADER(targetBase)->e_lfanew);
	auto exportDataDir = &targetHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (exportDataDir->Size == 0)
		return FALSE; // The real DLL doesn't have any exports

	// TODO - Consider mixed name/ordinal exports? (NumberOfNames != NumberOfFunctions)
	auto targetExportDirectory = PIMAGE_EXPORT_DIRECTORY(targetBase + exportDataDir->VirtualAddress);

	auto nameOffsetList = PDWORD(targetBase + targetExportDirectory->AddressOfNames);
	auto addressList = PDWORD(targetBase + targetExportDirectory->AddressOfFunctions);
	auto ordinalList = PWORD(targetBase + targetExportDirectory->AddressOfNameOrdinals);

	auto ourHeaders = (PIMAGE_NT_HEADERS)(ourBase + PIMAGE_DOS_HEADER(ourBase)->e_lfanew);
	auto ourExportDataDir = &ourHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (ourExportDataDir->Size == 0)
		return FALSE; // Our DLLs doesn't have any exports

	auto ourExportDirectory = PIMAGE_EXPORT_DIRECTORY(ourBase + ourExportDataDir->VirtualAddress);

	///
	// 2 - Add all of the target DLL export names and code addresses to a map
	///

	for (DWORD i = 0; i < targetExportDirectory->NumberOfNames; i++) {
		std::string functionName = LPSTR(targetBase + nameOffsetList[i]);
		if (functionName.empty()) continue;
		PBYTE code = PBYTE(targetBase + addressList[ordinalList[i]]);
		exports.insert(std::pair<std::string, PBYTE>(functionName, code));
	}

	///
	// 3 - Loop all loaded modules and patch existing IATs
	///

#if defined(_WIN64)
	auto peb = PPEB(__readgsqword(0x60));
#else
	auto peb = PPEB(__readfsdword(0x30));
#endif

	auto ldr = peb->Ldr;
	auto lpHead = &ldr->InMemoryOrderModuleList, lpCurrent = lpHead;

	while ((lpCurrent = lpCurrent->Flink) != lpHead)
	{
		PLDR_DATA_TABLE_ENTRY dataTable = CONTAINING_RECORD(lpCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		auto base = PBYTE(dataTable->DllBase);
		auto ntHeaders = PIMAGE_NT_HEADERS(PBYTE(dataTable->DllBase) + PIMAGE_DOS_HEADER(dataTable->DllBase)->e_lfanew);
		auto iatDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
		auto importDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		if (iatDirectory->Size == 0 || importDirectory->Size == 0)
			continue;

		auto importList = PIMAGE_IMPORT_DESCRIPTOR(base + importDirectory->VirtualAddress);
		auto iatList = PIMAGE_THUNK_DATA(base + iatDirectory->VirtualAddress);

		// Un-Protect the IAT for the module
		DWORD oldProtect = 0;
		if (!VirtualProtect(
			iatList,
			iatDirectory->Size,
			PAGE_READWRITE,
			&oldProtect)) {
			return FALSE;
		}

		CHAR ourPath[MAX_PATH];
		LPSTR ourName = ourPath;
		GetModuleFileNameA((HMODULE)ourBase, ourPath, MAX_PATH);

		for (DWORD i = 0; ourPath[i] != NULL; i++) {
			if (ourPath[i] == '\\' || ourPath[i] == '/')
				ourName = &ourPath[i + 1];
		}

		for (; importList->OriginalFirstThunk != 0; importList++)
		{
			auto moduleName = LPSTR(base + importList->Name);
			if (_stricmp(ourName, moduleName) != 0)
				continue;

			auto thunkData = PIMAGE_THUNK_DATA(base + importList->FirstThunk);
			auto originalThunkData = PIMAGE_THUNK_DATA(base + importList->OriginalFirstThunk);

			for (; originalThunkData->u1.AddressOfData != 0; originalThunkData++, thunkData++) {
				if (originalThunkData->u1.AddressOfData & IMAGE_ORDINAL_FLAG) {
					OutputDebugString(L"[!!] Ordinal import\n");
					continue; // Skip anything loaded by ordinal
				}

				PIMAGE_IMPORT_BY_NAME importByName = PIMAGE_IMPORT_BY_NAME(base + originalThunkData->u1.AddressOfData);
				std::map<std::string, PBYTE>::const_iterator pos = exports.find(std::string(importByName->Name));
				if (pos == exports.end())
					continue;

				OutputDebugString(L"[++] Patching IAT for: ");
				OutputDebugStringA(importByName->Name);

				// If the name matches, patch the address to point to the real DLL

				thunkData->u1.AddressOfData = ULONGLONG(pos->second);
			}

			break;
		}

		// Re-Protect the IAT for the module
		if (!VirtualProtect(
			iatList,
			iatDirectory->Size,
			oldProtect,
			&oldProtect)) {
			return FALSE;
		}
	}

	///
	// 4 - Clone our export table to match the target DLL (for GetProcAddress)
	///

	// Make current header data RW for redirections
	DWORD oldProtect = 0;
	if (!VirtualProtect(
		ourExportDirectory,
		64, PAGE_READWRITE,
		&oldProtect)) {
		return FALSE;
	}

	DWORD totalAllocationSize = 0;

	// Add the size of jumps
	totalAllocationSize += targetExportDirectory->NumberOfFunctions * (sizeof(jmpPrefix) + sizeof(jmpRax) + sizeof(LPVOID));

	// Add the size of function table
	totalAllocationSize += targetExportDirectory->NumberOfFunctions * sizeof(INT);

	// Add total size of names
	PINT targetAddressOfNames = (PINT)((PBYTE)targetBase + targetExportDirectory->AddressOfNames);
	for (DWORD i = 0; i < targetExportDirectory->NumberOfNames; i++)
		totalAllocationSize += (DWORD)strlen(((LPCSTR)((PBYTE)targetBase + targetAddressOfNames[i]))) + 1;

	// Add size of name table
	totalAllocationSize += targetExportDirectory->NumberOfNames * sizeof(INT);

	// Add the size of ordinals:
	totalAllocationSize += targetExportDirectory->NumberOfFunctions * sizeof(USHORT);

	// Allocate usuable memory for rebuilt export data
	PBYTE exportData = AllocateUsableMemory((PBYTE)ourBase, totalAllocationSize, PAGE_READWRITE);
	if (!exportData)
		return FALSE;

	PBYTE sideAllocation = exportData; // Used for VirtualProtect later

	// Copy Function Table
	PINT newFunctionTable = (PINT)exportData;
	CopyMemory(newFunctionTable, (PBYTE)targetBase + targetExportDirectory->AddressOfNames, targetExportDirectory->NumberOfFunctions * sizeof(INT));
	exportData += targetExportDirectory->NumberOfFunctions * sizeof(INT);
	ourExportDirectory->AddressOfFunctions = DWORD((PBYTE)newFunctionTable - (PBYTE)ourBase);

	// Write JMPs and update RVAs in the new function table
	PINT targetAddressOfFunctions = (PINT)((PBYTE)targetBase + targetExportDirectory->AddressOfFunctions);
	for (DWORD i = 0; i < targetExportDirectory->NumberOfFunctions; i++) {
		newFunctionTable[i] = DWORD((exportData - (PBYTE)ourBase));

		CopyMemory(exportData, jmpPrefix, sizeof(jmpPrefix));
		exportData += sizeof(jmpPrefix);

		PBYTE realAddress = (PBYTE)((PBYTE)targetBase + targetAddressOfFunctions[i]);
		CopyMemory(exportData, &realAddress, sizeof(LPVOID));
		exportData += sizeof(LPVOID);

		CopyMemory(exportData, jmpRax, sizeof(jmpRax));
		exportData += sizeof(jmpRax);
	}

	// Copy Name RVA Table
	PINT newNameTable = (PINT)exportData;
	CopyMemory(newNameTable, (PBYTE)targetBase + targetExportDirectory->AddressOfNames, targetExportDirectory->NumberOfNames * sizeof(DWORD));
	exportData += targetExportDirectory->NumberOfNames * sizeof(DWORD);
	ourExportDirectory->AddressOfNames = DWORD(((PBYTE)newNameTable - (PBYTE)ourBase));

	// Copy names and apply delta to all the RVAs in the new name table
	for (DWORD i = 0; i < targetExportDirectory->NumberOfNames; i++) {
		PBYTE realAddress = (PBYTE)((PBYTE)targetBase + targetAddressOfNames[i]);
		DWORD length = (DWORD)strlen((LPCSTR)realAddress);
		CopyMemory(exportData, realAddress, length);
		newNameTable[i] = DWORD((PBYTE)exportData - (PBYTE)ourBase);
		exportData += (ULONG_PTR)length + 1;
	}

	// Copy Ordinal Table
	PINT newOrdinalTable = (PINT)exportData;
	CopyMemory(newOrdinalTable, (PBYTE)targetBase + targetExportDirectory->AddressOfNameOrdinals, targetExportDirectory->NumberOfFunctions * sizeof(USHORT));
	exportData += targetExportDirectory->NumberOfFunctions * sizeof(USHORT);
	ourExportDirectory->AddressOfNameOrdinals = DWORD((PBYTE)newOrdinalTable - (PBYTE)ourBase);

	if (!VirtualProtect(
		ourExportDirectory,
		64, oldProtect,
		&oldProtect)) {
		return FALSE;
	}

	if (!VirtualProtect(
		sideAllocation,
		totalAllocationSize,
		PAGE_EXECUTE_READ,
		&oldProtect)) {
		return FALSE;
	}

	return TRUE;
}

#endif