/*+===================================================================
File:      dbfix.cpp

Summary:   Anti-pirated IDB patches for IDA 7.

* Copyright (c) 2020 Quang Nguyen.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, version 3.
*
* This program is distributed in the hope that it will be useful, but
* WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.

===================================================================+*/
#define WIN32_LEAN_AND_MEAN
#include <tchar.h>
#include <windows.h>

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: Patch

Summary:  Patch memory of current process.

Args:
LPBYTE lpAddress
A pointer an address that should be patched.
LPBYTE lpCode
A pointer to the buffer containing the data to be written.
SIZE_T nCodeSize
The number of bytes to be written.

Returns:  BOOL
If the function succeeds, the return value is nonzero.
If the function fails, the return value is zero.
-----------------------------------------------------------------F-F*/
BOOL Patch(
	_In_ LPBYTE lpAddress,
	_In_ LPBYTE lpCode,
	_In_ SIZE_T nCodeSize) {
	DWORD dwProtect;
	if (VirtualProtect(lpAddress, nCodeSize, PAGE_EXECUTE_READWRITE, &dwProtect)) {
		CopyMemory(lpAddress, lpCode, nCodeSize);
		VirtualProtect(lpAddress, nCodeSize, dwProtect, &dwProtect);
		return TRUE;
	}
	return FALSE;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: CompareAndPatch

Summary:  Compare before patching.

Args:
LPBYTE lpAddress
A pointer an address that should be patched.
LPBYTE lpOldData
A pointer to the buffer containing the data to be expected.
LPBYTE lpNewData
A pointer to the buffer containing the data to be written.
SIZE_T nCodeSize
The number of bytes to be written.

Returns:  BOOL
If the function succeeds, the return value is nonzero.
If the function fails, the return value is zero.
-----------------------------------------------------------------F-F*/
BOOL CompareAndPatch(
	_In_ LPBYTE lpAddress, 
	_In_ LPBYTE lpOldData, 
	_In_ LPBYTE lpNewData, 
	_In_ SIZE_T nCodeSize) {
	if (memcmp(lpAddress, lpNewData, nCodeSize) == 0) {
		return TRUE; // already patched
	}

	if (memcmp(lpAddress, lpOldData, nCodeSize) == 0) {
		return Patch(lpAddress, lpNewData, nCodeSize); // should patch
	}
	
	return FALSE; // wrong version
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: PatchIda

Summary:  Patch ida.dll.
IDA Version: 7.0.170914
-----------------------------------------------------------------F-F*/
void PatchIda_7_0_170914() {
	HMODULE hIda = GetModuleHandle(_T("ida.dll"));
	if (!hIda) {
		return;
	}

	LPBYTE lpIdaBase = (LPBYTE)hIda;

	CompareAndPatch(lpIdaBase + 0x3DDAD, (LPBYTE)"\x74", (LPBYTE)"\xeb", 1);
	CompareAndPatch(lpIdaBase + 0x1B4251, (LPBYTE)"\x32\xDB", (LPBYTE)"\xB3\x01", 2);
	CompareAndPatch(lpIdaBase + 0x1677C0, (LPBYTE)"\xB0\x01", (LPBYTE)"\xB0\x00", 2);
	CompareAndPatch(lpIdaBase + 0x1679F9, (LPBYTE)"\xB0\x01", (LPBYTE)"\xB0\x00", 2);
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: PatchIda64

Summary:  Patch ida64.dll.
IDA Version: 7.0.170914
-----------------------------------------------------------------F-F*/

void PatchIda64_7_0_170914() {
	HMODULE hIda = GetModuleHandle(_T("ida64.dll"));
	if (!hIda) {
		return;
	}

	LPBYTE lpIdaBase = (LPBYTE)hIda;

	CompareAndPatch(lpIdaBase + 0x3E86E, (LPBYTE)"\x74", (LPBYTE)"\xeb", 1);
	CompareAndPatch(lpIdaBase + 0x1BAFA1, (LPBYTE)"\x32\xDB", (LPBYTE)"\xB3\x01", 2);
	CompareAndPatch(lpIdaBase + 0x16DBF0, (LPBYTE)"\xB0\x01", (LPBYTE)"\xB0\x00", 2);
	CompareAndPatch(lpIdaBase + 0x16DE29, (LPBYTE)"\xB0\x01", (LPBYTE)"\xB0\x00", 2);
}


/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: PatchIda

Summary:  Patch ida.dll.
IDA Version: 7.2.181105
-----------------------------------------------------------------F-F*/
void PatchIda_7_2_181105() {
	HMODULE hIda = GetModuleHandle(_T("ida.dll"));
	if (!hIda) {
		return;
	}

	LPBYTE lpIdaBase = (LPBYTE)hIda;

	CompareAndPatch(lpIdaBase + 0x1E5DB, (LPBYTE)"\x74", (LPBYTE)"\xeb", 1);
	CompareAndPatch(lpIdaBase + 0x1ADFF5, (LPBYTE)"\x75", (LPBYTE)"\xeb", 1);
	CompareAndPatch(lpIdaBase + 0x1ADEC5, (LPBYTE)"\x75", (LPBYTE)"\xeb", 1);
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Function: PatchIda64

Summary:  Patch ida64.dll.
IDA Version: 7.2.181105
-----------------------------------------------------------------F-F*/

void PatchIda64_7_2_181105() {
	HMODULE hIda = GetModuleHandle(_T("ida64.dll"));
	if (!hIda) {
		return;
	}

	LPBYTE lpIdaBase = (LPBYTE)hIda;

	CompareAndPatch(lpIdaBase + 0x1EAAC, (LPBYTE)"\x74", (LPBYTE)"\xeb", 1);
	CompareAndPatch(lpIdaBase + 0x158195, (LPBYTE)"\x75", (LPBYTE)"\xeb", 1);
	CompareAndPatch(lpIdaBase + 0x1582C5, (LPBYTE)"\x75", (LPBYTE)"\xeb", 1);
}



BOOL WINAPI DllMain(
	_In_ HMODULE hInstance,
	_In_ DWORD fdwReason,
	_In_ LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hInstance);

		// IDA Version: 7.0.170914
		PatchIda_7_0_170914();
		PatchIda64_7_0_170914();

		// IDA Version: 7.2.181105
		PatchIda_7_2_181105();
		PatchIda64_7_2_181105();
	}
	return TRUE;
}
