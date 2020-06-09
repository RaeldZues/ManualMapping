#pragma once

#include <windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

// Function pointers
// TODO How to change this to be LoadLibraryW
// PCHAR does not work for some reason
using f_LoadLibraryA = HINSTANCE(WINAPI*)(CONST CHAR* lpLibFilename);
using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE hModule, CONST PCHAR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(PVOID hDll, DWORD dwReason, PVOID pReserved);

struct MANUAL_MAPPING_DATA
{
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
    HINSTANCE hModule;
};

BOOL ManualMap(HANDLE hProc, CONST WCHAR *szDllFile);
