#include "Injection.h"


INT main()
{
    // Sample dll to inject 
    CONST WCHAR szDllFile[] = L"C:\\Users\\red\\source\\repos\\ManualMapping\\x64\\Debug\\Test-DLL.dll";

    // Sample process name to inject into
    CONST WCHAR szProc[] = L"chrome.exe";

    // Setup to walking process list 
    PROCESSENTRY32 PE32{0}; // NOLINT(clang-diagnostic-missing-field-initializers)
    PE32.dwSize = sizeof(PE32);
    // Get handle to process
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        printf("Unable to create snapshot\n");
        return GetLastError();
    }
        
    // Walk the process list to get the PID of the approrpiate process 
    DWORD PID = 0;
    BOOL bRet = Process32First(hSnap, &PE32);
    while (bRet)
    {
        // Case insensitive search for the process to inject into 
        if (!_wcsicmp(szProc, PE32.szExeFile))
        {
            PID = PE32.th32ProcessID;
            break;
        }
        bRet = Process32Next(hSnap, &PE32);
    }
    CloseHandle(hSnap);
    // Get a handle of the process to inject into 
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc)
    {
        printf("Unable to open process\n");
        return GetLastError();
    }
        
    // Manually map the dll to the process 
    if (!ManualMap(hProc, szDllFile))
    {
        CloseHandle(hProc);
        printf("Unable to manually map dll to process\n");
        return GetLastError();
    }
    CloseHandle(hProc);
}
