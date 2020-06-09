#include "Injection.h"

#ifdef _WIN64
#define RELOC_FLAG(RelInfo) (((RelInfo) >> 0x0C) == IMAGE_REL_BASED_DIR64)
#else
#define RELOC_FLAG(RelInfo) (((RelInfo) >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#endif

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
{
    if (!pData || !pData->pLoadLibraryA)
        return;

    auto* pBase = reinterpret_cast<PBYTE>(pData);
    auto* pOpt = &reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + reinterpret_cast<PIMAGE_DOS_HEADER>(pData)->e_lfanew)->OptionalHeader;
    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
    auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);
    PBYTE LocationDelta = pBase - pOpt->ImageBase;
    // If not zero, 
    if (LocationDelta)
    {
        if(!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
            return;
        auto* pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        // Finding appropriate relocation address Looking for the 
        while (pRelocData->VirtualAddress)
        {
            UINT EntryCount = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);
            PWORD pRelativeInfo = reinterpret_cast<PWORD>(pRelocData + 1);
            for (UINT i = 0; i != EntryCount; ++i, ++pRelativeInfo)
            {
                if (RELOC_FLAG(*pRelativeInfo))
                {
                    PUINT_PTR pPatch = reinterpret_cast<PUINT_PTR>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                    *pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
                }
            }
            pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(pRelocData) + pRelocData->SizeOfBlock);
        }
    }
    // if size == 0 do some importing 
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        auto* pImportDescr = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDescr->Name)
        {
            //PWCHAR szMod = reinterpret_cast<PWCHAR>(pBase + pImportDescr->Name);
            PCHAR szMod = reinterpret_cast<PCHAR>(pBase + pImportDescr->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);
            PULONG_PTR pThunkRef = reinterpret_cast<PULONG_PTR>(pBase + pImportDescr->OriginalFirstThunk);
            PULONG_PTR pFuncRef = reinterpret_cast<PULONG_PTR>(pBase + pImportDescr->FirstThunk);
            if (!pThunkRef)
                pThunkRef = pFuncRef;

            for(; *pThunkRef; ++pThunkRef, ++pFuncRef)
            {
                if(IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
                {
                    *pFuncRef = _GetProcAddress(hDll, reinterpret_cast<PCHAR>(*pThunkRef & 0xFFFF));
                }
                else
                {
                    auto* pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pBase + (*pThunkRef));
                    *pFuncRef = _GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDescr;
        }
    }
    if(pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        auto* pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        // pointer to pointer
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        for(; pCallback && *pCallback; ++pCallback)
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }
    _DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);
    pData->hModule = reinterpret_cast<HINSTANCE>(pBase);
}

BOOL ManualMap(HANDLE hProc, CONST WCHAR *szDllFile)
{
    BYTE* pSourceData = nullptr;
    PIMAGE_NT_HEADERS pOldNtHeader = nullptr;
    PIMAGE_OPTIONAL_HEADER pOldOptHeader = nullptr;
    PIMAGE_FILE_HEADER pOldFileHeader = nullptr;
    PBYTE pTargetBase = nullptr;
    
    if (GetFileAttributes(szDllFile) == INVALID_FILE_ATTRIBUTES)
        return false;

    std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);

    // Validate file 
    if (File.fail())
    {
        std::cout << "Opening file failed: " << File.rdstate() << "\n";
        return false;
    }
    const auto FileSize = File.tellg();
    // TODO validate size minimum requirement 
    if (FileSize < 0x1000)
    {
        std::cout << "File size is invalid\n";
        File.close();
        return false;
    }

    pSourceData = new BYTE[static_cast<UINT_PTR>(FileSize)];
    if (!pSourceData)
    {
        printf("Memory allocation failed\n");
        File.close();
        return false;
    }
    memset(pSourceData, 0, static_cast<UINT_PTR>(FileSize));
    // Seek back to beginning of file 
    File.seekg(0, std::ios::beg);
    File.read(reinterpret_cast<PCHAR>(pSourceData), FileSize);
    File.close();
    // Validate that the file contains the valid magic number MZ
    if (reinterpret_cast<PIMAGE_DOS_HEADER>(pSourceData)->e_magic != 0x5A4D)
    {
        std::cout << "Invalid magic number on file\n";
        delete[] pSourceData;
        return false;
    }
    // Obtain pointer to NT Header with some cast magic foo
    pOldNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pSourceData + reinterpret_cast<PIMAGE_DOS_HEADER>(pSourceData)->e_lfanew);
    pOldOptHeader = &pOldNtHeader->OptionalHeader;
    pOldFileHeader = &pOldNtHeader->FileHeader;
    
    // Check platform
#ifdef _WIN64
    if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        std::cout << "Invalid platform\n";
        delete[] pSourceData;
        return false;
    }
#else
    if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        std::cout << "Invalid platform\n";
        delete[] pSourceData;
        return false;
    }
#endif
    // Allocate memory in target process
    // TODO avoid virtualallocex?
    // TODO avoid page execute read write?
    pTargetBase = static_cast<PBYTE>(VirtualAllocEx(hProc, reinterpret_cast<PVOID>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!pTargetBase)
    {
        // Attempt to recover if 
        pTargetBase = static_cast<PBYTE>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!pTargetBase)
        {
            std::cout << "Memory allocation (ex) failed\n" << GetLastError() << "\n";
            delete[] pSourceData;
            return false;
        }
    }
    MANUAL_MAPPING_DATA data{nullptr};
    // Why create function pointers if im going to use the base ones?
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

    // Get the first section header out of the NT header
    auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
    // ITerate through sections, idenitfy if the section header contains raw data, if there is, write to that raw section based virtual address
    for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
    {
        // If the section contains a raw data section
        // CRITICAL requirement
        if (pSectionHeader->SizeOfRawData)
        {
            // Attempt to write the pointer to raw data area 
            if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress,
                pSourceData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
            {
                printf("Unable to map sections: 0x%x\n", GetLastError());
                delete[] pSourceData;
                VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
                return false;
            }
        }
    }
    memcpy(pSourceData, &data, sizeof(data));
    WriteProcessMemory(hProc, pTargetBase, pSourceData, 0x1000, nullptr);
    delete[] pSourceData;

    void * pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode)
    {
        printf("Memory allocation failed (ex) 0x%X\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr);

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);
    if (hThread == INVALID_HANDLE_VALUE)
    {
        printf("Failed to allocate thread (ex), 0x%x\n", GetLastError());
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    CloseHandle(hThread);
    HINSTANCE hCheck = NULL;
    while (!hCheck)
    {
        MANUAL_MAPPING_DATA data_checked{0};
        ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
        hCheck = data_checked.hModule;
        Sleep(10);
    }

    VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
    return true;
}
