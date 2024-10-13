#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <tchar.h>
#include <strsafe.h>
#include <winnt.h>
#include <vector>
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

DWORD GetProcessId(const wchar_t* processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::cerr << "Error: Could not create snapshot of processes. Error code: " << error << std::endl;
        return 0;
    }

    if (Process32First(hSnapshot, &processEntry)) {
        do {
            if (wcscmp(processEntry.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }

    CloseHandle(hSnapshot);
    std::cerr << "Error: Process not found." << std::endl;
    return 0;
}


uintptr_t GetModuleBaseAddress(DWORD processId, const wchar_t* moduleName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::cerr << "Error: Could not create snapshot of modules. Error code: " << error << std::endl;
        return 0;
    }

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnapshot, &moduleEntry)) {
        do {
            if (wcscmp(moduleEntry.szModule, moduleName) == 0) {
                CloseHandle(hSnapshot);
                return (uintptr_t)moduleEntry.modBaseAddr;
            }
        } while (Module32Next(hSnapshot, &moduleEntry));
    }

    CloseHandle(hSnapshot);
    std::cerr << "Error: Module not found." << std::endl;
    return 0;
}


FARPROC GetProcAddressEx(HANDLE hProcess, DWORD processId, const wchar_t* moduleName, const char* functionName) {
    uintptr_t moduleBase = GetModuleBaseAddress(processId, moduleName);
    if (moduleBase == 0) {
        std::cerr << "Error: Could not get module base address." << std::endl;
        return NULL;
    }

    try {
        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS ntHeaders;

        if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL)) {
            DWORD error = GetLastError();
            std::cerr << "Error: Could not read DOS header. Error code: " << error << std::endl;
            return NULL;
        }

        if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + dosHeader.e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS), NULL)) {
            DWORD error = GetLastError();
            std::cerr << "Error: Could not read NT headers. Error code: " << error << std::endl;
            return NULL;
        }

        IMAGE_EXPORT_DIRECTORY exportDir;

        if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), &exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), NULL)) {
            DWORD error = GetLastError();
            std::cerr << "Error: Could not read export directory. Error code: " << error << std::endl;
            return NULL;
        }


        std::vector<DWORD> namePtr(exportDir.NumberOfNames);

        if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + exportDir.AddressOfNames), &namePtr[0], exportDir.NumberOfNames * sizeof(DWORD), NULL)) {
            DWORD error = GetLastError();
            std::cerr << "Error: Could not read function names. Error code: " << error << std::endl;
            return NULL;
        }

        for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
            char funcName[100];
            if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + namePtr[i]), &funcName[0], sizeof(funcName), NULL)) {
                DWORD error = GetLastError();
                std::cerr << "Error: Could not read function name. Error code: " << error << std::endl;
                continue; 
            }

            if (strcmp(funcName, functionName) == 0) {
                std::vector<WORD> ordinalPtr(exportDir.NumberOfFunctions);
                if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + exportDir.AddressOfNameOrdinals), &ordinalPtr[0], exportDir.NumberOfFunctions * sizeof(WORD), NULL)) {
                    DWORD error = GetLastError();
                    std::cerr << "Error: Could not read function ordinals. Error code: " << error << std::endl;
                    return NULL; 
                }

                WORD ordinal = ordinalPtr[i];
                std::vector<DWORD> funcAddressPtr(exportDir.NumberOfFunctions);
                if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + exportDir.AddressOfFunctions), &funcAddressPtr[0], exportDir.NumberOfFunctions * sizeof(DWORD), NULL)) {
                    DWORD error = GetLastError();
                    std::cerr << "Error: Could not read function addresses. Error code: " << error << std::endl;
                    return NULL;
                }
                DWORD funcAddress = funcAddressPtr[ordinal];
                return (FARPROC)(moduleBase + funcAddress);
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception caught in GetProcAddressEx: " << e.what() << std::endl;
    }

    std::cerr << "Error: Function not found." << std::endl;
    return NULL;
}

namespace injection {
    void inject_dll(const char* dll_path, const char* process_name) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(entry);

        if (Process32First(snapshot, &entry)) {
            do {
                if (!stricmp(entry.szExeFile, process_name)) {
                    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                    HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, dll_path, 0, NULL);
                    CloseHandle(process);
                }
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
    }
}

namespace bypass {
    bool is_radar_hack_detected() {
        HANDLE process = GetCurrentProcess();
        HMODULE module = GetModuleHandleA("kernel32.dll");
        MODULEINFO info;
        GetModuleInformation(process, module, &info, sizeof(info));

       IMAGE_DOS_HEADER dos_header = *(IMAGE_DOS_HEADER*)info.lpBaseOfDll;
        IMAGE_NT_HEADERS nt_headers = *(IMAGE_NT_HEADERS*)((DWORD)info.lpBaseOfDll + dos_header.e_lfanew);

        IMAGE_SECTION_HEADER section = *(IMAGE_SECTION_HEADER*)((DWORD)&nt_headers.OptionalHeader + nt_headers.FileHeader.SizeOfOptionalHeader);

        for (int i = 0; i < nt_headers.FileHeader.NumberOfSections; i++) {
            if (!strcmp((char*)section.Name, ".text")) {
                DWORD old_protection;
                VirtualProtect((void*)((DWORD)info.lpBaseOfDll + section.VirtualAddress), section.SizeOfRawData, PAGE_EXECUTE_READWRITE, &old_protection);

                BYTE* code = (BYTE*)((DWORD)info.lpBaseOfDll + section.VirtualAddress);
                for (int j = 0; j < section.SizeOfRawData; j++) {
                    if (code[j] == 0xC3) {
                        DWORD fun_address = (DWORD)(code + j) - (DWORD)info.lpBaseOfDll;
                        if (fun_address == 0x7B80 || fun_address == 0x7B90 || fun_address == 0x7D40) {
                            VirtualProtect((void*)((DWORD)info.lpBaseOfDll + section.VirtualAddress), section.SizeOfRawData, old_protection, &old_protection);
                            return true;
                        }
                    }
                }

                VirtualProtect((void*)((DWORD)info.lpBaseOfDll + section.VirtualAddress), section.SizeOfRawData, old_protection, &old_protection);
            }

            section = *(IMAGE_SECTION_HEADER*)((DWORD)&section + sizeof(IMAGE_SECTION_HEADER));
        }

        return false;
    }

    void bypass_anti_cheat() {
        HANDLE process = GetCurrentProcess();
        HMODULE module = GetModuleHandleA("kernel32.dll");
        MODULEINFO info;
        GetModuleInformation(process, module, &info, sizeof(info));

        IMAGE_DOS_HEADER dos_header = *(IMAGE_DOS_HEADER*)info.lpBaseOfDll;
        IMAGE_NT_HEADERS nt_headers = *(IMAGE_NT_HEADERS*)((DWORD)info.lpBaseOfDll + dos_header.e_lfanew);

        IMAGE_SECTION_HEADER section = *(IMAGE_SECTION_HEADER*)((DWORD)&nt_headers.OptionalHeader + nt_headers.FileHeader.SizeOfOptionalHeader);

        for (int i = 0; i < nt_headers.FileHeader.NumberOfSections; i++) {
            if (!strcmp((char*)section.Name, ".text")) {
                DWORD old_protection;
                VirtualProtect((void*)((DWORD)info.lpBaseOfDll + section.VirtualAddress), section.SizeOfRawData, PAGE_EXECUTE_READWRITE, &old_protection);

                BYTE* code = (BYTE*)((DWORD)info.lpBaseOfDll + section.VirtualAddress);
                for (int j = 0; j < section.SizeOfRawData; j++) {
                    if (code[j] == 0xC3) {
                        DWORD fun_address = (DWORD)(code + j) - (DWORD)info.lpBaseOfDll;
                        if (fun_address == 0x7B80 || fun_address == 0x7B90 || fun_address == 0x7D40) {
                            VirtualProtect((void*)((DWORD)info.lpBaseOfDll + section.VirtualAddress), section.SizeOfRawData, old_protection, &old_protection);
                            return;
                        }
                    }
                }

                VirtualProtect((void*)((DWORD)info.lpBaseOfDll + section.VirtualAddress), section.SizeOfRawData, old_protection, &old_protection);
            }

            section = *(IMAGE_SECTION_HEADER*)((DWORD)&section + sizeof(IMAGE_SECTION_HEADER));
        }
    }
}

int main() {
    const wchar_t* targetProcess = L"target_process.exe";
    DWORD processId = GetProcessId(targetProcess);
    
    if (processId == 0) {
        std::cerr << "Error: Could not retrieve the process ID." << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Error: Could not open process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    const wchar_t* moduleName = L"target_module.dll";
    const char* functionName = "targetFunction";

    FARPROC targetFunctionAddress = GetProcAddressEx(hProcess, processId, moduleName, functionName);
    if (targetFunctionAddress == NULL) {
        std::cerr << "Error: Could not retrieve the address of the target function." << std::endl;
        return 1;
    }

    // Use the targetFunctionAddress for further operations...

    CloseHandle(hProcess);

    return 0;
}
