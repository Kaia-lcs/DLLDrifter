#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <tchar.h>
#include <strsafe.h>
#include <winnt.h>
#include <vector>

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

int main() {
    const wchar_t* processName = L"GhostOfTsushima.exe";
    DWORD processId = GetProcessId(processName);

    if (processId == 0) {
        std::cerr << "Error: Failed to find process." << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    if (hProcess == NULL) {
        DWORD error = GetLastError();
        std::cerr << "Error: Failed to open process. Error code: " << error << std::endl;
        return 1;
    }

    // Please replace this path with the path to your actual DLL.
    const char* dllPath = "C:\\Your\\Path\\To\\DLL.dll"; 

    size_t dllPathLen = strlen(dllPath) + 1;
    void* allocatedMemory = VirtualAllocEx(hProcess, NULL, dllPathLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (allocatedMemory == NULL) {
        DWORD error = GetLastError();
        std::cerr << "Error: Failed to allocate memory. Error code: " << error << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    if (!WriteProcessMemory(hProcess, allocatedMemory, dllPath, dllPathLen, NULL)) {
        DWORD error = GetLastError();
        std::cerr << "Error: Failed to write DLL path to remote process. Error code: " << error << std::endl;
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    FARPROC loadLibraryAddress = GetProcAddressEx(hProcess, processId, L"kernel32.dll", "LoadLibraryA");

    if (loadLibraryAddress == NULL) {
        std::cerr << "Error: Failed to find LoadLibraryA function." << std::endl;
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, allocatedMemory, 0, NULL);

    if (hThread == NULL) {
        DWORD error = GetLastError();
        std::cerr << "Error: Failed to create remote thread. Error code: " << error << std::endl;
        VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, allocatedMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}