package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

type UNICODE_STR struct {
	Length        uint16
	MaximumLength uint16
	pBuffer       *uint16
}

type LDR_DLL_LOADED_NOTIFICATION_DATA struct {
	Flags       uint32
	FullDllName *UNICODE_STR
	BaseDllName *UNICODE_STR
	DllBase     uintptr
	SizeOfImage uint32
}

func main() {
	// Get handle of ntdll.dll
	ntdll := syscall.NewLazyDLL("ntdll.dll")

	if ntdll != nil {
		// Find the LdrRegisterDllNotification function
		pLdrRegisterDllNotification := ntdll.NewProc("LdrRegisterDllNotification")

		// Register Mycallback function as a DLL Notification callback
		var cookie uintptr
		status, _, _ := pLdrRegisterDllNotification.Call(0, syscall.NewCallback(MyCallback), 0, uintptr(unsafe.Pointer(&cookie)))
		if status == 0 {
			fmt.Println("[+] Successfully registered callback")
		} else {
			fmt.Println("[-] Failed to register callback")
		}

		// Get char break
		fmt.Println("[+] Press enter to continue")
		fmt.Scanln()

		// Load some dll to trigger our callback
		fmt.Println("[+] Loading USER32 DLL now")
		syscall.LoadLibrary("USER32.dll")
	} else {
		fmt.Println("[-] Failed to load ntdll.dll")
	}

}

// MyCallback is the callback function that will be called when a DLL is loaded
func MyCallback(NotificationReason uint32, NotificationData uintptr, Context uintptr) uintptr {
	loadedData := (*LDR_DLL_LOADED_NOTIFICATION_DATA)(unsafe.Pointer(NotificationData))
	baseDllName := syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(loadedData.BaseDllName.pBuffer))[:loadedData.BaseDllName.Length/2])
	fmt.Printf("[MyCallback] DLL loaded: %s\n", baseDllName)
	return 0
}
