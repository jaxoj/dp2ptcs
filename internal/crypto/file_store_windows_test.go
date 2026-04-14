//go:build windows

package crypto

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32_test                 = windows.NewLazySystemDLL("advapi32.dll")
	procGetNamedSecurityInfoW        = modadvapi32_test.NewProc("GetNamedSecurityInfoW")
	procGetSecurityDescriptorControl = modadvapi32_test.NewProc("GetSecurityDescriptorControl")
	procGetAclInformation            = modadvapi32_test.NewProc("GetAclInformation")
	procGetAce                       = modadvapi32_test.NewProc("GetAce")
)

// Win32 Constants and Structs missing from the windows package
const (
	AclSizeInformation = 2
)

type ACL_SIZE_INFORMATION struct {
	AceCount      uint32
	AclBytesInUse uint32
	AclBytesFree  uint32
}

type ACE_HEADER struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
}

type ACCESS_ALLOWED_ACE struct {
	Header   ACE_HEADER
	Mask     uint32
	SidStart uint32 // This is the start of the SID buffer
}

func VerifyOnlyCurrentUserHasAccess(path string) error {
	// Get current user SID
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	currentUserSid := tokenUser.User.Sid

	// Get Security Descriptor using raw DLL call
	var dacl *windows.ACL
	var secDesc windows.Handle
	pathPtr, _ := windows.UTF16PtrFromString(path)

	ret, _, _ := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(windows.SE_FILE_OBJECT),
		uintptr(windows.DACL_SECURITY_INFORMATION),
		0, 0, // No Owner/Group
		uintptr(unsafe.Pointer(&dacl)),
		0, // No SACL
		uintptr(unsafe.Pointer(&secDesc)),
	)
	if ret != 0 {
		return windows.Errno(ret)
	}
	defer windows.LocalFree(secDesc)

	// Verify Inheritance is disabled (SE_DACL_PROTECTED)
	var control uint16
	var version uint32
	ret, _, _ = procGetSecurityDescriptorControl.Call(
		uintptr(secDesc),
		uintptr(unsafe.Pointer(&control)),
		uintptr(unsafe.Pointer(&version)),
	)
	if ret == 0 { // Win32 returns 0 for failure on this specific call
		return fmt.Errorf("failed to get security descriptor control")
	}

	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("OPSEC failure: DACL is not protected (inheritance enabled)")
	}

	// Get ACL Info
	var aclSize ACL_SIZE_INFORMATION
	ret, _, _ = procGetAclInformation.Call(
		uintptr(unsafe.Pointer(dacl)),
		uintptr(unsafe.Pointer(&aclSize)),
		uintptr(uint32(unsafe.Sizeof(aclSize))),
		uintptr(AclSizeInformation),
	)
	if ret == 0 {
		return fmt.Errorf("failed to get ACL information")
	}

	if aclSize.AceCount != 1 {
		return fmt.Errorf("expected 1 ACE, found %d", aclSize.AceCount)
	}

	// Verify the SID in the ACE
	var ace *ACCESS_ALLOWED_ACE
	ret, _, _ = procGetAce.Call(
		uintptr(unsafe.Pointer(dacl)),
		uintptr(0), // Index 0
		uintptr(unsafe.Pointer(&ace)),
	)
	if ret == 0 {
		return fmt.Errorf("failed to get ACE")
	}

	// The SID is located immediately after the Mask in the ACE struct
	aceSid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !windows.EqualSid(aceSid, currentUserSid) {
		return fmt.Errorf("ACE SID mismatch: file is accessible by someone else")
	}

	return nil
}
