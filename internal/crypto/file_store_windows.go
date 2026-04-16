//go:build windows

package crypto

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procSetEntriesInAclW = modadvapi32.NewProc("SetEntriesInAclW")
	procLocalFree        = windows.NewLazySystemDLL("kernel32.dll").NewProc("LocalFree")
)

func setEntriesInAcl(
	count uint32,
	explicitAccess *windows.EXPLICIT_ACCESS,
	oldAcl *windows.ACL,
	newAcl **windows.ACL,
) error {
	ret, _, _ := procSetEntriesInAclW.Call(
		uintptr(count),
		uintptr(unsafe.Pointer(explicitAccess)),
		uintptr(unsafe.Pointer(oldAcl)),
		uintptr(unsafe.Pointer(newAcl)),
	)
	if ret != 0 {
		return syscall.Errno(ret)
	}
	return nil
}

func saveFileSecure(path string, data []byte) error {
	tmp := path + ".tmp"

	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}

	// Restrict ACL to current user only
	if err := restrictToCurrentUser(tmp); err != nil {
		return err
	}

	// Atomic replace (windows style)
	tmpPtr, _ := windows.UTF16PtrFromString(tmp)
	pathPtr, _ := windows.UTF16PtrFromString(path)
	return windows.MoveFileEx(tmpPtr, pathPtr, windows.MOVEFILE_REPLACE_EXISTING)
}

func restrictToCurrentUser(path string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}

	// Build EXPLICIT_ACCESS entry
	ea := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_READ | windows.GENERIC_WRITE | windows.DELETE,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValue(unsafe.Pointer(user.User.Sid)),
		},
	}

	// Create new ACL
	var acl *windows.ACL
	if err := setEntriesInAcl(1, &ea, nil, &acl); err != nil {
		return err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(acl)))

	// Apply the ACL to the file and DISABLE inheritance (PROTECTED_DACL)
	// This strips any permissions inherited from the parent folder (like "Everyone" or "Users")
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, // Owner
		nil, // Group
		acl, // DACL
		nil, // SACL
	)
}
