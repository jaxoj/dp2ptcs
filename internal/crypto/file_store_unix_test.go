//go:build !windows

package crypto_test

import (
	"fmt"
	"os"
)

func VerifyOnlyCurrentUserHasAccess(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0600 {
		return fmt.Errorf("permissions are not 0600")
	}
	return nil
}
