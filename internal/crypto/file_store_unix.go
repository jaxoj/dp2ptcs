//go:build !windows

package crypto

import (
	"os"
)

func saveFileSecure(path string, data []byte) error {
	// Atomic write: tempfile + rename
	tmp := path + ".tmp"

	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}

	// Ensure correct permissions (replace, not append)
	if err := os.Chmod(tmp, 0600); err != nil {
		return err
	}

	return os.Rename(tmp, path)
}
