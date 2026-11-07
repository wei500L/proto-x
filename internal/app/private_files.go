package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Output directories and their parents must be trusted. Lstat rejects even
// dangling symlinks; exclusive creation below also closes the check/write race
// for the final path component. Neither operation overwrites existing entries.
func requireNewFiles(dir string, names ...string) error {
	for _, name := range names {
		_, err := os.Lstat(filepath.Join(dir, name))
		if err == nil {
			return fmt.Errorf("refusing to overwrite %s", name)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("checking output %s: %w", name, err)
		}
	}
	return nil
}

func writeNewPrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
