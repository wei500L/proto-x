package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

type webInitSecurityCase struct {
	name    string
	outputs []string
	run     func(string) error
}

func webInitSecurityCases() []webInitSecurityCase {
	outputs := []string{"server.json", "client.json", "token", "server.key", "server.crt"}
	return []webInitSecurityCase{
		{name: "legacy", outputs: outputs, run: func(dir string) error {
			return Init(dir, "127.0.0.1", 14443, 14443)
		}},
		{name: "web", outputs: outputs, run: func(dir string) error {
			return InitWeb(dir, "127.0.0.1", "localhost", 14443, 14443)
		}},
		{name: "ech", outputs: []string{"ech-config.bin", "ech-keys.json"}, run: func(dir string) error {
			return GenerateECH(dir, "cover.example")
		}},
	}
}

// An output pathname is already occupied even when a symlink's target does not
// yet exist. Initializers must refuse before creating the target or other files.
func TestPrivateInitializersRejectDanglingSymlinks(t *testing.T) {
	for _, initializer := range webInitSecurityCases() {
		t.Run(initializer.name, func(t *testing.T) {
			for _, name := range initializer.outputs {
				t.Run(name, func(t *testing.T) {
					dir := t.TempDir()
					target := filepath.Join(t.TempDir(), "must-not-be-created")
					link := filepath.Join(dir, name)
					if err := os.Symlink(target, link); err != nil {
						t.Fatal(err)
					}
					if err := initializer.run(dir); err == nil {
						t.Error("initializer accepted an existing dangling symlink")
					}
					if _, err := os.Lstat(target); !os.IsNotExist(err) {
						t.Errorf("symlink target changed: expected absence, got %v", err)
					}
					if got, err := os.Readlink(link); err != nil || got != target {
						t.Errorf("existing symlink changed: target matches=%v, error=%v", got == target, err)
					}
					assertWebInitOutputUnchanged(t, dir, name)
				})
			}
		})
	}
}

func TestPrivateInitializersRejectExistingRegularFiles(t *testing.T) {
	for _, initializer := range webInitSecurityCases() {
		t.Run(initializer.name, func(t *testing.T) {
			for _, name := range initializer.outputs {
				t.Run(name, func(t *testing.T) {
					dir := t.TempDir()
					path := filepath.Join(dir, name)
					original := []byte("existing material must remain unchanged\n")
					if err := os.WriteFile(path, original, 0600); err != nil {
						t.Fatal(err)
					}
					before, err := os.Lstat(path)
					if err != nil {
						t.Fatal(err)
					}
					if err := initializer.run(dir); err == nil {
						t.Error("initializer accepted an existing regular file")
					}
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, original) {
						t.Errorf("existing contents changed: match=%v, error=%v", bytes.Equal(got, original), err)
					}
					after, err := os.Lstat(path)
					if err != nil {
						t.Fatal(err)
					}
					if !os.SameFile(before, after) || after.Mode() != before.Mode() {
						t.Error("existing file identity or mode changed")
					}
					assertWebInitOutputUnchanged(t, dir, name)
				})
			}
		})
	}
}

func assertWebInitOutputUnchanged(t *testing.T, dir, existingName string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != existingName {
		t.Error("rejected initializer created or removed other output entries")
	}
}
