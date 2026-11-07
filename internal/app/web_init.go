package app

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"os"
	"path/filepath"

	"proto-x/internal/carrier"
)

//go:embed site/*
var defaultSite embed.FS

func writeDefaultSite(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	entries, err := defaultSite.ReadDir("site")
	if err != nil {
		return err
	}
	for _, e := range entries {
		b, err := defaultSite.ReadFile("site/" + e.Name())
		if err != nil {
			return err
		}
		if err := writeNewPrivateFile(filepath.Join(dir, e.Name()), b); err != nil {
			return err
		}
	}
	return nil
}

// GenerateECH writes standard ECH configuration, not a custom encryption layer.
// Applying these files to an existing deployment remains an explicit config edit.
func GenerateECH(dir, publicName string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := requireNewFiles(dir, "ech-config.bin", "ech-keys.json"); err != nil {
		return err
	}
	list, key, err := carrier.GenerateWebECH(publicName)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent([]tls.EncryptedClientHelloKey{key}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNewPrivateFile(filepath.Join(dir, "ech-keys.json"), b); err != nil {
		return err
	}
	return writeNewPrivateFile(filepath.Join(dir, "ech-config.bin"), list)
}
