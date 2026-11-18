// Command packager zips a built plugin library the way the CLIProxyAPI plugin store expects:
// <id>_<version>_<goos>_<goarch>.zip with the library at the archive root, plus a sha256 line.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

var extensions = map[string]string{"linux": ".so", "darwin": ".dylib", "windows": ".dll"}

func main() {
	lib := flag.String("lib", "", "path to the built plugin library")
	id := flag.String("id", "key-access", "plugin id")
	version := flag.String("version", "", "version without the leading v")
	goos := flag.String("goos", "", "target GOOS")
	goarch := flag.String("goarch", "", "target GOARCH")
	out := flag.String("out", "dist", "output directory")
	flag.Parse()
	if err := run(*lib, *id, *version, *goos, *goarch, *out); err != nil {
		fmt.Fprintln(os.Stderr, "packager:", err)
		os.Exit(1)
	}
}

func run(lib, id, version, goos, goarch, out string) error {
	ext, ok := extensions[goos]
	if !ok {
		return fmt.Errorf("unsupported goos %q", goos)
	}
	if lib == "" || version == "" || goarch == "" {
		return fmt.Errorf("-lib, -version and -goarch are required")
	}
	name := id + ext
	if filepath.Base(lib) != name {
		return fmt.Errorf("library file must be named %s, got %s", name, filepath.Base(lib))
	}
	data, err := os.ReadFile(lib)
	if err != nil {
		return fmt.Errorf("read library: %w", err)
	}
	info, err := os.Stat(lib)
	if err != nil {
		return fmt.Errorf("stat library: %w", err)
	}
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return fmt.Errorf("create zip header: %w", err)
	}
	header.Name, header.Method = name, zip.Deflate
	header.SetMode(0o755)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entry, err := zw.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create zip entry: %w", err)
	}
	if _, err := entry.Write(data); err != nil {
		return fmt.Errorf("write zip entry: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("close zip: %w", err)
	}

	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	archive := fmt.Sprintf("%s_%s_%s_%s.zip", id, version, goos, goarch)
	if err := os.WriteFile(filepath.Join(out, archive), buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write archive: %w", err)
	}
	sum := sha256.Sum256(buf.Bytes())
	line := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), archive)
	return os.WriteFile(filepath.Join(out, archive+".sha256"), []byte(line), 0o644)
}
