package main

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// writeTestPackage builds a .pkg.tar.zst holding the given members, mimicking
// what makepkg produces: pacman metadata first, then the payload.
func writeTestPackage(t *testing.T, path string, members map[string][]byte) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = f.Close()
	}()

	zw, err := zstd.NewWriter(f)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)

	for name, content := range members {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

// The test binary itself is a dynamically linked ELF, so it is a real object
// with a dynamic section to read DT_NEEDED from.
func testELF(t *testing.T) []byte {
	t.Helper()

	self, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate test binary: %v", err)
	}
	content, err := os.ReadFile(self)
	if err != nil {
		t.Skipf("cannot read test binary: %v", err)
	}
	return content
}

func TestScanPackagesSonames(t *testing.T) {
	t.Parallel()

	elf := testELF(t)
	dir := t.TempDir()
	pkg := filepath.Join(dir, "test-1.0-1-x86_64.pkg.tar.zst")
	writeTestPackage(t, pkg, map[string][]byte{
		".PKGINFO":             []byte("pkgname = test\npkgbase = test\n"),
		".MTREE":               []byte("not an elf"),
		"usr/bin/test":         elf,
		"usr/share/doc/notes":  []byte("plain text, skipped"),
		"usr/lib/libtest.so.1": []byte("too short to be an ELF"),
	})

	scan, err := scanPackagesSonames([]string{pkg})
	if err != nil {
		t.Fatalf("scanPackagesSonames: %v", err)
	}

	// the test binary is cgo-linked against libc, so at minimum that shows up
	var found bool
	for need := range scan.Needed {
		if need.Bits != bits64 {
			t.Errorf("unexpected ELF class for %s: %d", need.Name, need.Bits)
		}
		if need.Name == soLibc6 {
			found = true
		}
	}
	if !found {
		if len(scan.Needed) == 0 {
			t.Skip("test binary is statically linked, nothing to read")
		}
		t.Errorf("expected %s among %v", soLibc6, scan.Needed)
	}

	// soname-shaped payload names are recorded, everything else is not
	if _, ok := scan.Shipped["libtest.so.1"]; !ok {
		t.Error("libtest.so.1 should be recorded as shipped")
	}
	for _, skipped := range []string{".PKGINFO", ".MTREE", "notes", "test"} {
		if _, ok := scan.Shipped[skipped]; ok {
			t.Errorf("%s should not be recorded as shipped", skipped)
		}
	}
}

func TestScanPackagesSonamesEmpty(t *testing.T) {
	t.Parallel()

	scan, err := scanPackagesSonames(nil)
	if err != nil {
		t.Fatalf("scanPackagesSonames(nil): %v", err)
	}
	if len(scan.Needed) != 0 || len(scan.Shipped) != 0 {
		t.Errorf("expected empty result, got %+v", scan)
	}
}

func TestScanPackagesSonamesMissingFile(t *testing.T) {
	t.Parallel()

	if _, err := scanPackagesSonames([]string{filepath.Join(t.TempDir(), "absent.pkg.tar.zst")}); err == nil {
		t.Error("expected an error for a missing package file")
	}
}
