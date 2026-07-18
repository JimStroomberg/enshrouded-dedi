package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

type tarTestEntry struct {
	name     string
	contents string
	typeflag byte
}

func TestExtractArchiveRejectsTraversal(t *testing.T) {
	archive := writeTarGz(t, []tarTestEntry{{name: "../outside", contents: "bad", typeflag: tar.TypeReg}})
	dest := filepath.Join(t.TempDir(), "restore")
	if err := extractArchiveWithLimits(archive, dest, archiveLimits{MaxFiles: 10, MaxBytes: 1024}); err == nil {
		t.Fatal("traversal archive unexpectedly extracted")
	}
}

func TestExtractArchiveRejectsDuplicatePaths(t *testing.T) {
	archive := writeTarGz(t, []tarTestEntry{
		{name: "world", contents: "one", typeflag: tar.TypeReg},
		{name: "world", contents: "two", typeflag: tar.TypeReg},
	})
	if err := extractArchiveWithLimits(archive, t.TempDir(), archiveLimits{MaxFiles: 10, MaxBytes: 1024}); err == nil {
		t.Fatal("duplicate archive path unexpectedly extracted")
	}
}

func TestExtractArchiveRejectsExpansionBeyondLimit(t *testing.T) {
	archive := writeTarGz(t, []tarTestEntry{{name: "world", contents: "12345", typeflag: tar.TypeReg}})
	if err := extractArchiveWithLimits(archive, t.TempDir(), archiveLimits{MaxFiles: 10, MaxBytes: 4}); err == nil {
		t.Fatal("oversized archive unexpectedly extracted")
	}
}

func TestExtractArchiveRejectsSymlink(t *testing.T) {
	archive := writeTarGz(t, []tarTestEntry{{name: "link", typeflag: tar.TypeSymlink}})
	if err := extractArchiveWithLimits(archive, t.TempDir(), archiveLimits{MaxFiles: 10, MaxBytes: 1024}); err == nil {
		t.Fatal("symlink archive unexpectedly extracted")
	}
}

func TestExtractZipRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "test.zip")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	header := &zip.FileHeader{Name: "link", Method: zip.Store}
	header.SetMode(os.ModeSymlink | 0o777)
	w, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("target")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractArchiveWithLimits(archive, filepath.Join(root, "dest"), archiveLimits{MaxFiles: 10, MaxBytes: 1024}); err == nil {
		t.Fatal("zip symlink unexpectedly extracted")
	}
}

func TestExtractArchiveAcceptsValidSave(t *testing.T) {
	archive := writeTarGz(t, []tarTestEntry{
		{name: "3ad85aea", contents: "world", typeflag: tar.TypeReg},
		{name: "3ad85aea-index", contents: "index", typeflag: tar.TypeReg},
	})
	dest := t.TempDir()
	if err := extractArchiveWithLimits(archive, dest, archiveLimits{MaxFiles: 10, MaxBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	if !regularFileExists(filepath.Join(dest, "3ad85aea")) {
		t.Fatal("valid save file missing")
	}
}

func writeTarGz(t *testing.T, entries []tarTestEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: 0o600, Size: int64(len(entry.contents)), Typeflag: entry.typeflag}
		if entry.typeflag == 0 {
			header.Typeflag = tar.TypeReg
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if entry.typeflag == tar.TypeReg || entry.typeflag == 0 {
			if _, err := tw.Write([]byte(entry.contents)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
