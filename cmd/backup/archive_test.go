package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
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

func TestExtractZipAcceptsValidSaveAndDirectories(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "save.zip")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	if _, err := zw.Create("nested/"); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"nested/3ad85aea":       "world",
		"nested/3ad85aea-index": "index",
	} {
		entry, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "dest")
	if err := extractArchiveWithLimits(archive, dest, archiveLimits{MaxFiles: 10, MaxBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	if !regularFileExists(filepath.Join(dest, "nested", "3ad85aea")) {
		t.Fatal("valid zip save file missing")
	}
}

func TestExtractZipRejectsTraversalDuplicatesAndLimits(t *testing.T) {
	tests := []struct {
		name    string
		entries []tarTestEntry
		limits  archiveLimits
	}{
		{"traversal", []tarTestEntry{{name: "../outside", contents: "bad"}}, archiveLimits{MaxFiles: 10, MaxBytes: 1024}},
		{"duplicate", []tarTestEntry{{name: "world", contents: "one"}, {name: "world", contents: "two"}}, archiveLimits{MaxFiles: 10, MaxBytes: 1024}},
		{"file-count", []tarTestEntry{{name: "one", contents: "1"}, {name: "two", contents: "2"}}, archiveLimits{MaxFiles: 1, MaxBytes: 1024}},
		{"expanded-size", []tarTestEntry{{name: "world", contents: "12345"}}, archiveLimits{MaxFiles: 10, MaxBytes: 4}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := writeZip(t, test.entries)
			if err := extractArchiveWithLimits(archive, t.TempDir(), test.limits); err == nil {
				t.Fatal("unsafe zip unexpectedly extracted")
			}
		})
	}
}

func TestListArchiveContentsSupportsTarAndZip(t *testing.T) {
	entries := []tarTestEntry{{name: "3ad85aea", contents: "world"}, {name: "3ad85aea-index", contents: "index"}}
	for _, archive := range []string{writeTarGz(t, entries), writeZip(t, entries)} {
		items, err := listArchiveContents(archive, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 2 {
			t.Fatalf("listed %d items, want 2", len(items))
		}
	}
}

func TestArchiveDirRoundTrip(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "savegame"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "savegame", "3ad85aea"), []byte("world"), 0o600); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "snapshot.tar.gz")
	archive, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := archiveDir(root, archive); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := extractArchive(archivePath, dest); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dest, "savegame", "3ad85aea"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "world" {
		t.Fatalf("unexpected round-trip contents %q", data)
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

func writeZip(t *testing.T, entries []tarTestEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, entry := range entries {
		writer, err := zw.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(entry.contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
