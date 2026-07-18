package main

import (
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
)

func TestSelectRetentionAcrossBoundaries(t *testing.T) {
	objects := []minio.ObjectInfo{
		retentionObject("backup-20260718-120000.tar.gz"),
		retentionObject("backup-20260710-120000.tar.gz"),
		retentionObject("backup-20260620-120000.tar.gz"),
		retentionObject("backup-20260510-120000.tar.gz"),
		retentionObject("backup-20260410-120000.tar.gz"),
		{Key: "manual-important.zip", LastModified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	keep := selectRetention(objects, 1, 1, 2, nil)
	for _, name := range []string{
		"backup-20260718-120000.tar.gz",
		"backup-20260710-120000.tar.gz",
		"backup-20260620-120000.tar.gz",
		"backup-20260510-120000.tar.gz",
		"manual-important.zip",
	} {
		if !keep[name] {
			t.Errorf("expected %s to be retained", name)
		}
	}
	if keep["backup-20260410-120000.tar.gz"] {
		t.Fatal("old backup outside all retention windows should be pruned")
	}
}

func TestSelectRetentionUsesNewestObjectPerBucket(t *testing.T) {
	newer := retentionObject("backup-20260718-180000.tar.gz")
	older := retentionObject("backup-20260718-090000.tar.gz")
	keep := selectRetention([]minio.ObjectInfo{older, newer}, 1, 0, 0, nil)
	if !keep[newer.Key] || keep[older.Key] {
		t.Fatalf("unexpected retention selection: %#v", keep)
	}
}

func retentionObject(name string) minio.ObjectInfo {
	ts, err := parseTimestamp(name)
	if err != nil {
		panic(err)
	}
	return minio.ObjectInfo{Key: name, LastModified: ts}
}
