package main

import (
	"testing"
	"time"
)

func TestParseTimestamp(t *testing.T) {
	want := time.Date(2026, time.July, 18, 17, 54, 40, 0, time.UTC)
	for _, name := range []string{
		"backup-20260718-175440.tar.gz",
		"backup-20260718-175440.tgz",
		"manual-prefix-20260718-175440.zip",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseTimestamp(name)
			if err != nil {
				t.Fatalf("parseTimestamp(%q): %v", name, err)
			}
			if !got.Equal(want) {
				t.Fatalf("parseTimestamp(%q) = %s, want %s", name, got, want)
			}
		})
	}
}

func TestParseTimestampRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{
		"backup-20260718-175440.tar",
		"backup-invalid.tar.gz",
		"backup-20260718.tar.gz",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTimestamp(name); err == nil {
				t.Fatalf("parseTimestamp(%q) unexpectedly succeeded", name)
			}
		})
	}
}
