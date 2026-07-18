package main

import (
	"testing"
	"time"
)

func TestMaintenanceWindowContainsDaytimeAndOvernight(t *testing.T) {
	tests := []struct {
		window string
		time   string
		want   bool
	}{
		{"03:00-05:00", "04:00", true},
		{"03:00-05:00", "05:00", false},
		{"23:00-02:00", "23:30", true},
		{"23:00-02:00", "01:30", true},
		{"23:00-02:00", "12:00", false},
	}
	for _, test := range tests {
		t.Run(test.window+"/"+test.time, func(t *testing.T) {
			window, err := parseMaintenanceWindow(test.window)
			if err != nil {
				t.Fatal(err)
			}
			now, err := time.Parse("15:04", test.time)
			if err != nil {
				t.Fatal(err)
			}
			if got := window.contains(now); got != test.want {
				t.Fatalf("contains = %t, want %t", got, test.want)
			}
		})
	}
}

func TestMaintenanceWindowRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"03:00", "25:00-03:00", "03:00-03:00", "nope"} {
		if _, err := parseMaintenanceWindow(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}
