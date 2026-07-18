package main

import (
	"fmt"
	"sort"

	"github.com/minio/minio-go/v7"
)

func selectRetention(items []minio.ObjectInfo, dailyLimit, weeklyLimit, monthlyLimit int, onUnrecognized func(string, error)) map[string]bool {
	ordered := append([]minio.ObjectInfo(nil), items...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].LastModified.After(ordered[j].LastModified) })
	keep := map[string]bool{}
	dailyCount, weeklyCount, monthlyCount := 0, 0, 0
	seenDay, seenWeek, seenMonth := map[string]bool{}, map[string]bool{}, map[string]bool{}

	for _, obj := range ordered {
		ts, err := parseTimestamp(obj.Key)
		if err != nil {
			keep[obj.Key] = true
			if onUnrecognized != nil {
				onUnrecognized(obj.Key, err)
			}
			continue
		}
		dayKey := ts.Format("2006-01-02")
		year, week := ts.ISOWeek()
		weekKey := fmt.Sprintf("%d-%02d", year, week)
		monthKey := ts.Format("2006-01")

		switch {
		case dailyCount < dailyLimit && !seenDay[dayKey]:
			keep[obj.Key] = true
			seenDay[dayKey] = true
			dailyCount++
		case weeklyCount < weeklyLimit && !seenWeek[weekKey]:
			keep[obj.Key] = true
			seenWeek[weekKey] = true
			weeklyCount++
		case monthlyCount < monthlyLimit && !seenMonth[monthKey]:
			keep[obj.Key] = true
			seenMonth[monthKey] = true
			monthlyCount++
		}
	}
	return keep
}
