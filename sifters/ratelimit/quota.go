package ratelimit

import (
	"time"

	"github.com/jiftechnify/strfry-evsifter/sifters/internal/utils"
	"github.com/throttled/throttled/v2"
)

type Rate = throttled.Rate

// PerSec represents a number of requests per second.
func PerSec(n int) Rate { return throttled.PerSec(n) }

// PerMin represents a number of requests per minute.
func PerMin(n int) Rate { return throttled.PerMin(n) }

// PerHour represents a number of requests per hour.
func PerHour(n int) Rate { return throttled.PerHour(n) }

// PerDay represents a number of requests per day.
func PerDay(n int) Rate { return throttled.PerDay(n) }

// PerDuration represents a number of requests per provided duration.
func PerDuration(n int, d time.Duration) Rate { return throttled.PerDuration(n, d) }

type Quota = throttled.RateQuota

type QuotaForKind struct {
	matchKind func(int) bool
	quota     Quota
}

func QuotaForKindList(kinds []int, quota Quota) QuotaForKind {
	kindSet := utils.SliceToSet(kinds)
	return QuotaForKind{
		matchKind: func(kind int) bool {
			_, ok := kindSet[kind]
			return ok
		},
		quota: quota,
	}
}

func QuotaForMatchingKinds(matcher func(int) bool, quota Quota) QuotaForKind {
	return QuotaForKind{
		matchKind: matcher,
		quota:     quota,
	}
}
