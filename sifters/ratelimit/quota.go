package ratelimit

import (
	"time"

	"github.com/jiftechnify/strfrui/sifters/internal/utils"
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

type KindQuota struct {
	matchKind func(int) bool
	quota     Quota
}

func QuotaForKinds(kinds []int, quota Quota) KindQuota {
	kindSet := utils.SliceToSet(kinds)
	return KindQuota{
		matchKind: func(kind int) bool {
			_, ok := kindSet[kind]
			return ok
		},
		quota: quota,
	}
}

func QuotaForKindsFn(matcher func(int) bool, quota Quota) KindQuota {
	return KindQuota{
		matchKind: matcher,
		quota:     quota,
	}
}
