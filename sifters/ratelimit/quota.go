package ratelimit

import (
	"time"

	"github.com/jiftechnify/strfrui/sifters/internal/utils"
	"github.com/throttled/throttled/v2"
)

// Rate describes an allowed rate of write requests.
//
// Re-exporting [github.com/throttled/throttled/v2.Rate].
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

// Quota describes the number of requests allowed per time period with burst.
// For details, see [github.com/throttled/throttled/v2.RateQuota].
type Quota = throttled.RateQuota

// KindQuota defines a quota of write requests of specific kinds of events.
//
// This type is exposed only for document organization purpose. You shouldn't initialize this struct directly.
type KindQuota struct {
	matchKind func(int) bool
	quota     Quota
}

// QuotaForAllKinds makes an instance of KindQuota that defines a request quota for given set of kinds.
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

// QuotaForKindsFn makes an instance of KindQuota that defines a request quota for kinds that match the given matcher function.
//
// You can use kind matchers defined in [github.com/jiftechnify/strfrui/sifters] here, such as sifters.KindsAllReplaceable.
func QuotaForKindsFn(matcher func(int) bool, quota Quota) KindQuota {
	return KindQuota{
		matchKind: matcher,
		quota:     quota,
	}
}
