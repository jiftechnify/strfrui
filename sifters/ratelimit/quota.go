package ratelimit

import (
	"time"

	"github.com/jiftechnify/strfrui/sifters/internal/utils"
	"github.com/throttled/throttled/v2"
)

// Quota describes the number of requests allowed per time period with burst.
//
// You can concisely create instants of Quota using functions [QuotaPerSec], [QuotaPerMin], [QuotaPerHour] and so on.
// The Quota created by these constructors doesn't allow any bursts. To allow bursts, use [Quota.WithBurst].
type Quota throttled.RateQuota

// QuotaForKinds defines a quota of write requests of specific kinds of events.
//
// This type is exposed only for document organization purpose. You shouldn't initialize this struct directly.
type QuotaForKinds struct {
	matchKind func(int) bool
	quota     Quota
}

// QuotaPerSec creates a [Quota] with max rate of n per second.
func QuotaPerSec(n int) Quota { return Quota{MaxRate: throttled.PerSec(n), MaxBurst: 0} }

// QuotaPerMin creates a [Quota] with max rate of n per minute.
func QuotaPerMin(n int) Quota { return Quota{MaxRate: throttled.PerMin(n), MaxBurst: 0} }

// QuotaPerHour creates a [Quota] with max rate of n per hour.
func QuotaPerHour(n int) Quota { return Quota{MaxRate: throttled.PerHour(n), MaxBurst: 0} }

// QuotaPerDay creates a [Quota] with max rate of n per day.
func QuotaPerDay(n int) Quota { return Quota{MaxRate: throttled.PerDay(n), MaxBurst: 0} }

// QuotaPerDuration creates a [Quota] with max rate of n per provided duration.
func QuotaPerDuration(n int, d time.Duration) Quota {
	return Quota{MaxRate: throttled.PerDuration(n, d), MaxBurst: 0}
}

// WithBurst creates new [Quota] that allows bursts, with max rate of q.
func (q Quota) WithBurst(maxBurst int) Quota {
	return Quota{MaxRate: q.MaxRate, MaxBurst: maxBurst}
}

// ForKinds makes the [Quota] q be only applied to events of the given set of kinds.
func (q Quota) ForKinds(kinds ...int) QuotaForKinds {
	kindSet := utils.SliceToSet(kinds)
	return QuotaForKinds{
		matchKind: func(kind int) bool {
			_, ok := kindSet[kind]
			return ok
		},
		quota: q,
	}
}

// ForKindsMatching makes the [Quota] q be only applied to events of kinds that match the given matcher function.
//
// You can use kind matchers defined in [github.com/jiftechnify/strfrui/sifters], such as [github.com/jiftechnify/strfrui/sifters.KindsAllReplaceable].
func (q Quota) ForKindsMatching(matchKind func(int) bool) QuotaForKinds {
	return QuotaForKinds{
		matchKind: matchKind,
		quota:     q,
	}
}
