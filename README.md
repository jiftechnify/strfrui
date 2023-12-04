# strfrui
A framework for writing [strfry](https://github.com/hoytech/strfry)'s [event-sifter](https://github.com/hoytech/strfry/blob/master/docs/plugins.md) (write policy) plugins in Go.

> This project is formerly known as [strfry-evsifter](https://github.com/jiftechnify/strfry-evsifter).

## Installation

```bash
go get github.com/jiftechnify/strfrui
```

## Features
* Offers **out-of-the-box** event-sifters, including **rate limiters**.
* **Sifter combinators**: you can build own event-sifters by composing small parts together.
* Gives you foundations for writing a custom event-sifter as a simple function and running it.

## Examples
### Using Out-of-the-Box Sifters

The code below implements the same logic as [this example](https://github.com/hoytech/strfry/blob/master/docs/plugins.md#example-whitelist) using built-in event sifters in `sifters` package:

```go
package main

import (
    "github.com/jiftechnify/strfrui"
    "github.com/jiftechnify/strfrui/sifters"
)

var whiteList = []string{
    "003ba9b2c5bd8afeed41a4ce362a8b7fc3ab59c25b6a1359cae9093f296dac01",
}

func main() {
    // Initializing a strfrui.Runner with an event-sifter
    // that accepts events from pubkeys in the whitelist.
    // Then, start the sifting routine by calling Run().
    strfrui.New(sifters.AuthorList(whiteList, sifters.Allow)).Run()
}
```

The complete list of available built-in sifters is [here](https://github.com/jiftechnify/strfrui#list-of-built-in-event-sifters).


### Using Combinators to Compose Multiple Sifters

strfrui offers ways to compose multiple event-sifters together, called "combinators". They combine sifters and make a single big sifter. 

The code below shows the usage of these combinators:

```go
package main

import (
    "github.com/jiftechnify/strfrui"
    "github.com/jiftechnify/strfrui/sifters"
)

var (
    adminList = []string{"admin"}
    blacklist = []string{"spammer", "scammer"}
)

func main() {
    acceptAdmin := sifters.AuthorList(adminList, sifters.Allow)
    rejectBlacklist := sifters.AuthorList(blacklist, sifters.Deny)

    // sifters.WithMod() makes sifters modifiable. 
    // Sifter modification changes sifter's bahavior within combinators.
    // Here is an example of using OnlyIf() modifier.
    // * base sifter says: event’s content must contain the word "nostr".
    // * OnlyIf(...) says: restriction above applies to only kind 1 events.
    nostrPostsOnly := sifters.WithMod(
        sifters.ContentHasAnyWord([]string{"nostr"}, sifters.Allow)
    ).OnlyIf(sifters.KindList([]int{1}, sifters.Allow))

    finalSifter := sifters.      // finalSifter accepts if...
        OneOf(                   // the input satisfies *one of* conditions:
            acceptAdmin,         // 1. author is the admin
            sifters.Pipeline(    // 2. the input satisfies *all* conditions:
                rejectBlacklist, //    a. author is not in the blacklist
                nostrPostsOnly,  //    b. if kind == 1, its content must contain the word "nostr"
            ),
        )
    // run the finalSifter!
    strfrui.New(finalSifter).Run()
}
```

The complete list of available combinators and modifiers is [here](https://github.com/jiftechnify/strfrui#list-of-sifter-combinators).

### Bringing Rate Limiter to Strfry

You can easily set up a rate limiter to your Strfry relay by using built-in sifters under `ratelimit` package!

Below is a brief example of how to apply a rate limiter:

```go
package main

import (
    "github.com/jiftechnify/strfrui"
    "github.com/jiftechnify/strfrui/sifters/ratelimit"
)

func main() {
    // every users can write 2 events per second, allowing burst of 5 events.
    limiter := ratelimit.ByUser(
        ratelimit.Quota{MaxRate: ratelimit.PerSec(2), MaxBurst: 5},
        ratelimit.Pubkey, // "user" is identified by pubkey.
                          // you can also use ratelimit.IPAddr here.
    )
    strfrui.New(limiter).Run()
}
```

You may want to use `ratelimit.ByUserAndKind` to impose different limits for diffrent event kinds.


### Writing Custom Sifter from Scratch

Essentially, event-sifter is just a function that takes an "input" (event + metadata of event source etc.) and returns "result" (action to take on the event: accept or reject). 

```go
type Sifter interface {
    Sift (*strfrui.Input) (*strfrui.Result, error)
}
```

If you feel cumbersome to build sifters you want by combining small blocks, you can still implement overall sifter logic as a Go function. Of course, sifters written in such a way are also composable using the combinators!

The code below is a example of writing event-sifter as a function.  The logic is equivalent to the sifter in the first example, but it adds custom logging.

```go
package main

import (
	"log"
	"github.com/jiftechnify/strfrui"
)

var whitelist = map[string]struct{}{
	"003ba9b2c5bd8afeed41a4ce362a8b7fc3ab59c25b6a1359cae9093f296dac01": {},
}

// event-sifting function
func acceptWhitelisted(input *strfrui.Input) (*strfrui.Result, error) {
	if _, ok := whitelist[input.Event.PubKey]; ok {
		return input.Accept()
	} 

	// you can emit arbitrary logs by log.Print() family
	log.Println("blocking event!")
	return input.Reject("blocked: not on white-list")
}

func main() {
    // note that we use *NewWithSifterFunc* here to set a sifting function
    // instead of a Sifter interface implementation.
    strfrui.NewWithSifterFunc(acceptWhitelisted).Run()
}
```

## Details
### About the `mode` parameter of built-in sifters

Most of built-in event-sifters take `mode` parameter that specifies the behavior of sifters when an input matches given condition.

- `sifters.Allow`: *Accept* the input if it matches given conditions ("whitelist").
- `sifters.Deny`: *Reject* the input if it matches given conditions ("blacklist").


### List of built-in event-sifters

Sifters in `sifters` package:

#### Match event against Nostr filters
- `MatchesFilters(filters, mode)`

#### Match event author (`pubkey`)
- `AuthorMatcher(matcher, mode)`
- `AuthorList(authors, mode)`

#### Match event `kind`
- `KindMatcherFallible(matcher, mode)`
- `KindMatcher(matcher, mode)`
- `KindList(kinds, mode)`

#### Match event `tags`
- `TagsMatcher(matcher, mode)`

#### Limit event timestamp (`created_at`)
- `CreatedAtRange(timeRange, mode)`

#### Match `content`
- `ContentMatcher(matcher, mode)`
- `ContentHasAnyWord(words, mode)`
- `ContentHasAllWords(words, mode)`
- `ContentMatchesAnyRegexp(regexps, mode)`
- `ContentMatchesAllRegexps(regexps, mode)`

#### Set PoW minimum difficulty
- `PoWMinDifficulty(minDifficulty)`

#### Match IP address of event source
- `SourceIPMatcher(matcher, mode, modeForUnknownSource)`
- `SourceIPPrefixList(ipPrefixes, mode, modeForUnknownSource)`

---

Rate limiting sifters in `ratelimit` package:

- `ByUser(quota, userKey)`
- `ByUserAndKind(quotas, userKey)`


### List of sifter combinators

All combinators are in `sifters` package.

#### `Pipeline(...sifters)`

Combines a list of sifters into one. The resulting sifter accepts an input if *all* sub-sifters accept it. 

If any sub-sifter rejects the input, the combined sifter rejects with the result from the rejecting sub-sifter.

#### `OneOf(...sifters)`

Combines a list of sifters into one. The resulting sifter accepts an input if *one of* sub-sifters accepts it.

If all sub-sifters rejects the input, the combined sifter rejects with message: `"blocked: any of sub-sifters didn't accept the event"` by default. You can customize rejection behavior by calling `.RejectWithMsg()/.RejectWithMsgFromInput()/.ShadowReject()` methods on it.


### List of sifter modifiers

Sifter modifiers modifies behavior of the underlying sifter when it is composed via sifter combinators.

You can start modification by wrapping a sifter with `sifters.WithMod(sifter)`, then chain method calls on the wrapper.

#### `.AcceptEarly()`

If a sifter modified by `.AcceptEarly()` are used in `Pipeline(...)` and the modified sifter accepts an event, the overall pipeline accepts it immediately, and all sifters after that sifter are skipped.

#### `.OnlyIf(cond) / .OnlyIfNot(cond)`

If a sifter modified by `.OnlyIf(cond)` are used in `Pipeline(...)` or `OneOf(...)`, the combined sifter first applies `cond` to an input. Then,
- if `cond` *accepts* the input, the modified sifter is applied to the input normally.
- if `cond` *rejects* the input, the modified sifter is *skipped* and move to next.

`.OnlyIfNot(cond)` is opposite of `.OnlyIf(cond)`.

`cond` can be arbitrary event-sifter. 


## License
MIT
