# strfrui
A framework for writing [strfry](https://github.com/hoytech/strfry)'s [event-sifter](https://github.com/hoytech/strfry/blob/master/docs/plugins.md) (write policy) plugins in Go.

> This project is formerly known as [strfry-evsifter](https://github.com/jiftechnify/strfry-evsifter).

## Installation

```bash
go get github.com/jiftechnify/strfrui
```

## Features
* Gives you foundations for writing a custom event-sifter as a simple function and running it.
* Offers out-of-the-box event-sifters, including rate limiters.
* Sifter combinators: you can build own event-sifters by composing small parts together.

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
    // initialize a strfrui.Runner with 
    // an event-sifter that accepts events from pubkeys in the whitelist
    // then start the sifting routine
    strfrui.New(sifters.AuthorList(whiteList, sifters.Allow)).Run()
}
```

The complete list of available out-of-the-box sifters is [here]().


### Using Combinators to Compose Multiple Sifters

strfrui offers ways to compose multiple event-sifters together, called "combinators". They combine sifters and make a single big sifter. 

The code below shows the usage of these combinators:

```go
package main

import (
    "github.com/jiftechnify/strfrui"
    "github.com/jiftechnify/strfrui/sifters"
)

const adminPubkey = "admin"
var blacklist = []string{"spammer", "scammer"}

func main() {
    acceptAdmin := sifters.AuthorList([]string{adminPubkey}, sifters.Allow)
    rejectBlacklist := sifters.AuthorList(blacklist, sifters.Deny)

    nostrPostsOnly := sifters.IfThen(
        sifters.KindList(          // if kind == 1 ...
            []int{1},
            sifters.Allow
        ), 
        sifters.ContentHasAnyWord( // its content must contain the word "nostr"
            []string{"nostr"},     // (otherwise, always accept)
            sifters.Allow,
        ), 
    )                                                                

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

The complete list of available combinators is [here]().

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

You may want to use `ratelimit.ByUserAndKind` to impose different limit for diffrent event kinds.


### Writing Custom Sifter from Scratch

Essentially, event-sifter is just a function that takes an "input" (event + metadata of event source etc.) and returns "result" (action to take on the event: accept or reject). If you feel cumbersome to build sifters you want by combining small blocks, you can still implement overall sifter logic as a Go function. Of course, sifters written in such a way are also composable using the combinators!

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
### List of sifter combinators

All combinators is in `sifters` package.

#### `Pipeline(...sifters)`

Combines a list of sifters into one. The resulting sifter accepts an input if *all* sub-sifters accept it. 

If any sub-sifter rejects the input, the combined sifter rejects with the result from the rejecting sub-sifter.

#### `OneOf(...sifters)`

Combines a list of sifters into one. The resulting sifter accepts an input if *one of* sub-sifters accepts it.

If all sub-sifters rejects the input, the combined sifter rejects with message: `"blocked: any of sub-sifters didn't accept the event"` by default. You can customize rejection behavior by calling `.RejectWithMsg()/.RejectWithMsgFromInput()/.ShadowReject()` methods on it.

#### `IfThen(cond, body)`

*Only if* the first sifter (`cond`) *accepts* an input, evaluates the second one (`body`) to determine whether the input should be accepted or not. If the first one *rejects*, overall sifter accepts.

You can roughly think it as:

```go
if (cond(input)) {
    return body(input)
}
```

#### `IfNotThen(cond, body)`

*Only if* the first sifter (`cond`) *rejects* an input, evaluates the second one (`body`) to determine whether the input should be accepted or not. If the first one *accepts*, overall sifter accepts.

You can roughly think it as:

```go
if (!cond(input)) {
    return body(input)
}
```


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

### About the `mode` parameter of built-in sifters

Most of built-in event-sifters take `mode` parameter that specifies the behavior of sifters when an input matches given condition. Available `mode`s are:

- `sifters.Allow`: *Accept* the input if it matches given conditions ("whitelist").
- `sifters.Deny`: *Reject* the input if it matches given conditions ("blacklist").


## License
MIT
