# strfrui

[![GoDoc](https://pkg.go.dev/badge/github.com/jiftechnify/strfrui.svg)](https://pkg.go.dev/github.com/jiftechnify/strfrui)

A framework for writing [strfry](https://github.com/hoytech/strfry)'s [event-sifter](https://github.com/hoytech/strfry/blob/master/docs/plugins.md) (write policy) plugins in Go.

> This project is formerly known as [strfry-evsifter](https://github.com/jiftechnify/strfry-evsifter).

## Installation

```bash
go get github.com/jiftechnify/strfrui
```

## Features

- Offers **out-of-the-box** event-sifters, including **rate limiters**.
- **Sifter combinators**: you can build own event-sifters by composing small parts together.
- Provides you foundations for writing a custom event-sifter as a simple function and running it.

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

The complete list of available built-in sifters is [here](https://github.com/jiftechnify/strfrui/wiki/All-built%E2%80%90in-event%E2%80%90sifters).

### Using Combinators to Compose Multiple Sifters

strfrui offers ways to compose multiple event-sifters together, called "combinators". They can be used to make a single complex sifter logic from small parts.

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
    // Sifter modification changes sifter's behavior within combinators.
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

The complete list of available combinators and modifiers is [here](https://github.com/jiftechnify/strfrui/wiki/Sifter-combinators-and-modifiers).

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
    limiter := ratelimit.ByUser(
        // every users can write 2 events per second, allowing burst up to 5 events.
        ratelimit.QuotaPerSec(2).WithBurst(5),
        // "users" are identified by pubkey. You can also use ratelimit.IPAddr here.
        ratelimit.Pubkey, 
    ).
    // exclude all ephemeral events from rate limiting
    Exclude(func(input *strfrui.Input) bool { 
        return sifters.KindsAllEphemeral(input.Event.Kind)
    })

    strfrui.New(limiter).Run()
}
```

You may want to use `ratelimit.ByUserAndKind` to impose different limits for different event kinds.

```go
limiter := ratelimit.ByUserAndKind([]ratelimit.QuotaForKinds{
    // 2 events/s, burst up to 10 events for kind:1 
    ratelimit.QuotaPerSec(2).WithBurst(10).ForKinds(1),
    // 5 events/s, burst up to 50 events for kind:7
    ratelimit.QuotaPerSec(5).WithBurst(50).ForKinds(7),
}, ratelimit.Pubkey)
```

### Writing Custom Sifter from Scratch

Essentially, event-sifter is just a function that takes an "input" (event + metadata of event source etc.) and returns "result" (action to take on the event: accept or reject).

```go
type Sifter interface {
    Sift (*strfrui.Input) (*strfrui.Result, error)
}
```

If you feel cumbersome to build sifters you want by combining small blocks, you can still implement overall sifter logic as a Go function. Of course, sifters written in such a way are also composable using the combinators!

The code below is a example of writing event-sifter as a function. The logic is equivalent to the sifter in the first example, but it adds custom logging.

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

## License

MIT
