# strfry-evsifter
A tiny framework for writing [strfry](https://github.com/hoytech/strfry)'s [event sifter](https://github.com/hoytech/strfry/blob/master/docs/plugins.md) (write policy) plugin in Go.

## Installation

```bash
go get github.com/jiftechnify/strfry-evsifter
```

## Example
The same logic as [the example](https://github.com/hoytech/strfry/blob/master/docs/plugins.md#example-whitelist) implemented using this framework.

```go
package main

import (
	"log"

	evsifter "github.com/jiftechnify/strfry-evsifter"
)

var whiteList = map[string]struct{}{
	"003ba9b2c5bd8afeed41a4ce362a8b7fc3ab59c25b6a1359cae9093f296dac01": {},
}

// event-sifting function
func acceptWhiteListed(input *evsifter.Input) (*evsifter.Result, error) {
	if _, ok := whiteList[input.Event.PubKey]; ok {
		return input.Accept()
	}

	// you can emit arbitrary logs by log.Print() family
	log.Println("blocking event!")
	return input.Reject("blocked: not on white-list")
}

func main() {
	// initialize a evsifter.Runner and set an event-sifting function
	var s evsifter.Runner
	s.SiftWithFunc(acceptWhiteListed)

	// start the event sifter routine
	s.Run()
}
```

## License
MIT
