// Package strfrui provides foundations for building [strfry's event-sifters plugins] in Go.
//
// If you want to explore built-in event-sifter implementaions and combinators,
// which can be used to make complex sifter logics from small parts,
// see the doc of [github.com/jiftechnify/strfrui/sifters] package.
//
// [strfry's event-sifters plugins]: https://github.com/hoytech/strfry/blob/master/docs/plugins.md
package strfrui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/nbd-wtf/go-nostr"
)

// SourceType represents a source type of a Nostr event, in other words, where an event came from.
type SourceType string

const (
	// SourceTypeIP4 shows that an event was sent from a client which has an IPv4 address.
	SourceTypeIP4 SourceType = "IP4"

	// SourceTypeIP6 shows that an event was sent from a client which has an IPv6 address.
	SourceTypeIP6 SourceType = "IP6"

	// SourceTypeImport shows that an event was imported via "strfry import" command.
	SourceTypeImport SourceType = "Import"

	// SourceTypeStream shows that an event was imported from another relay via "strfry stream" or "strfry router" command.
	SourceTypeStream SourceType = "Stream"

	// SourceTypeSync shows that an event was imported from another relay via "strfry sync" command.
	SourceTypeSync SourceType = "Sync"
)

// IsEndUser checks whether the source is an "end-user" (or, a "user-facing client").
func (st SourceType) IsEndUser() bool {
	switch st {
	case SourceTypeIP4, SourceTypeIP6:
		return true
	default:
		return false
	}
}

// Action represents a type of action by event sifter, in other words, how to process an event.
type Action string

const (
	ActionAccept       Action = "accept"
	ActionReject       Action = "reject"
	ActionShadowReject Action = "shadowReject"
)

// Input is a data structure of event sifter's input.
type Input struct {
	// A type of input. As of strfry 0.9.6, it is always "new".
	Type string `json:"type"`

	// An event data sent by a client or imported from file / another relay.
	Event *nostr.Event `json:"event"`

	// Unix timestamp (in second) of when the event was received by the relay.
	ReceivedAt uint64 `json:"receivedAt"`

	// The source type, or where the event came from.
	SourceType SourceType `json:"sourceType"`

	// Information about event source. If SourceType is...
	//
	//   - SourceTypeIP4 or SourceTypeIP6, it's a string representaion of client's IP address.
	//   - SourceTypeStream or SourceTypeSync, it's a URL of a source relay.
	//   - SourceTypeImport, it's an empty string.
	SourceInfo string `json:"sourceInfo"`
}

// Result is a data structure of event sifter's output.
// It can be generated from methods of an Input.
type Result struct {
	// The ID of the target event, taken from the ID field of Input.
	ID string `json:"id"`

	// An action to take on the target event.
	Action Action `json:"action"`

	// A message to be sent to a client (included in an OK message) if event is rejected.
	Msg string `json:"msg"`
}

// Accept accepts the event in the input.
func (i *Input) Accept() (*Result, error) {
	return &Result{
		ID:     i.Event.ID,
		Action: ActionAccept,
	}, nil
}

// Reject rejects the event in the input with a rejection message to the client.
//
// As per [NIP-01], the message should be prefixed with a machine-readable word followed by ":" (e.g. "blocked: you are not allowed to write events").
// You can use [BuildRejectMessage] to build a rejection message in that format.
//
// [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md
func (i *Input) Reject(msg string) (*Result, error) {
	return &Result{
		ID:     i.Event.ID,
		Action: ActionReject,
		Msg:    msg,
	}, nil
}

// ShadowReject silently rejects the event in the input, that is, makes it look accepted to the client, but actually reject it.
func (i *Input) ShadowReject() (*Result, error) {
	return &Result{
		ID:     i.Event.ID,
		Action: ActionShadowReject,
	}, nil
}

// "Machine-readable prefixes" for rejection messages. Use them with [BuildRejectMessage].
const (
	RejectReasonPrefixBlocked     = "blocked"
	RejectReasonPrefixRateLimited = "rate-limited"
	RejectReasonPrefixInvalid     = "invalid"
	RejectReasonPrefixPoW         = "pow"
	RejectReasonPrefixError       = "error"
)

// BuildRejectMessage builds a rejection message with a machine-readable prefix.
//
// The message format is defined in [NIP-01].
//
// [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md#from-relay-to-client-sending-events-and-notices
func BuildRejectMessage(prefix string, body string) string {
	return prefix + ": " + body
}

// A Sifter decides whether accept or reject an event based on Input, the event data itself with context information.
//
// Sift should return either Result with an action to take on the event, or error if it couldn't process the input.
// If error is returned from Sift, the event is rejected by default.
type Sifter interface {
	Sift(input *Input) (*Result, error)
}

// SifterFunc is an adapter to allow the use of functions which takes a sifter Input and returns a sifter Result as a Sifter.
type SifterFunc func(input *Input) (*Result, error)

func (s SifterFunc) Sift(input *Input) (*Result, error) {
	return s(input)
}

// Runner implements the main routine of a event sifter as Run() method.
// You may want to use [strfrui.New] to initialize a Runner and set a Sifter at the same time.
//
// The zero value for Runner is a valid Runner that accepts all events.
type Runner struct {
	sifter Sifter
}

var acceptAll = SifterFunc(func(input *Input) (*Result, error) {
	return input.Accept()
})

// Run executes the main routine of a event sifter.
func (r *Runner) Run() {
	var (
		scanner   = bufio.NewScanner(os.Stdin)
		bufStdout = bufio.NewWriter(os.Stdout)
		jsonEnc   = json.NewEncoder(bufStdout)
	)

	var processInput = func(input *Input) (*Result, error) {
		if input.Type != "new" {
			return nil, fmt.Errorf("unexpected input type: %s", input.Type)
		}

		sifter := r.sifter
		if sifter == nil {
			sifter = acceptAll
		}
		return sifter.Sift(input)
	}

	for scanner.Scan() {
		var input Input
		if err := json.Unmarshal(scanner.Bytes(), &input); err != nil {
			log.Printf("failed to parse input: %v", err)

			// write malformed output in order to reject event
			_ = jsonEnc.Encode(Result{ID: ""})
			bufStdout.Flush()
			continue
		}

		res, err := processInput(&input)
		if err != nil {
			log.Println(err)

			// reject the event by default if sifter returns error
			res, _ = input.Reject("error: event sifter failed to process input")
		}

		if err := jsonEnc.Encode(res); err != nil {
			log.Printf("failed to encode event sifter result to JSON: %v", err)
		}
		bufStdout.Flush()
	}
}

// New initializes a new Runner and set the passed Sifter at the same time.
func New(s Sifter) *Runner {
	return &Runner{
		sifter: s,
	}
}

// NewWithSifterFunc initializes a new Runner and set the passed event sifting function as a Sifter at the same time.
func NewWithSifterFunc(sf func(input *Input) (*Result, error)) *Runner {
	return &Runner{
		sifter: SifterFunc(sf),
	}
}

// SiftWith replaces the Sifter in the Runner with the passed one.
func (r *Runner) SiftWith(s Sifter) {
	r.sifter = s
}

// SiftWithFunc replaces the Sifter in the Runner with the passed event sifting function.
func (r *Runner) SiftWithFunc(sf func(input *Input) (*Result, error)) {
	r.sifter = SifterFunc(sf)
}
