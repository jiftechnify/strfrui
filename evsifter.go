package evsifter

import (
	"bufio"
	"encoding/json"
	"log"
	"os"

	"github.com/nbd-wtf/go-nostr"
)

type SourceType string

const (
	SourceTypeIP4    SourceType = "IP4"
	SourceTypeIP6    SourceType = "IP6"
	SourceTypeImport SourceType = "Import"
	SourceTypeStream SourceType = "Stream"
	SourceTypeSync   SourceType = "Sync"
)

type Action string

const (
	ActionAccept       Action = "accept"
	ActionReject       Action = "reject"
	ActionShadowReject Action = "shadowReject"
)

type Input struct {
	Type       string       `json:"type"`
	Event      *nostr.Event `json:"event"`
	ReceivedAt uint64       `json:"receivedAt"`
	SourceType SourceType   `json:"sourceType"`
	SourceInfo string       `json:"sourceInfo"`
}

type Result struct {
	ID     string `json:"id"`
	Action Action `json:"action"`
	Msg    string `json:"msg"`
}

func (i *Input) Accept() *Result {
	return &Result{
		ID:     i.Event.ID,
		Action: ActionAccept,
	}
}

func (i *Input) Reject(msg string) *Result {
	return &Result{
		ID:     i.Event.ID,
		Action: ActionReject,
		Msg:    msg,
	}
}

func (i *Input) ShadowReject() *Result {
	return &Result{
		ID:     i.Event.ID,
		Action: ActionShadowReject,
	}
}

type Sifter interface {
	Sift(input *Input) (*Result, error)
}

type SifterFunc func(input *Input) (*Result, error)

func (s SifterFunc) Sift(input *Input) (*Result, error) {
	return s(input)
}

type Runner struct {
	sifter Sifter
}

var acceptAll = SifterFunc(func(input *Input) (*Result, error) {
	return input.Accept(), nil
})

func (r *Runner) Run() {
	var (
		scanner   = bufio.NewScanner(os.Stdin)
		bufStdout = bufio.NewWriter(os.Stdout)
		jsonEnc   = json.NewEncoder(bufStdout)
	)

	for scanner.Scan() {
		var input Input
		if err := json.Unmarshal(scanner.Bytes(), &input); err != nil {
			log.Printf("failed to parse input: %v", err)
			continue
		}

		sifter := r.sifter
		if sifter == nil {
			sifter = acceptAll
		}

		out, err := sifter.Sift(&input)
		if err != nil {
			log.Println(err)
			continue
		}

		if err := jsonEnc.Encode(out); err != nil {
			log.Printf("failed to encode event sifter result to JSON: %v", err)
		}
		bufStdout.Flush()
	}
}

func (r *Runner) SiftWith(s Sifter) {
	r.sifter = s
}

func (r *Runner) SiftWithFunc(sf func(input *Input) (*Result, error)) {
	r.sifter = SifterFunc(sf)
}
