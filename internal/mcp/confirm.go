package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"sshr.dev/internal/app"
)

// confirmWait is how long a question to the user waits for an answer
var confirmWait = 5 * time.Minute

// elicitSince is the first protocol version with elicitation
const elicitSince = "2025-06-18"

// ErrNotConfirmed means the user did not allow a command, or could not be
// asked
var ErrNotConfirmed = errors.New("the command was not confirmed")

// canElicit reads the elicitation capability of initialize: present, and
// with form mode when it lists modes (an empty object means form)
func canElicit(version string, caps json.RawMessage) bool {
	if version < elicitSince {
		return false
	}
	var c struct {
		Elicitation json.RawMessage `json:"elicitation"`
	}
	if json.Unmarshal(caps, &c) != nil || len(c.Elicitation) == 0 || string(c.Elicitation) == "null" {
		return false
	}
	var modes map[string]json.RawMessage
	if json.Unmarshal(c.Elicitation, &modes) != nil {
		return false
	}
	_, form := modes["form"]
	return len(modes) == 0 || form
}

// confirm asks the user through the client whether command may run on h,
// anything but an explicit yes refuses: decline, cancel, an error, no
// answer in confirmWait, a client that went away or cannot ask
func (s *server) confirm(h *app.Host, command string) error {
	s.mu.Lock()
	can := s.elicit
	s.mu.Unlock()
	if !can {
		return fmt.Errorf("%w: sshr asks before every command and this client cannot show the question, run it in a terminal or start sshr mcp without --confirm-commands", ErrNotConfirmed)
	}
	name, _ := dataText(h.Name)
	s.mu.Lock()
	s.nextID++
	id := fmt.Sprintf(`"sshr-%d"`, s.nextID)
	answer := make(chan request, 1)
	s.pending[id] = answer
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
	}()
	s.write(map[string]any{
		"jsonrpc": "2.0", "id": json.RawMessage(id), "method": "elicitation/create",
		"params": map[string]any{
			"message": fmt.Sprintf("Run this command on %s (%s:%d)?\n%q", name, h.Dest(), h.Port, command),
			"requestedSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"run": map[string]any{"type": "boolean", "title": "Run this command", "default": false},
				},
				"required": []string{"run"},
			},
		},
	})
	select {
	case r := <-answer:
		if len(r.Error) > 0 {
			return fmt.Errorf("%w: the client could not ask: %s", ErrNotConfirmed, r.Error)
		}
		var res struct {
			Action  string `json:"action"`
			Content struct {
				Run bool `json:"run"`
			} `json:"content"`
		}
		if json.Unmarshal(r.Result, &res) != nil || res.Action != "accept" || !res.Content.Run {
			return fmt.Errorf("%w: the user did not allow it", ErrNotConfirmed)
		}
		return nil
	case <-time.After(confirmWait):
		return fmt.Errorf("%w: no answer in %v", ErrNotConfirmed, confirmWait)
	case <-s.done:
		return fmt.Errorf("%w: the client went away", ErrNotConfirmed)
	}
}

// deliver hands a response of the client to the question waiting for it,
// a response nobody waits for is dropped
func (s *server) deliver(r request) {
	key := string(bytes.TrimSpace(r.ID))
	s.mu.Lock()
	answer := s.pending[key]
	delete(s.pending, key)
	s.mu.Unlock()
	if answer != nil {
		answer <- r
	}
}
