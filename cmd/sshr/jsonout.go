package main

import (
	"encoding/json"
	"os"

	"sshr.dev/internal/app"
)

// The --json output of list, ping and run, fields are fixed and carry no
// secrets, the host part is app.HostSummary, the same the REST API returns

type healthJSON struct {
	State     string `json:"state"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Cause     string `json:"cause,omitempty"`
}

type listJSON struct {
	app.HostSummary
	Status *healthJSON `json:"status,omitempty"`
}

type pingJSON struct {
	Name string `json:"name"`
	ID   string `json:"id"`
	healthJSON
}

type runJSON struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

func toHealthJSON(r app.Health) healthJSON {
	return healthJSON{State: r.State, LatencyMS: r.Latency.Milliseconds(), Reason: r.Reason, Cause: r.Cause}
}

// printJSON writes v indented with a newline, an empty list as []
func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatal(err)
	}
}
