package sshcmd

import (
	"errors"
	"testing"
)

// the walk up the parents finds root, stops at a process outside it and
// at a loop or a missing entry
func TestDescendantOf(t *testing.T) {
	parents := map[int]int{40: 30, 30: 20, 20: 1, 50: 1, 60: 60, 70: 999}
	parent := func(pid int) (int, error) {
		p, ok := parents[pid]
		if !ok {
			return 0, errors.New("no such process")
		}
		return p, nil
	}
	for _, c := range []struct {
		pid  int
		want bool
	}{{20, true}, {30, true}, {40, true}, {50, false}, {60, false}, {70, false}, {1, false}} {
		if got := descendantOf(c.pid, 20, parent); got != c.want {
			t.Errorf("pid %d: %v, want %v", c.pid, got, c.want)
		}
	}
}
