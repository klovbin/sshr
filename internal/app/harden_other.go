//go:build !linux && !darwin

package app

// harden has nothing to set here, Windows keeps the memory of a process
// from other users already, a process of the same user can still read it
func harden() error { return nil }
