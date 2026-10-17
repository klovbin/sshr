package main

import (
	"os"
	"os/signal"
	"syscall"
)

// forwardSignals passes SIGINT, SIGTERM and SIGHUP sent to sshr on to the
// child until the returned func runs, on Windows only Ctrl+C exists and
// it already reaches the child through the console
func forwardSignals(child *os.Process) func() {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-ch:
				child.Signal(s)
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}
