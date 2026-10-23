package main

import "net"

// listenPrivate opens a unix socket, Windows gives it the ACL of its
// directory and has no mode bits to set
func listenPrivate(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}
