//go:build !linux && !darwin

package main

import "net"

// peerUID cannot ask the socket here, the mode of the socket (its ACL on
// Windows) is the only check
func peerUID(c net.Conn) (int, error) {
	if _, err := unixRaw(c); err != nil {
		return -1, err
	}
	return -1, errPeerUnknown
}
