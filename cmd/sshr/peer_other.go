//go:build !linux && !darwin

package main

import "net"

// peerUID cannot ask the socket here, the mode of the socket (its ACL on
// Windows) is the only check
func peerUID(net.Conn) (int, error) { return -1, errPeerUnknown }
