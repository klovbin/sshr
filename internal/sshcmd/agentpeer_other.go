//go:build !linux && !darwin && !windows

package sshcmd

import "net"

// peerPID gives no peer here, the BSDs are not covered yet
func peerPID(net.Conn) (int, bool, error) { return 0, false, nil }

func parentPID(int) (int, error) { return 0, nil }
