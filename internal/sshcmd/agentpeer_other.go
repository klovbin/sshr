//go:build !linux && !darwin

package sshcmd

import "net"

// peerPID gives no peer here, a Windows pipe of sshr lets only this user
// and administrators in by its security descriptor, the BSDs are not
// covered yet
func peerPID(net.Conn) (int, bool, error) { return 0, false, nil }

func parentPID(int) (int, error) { return 0, nil }
