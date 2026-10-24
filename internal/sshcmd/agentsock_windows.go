package sshcmd

import (
	"net"

	"github.com/Microsoft/go-winio"
)

// listenAgent opens a named pipe, Windows OpenSSH reads SSH_AUTH_SOCK as a
// pipe path, the default security descriptor lets only this user and
// administrators open it
func listenAgent(name string) (ln net.Listener, sock string, cleanup func(), err error) {
	sock = `\\.\pipe\sshr-agent-` + name
	if ln, err = winio.ListenPipe(sock, nil); err != nil {
		return nil, "", nil, err
	}
	return ln, sock, func() { ln.Close() }, nil
}

// dialAgent connects to an agent pipe
func dialAgent(sock string) (net.Conn, error) {
	return winio.DialPipe(sock, nil)
}
