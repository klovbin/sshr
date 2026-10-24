package main

import (
	"strings"
	"testing"
)

// authorized_keys is split into keys on a token and others, options before
// a key and comments are read past, a line that is no key is left out
func TestAuthorizedKeyTypes(t *testing.T) {
	data := "# keys of the team\n" +
		"sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIHIbECQGRB3NLg97SPN3A8L+r0iy7tQjMlb9OqjlYhH6AAAABHNzaDo= yubi\n" +
		"not a key at all\n" +
		`from="10.0.0.0/8",no-agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl laptop` + "\n"
	sk, other := authorizedKeyTypes([]byte(data))
	if len(sk) != 1 || !strings.HasPrefix(sk[0], "sk-ssh-ed25519@openssh.com SHA256:") || !strings.HasSuffix(sk[0], "yubi") {
		t.Errorf("sk %q", sk)
	}
	if len(other) != 1 || !strings.HasPrefix(other[0], "ssh-ed25519 SHA256:") || !strings.HasSuffix(other[0], "laptop") {
		t.Errorf("other %q", other)
	}
	if sk, other := authorizedKeyTypes(nil); len(sk)+len(other) != 0 {
		t.Error("an empty file gave keys")
	}
}
