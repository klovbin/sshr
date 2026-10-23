package hosts

import "testing"

func TestCheckSession(t *testing.T) {
	if checkSession("screen") == nil || checkSession(SessionTmux) != nil || checkSession("") != nil {
		t.Error("checkSession")
	}
}
