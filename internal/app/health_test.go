package app

import (
	"net"
	"testing"
	"time"
)

func listen(t *testing.T, reply string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte(reply))
			time.Sleep(50 * time.Millisecond)
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestCheckHealth(t *testing.T) {
	ssh := listen(t, "hello\r\nSSH-2.0-OpenSSH_9.9\r\n")
	web := listen(t, "HTTP/1.1 400 Bad Request\r\n\r\n")
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()

	hosts := []Host{
		{ID: "a", Name: "a", Host: "127.0.0.1", Port: ssh},
		{ID: "b", Name: "b", Host: "127.0.0.1", Port: web},
		{ID: "c", Name: "c", Host: "127.0.0.1", Port: closedPort},
		{ID: "d", Name: "d", Host: "10.0.0.1", Jump: "bastion"},
		{ID: "e", Name: "myalias.invalid", Host: "myalias.invalid"},
	}
	got := CheckHealthAll(hosts)
	want := map[string]string{"a": HealthUp, "b": HealthNotSSH, "c": HealthDown, "d": HealthUnknown, "e": HealthUnknown}
	for id, st := range want {
		if got[id].State != st {
			t.Errorf("%s: %+v, want %s", id, got[id], st)
		}
	}
	if got["c"].Reason == "" || got["a"].Label() == "up" {
		t.Errorf("labels: %+v", got)
	}
}

func TestHealthCause(t *testing.T) {
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	web := listen(t, "HTTP/1.1 400 Bad Request\r\n\r\n")
	got := CheckHealthAll([]Host{
		{ID: "refused", Name: "r", Host: "127.0.0.1", Port: closedPort},
		{ID: "dns", Name: "n", Host: "no-such-host.invalid"},
		{ID: "banner", Name: "b", Host: "127.0.0.1", Port: web},
		{ID: "jump", Name: "j", Host: "10.0.0.1", Jump: "bastion"},
	})
	for id, want := range map[string]string{"refused": "refused", "dns": "dns", "banner": "no_banner", "jump": "jump"} {
		if got[id].Cause != want {
			t.Errorf("%s: cause %q, want %q (%+v)", id, got[id].Cause, want, got[id])
		}
	}
}

func TestHealthEvery(t *testing.T) {
	for in, want := range map[int]time.Duration{0: 5 * time.Minute, 10: time.Minute, 600: 10 * time.Minute} {
		if got := (Settings{HealthInterval: in}).HealthEvery(); got != want {
			t.Errorf("%d: %v", in, got)
		}
	}
}
