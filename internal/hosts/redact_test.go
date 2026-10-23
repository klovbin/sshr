package hosts

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// no fmt verb of a host shows a secret or a secret reference (#100)
func TestHostFormatRedacts(t *testing.T) {
	h := Host{Name: "web", Host: "example.com", User: "u", Password: "pw-plain", PasswordSealed: "v2:sealedpw",
		PlainPassword: "old-plain", PasswordRef: "op://vault/item/password", KeyData: []byte("PRIVATE KEY"),
		KeyPassphrase: "kpass", KeySealed: "v2:sealedkey", KeyRef: "op://vault/key/private key",
		extra: map[string]json.RawMessage{"future_token": []byte(`"tok-secret"`)}}
	secrets := []string{"pw-plain", "sealedpw", "old-plain", "op://", "PRIVATE KEY", "kpass", "sealedkey", "tok-secret"}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		for _, v := range []any{h, &h} {
			out := fmt.Sprintf(verb, v)
			for _, s := range secrets {
				if strings.Contains(out, s) {
					t.Errorf("%s of %T shows %q: %s", verb, v, s, out)
				}
			}
			if !strings.Contains(out, "example.com") {
				t.Errorf("%s of %T lost the address: %s", verb, v, out)
			}
		}
	}
	if h.Password != "pw-plain" || string(h.KeyData) != "PRIVATE KEY" {
		t.Error("printing changed the host")
	}
}
