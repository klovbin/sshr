package app

import (
	"bytes"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
)

// hostKeys are the JSON names of the fields of Host in lower case,
// encoding/json matches keys without regard to case, so "Key_Sealed" is
// the key_sealed field and not a field of a newer sshr
var hostKeys = func() map[string]bool {
	keys := map[string]bool{}
	typ := reflect.TypeOf(Host{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		keys[strings.ToLower(name)] = true
	}
	return keys
}()

// decodeHost reads a host file, the keys this build does not know (a
// field a newer sshr wrote) are kept in h.extra and written back on save
func decodeHost(b []byte) (Host, error) {
	var h Host
	if err := json.Unmarshal(b, &h); err != nil {
		return Host{}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return Host{}, err
	}
	for k, v := range raw {
		if hostKeys[strings.ToLower(k)] {
			continue
		}
		if h.extra == nil {
			h.extra = map[string]json.RawMessage{}
		}
		h.extra[k] = v
	}
	return h, nil
}

// encodeHost writes a host file, the fields of Host as before, then the
// kept keys of a newer sshr in name order, a host without them gives the
// same bytes as a plain marshal
func encodeHost(h *Host) ([]byte, error) {
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil || len(h.extra) == 0 {
		return b, err
	}
	end := bytes.LastIndexByte(b, '}')
	var out bytes.Buffer
	out.Write(bytes.TrimRight(b[:end], " \n"))
	for _, k := range slices.Sorted(maps.Keys(h.extra)) {
		name, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		var v bytes.Buffer
		if err := json.Compact(&v, h.extra[k]); err != nil {
			return nil, err
		}
		out.WriteString(",\n  ")
		out.Write(name)
		out.WriteString(": ")
		out.Write(v.Bytes())
	}
	out.WriteString("\n}")
	return out.Bytes(), nil
}
