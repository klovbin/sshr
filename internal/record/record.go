// Package record keeps the files of sshr readable across versions: the
// keys a newer sshr wrote are found, kept and written back, the "version"
// of a file says whether this build may write it, it imports nothing of
// sshr
package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
)

// ErrNewerFormat means a file was written by a newer sshr in a format this
// build reads but must not write, it would erase what it does not know
var ErrNewerFormat = errors.New("newer_format")

// JSONKeys are the JSON names of the exported fields of typ in lower case
func JSONKeys(typ reflect.Type) map[string]bool {
	keys := map[string]bool{}
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
}

// UnknownKeys are the keys of the JSON object b that match none of known
// and are not "version", nil when there are none
func UnknownKeys(b []byte, known map[string]bool) (map[string]json.RawMessage, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	var out map[string]json.RawMessage
	for k, v := range raw {
		if known[strings.ToLower(k)] || k == "version" {
			continue
		}
		if out == nil {
			out = map[string]json.RawMessage{}
		}
		out[k] = v
	}
	return out, nil
}

// FormatOf is the "version" of the JSON object b, 0 when it has none
func FormatOf(b []byte) (int, error) {
	var v struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return 0, fmt.Errorf("version: %v", err)
	}
	return v.Version, nil
}

// AppendKeys writes the keys of extra in name order into the JSON object
// b, indented as MarshalIndent with two spaces writes, b comes back as it
// is when extra is empty
func AppendKeys(b []byte, extra map[string]json.RawMessage) ([]byte, error) {
	if len(extra) == 0 {
		return b, nil
	}
	end := bytes.LastIndexByte(b, '}')
	var out bytes.Buffer
	out.Write(bytes.TrimRight(b[:end], " \n"))
	for _, k := range slices.Sorted(maps.Keys(extra)) {
		name, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		var v bytes.Buffer
		if err := json.Compact(&v, extra[k]); err != nil {
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

// Extra reads the keys of the JSON object b that are no field of the
// struct type typ, with the "version" of b, for a file that keeps what a
// newer sshr wrote
func Extra(b []byte, typ reflect.Type) (map[string]json.RawMessage, int, error) {
	format, err := FormatOf(b)
	if err != nil {
		return nil, 0, err
	}
	extra, err := UnknownKeys(b, JSONKeys(typ))
	return extra, format, err
}
