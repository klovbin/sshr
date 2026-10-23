package record

import (
	"encoding/json"
	"reflect"
	"testing"
)

type file struct {
	Name string `json:"name"`
	Skip string `json:"-"`
}

// a key a newer sshr wrote is found and written back, the version is read
func TestKeepUnknownKeys(t *testing.T) {
	in := []byte(`{"version":2,"Name":"a","future":{"x":1}}`)
	if v, err := FormatOf(in); err != nil || v != 2 {
		t.Fatalf("version %d %v", v, err)
	}
	extra, err := UnknownKeys(in, JSONKeys(reflect.TypeOf(file{})))
	if err != nil || len(extra) != 1 || string(extra["future"]) != `{"x":1}` {
		t.Fatalf("extra %v %v", extra, err)
	}
	b, _ := json.MarshalIndent(file{Name: "a"}, "", "  ")
	out, err := AppendKeys(b, extra)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]json.RawMessage
	if err := json.Unmarshal(out, &back); err != nil || string(back["future"]) != `{"x":1}` {
		t.Fatalf("written back %s %v", out, err)
	}
}
