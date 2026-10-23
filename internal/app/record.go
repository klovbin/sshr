package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"sshr.dev/internal/record"
)

// hostFormat is the format of host files this build writes, a file
// without "version" is format 1, a breaking change of a known field
// raises it and adds a migration on load, a new optional field does not
const hostFormat = 1

// newerHostError says that h is of a newer format and stays as it is
func newerHostError(h *Host) error {
	return fmt.Errorf("%w: %s was saved by a newer sshr (format %d), this one reads it but does not change it, update sshr to edit it", ErrNewerFormat, h.Name, h.format)
}

// ErrNewerFormat means a file was written by a newer sshr in a format this
// build reads but must not write, it would erase what it does not know
var ErrNewerFormat = record.ErrNewerFormat

// hostKeys are the JSON names of the fields of Host in lower case,
// encoding/json matches keys without regard to case, so "Key_Sealed" is
// the key_sealed field and not a field of a newer sshr
var hostKeys = record.JSONKeys(reflect.TypeOf(Host{}))

// decodeHost reads a host file, the keys this build does not know (a
// field a newer sshr wrote) are kept in h.extra and written back on save
func decodeHost(b []byte) (Host, error) {
	var h Host
	// the format first: a newer sshr may have changed the type of a known
	// field, such a host is read with what still decodes, read only,
	// instead of showing as a broken file
	format, err := record.FormatOf(b)
	if err != nil {
		return Host{}, err
	}
	if err := json.Unmarshal(b, &h); err != nil && format <= hostFormat {
		return Host{}, err
	}
	h.format = format
	if h.extra, err = record.UnknownKeys(b, hostKeys); err != nil {
		return Host{}, err
	}
	return h, nil
}

// encodeHost writes a host file, the fields of Host as before, then the
// kept keys of a newer sshr in name order, a host without them gives the
// same bytes as a plain marshal
func encodeHost(h *Host) ([]byte, error) {
	if h.format > hostFormat {
		return nil, newerHostError(h)
	}
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return nil, err
	}
	return record.AppendKeys(b, h.extra)
}

// localPrefix starts the keys a newer sshr keeps on its own machine, they
// never travel in sync, a sealed value bound to this machine would break
// anywhere else
const localPrefix = "local_"

// HostPayloadJSON is h as it travels in sync, the fields of Host and the
// kept keys of a newer sshr except the local ones, a host without such
// keys gives the bytes of a plain marshal, so the local change check of
// the sync sees no change
func HostPayloadJSON(h Host) ([]byte, error) {
	// a host of a newer format may have fields this build did not decode,
	// it is not sent from here, the devices that know the format keep the
	// version its own device wrote
	if h.format > hostFormat {
		return nil, fmt.Errorf("%w: %s was saved by a newer sshr (format %d), this one does not sync it, update sshr here", ErrNewerFormat, h.Name, h.format)
	}
	b, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	var keys []string
	for k := range h.extra {
		if !strings.HasPrefix(k, localPrefix) {
			keys = append(keys, k)
		}
	}
	extra := h.extra
	if len(keys) == 0 {
		return b, nil
	}
	slices.Sort(keys)
	var out bytes.Buffer
	out.Write(b[:bytes.LastIndexByte(b, '}')])
	for _, k := range keys {
		name, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		var v bytes.Buffer
		if err := json.Compact(&v, extra[k]); err != nil {
			return nil, err
		}
		out.WriteByte(',')
		out.Write(name)
		out.WriteByte(':')
		out.Write(v.Bytes())
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// HostFromPayloadJSON reads a host that came in sync, with the keys of a
// newer sshr it carried, a local key in it is dropped
func HostFromPayloadJSON(b []byte) (Host, error) {
	h, err := decodeHost(b)
	if err != nil {
		return Host{}, err
	}
	for k := range h.extra {
		if strings.HasPrefix(k, localPrefix) {
			delete(h.extra, k)
		}
	}
	return h, nil
}

// mergeExtra is what a host from another device keeps of the unknown keys:
// what it carried, and the local keys of the host here, a payload with no
// unknown keys at all (from an older sshr) keeps every key of the host
// here, it could not have carried them
func mergeExtra(in, cur map[string]json.RawMessage) map[string]json.RawMessage {
	if len(in) == 0 {
		return maps.Clone(cur)
	}
	out := maps.Clone(in)
	for k, v := range cur {
		if strings.HasPrefix(k, localPrefix) {
			out[k] = v
		}
	}
	return out
}

// RecordExtra reads the keys of the JSON object b that are no field of the
// struct type typ and its "version", for a file of another package that
// keeps what a newer sshr wrote
func RecordExtra(b []byte, typ reflect.Type) (map[string]json.RawMessage, int, error) {
	format, err := record.FormatOf(b)
	if err != nil {
		return nil, 0, err
	}
	extra, err := record.UnknownKeys(b, record.JSONKeys(typ))
	return extra, format, err
}

// AppendRecordKeys writes the kept keys extra into the JSON object b,
// written by json.MarshalIndent with two spaces
func AppendRecordKeys(b []byte, extra map[string]json.RawMessage) ([]byte, error) {
	return record.AppendKeys(b, extra)
}
