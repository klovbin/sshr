package ext

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"time"

	"sshr.dev/internal/app"
)

// importMaxBytes and importMaxHosts bound what an importer may hand over
const (
	importMaxBytes = 8 << 20
	importMaxHosts = 5000
)

// ExtHost is the only shape of a host an importer can give sshr, a fixed
// list of fields and no secret among them, anything else it prints is
// dropped with a warning
type ExtHost struct {
	// Key is the identity of the host in the source, a session name, an id,
	// it makes the same host come back as the same one on the next import
	Key  string `json:"key"`
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`
	// KeyFile is the path of a private key file on this machine, never the
	// key itself
	KeyFile  string   `json:"key_file"`
	Jump     string   `json:"jump"`
	Session  string   `json:"session"`
	Tags     []string `json:"tags"`
	Forwards []string `json:"forwards"`
}

var extHostFields = map[string]bool{
	"key": true, "name": true, "host": true, "port": true, "user": true,
	"key_file": true, "jump": true, "session": true, "tags": true, "forwards": true,
}

// ParseImport reads what an importer printed: {"hosts": [...]}, the fields
// outside ExtHost, a password or a key among them, are not read and come
// back as warnings
func ParseImport(data []byte) (hosts []ExtHost, warnings []string, err error) {
	var doc struct {
		Hosts []json.RawMessage `json:"hosts"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("the importer did not print {\"hosts\": [...]}: %v", err)
	}
	if len(doc.Hosts) > importMaxHosts {
		return nil, nil, fmt.Errorf("the importer printed %d hosts, at most %d are taken", len(doc.Hosts), importMaxHosts)
	}
	dropped := map[string]bool{}
	for i, raw := range doc.Hosts {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, nil, fmt.Errorf("host %d: %v", i+1, err)
		}
		for name := range fields {
			if !extHostFields[name] {
				dropped[name] = true
			}
		}
		var h ExtHost
		if err := json.Unmarshal(raw, &h); err != nil {
			return nil, nil, fmt.Errorf("host %d: %v", i+1, err)
		}
		if strings.TrimSpace(h.Key) == "" {
			return nil, nil, fmt.Errorf("host %d has no key, the importer must name each host so a second import finds it again", i+1)
		}
		hosts = append(hosts, h)
	}
	for name := range dropped {
		warnings = append(warnings, fmt.Sprintf("the field %q is not read, sshr takes no secrets and nothing outside the list from an importer", name))
	}
	sort.Strings(warnings)
	return hosts, warnings, nil
}

// HostID is the ID of the host with key from the importer called ext, the
// same pair always gives the same ID, so an import twice finds the host again
// and an importer cannot overwrite a host of another source by guessing an ID
func HostID(extension, key string) string {
	sum := sha256.Sum256([]byte("sshr extension import\x00" + extension + "\x00" + key))
	return hex.EncodeToString(sum[:16])
}

// ToHost turns what an importer gave into a host of sshr, the checks of the
// store run when it is saved
func (e ExtHost) ToHost(extension string) (app.Host, error) {
	h := app.Host{
		ID:        HostID(extension, e.Key),
		Name:      strings.TrimSpace(e.Name),
		Host:      e.Host,
		Port:      e.Port,
		User:      e.User,
		Key:       strings.TrimSpace(e.KeyFile),
		Jump:      e.Jump,
		Session:   e.Session,
		Tags:      app.SplitTags(strings.Join(e.Tags, " ")),
		CreatedAt: time.Now().UTC(),
	}
	for _, spec := range e.Forwards {
		f, err := app.ParseForward(spec)
		if err != nil {
			return app.Host{}, err
		}
		h.Forwards = append(h.Forwards, f)
	}
	return h, nil
}

// Collect starts cmd and returns what it prints on its output, at most
// importMaxBytes, the input and the error output stay with the caller, so the
// importer can ask the user and report problems
func Collect(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(out, importMaxBytes+1))
	if len(data) > importMaxBytes {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, errors.New("the importer printed more than 8 MiB")
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("the importer failed: %v", err)
	}
	if readErr != nil {
		return nil, readErr
	}
	return bytes.TrimSpace(data), nil
}
