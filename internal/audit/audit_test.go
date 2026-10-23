package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func readLines(t *testing.T, path string) []Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("a broken line %q: %v", sc.Text(), err)
		}
		out = append(out, r)
	}
	return out
}

// TestHelperWriter is not a test, TestTwoProcesses runs the test binary
// again with AUDIT_HELPER_DIR set to write as a second process
func TestHelperWriter(t *testing.T) {
	dir := os.Getenv("AUDIT_HELPER_DIR")
	if dir == "" {
		return
	}
	l, err := Open(dir, 0, false)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	n, _ := strconv.Atoi(os.Getenv("AUDIT_HELPER_N"))
	writeMany(l, n)
	os.Exit(0)
}

func writeMany(l *Log, n int) {
	var wg sync.WaitGroup
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n; i++ {
				end, err := l.Begin(Record{Surface: "mcp", Action: "run_command", HostName: "web", Command: "uptime"})
				if err != nil {
					panic(err)
				}
				end(0, 0, nil)
			}
		}()
	}
	wg.Wait()
}

// two processes with several goroutines each never break or lose a line
// (#101)
func TestTwoProcesses(t *testing.T) {
	dir := t.TempDir()
	const n = 40
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperWriter$")
	cmd.Env = append(os.Environ(), "AUDIT_HELPER_DIR="+dir, "AUDIT_HELPER_N="+strconv.Itoa(n))
	done := make(chan error, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		if err != nil {
			err = fmt.Errorf("%v %s", err, out)
		}
		done <- err
	}()
	l, err := Open(dir, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	writeMany(l, n)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got, want := len(readLines(t, filepath.Join(dir, FileName))), 2*5*n*2; got != want {
		t.Fatalf("%d lines, want %d", got, want)
	}
}

// a full log moves to .1 and only two files stay (#101)
func TestRotation(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	l.maxBytes = 2 << 10
	for i := 0; i < 200; i++ {
		end, err := l.Begin(Record{Surface: "rest", Action: "upload", HostName: "web"})
		if err != nil {
			t.Fatal(err)
		}
		end(0, 10, nil)
	}
	files, _ := filepath.Glob(filepath.Join(dir, FileName+"*"))
	if len(files) != 3 { // the log, .1 and the lock file
		t.Fatalf("files %v", files)
	}
	for _, f := range []string{FileName, FileName + ".1"} {
		if fi, err := os.Stat(filepath.Join(dir, f)); err != nil || fi.Size() > 3<<10 {
			t.Errorf("%s: %v %v", f, fi, err)
		}
	}
}

// a command is kept as length, program and keyed hash unless the whole
// text is asked for, control characters cannot split a line (#101)
func TestCommandNotKept(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, 0, false)
	cmd := "mysql -pSECRET\r\x1b[2K -e 'select 1'\nfake line"
	end, err := l.Begin(Record{Surface: "mcp", Action: "run_command", HostName: "web\nx", Command: cmd})
	if err != nil {
		t.Fatal(err)
	}
	end(1, 0, fmt.Errorf("exit 1"))
	b, _ := os.ReadFile(filepath.Join(dir, FileName))
	if strings.Contains(string(b), "SECRET") || strings.Count(string(b), "\n") != 2 {
		t.Fatalf("log: %s", b)
	}
	recs := readLines(t, filepath.Join(dir, FileName))
	if recs[0].CmdProg != "mysql" || recs[0].CmdLen != len(cmd) || len(recs[0].CmdHMAC) != 32 || recs[1].Req != recs[0].Req || *recs[1].Exit != 1 {
		t.Fatalf("%+v", recs)
	}
	full, _ := Open(t.TempDir(), 0, true)
	end, _ = full.Begin(Record{Action: "run_command", Command: strings.Repeat("x", 10000)})
	end(0, 0, nil)
	if fi, _ := os.Stat(filepath.Join(full.path)); fi.Size() > 2*recordMax {
		t.Fatalf("a long command made a %d byte log", fi.Size())
	}
}

// a log that cannot be written refuses the start, a nil log writes nothing
// (#101)
func TestStartFailsClosed(t *testing.T) {
	var none *Log
	if _, err := none.Begin(Record{Action: "run_command"}); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("directory modes do not stop writes here")
	}
	dir := t.TempDir()
	l, err := Open(dir, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o500)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if _, err := l.Begin(Record{Action: "run_command"}); err == nil {
		t.Fatal("the start went through a log that cannot be written")
	}
}
