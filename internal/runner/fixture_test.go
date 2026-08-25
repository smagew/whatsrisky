package runner

import (
	"os/exec"
	"testing"

	"github.com/smagew/whatsrisky/internal/fixture"
)

func testConfig(t *testing.T, root string) Config {
	t.Helper()
	return Config{
		Target:          root,
		WorkDir:         t.TempDir(),
		SemgrepConfigs:  []string{"p/security-audit"},
		SemgrepTimeout:  timeout,
		TrivyScanners:   "vuln,misconfig",
		TrivyTimeout:    timeout,
		GitleaksMode:    "auto",
		GitleaksTimeout: timeout,
	}
}

// requireBinary skips a test that needs a real scanner: under -short always, and
// otherwise when the binary is not installed. `make test` therefore runs on a
// machine with nothing installed, and `make test-all` exercises the real thing.
func requireBinary(t *testing.T, binary string) {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: skipping the tests that need " + binary)
	}
	if _, err := exec.LookPath(binary); err != nil {
		t.Skipf("%s is not installed", binary)
	}
}

// vulnApp builds the shared vulnerable fixture.
func vulnApp(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required to build the fixture")
	}
	root := t.TempDir()
	if err := fixture.Write(root); err != nil {
		t.Fatalf("building the fixture: %v", err)
	}
	return root
}
