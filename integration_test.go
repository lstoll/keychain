//go:build darwin

package keychain

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// requireIntegration skips unless KEYCHAIN_INTEGRATION=1. Integration tests
// touch this machine's real keychain or Secure Enclave without needing a human.
func requireIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("KEYCHAIN_INTEGRATION") != "1" {
		t.Skip("KEYCHAIN_INTEGRATION is not set to 1")
	}
}

// requireInteractive skips unless KEYCHAIN_INTERACTIVE=1. Interactive tests
// show prompts that need a human.
func requireInteractive(t *testing.T) {
	t.Helper()
	if os.Getenv("KEYCHAIN_INTERACTIVE") != "1" {
		t.Skip("KEYCHAIN_INTERACTIVE is not set to 1")
	}
}

var (
	seProbeOnce sync.Once
	seProbeErr  error
)

// requireSecureEnclave requires integration tests and a usable Secure Enclave.
// A probe failure is fatal where a Secure Enclave is expected (Apple silicon,
// not a VM) and a skip otherwise.
func requireSecureEnclave(t *testing.T) {
	t.Helper()
	requireIntegration(t)
	seProbeOnce.Do(func() {
		_, seProbeErr = CreateSecureEnclaveKey(SecureEnclaveKeyOptions{})
	})
	if seProbeErr == nil {
		return
	}
	if secureEnclaveExpected() {
		t.Fatalf("Secure Enclave expected but unavailable: %v", seProbeErr)
	}
	t.Skipf("Secure Enclave unavailable: %v", seProbeErr)
}

func secureEnclaveExpected() bool {
	return runtime.GOARCH == "arm64" && !isVM()
}

func isVM() bool {
	out, err := exec.Command("sysctl", "-n", "kern.hv_vmm_present").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "1"
}
