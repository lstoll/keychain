//go:build darwin

package keychain

import (
	"os/exec"
	"strings"
	"testing"
)

func TestPlatformUUID(t *testing.T) {
	got, err := PlatformUUID()
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("empty UUID")
	}

	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		t.Skipf("ioreg: %v", err)
	}
	want := ""
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		parts := strings.Split(line, `"`)
		if len(parts) >= 4 {
			want = parts[len(parts)-2]
		}
	}
	if want == "" {
		t.Skip("could not parse ioreg IOPlatformUUID")
	}
	if got != want {
		t.Fatalf("PlatformUUID=%q ioreg=%q", got, want)
	}
}
