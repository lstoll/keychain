//go:build darwin

package keychain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCacheValidation(t *testing.T) {
	if _, err := NewCache(CacheOptions{}); err == nil {
		t.Fatal("accepted empty service")
	}
	if _, err := NewCache(CacheOptions{Service: "x", Identity: "id"}); err != nil {
		t.Fatal(err)
	}
}

func newTestCache(t *testing.T, service, identity string) *Cache {
	t.Helper()
	c, err := NewCache(CacheOptions{Service: service, Identity: identity})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Clear(); err != nil {
			t.Error(err)
		}
	})
	return c
}

func testCacheService() string {
	return fmt.Sprintf("lds.li/keychain/test/cache/%d", time.Now().UnixNano())
}

func TestCacheE2E(t *testing.T) {
	requireIntegration(t)
	svc := testCacheService()
	c := newTestCache(t, svc, "one")

	if v, ok, err := c.Get("missing"); err != nil || ok || v != nil {
		t.Fatalf("missing: %q %v %v", v, ok, err)
	}
	if err := c.Put("k", []byte("v1"), ""); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := c.Get("k"); err != nil || !ok || string(v) != "v1" {
		t.Fatalf("get: %q %v %v", v, ok, err)
	}
	if err := c.Put("k", []byte("v2"), ""); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := c.Get("k"); err != nil || !ok || string(v) != "v2" {
		t.Fatalf("overwrite: %q %v %v", v, ok, err)
	}
	if err := c.Put("l", []byte("x"), "My Label"); err != nil {
		t.Fatal(err)
	}
	list, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{}
	for _, e := range list {
		labels[e.Key] = e.Label
	}
	if len(list) != 2 || labels["k"] != "k" || labels["l"] != "My Label" {
		t.Fatalf("list: %+v", list)
	}

	if err := c.Delete("k"); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete("k"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if _, ok, err := c.Get("k"); err != nil || ok {
		t.Fatalf("after delete: %v %v", ok, err)
	}
}

func TestCacheIdentityMismatch(t *testing.T) {
	requireIntegration(t)
	svc := testCacheService()
	a := newTestCache(t, svc, "one")
	b := newTestCache(t, svc, "other")

	if err := a.Put("k", []byte("secret"), ""); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := b.Get("k"); err != nil || ok || v != nil {
		t.Fatalf("mismatch get: %q %v %v", v, ok, err)
	}
	if _, ok, err := a.Get("k"); err != nil || ok {
		t.Fatalf("entry should have been removed: %v %v", ok, err)
	}
	if list, err := a.List(); err != nil || len(list) != 0 {
		t.Fatalf("list after removal: %v %v", list, err)
	}
}

func TestCacheListFiltersAndClear(t *testing.T) {
	requireIntegration(t)
	svc := testCacheService()
	a := newTestCache(t, svc, "one")
	b := newTestCache(t, svc, "other")

	if err := a.Put("a", []byte("1"), ""); err != nil {
		t.Fatal(err)
	}
	if err := b.Put("b", []byte("2"), ""); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		c    *Cache
		want string
	}{{a, "a"}, {b, "b"}} {
		list, err := tc.c.List()
		if err != nil || len(list) != 1 || list[0].Key != tc.want {
			t.Fatalf("list want %q: %+v %v", tc.want, list, err)
		}
	}
	if err := a.Clear(); err != nil {
		t.Fatal(err)
	}
	all, err := a.store.List()
	if err != nil || len(all) != 0 {
		t.Fatalf("after clear: %+v %v", all, err)
	}
	if list, err := b.List(); err != nil || list == nil || len(list) != 0 {
		t.Fatalf("empty list should be non-nil empty: %#v %v", list, err)
	}
}

// TestCacheRefPinsItem checks that reads and deletes through a looked-up item
// never reach an item that replaced it.
func TestCacheRefPinsItem(t *testing.T) {
	requireIntegration(t)
	svc := testCacheService()
	a := newTestCache(t, svc, "one")
	b := newTestCache(t, svc, "other")
	if err := a.Put("k", []byte("old"), ""); err != nil {
		t.Fatal(err)
	}
	e, err := a.find("k")
	if err != nil || e == nil {
		t.Fatalf("find: %v %v", e, err)
	}
	defer a.store.cf.Release(e.ref)
	if err := b.Put("k", []byte("new"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.readRef(e.ref); !errors.Is(err, errReplaced) {
		t.Fatalf("readRef after replace: %v, want errReplaced", err)
	}
	if err := a.deleteRef(e.ref); !errors.Is(err, errReplaced) {
		t.Fatalf("deleteRef after replace: %v, want errReplaced", err)
	}
	if v, ok, err := b.Get("k"); err != nil || !ok || string(v) != "new" {
		t.Fatalf("replacement: %q %v %v", v, ok, err)
	}
}

// TestCacheCrossBinary checks that a differently built binary sees a miss
// instead of a keychain prompt. On arm64 the ad-hoc signatures differ per
// build; on amd64 unsigned binaries fall back to file hashes, which also differ.
func TestCacheCrossBinary(t *testing.T) {
	requireIntegration(t)
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH")
	}
	// SecItemDelete only lets a rebuilt binary delete the previous build's
	// items when the executable file name matches; Cache also handles a
	// differently named binary.
	dir := t.TempDir()
	build := func(variant, name string) string {
		out := filepath.Join(dir, variant, name)
		cmd := exec.Command(goBin, "build", "-ldflags=-X main.build="+variant, "-o", out, "./testdata/cachehelper")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building %s: %v\n%s", out, err, b)
		}
		return out
	}
	binA, binB := build("a", "cachehelper"), build("b", "cachehelper")
	binOther := build("c", "otherhelper")

	run := func(bin string, args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var stdout, stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("%s %v timed out: likely a keychain access prompt", bin, args)
		}
		if err != nil {
			return "", fmt.Errorf("%s %v: %w: %s", bin, args, err, stderr.String())
		}
		return strings.TrimSpace(stdout.String()), nil
	}
	mustRun := func(bin string, args ...string) string {
		t.Helper()
		out, err := run(bin, args...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	svc := testCacheService()
	t.Cleanup(func() {
		if _, err := run(binB, svc, "clear"); err != nil {
			t.Error(err)
		}
	})

	mustRun(binA, svc, "put", "k", "secret")
	if got := mustRun(binA, svc, "get", "k"); got != "hit secret" {
		t.Fatalf("binary A get: %q", got)
	}
	if got := mustRun(binB, svc, "get", "k"); got != "miss" {
		t.Fatalf("rebuilt binary get: %q, want miss", got)
	}
	mustRun(binB, svc, "put", "k", "renewed")
	if got := mustRun(binB, svc, "get", "k"); got != "hit renewed" {
		t.Fatalf("rebuilt binary get after put: %q", got)
	}

	// A differently named binary also replaces the entry, although plain
	// SecItemDelete refuses that.
	if got := mustRun(binOther, svc, "get", "k"); got != "miss" {
		t.Fatalf("differently named binary get: %q, want miss", got)
	}
	mustRun(binOther, svc, "put", "k", "other")
	if got := mustRun(binOther, svc, "get", "k"); got != "hit other" {
		t.Fatalf("differently named binary get after put: %q", got)
	}

	// Clear empties the whole service, including items Cache did not write
	// and that another executable created.
	plain, err := NewPasswordStore(PasswordStoreOptions{Service: svc})
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Create("plain", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	mustRun(binOther, svc, "clear")
	if all, err := plain.List(); err != nil || len(all) != 0 {
		t.Fatalf("after clear: %+v %v", all, err)
	}
}
