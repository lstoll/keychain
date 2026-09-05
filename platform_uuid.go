//go:build darwin

package keychain

import (
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
)

// PlatformUUID returns the Mac hardware UUID (IOPlatformUUID). It is stable
// across hostname changes and reboots; it is not an OS-install kern.uuid.
func PlatformUUID() (string, error) {
	if err := initIOKit(); err != nil {
		return "", err
	}
	return iokit.uuid, iokit.err
}

var (
	iokitOnce sync.Once
	iokit     struct {
		uuid string
		err  error
	}
)

func initIOKit() error {
	iokitOnce.Do(func() {
		iokit.uuid, iokit.err = readIOPlatformUUID()
	})
	return iokit.err
}

func readIOPlatformUUID() (string, error) {
	cf, err := getCoreFoundation()
	if err != nil {
		return "", err
	}
	handle, err := dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return "", err
	}

	ioMainPort, err := registerFunc[func(bootstrap uint32, main *uint32) int32](handle, "IOMainPort")
	if err != nil {
		return "", err
	}
	ioServiceMatching, err := registerFunc[func(name *byte) _CFDictionaryRef](handle, "IOServiceMatching")
	if err != nil {
		return "", err
	}
	ioServiceGetMatchingService, err := registerFunc[func(mainPort uint32, matching _CFDictionaryRef) uint32](handle, "IOServiceGetMatchingService")
	if err != nil {
		return "", err
	}
	ioRegistryEntryCreateCFProperty, err := registerFunc[func(entry uint32, key _CFStringRef, allocator _CFAllocatorRef, options uint32) _CFTypeRef](handle, "IORegistryEntryCreateCFProperty")
	if err != nil {
		return "", err
	}
	ioObjectRelease, err := registerFunc[func(object uint32) int32](handle, "IOObjectRelease")
	if err != nil {
		return "", err
	}

	var mainPort uint32
	if kr := ioMainPort(0, &mainPort); kr != 0 {
		return "", fmt.Errorf("IOMainPort: 0x%x", kr)
	}

	name := append([]byte("IOPlatformExpertDevice"), 0)
	matching := ioServiceMatching(&name[0])
	if matching == 0 {
		return "", fmt.Errorf("IOServiceMatching IOPlatformExpertDevice failed")
	}
	service := ioServiceGetMatchingService(mainPort, matching)
	if service == 0 {
		return "", fmt.Errorf("IOPlatformExpertDevice not found")
	}
	defer ioObjectRelease(service)

	key := cf.StringToCFString("IOPlatformUUID")
	defer cf.Release(_CFTypeRef(key))
	ref := ioRegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0)
	if ref == 0 {
		return "", fmt.Errorf("IOPlatformUUID missing")
	}
	defer cf.Release(ref)
	uuid := cf.CFStringToString(_CFStringRef(ref))
	if uuid == "" {
		return "", fmt.Errorf("empty IOPlatformUUID")
	}
	return uuid, nil
}
