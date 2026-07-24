package mesh

import (
	"bytes"
	"testing"
)

// --- registry self-registration tests ---

func TestObfuscatorRegistryHasBuiltInModes(t *testing.T) {
	// After init(), all three built-in modes should be registered.
	expected := []string{"none", "padded", "websocket"}
	for _, name := range expected {
		_, ok := ObfuscatorRegistry.Get(name)
		if !ok {
			t.Errorf("ObfuscatorRegistry.Get(%q) = false, want true", name)
		}
	}
}

func TestObfuscatorRegistryNames(t *testing.T) {
	names := ObfuscatorRegistry.Names()
	if len(names) < 3 {
		t.Errorf("expected at least 3 registered modes, got %d: %v", len(names), names)
	}
}

func TestRegistryLookupUnknownMode(t *testing.T) {
	_, ok := ObfuscatorRegistry.Get("nonexistent")
	if ok {
		t.Error("Get should return false for unregistered mode")
	}
}

func TestRegistryMustGetPanicsOnUnknown(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustGet should panic for unregistered mode")
		}
	}()
	ObfuscatorRegistry.MustGet("nonexistent")
}

// --- factory uses registry tests ---

func TestNewObfuscatorUsesRegistry(t *testing.T) {
	// All built-in modes should produce working obfuscators via the registry.
	modes := []ObfuscationMode{
		ObfuscationNone,
		ObfuscationPadded,
		ObfuscationWebSocket,
	}
	for _, m := range modes {
		o := NewObfuscator(m)
		if o == nil {
			t.Errorf("NewObfuscator(%v) returned nil", m)
		}
		if o.Mode() != m {
			t.Errorf("NewObfuscator(%v).Mode() = %v, want %v", m, o.Mode(), m)
		}
	}
}

func TestNewObfuscatorUnregisteredModeFallsBackToPadded(t *testing.T) {
	// An unregistered ObfuscationMode value whose String() returns "padded"
	// (the default for unknown values) should resolve to padded mode.
	o := NewObfuscator(ObfuscationMode(999))
	if o == nil {
		t.Fatal("NewObfuscator returned nil for unregistered mode")
	}
	if o.Mode() != ObfuscationPadded {
		t.Errorf("expected fallback to padded, got %v", o.Mode())
	}
}

// --- new mode registration test (proves extensibility without core changes) ---

// testPassthroughObfuscator is a trivial obfuscator used to prove that a
// new mode can be registered and used without modifying any core code.
type testPassthroughObfuscator struct{}

func (testPassthroughObfuscator) WrapOutbound(packet []byte) ([]byte, error) {
	return packet, nil
}
func (testPassthroughObfuscator) UnwrapInbound(data []byte) ([]byte, error) {
	return data, nil
}
func (testPassthroughObfuscator) Mode() ObfuscationMode {
	return ObfuscationMode(100)
}

// testModeName is the registry name for the test obfuscator.
const testModeName = "test-passthrough"

func TestRegisterAndUseNewObfuscationMode(t *testing.T) {
	// Register a new obfuscation mode via the registry — no core code modified.
	RegisterObfuscator(testModeName, func(cfg ObfuscationConfig) Obfuscator {
		return testPassthroughObfuscator{}
	})

	// Look it up through the registry.
	factory, ok := ObfuscatorRegistry.Get(testModeName)
	if !ok {
		t.Fatal("registered mode not found in registry")
	}

	// Create an obfuscator instance from the factory.
	o := factory(ObfuscationConfig{})
	if o == nil {
		t.Fatal("factory returned nil obfuscator")
	}

	// Verify it works — round-trip should be identity.
	original := []byte("hello wireguard")
	out, err := o.WrapOutbound(original)
	if err != nil {
		t.Fatalf("WrapOutbound error: %v", err)
	}
	if !bytes.Equal(out, original) {
		t.Error("passthrough obfuscator should not modify packets")
	}
	back, err := o.UnwrapInbound(out)
	if err != nil {
		t.Fatalf("UnwrapInbound error: %v", err)
	}
	if !bytes.Equal(back, original) {
		t.Error("round-trip should preserve data")
	}

	// Verify the mode is reported correctly.
	if o.Mode() != ObfuscationMode(100) {
		t.Errorf("Mode() = %v, want %v", o.Mode(), ObfuscationMode(100))
	}
}

// --- duplicate registration panics test ---

func TestRegisterObfuscatorDuplicatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("RegisterObfuscator should panic on duplicate registration")
		}
	}()
	RegisterObfuscator("padded", func(cfg ObfuscationConfig) Obfuscator {
		return noneObfuscator{} // intentionally wrong, just to test panic
	})
}
