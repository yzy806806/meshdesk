package p2p

import (
	"testing"
)

func TestNodeMetaMarshalRoundTrip(t *testing.T) {
	original := &NodeMeta{
		PublicKey:     "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Hostname:      "test-node-1",
		Role:          "relay",
		CapRelay:      true,
		CapExit:       false,
		CapProxyEntry: true,
		Endpoints:     []string{"203.0.113.5:51820", "192.168.1.5:51820"},
		NatType:       "full_cone",
		MeshIP:        "10.10.1.2",
		LoadCPU:       0.3,
		LoadMem:       0.5,
		LoadCircuits:  10,
		LoadBW:        500,
		MaxCircuits:   1024,
		ExitLatency:   map[string]int{"us-west": 8, "eu": 150},
		Version:       "1.0.0",
		Seq:           42,
	}

	data, err := original.MarshalMeta()
	if err != nil {
		t.Fatalf("MarshalMeta failed: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("MarshalMeta returned empty data")
	}

	// Verify size is within memberlist's 512-byte indirect broadcast limit.
	if len(data) > 512 {
		t.Errorf("NodeMeta serialized size %d exceeds 512-byte limit", len(data))
	}

	decoded, err := UnmarshalMeta(data)
	if err != nil {
		t.Fatalf("UnmarshalMeta failed: %v", err)
	}

	// Verify all fields.
	if decoded.PublicKey != original.PublicKey {
		t.Errorf("PublicKey mismatch: got %s, want %s", decoded.PublicKey, original.PublicKey)
	}
	if decoded.Hostname != original.Hostname {
		t.Errorf("Hostname mismatch: got %s, want %s", decoded.Hostname, original.Hostname)
	}
	if decoded.Role != original.Role {
		t.Errorf("Role mismatch: got %s, want %s", decoded.Role, original.Role)
	}
	if decoded.CapRelay != original.CapRelay {
		t.Errorf("CapRelay mismatch: got %v, want %v", decoded.CapRelay, original.CapRelay)
	}
	if decoded.CapExit != original.CapExit {
		t.Errorf("CapExit mismatch: got %v, want %v", decoded.CapExit, original.CapExit)
	}
	if decoded.CapProxyEntry != original.CapProxyEntry {
		t.Errorf("CapProxyEntry mismatch: got %v, want %v", decoded.CapProxyEntry, original.CapProxyEntry)
	}
	if len(decoded.Endpoints) != len(original.Endpoints) {
		t.Errorf("Endpoints length mismatch: got %d, want %d", len(decoded.Endpoints), len(original.Endpoints))
	} else {
		for i, ep := range original.Endpoints {
			if decoded.Endpoints[i] != ep {
				t.Errorf("Endpoint[%d] mismatch: got %s, want %s", i, decoded.Endpoints[i], ep)
			}
		}
	}
	if decoded.NatType != original.NatType {
		t.Errorf("NatType mismatch: got %s, want %s", decoded.NatType, original.NatType)
	}
	if decoded.MeshIP != original.MeshIP {
		t.Errorf("MeshIP mismatch: got %s, want %s", decoded.MeshIP, original.MeshIP)
	}
	if decoded.LoadCPU != original.LoadCPU {
		t.Errorf("LoadCPU mismatch: got %f, want %f", decoded.LoadCPU, original.LoadCPU)
	}
	if decoded.LoadMem != original.LoadMem {
		t.Errorf("LoadMem mismatch: got %f, want %f", decoded.LoadMem, original.LoadMem)
	}
	if decoded.LoadCircuits != original.LoadCircuits {
		t.Errorf("LoadCircuits mismatch: got %d, want %d", decoded.LoadCircuits, original.LoadCircuits)
	}
	if decoded.LoadBW != original.LoadBW {
		t.Errorf("LoadBW mismatch: got %d, want %d", decoded.LoadBW, original.LoadBW)
	}
	if decoded.MaxCircuits != original.MaxCircuits {
		t.Errorf("MaxCircuits mismatch: got %d, want %d", decoded.MaxCircuits, original.MaxCircuits)
	}
	if len(decoded.ExitLatency) != len(original.ExitLatency) {
		t.Errorf("ExitLatency length mismatch: got %d, want %d", len(decoded.ExitLatency), len(original.ExitLatency))
	} else {
		for k, v := range original.ExitLatency {
			if decoded.ExitLatency[k] != v {
				t.Errorf("ExitLatency[%s] mismatch: got %d, want %d", k, decoded.ExitLatency[k], v)
			}
		}
	}
	if decoded.Version != original.Version {
		t.Errorf("Version mismatch: got %s, want %s", decoded.Version, original.Version)
	}
	if decoded.Seq != original.Seq {
		t.Errorf("Seq mismatch: got %d, want %d", decoded.Seq, original.Seq)
	}
}

func TestNodeMetaMinimalSize(t *testing.T) {
	// A minimal NodeMeta should serialize to a small size.
	minimal := &NodeMeta{
		PublicKey: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		MeshIP:    "10.10.0.1",
		Version:   "1.0.0",
	}

	data, err := minimal.MarshalMeta()
	if err != nil {
		t.Fatalf("MarshalMeta failed: %v", err)
	}

	if len(data) > 200 {
		t.Errorf("Minimal NodeMeta size %d is unexpectedly large", len(data))
	}
}

func TestUnmarshalMetaInvalidData(t *testing.T) {
	_, err := UnmarshalMeta([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Error("UnmarshalMeta should fail on invalid data")
	}
}

func TestNodeMetaSeqIncrement(t *testing.T) {
	meta := &NodeMeta{
		PublicKey: "abcdef0123456789",
		Seq:       1,
	}

	delegate := newMeshDelegate(meta)

	// Update metadata — Seq should increment.
	delegate.updateLocalMeta(func(m *NodeMeta) {
		m.LoadCPU = 0.5
		m.Seq++
	})

	updated := delegate.getLocalMeta()
	if updated.Seq != 2 {
		t.Errorf("Seq should be 2 after increment, got %d", updated.Seq)
	}
	if updated.LoadCPU != 0.5 {
		t.Errorf("LoadCPU should be 0.5, got %f", updated.LoadCPU)
	}
}
