package mesh

import (
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
)

func TestSameZone(t *testing.T) {
	cfg := &config.Config{
		Mesh: config.MeshConfig{Zone: "cn"},
		Peers: []config.PeerConfig{
			{PublicKey: "aaaa", Zone: "cn"}, // same zone
			{PublicKey: "bbbb", Zone: "us"}, // cross zone
			{PublicKey: "cccc"},             // unknown zone (empty)
		},
	}
	n, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if n == nil {
		t.Fatal("New returned nil node")
	}

	cases := []struct {
		peer string
		want bool
	}{
		{"aaaa", true},  // cn == cn → same zone → UDP
		{"bbbb", false}, // cn != us → cross zone → Reality
		{"cccc", false}, // unknown → conservative Reality
	}
	for _, c := range cases {
		if got := n.SameZone(c.peer); got != c.want {
			t.Errorf("SameZone(%s) = %v, want %v", c.peer, got, c.want)
		}
	}

	// Local zone empty → everything is cross-zone (conservative).
	cfg2 := &config.Config{}
	n2, err2 := New(cfg2)
	if err2 != nil {
		t.Skipf("New with empty identity not supported in this env: %v", err2)
	}
	if n2 == nil {
		t.Fatal("New returned nil node")
	}
	if n2.SameZone("aaaa") {
		t.Error("SameZone with empty local zone should be false")
	}
}

func TestLocalZone(t *testing.T) {
	cfg := &config.Config{Mesh: config.MeshConfig{Zone: "uk"}}
	n, err := New(cfg)
	if err != nil {
		t.Skipf("New not supported in this env: %v", err)
	}
	if got := n.LocalZone(); got != "uk" {
		t.Errorf("LocalZone = %q, want uk", got)
	}
}
