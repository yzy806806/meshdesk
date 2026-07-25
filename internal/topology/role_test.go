package topology

import "testing"

func TestDeriveRole_AllFlagsFalse(t *testing.T) {
	role := DeriveRole(false, false, false, false, false)
	if role != "dashboard" {
		t.Errorf("Expected 'dashboard' for all-false, got %q", role)
	}
}

func TestDeriveRole_EntryOnly(t *testing.T) {
	role := DeriveRole(true, false, false, false, false)
	if role != "entry" {
		t.Errorf("Expected 'entry', got %q", role)
	}
}

func TestDeriveRole_RelayOnly(t *testing.T) {
	role := DeriveRole(false, true, false, false, false)
	if role != "relay" {
		t.Errorf("Expected 'relay', got %q", role)
	}
}

func TestDeriveRole_ExitOnly(t *testing.T) {
	role := DeriveRole(false, false, true, false, false)
	if role != "exit" {
		t.Errorf("Expected 'exit', got %q", role)
	}
}

func TestDeriveRole_ExitAllowAll(t *testing.T) {
	role := DeriveRole(false, false, false, true, false)
	if role != "exit" {
		t.Errorf("Expected 'exit' for allow_all, got %q", role)
	}
}

func TestDeriveRole_DashboardOnly(t *testing.T) {
	role := DeriveRole(false, false, false, false, true)
	if role != "dashboard" {
		t.Errorf("Expected 'dashboard', got %q", role)
	}
}

func TestDeriveRole_EntryRelayExitDashboard(t *testing.T) {
	role := DeriveRole(true, true, true, false, true)
	expected := "entry+relay+exit+dashboard"
	if role != expected {
		t.Errorf("Expected %q, got %q", expected, role)
	}
}

func TestDeriveRole_EntryRelay(t *testing.T) {
	role := DeriveRole(true, true, false, false, false)
	if role != "entry+relay" {
		t.Errorf("Expected 'entry+relay', got %q", role)
	}
}

func TestDeriveRole_RelayExit(t *testing.T) {
	role := DeriveRole(false, true, true, false, false)
	if role != "relay+exit" {
		t.Errorf("Expected 'relay+exit', got %q", role)
	}
}

func TestDeriveRole_EntryExitDashboard(t *testing.T) {
	role := DeriveRole(true, false, true, false, true)
	expected := "entry+exit+dashboard"
	if role != expected {
		t.Errorf("Expected %q, got %q", expected, role)
	}
}

func TestJoinRoles_Empty(t *testing.T) {
	if joinRoles(nil) != "" {
		t.Error("Expected empty string for nil input")
	}
	if joinRoles([]string{}) != "" {
		t.Error("Expected empty string for empty slice")
	}
}

func TestJoinRoles_Single(t *testing.T) {
	if joinRoles([]string{"entry"}) != "entry" {
		t.Error("Expected 'entry' for single role")
	}
}

func TestJoinRoles_Multiple(t *testing.T) {
	result := joinRoles([]string{"entry", "relay", "exit"})
	if result != "entry+relay+exit" {
		t.Errorf("Expected 'entry+relay+exit', got %q", result)
	}
}
