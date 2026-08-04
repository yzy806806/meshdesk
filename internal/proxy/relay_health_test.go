package proxy

import (
	"testing"
	"time"
)

func TestRelayHealthTracker_InitiallyHealthy(t *testing.T) {
	h := NewRelayHealthTracker()
	if !h.IsHealthy("relayA") {
		t.Error("unknown relay should be considered healthy")
	}
	if h.IsUnhealthy("relayA") {
		t.Error("unknown relay should not be unhealthy")
	}
	if h.IsDegraded("relayA") {
		t.Error("unknown relay should not be degraded")
	}
}

func TestRelayHealthTracker_DegradedAfterOneFailure(t *testing.T) {
	h := NewRelayHealthTracker()
	h.RecordFailure("relayA")

	if !h.IsHealthy("relayA") {
		t.Error("relay should still be healthy (degraded is still eligible)")
	}
	if !h.IsDegraded("relayA") {
		t.Error("relay should be degraded after 1 failure")
	}
	if h.IsUnhealthy("relayA") {
		t.Error("relay should not be unhealthy after only 1 failure")
	}

	penalty := h.HealthPenalty("relayA")
	if penalty != 1.5 {
		t.Errorf("degraded penalty = %v, want 1.5", penalty)
	}
}

func TestRelayHealthTracker_UnhealthyAfterThreeFailures(t *testing.T) {
	h := NewRelayHealthTracker()
	h.RecordFailure("relayA")
	h.RecordFailure("relayA")
	h.RecordFailure("relayA")

	if h.IsHealthy("relayA") {
		t.Error("relay should not be healthy after 3 failures")
	}
	if !h.IsUnhealthy("relayA") {
		t.Error("relay should be unhealthy after 3 failures")
	}

	penalty := h.HealthPenalty("relayA")
	if penalty < 100 {
		t.Errorf("unhealthy penalty = %v, want very large", penalty)
	}
}

func TestRelayHealthTracker_RecoveryOnSuccess(t *testing.T) {
	h := NewRelayHealthTracker()
	h.RecordFailure("relayA")
	h.RecordFailure("relayA")
	h.RecordFailure("relayA")

	if !h.IsUnhealthy("relayA") {
		t.Fatal("relay should be unhealthy")
	}

	// Record success → should recover to healthy.
	h.RecordSuccess("relayA", 10*time.Millisecond)

	if !h.IsHealthy("relayA") {
		t.Error("relay should be healthy after success")
	}
	if h.IsDegraded("relayA") {
		t.Error("relay should not be degraded after success")
	}

	penalty := h.HealthPenalty("relayA")
	if penalty != 1.0 {
		t.Errorf("healthy penalty = %v, want 1.0", penalty)
	}
}

func TestRelayHealthTracker_CanRetry(t *testing.T) {
	h := NewRelayHealthTracker()
	// Use a short recovery delay for testing.
	h.healthRecoveryDelay = 50 * time.Millisecond

	h.RecordFailure("relayA")
	h.RecordFailure("relayA")
	h.RecordFailure("relayA")

	if !h.IsUnhealthy("relayA") {
		t.Fatal("relay should be unhealthy")
	}

	// Immediately after becoming unhealthy, should not be retryable.
	if h.CanRetry("relayA") {
		t.Error("relay should not be retryable immediately after becoming unhealthy")
	}

	// After the recovery delay, should be retryable.
	time.Sleep(60 * time.Millisecond)
	if !h.CanRetry("relayA") {
		t.Error("relay should be retryable after recovery delay")
	}
}

func TestRelayHealthTracker_UnhealthyRelays(t *testing.T) {
	h := NewRelayHealthTracker()
	h.RecordFailure("relayA")
	h.RecordFailure("relayA")
	h.RecordFailure("relayA")
	h.RecordFailure("relayB")
	h.RecordFailure("relayB")
	h.RecordFailure("relayB")

	unhealthy := h.UnhealthyRelays()
	if len(unhealthy) != 2 {
		t.Errorf("expected 2 unhealthy relays, got %d", len(unhealthy))
	}
}

func TestRelayHealthTracker_Reset(t *testing.T) {
	h := NewRelayHealthTracker()
	h.RecordFailure("relayA")
	h.RecordFailure("relayA")
	h.RecordFailure("relayA")

	h.Reset("relayA")

	if !h.IsHealthy("relayA") {
		t.Error("relay should be healthy after reset")
	}
}

func TestRelayHealthTracker_ResetAll(t *testing.T) {
	h := NewRelayHealthTracker()
	h.RecordFailure("relayA")
	h.RecordFailure("relayA")
	h.RecordFailure("relayA")
	h.RecordFailure("relayB")
	h.RecordFailure("relayB")
	h.RecordFailure("relayB")

	h.ResetAll()

	if !h.IsHealthy("relayA") {
		t.Error("relayA should be healthy after reset all")
	}
	if !h.IsHealthy("relayB") {
		t.Error("relayB should be healthy after reset all")
	}
}
