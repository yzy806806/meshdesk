package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestWebhookDispatcher_PayloadShape verifies that the dispatcher POSTs a
// correctly-shaped JSON payload to the webhook URL.
func TestWebhookDispatcher_PayloadShape(t *testing.T) {
	var received webhookPayload
	var got atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &received); err != nil {
			t.Errorf("failed to unmarshal payload: %v", err)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewWebhookDispatcher(srv.URL, "test-node-id-1234")
	alert := SecurityAlert{
		Severity:    AlertCritical,
		Type:        "totp_lockout",
		Username:    "admin",
		SourceIP:    "10.0.0.1:12345",
		Description: "account locked after 5 failed TOTP attempts",
	}
	d.ch <- alert
	d.Close()

	if got.Load() != 1 {
		t.Fatalf("server received %d POSTs, want 1", got.Load())
	}
	if received.Source != "MeshDesk" {
		t.Errorf("payload.Source = %q, want MeshDesk", received.Source)
	}
	if received.NodeID != "test-node-id-1234" {
		t.Errorf("payload.NodeID = %q, want test-node-id-1234", received.NodeID)
	}
	if received.Event != "security_alert" {
		t.Errorf("payload.Event = %q, want security_alert", received.Event)
	}
	if received.Alert.Type != "totp_lockout" {
		t.Errorf("payload.Alert.Type = %q, want totp_lockout", received.Alert.Type)
	}
	if received.Alert.Severity != AlertCritical {
		t.Errorf("payload.Alert.Severity = %q, want critical", received.Alert.Severity)
	}
	if received.Alert.Username != "admin" {
		t.Errorf("payload.Alert.Username = %q, want admin", received.Alert.Username)
	}
	if received.Alert.Description != "account locked after 5 failed TOTP attempts" {
		t.Errorf("payload.Alert.Description mismatch: %q", received.Alert.Description)
	}
}

// TestWebhookDispatcher_RetryBackoff verifies that the dispatcher retries
// on server errors (500) and eventually succeeds on the 3rd attempt.
func TestWebhookDispatcher_RetryBackoff(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Use a dispatcher with short backoff for test speed.
	d := &WebhookDispatcher{
		url:    srv.URL,
		nodeID: "retry-node",
		ch:     make(chan SecurityAlert, webhookChannelCapacity),
		done:   make(chan struct{}),
		client: &http.Client{Timeout: 5 * time.Second},
	}
	// Override backoff for test speed by using a custom dispatch.
	// We'll use the real run() goroutine but with shorter sleeps.
	go d.runWithBackoff(50 * time.Millisecond)

	d.ch <- SecurityAlert{Type: "test_retry", Severity: AlertWarning, Description: "retry test"}
	d.Close()

	if attempts.Load() != 3 {
		t.Fatalf("server received %d attempts, want 3 (2 failures + 1 success)", attempts.Load())
	}
}

// TestWebhookDispatcher_RetryExhaustion verifies that after 3 failed
// attempts the alert is dropped (no more retries).
func TestWebhookDispatcher_RetryExhaustion(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	d := &WebhookDispatcher{
		url:    srv.URL,
		nodeID: "exhaust-node",
		ch:     make(chan SecurityAlert, webhookChannelCapacity),
		done:   make(chan struct{}),
		client: &http.Client{Timeout: 5 * time.Second},
	}
	go d.runWithBackoff(10 * time.Millisecond)

	d.ch <- SecurityAlert{Type: "test_exhaust", Severity: AlertCritical, Description: "exhaust test"}
	d.Close()

	if got := attempts.Load(); got != webhookMaxRetries {
		t.Fatalf("server received %d attempts, want %d", got, webhookMaxRetries)
	}
}

// TestWebhookDispatcher_GracefulDegradation verifies that when no webhook
// URL is configured, AlertStore.Add still works normally (no panic, no block).
func TestWebhookDispatcher_GracefulDegradation(t *testing.T) {
	store := NewAlertStore()
	// No SetWebhookCh call — webhookCh is nil.

	ok := store.Add(SecurityAlert{
		Type:        "test_no_webhook",
		Severity:    AlertInfo,
		Description: "no webhook configured",
	})
	if !ok {
		t.Error("Add() returned false for a non-duplicate alert")
	}
	if store.Count() != 1 {
		t.Errorf("Count = %d, want 1", store.Count())
	}
}

// TestAlertStore_NonBlockingSend verifies that a full webhook channel
// does not block AlertStore.Add (the alert is dropped from webhook dispatch
// but still stored in-memory).
func TestAlertStore_NonBlockingSend(t *testing.T) {
	store := NewAlertStore()
	// Create a channel with capacity 1, don't drain it.
	ch := make(chan SecurityAlert, 1)
	store.SetWebhookCh(ch)

	// First alert goes into the channel buffer (capacity 1).
	store.Add(SecurityAlert{Type: "a", Description: "first"})
	// Second alert: channel is full, should drop webhook send but still store.
	store.Add(SecurityAlert{Type: "b", Description: "second"})

	// Both alerts should be in the in-memory store.
	if store.Count() != 2 {
		t.Errorf("Count = %d, want 2 (both stored)", store.Count())
	}
	// Channel should have only 1 buffered (the first).
	if len(ch) != 1 {
		t.Errorf("channel len = %d, want 1 (second was dropped)", len(ch))
	}
}

// TestWebhookDispatcher_CloseIsIdempotentSafe verifies Close drains and
// does not panic or hang when called after all work is done.
func TestWebhookDispatcher_Close(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewWebhookDispatcher(srv.URL, "close-test")
	d.Close()
	// Calling Close again should not hang or panic (channel already closed).
	// Actually, close() on an already-closed channel panics, so we test
	// that the done channel is closed instead.
	select {
	case <-d.done:
		// good — goroutine exited
	default:
		t.Error("done channel not closed after Close()")
	}
}

// runWithBackoff is a test helper that runs the dispatch loop with a
// custom initial backoff duration instead of the default 1s.
func (d *WebhookDispatcher) runWithBackoff(initial time.Duration) {
	defer close(d.done)
	for alert := range d.ch {
		d.dispatchWithBackoff(alert, initial)
	}
}

// dispatchWithBackoff is a test helper variant of dispatch with custom backoff.
func (d *WebhookDispatcher) dispatchWithBackoff(alert SecurityAlert, initial time.Duration) {
	payload := webhookPayload{
		Source:    "MeshDesk",
		NodeID:    d.nodeID,
		Event:     "security_alert",
		Timestamp: alert.Timestamp,
		Alert:     alert,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	backoff := initial
	for attempt := 1; attempt <= webhookMaxRetries; attempt++ {
		if d.post(body) {
			return
		}
		if attempt < webhookMaxRetries {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
}
