package web

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// webhookChannelCapacity is the buffer size for the alert dispatch channel.
// When the buffer is full, additional alerts are dropped (non-blocking send
// in AlertStore.Add) to prevent a slow or unresponsive webhook endpoint
// from stalling the alert pipeline.
const webhookChannelCapacity = 256

// webhookMaxRetries is the number of POST attempts before the alert is
// dropped. The intervals are exponential: 1s, 2s, 4s.
const webhookMaxRetries = 3

// WebhookDispatcher asynchronously delivers SecurityAlert events to an
// external HTTP endpoint (Slack, Discord, custom webhook). Alerts are
// sent on a buffered channel by AlertStore.Add; a background goroutine
// reads from that channel and performs HTTP POSTs with retry backoff.
//
// When the webhook URL is empty, no dispatcher is created — zero overhead.
type WebhookDispatcher struct {
	url    string
	nodeID string
	ch     chan SecurityAlert
	done   chan struct{}
	client *http.Client
}

// webhookPayload is the JSON body sent to the external webhook endpoint.
type webhookPayload struct {
	Source    string         `json:"source"`
	NodeID    string         `json:"node_id"`
	Event     string         `json:"event"`
	Timestamp time.Time      `json:"timestamp"`
	Alert     SecurityAlert `json:"alert"`
}

// NewWebhookDispatcher creates a dispatcher that posts alerts to the given
// URL. The nodeID is included in every payload to identify the source node.
// The dispatcher starts its background goroutine immediately.
func NewWebhookDispatcher(url, nodeID string) *WebhookDispatcher {
	d := &WebhookDispatcher{
		url:    url,
		nodeID: nodeID,
		ch:     make(chan SecurityAlert, webhookChannelCapacity),
		done:   make(chan struct{}),
		client: &http.Client{Timeout: 10 * time.Second},
	}
	go d.run()
	return d
}

// Channel returns the send-only channel that AlertStore uses to enqueue
// alerts for webhook dispatch.
func (d *WebhookDispatcher) Channel() chan<- SecurityAlert {
	return d.ch
}

// Close shuts down the background goroutine, draining any in-flight alerts
// that are already buffered in the channel. After Close returns, no further
// alerts will be dispatched.
func (d *WebhookDispatcher) Close() {
	close(d.ch)
	<-d.done
}

// run is the background goroutine that reads alerts from the channel and
// POSTs them to the webhook URL with exponential backoff retry.
func (d *WebhookDispatcher) run() {
	defer close(d.done)
	for alert := range d.ch {
		d.dispatch(alert)
	}
}

// dispatch attempts to POST a single alert to the webhook URL, retrying
// up to webhookMaxRetries times with exponential backoff (1s, 2s, 4s).
// After all retries are exhausted, the alert is dropped and logged.
func (d *WebhookDispatcher) dispatch(alert SecurityAlert) {
	payload := webhookPayload{
		Source:    "MeshDesk",
		NodeID:    d.nodeID,
		Event:     "security_alert",
		Timestamp: alert.Timestamp,
		Alert:     alert,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[webhook] failed to marshal alert payload: %v", err)
		return
	}

	backoff := 1 * time.Second
	for attempt := 1; attempt <= webhookMaxRetries; attempt++ {
		if d.post(body) {
			return // success
		}
		if attempt < webhookMaxRetries {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	log.Printf("[webhook] dropping alert type=%s after %d failed attempts",
		alert.Type, webhookMaxRetries)
}

// post sends the JSON body to the webhook URL and returns true on HTTP success
// (2xx status code). Non-2xx responses or transport errors return false.
func (d *WebhookDispatcher) post(body []byte) bool {
	resp, err := d.client.Post(d.url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[webhook] POST error: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[webhook] non-2xx status %d from %s", resp.StatusCode, d.url)
		return false
	}
	return true
}
