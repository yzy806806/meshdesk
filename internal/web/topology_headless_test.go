package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/topology"
	tmock "github.com/yzy806806/meshdesk/internal/topology/mock"
)

// TestTopologyHeadlessBrowser validates 3D rendering and particle animation
// via a headless Chromium browser (Puppeteer). This test:
//  1. Starts the MeshDesk web server with mock topology data.
//  2. Loads a Three.js test page in Chromium.
//  3. Asserts nodes are rendered at correct positions.
//  4. Asserts particle animation is active.
//  5. Asserts WebGL canvas is present.
//
// Skip conditions: CHROMIUM_PATH not set, or Chromium not found.
func TestTopologyHeadlessBrowser(t *testing.T) {
	chromiumPath := os.Getenv("CHROMIUM_PATH")
	if chromiumPath == "" {
		chromiumPath = "/snap/bin/chromium"
	}

	if _, err := os.Stat(chromiumPath); os.IsNotExist(err) {
		t.Skipf("Chromium not found at %s — skipping headless browser test", chromiumPath)
	}

	// Check that Node.js puppeteer is available.
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node.js not found — skipping headless browser test")
	}

	// Build server with mock topology data.
	cfg := config.Default()
	mockPeers := tmock.NewMockPeers()
	mockMetrics := tmock.NewMockMetrics()
	mockPaths := tmock.NewMockPaths()

	// Enable mock mode so the topology handler returns mock data.
	srv, err := New(Deps{
		Config:          cfg,
		TopologyPeers:   mockPeers,
		TopologyMetrics: mockMetrics,
		TopologyPaths:   mockPaths,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Also set mock mode so the server uses mock data.
	srv.mockTopologyQuery = func() bool { return true }
	srv.mockSnapshotFn = func() topology.TopologySnapshot {
		return tmock.Snapshot(mockPeers, mockMetrics, mockPaths)
	}

	// Start the SSE hub.
	go srv.sseHub.Run()

	// Set up mux with all routes.
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	// Add a route for the test HTML page.
	testHTMLPath := filepath.Join(os.Getenv("GOPATH"), "src/github.com/yzy806806/meshdesk/test/topology_3d_test.html")
	// Also try relative to project root.
	if _, err := os.Stat(testHTMLPath); os.IsNotExist(err) {
		// Try repo root relative paths.
		candidates := []string{
			"../../test/topology_3d_test.html",
			"test/topology_3d_test.html",
			"/root/meshdesk/test/topology_3d_test.html",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				testHTMLPath = c
				break
			}
		}
	}

	if _, err := os.Stat(testHTMLPath); os.IsNotExist(err) {
		t.Skipf("Test HTML page not found at %s — skipping headless browser test", testHTMLPath)
	}

	mux.HandleFunc("/test/topology_3d_test.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, testHTMLPath)
	})

	// Start HTTP test server.
	ts := httptest.NewServer(mux)
	defer ts.Close()

	t.Logf("Test server started at %s", ts.URL)

	// Run the Puppeteer test script.
	scriptPath := filepath.Join(filepath.Dir(testHTMLPath), "topology_headless_test.js")
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		t.Skipf("Puppeteer script not found at %s — skipping", scriptPath)
	}

	cmd := exec.Command("node", scriptPath)
	cmd.Env = append(os.Environ(),
		"CHROMIUM_PATH="+chromiumPath,
		"MESHTOPO_URL="+ts.URL,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	t.Log("Running Puppeteer headless browser test...")

	// Set a generous timeout for browser launch + rendering.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Headless browser test failed: %v", err)
		} else {
			t.Log("Headless browser test PASSED")
		}
	case <-time.After(60 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		t.Fatal("Headless browser test timed out after 60s")
	}
}
