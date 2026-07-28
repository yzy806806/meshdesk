package mesh

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// virtualPortFrameLen is the size of the port prefix frame in bytes.
const virtualPortFrameLen = 2

// writePortFrame writes a 2-byte big-endian port number to w.
func writePortFrame(w io.Writer, port uint16) error {
	var buf [virtualPortFrameLen]byte
	binary.BigEndian.PutUint16(buf[:], port)
	_, err := w.Write(buf[:])
	return err
}

// readPortFrame reads a 2-byte big-endian port number from r.
func readPortFrame(r io.Reader) (uint16, error) {
	var buf [virtualPortFrameLen]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}

// virtualPortMux is a multiplexer for smux streams based on virtual port numbers.
// It allows MeshNode to dispatch inbound smux streams to listeners registered
// for specific port numbers.
//
// Wire protocol: When a peer opens a stream for a virtual port, the first
// frame written on the stream is a 2-byte big-endian uint16 carrying the
// port number. The receiving side reads this frame and dispatches the stream
// to the listener registered for that port.
//
// All methods are safe for concurrent use.
type virtualPortMux struct {
	mu        sync.RWMutex
	listeners map[uint16]*VirtualListener
}

// newVirtualPortMux creates an empty virtual port multiplexer.
func newVirtualPortMux() *virtualPortMux {
	return &virtualPortMux{
		listeners: make(map[uint16]*VirtualListener),
	}
}

// register creates and registers a VirtualListener for the given port.
// If a listener already exists for this port, returns an error.
func (m *virtualPortMux) register(port uint16) (*VirtualListener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[port]; exists {
		return nil, fmt.Errorf("virtual port %d: listener already registered", port)
	}

	vl := &VirtualListener{
		port:     port,
		acceptCh: make(chan net.Conn),
		doneCh:   make(chan struct{}),
	}
	m.listeners[port] = vl
	return vl, nil
}

// unregister removes a listener for the given port. No-op if none registered.
func (m *virtualPortMux) unregister(port uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if vl, exists := m.listeners[port]; exists {
		delete(m.listeners, port)
		vl.Close()
	}
}

// dispatch delivers a stream to the listener registered for the given port.
// If no listener is registered, the stream is closed.
func (m *virtualPortMux) dispatch(port uint16, conn net.Conn) {
	m.mu.RLock()
	vl, exists := m.listeners[port]
	m.mu.RUnlock()

	if !exists {
		// No listener for this port — close the stream.
		conn.Close()
		return
	}

	select {
	case vl.acceptCh <- conn:
		// Delivered.
	case <-vl.doneCh:
		// Listener closed — close the stream.
		conn.Close()
	}
}

// VirtualListener implements net.Listener for a single virtual port.
// Accept() blocks until a peer opens a stream to this port (after the
// port-dispatch frame has been consumed).
type VirtualListener struct {
	port     uint16
	acceptCh chan net.Conn
	doneCh   chan struct{}
	once     sync.Once
}

// Accept blocks until a stream arrives on this virtual port.
func (vl *VirtualListener) Accept() (net.Conn, error) {
	select {
	case conn := <-vl.acceptCh:
		return conn, nil
	case <-vl.doneCh:
		return nil, errListenerClosed
	}
}

// Close unregisters the listener. Future streams for this port are dropped.
func (vl *VirtualListener) Close() error {
	vl.once.Do(func() {
		close(vl.doneCh)
	})
	return nil
}

// Addr returns a synthetic address for the listener.
func (vl *VirtualListener) Addr() net.Addr {
	return &virtualListenerAddr{port: vl.port}
}

// virtualListenerAddr is a synthetic net.Addr for VirtualListener.
type virtualListenerAddr struct {
	port uint16
}

func (a *virtualListenerAddr) Network() string { return "mesh" }
func (a *virtualListenerAddr) String() string  { return fmt.Sprintf("mesh:%d", a.port) }

// errListenerClosed is returned by VirtualListener.Accept after Close.
var errListenerClosed = fmt.Errorf("mesh: virtual listener closed")
