package app

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/yzy806806/meshdesk/internal/auth"
	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/dns"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/p2p"
	"github.com/yzy806806/meshdesk/internal/service"
	"github.com/yzy806806/meshdesk/internal/transfer"
	"github.com/yzy806806/meshdesk/internal/web"
	"github.com/yzy806806/meshdesk/internal/webssh"
	"os"
	"strings"
)

// startServices starts mesh virtual-port services: DNS, remote service
// management, file transfer, WebSSH.
func (a *App) startServices() {
	if a.cfg.Mesh.DNSEnabled && a.gossipLayer != nil {
		dnsProvider := &gossipDNSAdapter{gl: a.gossipLayer}
		dnsServer := dns.NewServer(dnsProvider, a.cfg.Mesh.DNSPort)
		// Forward non-.mesh queries to the system resolver so the mesh
		// DNS can act as a general-purpose resolver (T3.1).
		if up := systemResolver(); up != "" {
			dnsServer.SetUpstream(up)
		}
		if err := dnsServer.Start(); err != nil {
			log.Printf("Warning: failed to start mesh DNS server: %v", err)
		} else {
			a.dnsServer = dnsServer
		}
	}

	// Start the remote service management server (listens on mesh).
	// Every node accepts service management commands from authorized peers.
	remoteSvcListener := &meshListenerAdapter{node: a.node}
	// Use the raw service manager; the RemoteServer wraps it with
	// AuthorizedServiceManager per-request using the caller's PeerID.
	var remoteSvcMgr service.ServiceManager
	if execBackend, err := service.NewExecBackend("", 30*time.Second); err != nil {
		// Graceful degradation: use NullBackend when systemd is unavailable (Gap 5 fix).
		log.Printf("Warning: systemctl not available for remote service server: %v — using null backend", err)
		remoteSvcMgr = service.NewNullBackend()
	} else {
		remoteSvcMgr = execBackend
	}
	// Wire the auth engine into the remote server for per-peer capability
	// enforcement. Each incoming request's PeerID field is used to construct
	// an AuthorizedServiceManager scoped to that caller.
	remoteAuthEngine := auth.NewCapabilityEngine(a.cfg, auth.NewAuditLogger(log.Writer()))
	var remoteSvcServer *service.RemoteServer
	a.remoteAuthEngine = remoteAuthEngine
	if remoteAuthEngine != nil {
		remoteSvcServer = service.NewRemoteServerWithAuth(remoteSvcMgr, remoteAuthEngine, remoteSvcListener, service.DefaultServicePort)
	} else {
		remoteSvcServer = service.NewRemoteServer(remoteSvcMgr, remoteSvcListener, service.DefaultServicePort)
	}
	if err := remoteSvcServer.Start(); err != nil {
		log.Printf("Warning: failed to start remote service server: %v", err)
	} else {
		log.Printf("  Service RPC: listening on mesh port %d", service.DefaultServicePort)
	}
	a.remoteSvcServer = remoteSvcServer

	// Start the file transfer receiver (listens on mesh).
	// Every node accepts incoming file transfers from authorized peers.
	// The receiver is wired with capability enforcement (Gap 2 fix) and
	// file size limits from config (Gap 4 fix).
	transferListener := &meshListenerAdapter{node: a.node}
	transferAuthEngine := auth.NewCapabilityEngine(a.cfg, auth.NewAuditLogger(log.Writer()))
	a.transferAuthEngine = transferAuthEngine
	var transferAuthChecker transfer.AuthChecker
	if transferAuthEngine != nil {
		transferAuthChecker = auth.NewTransferAuthChecker(transferAuthEngine)
	}
	uploadDir := a.cfg.Transfer.UploadDir
	if uploadDir == "" {
		uploadDir = config.DefaultUploadDir
	}
	transferServer := transfer.NewReceiverWithAuth(
		transferListener, web.TransferPort, uploadDir,
		a.cfg.Transfer.MaxFileSize, transferAuthChecker,
	)
	if err := transferServer.Start(); err != nil {
		log.Printf("Warning: failed to start file transfer receiver: %v", err)
	} else {
		log.Printf("  File transfer: listening on mesh port %d (max %d bytes)", web.TransferPort, a.cfg.Transfer.MaxFileSize)
	}
	a.transferServer = transferServer

	// Start the WebSSH server (listens on mesh).
	// Every node accepts incoming SSH connections from the web node
	// for terminal sessions. The SSH server allocates a PTY and runs
	// a shell, providing remote terminal access via the mesh.
	sshListener := &meshListenerAdapter{node: a.node}
	sshServer, err := webssh.NewSSHServer(a.cfg.WebSSH.HostKey, a.cfg.WebSSH.Shell)
	if err != nil {
		log.Printf("Warning: failed to create WebSSH server: %v", err)
	} else {
		sshLn, err := sshListener.ListenMesh(a.cfg.WebSSH.Port)
		if err != nil {
			log.Printf("Warning: failed to listen for WebSSH on mesh port %d: %v", a.cfg.WebSSH.Port, err)
		} else {
			go func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if err := sshServer.Serve(ctx, sshLn); err != nil {
					log.Printf("WebSSH server stopped: %v", err)
				}
			}()
			log.Printf("  WebSSH:     listening on mesh port %d", a.cfg.WebSSH.Port)
			a.sshServer = sshServer
		}
	}
}

type gossipDNSAdapter struct {
	gl *p2p.GossipLayer
}

type meshListenerAdapter struct {
	node *mesh.MeshNode
}

func systemResolver() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			ip := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
			if ip == "" {
				continue
			}
			// Handle IPv6 (add brackets for the port form).
			if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
				ip = "[" + ip + "]"
			}
			return ip + ":53"
		}
	}
	return ""
}

func (a *meshListenerAdapter) ListenMesh(port int) (net.Listener, error) {
	return a.node.ListenVirtualPort(port)
}

func (a *gossipDNSAdapter) LocalMeta() *dns.NodeMeta {
	if a.gl == nil {
		return nil
	}
	meta := a.gl.LocalMeta()
	if meta == nil {
		return nil
	}
	return &dns.NodeMeta{
		Hostname:  meta.Hostname,
		VirtualIP: meta.VirtualIP,
	}
}

func (a *gossipDNSAdapter) KnownPeers() []*dns.NodeMeta {
	if a.gl == nil {
		return nil
	}
	peers := a.gl.KnownPeers()
	result := make([]*dns.NodeMeta, 0, len(peers))
	for _, p := range peers {
		if p == nil {
			continue
		}
		result = append(result, &dns.NodeMeta{
			Hostname:  p.Hostname,
			VirtualIP: p.VirtualIP,
		})
	}
	return result
}
