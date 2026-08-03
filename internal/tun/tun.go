// Package tun provides a minimal TUN virtual network interface using
// raw Linux syscalls against /dev/net/tun. No external dependencies.
//
// The implementation opens /dev/net/tun, issues the TUNSETIFF ioctl to
// create a TUN device (Layer 3 — no Ethernet headers), and returns a
// *os.File that can be read/written as IP packets. The caller is
// responsible for assigning an IP address and bringing the interface
// up (typically via the `ip` command or netlink).
//
// This package is Linux-only — it uses Linux-specific ioctl constants
// and the /dev/net/tun character device.
package tun

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// IFNAMSIZ is the maximum length of a network interface name on Linux.
const IFNAMSIZ = 16

// tunDevicePath is the path to the TUN/TAP character device on Linux.
const tunDevicePath = "/dev/net/tun"

// ifreq is the struct passed to the TUNSETIFF ioctl. The layout matches
// the kernel's struct ifreq (16-byte ifr_name + 16-byte ifr_data union).
// We use a byte array for the data union because the ioctl writes the
// assigned interface name back into ifr_name.
type ifreq struct {
	Name  [IFNAMSIZ]byte // ifr_name — interface name (null-terminated)
	Flags uint16         // ifr_flags — IFF_TUN, IFF_NO_PI, etc.
	_     [IFNAMSIZ - 2]byte // padding to match kernel struct size
}

// ioctl constants for TUN device operations.
const (
	TUNSETIFF = 0x400454ca
	IFF_TUN   = 0x0001 // Layer 3 tunnel (no Ethernet headers)
	IFF_NO_PI = 0x1000 // Do not include packet information (4-byte prefix)
)

// Device wraps an open TUN device file and its metadata.
type Device struct {
	// file is the open /dev/net/tun file descriptor. Reading from it
	// yields inbound IP packets; writing to it injects outbound IP
	// packets into the kernel networking stack.
	file *os.File

	// name is the kernel-assigned interface name (e.g. "mesh0", "tun0").
	name string

	// mtu is the configured maximum transmission unit.
	mtu int

	// addr is the IPv4 address assigned to the TUN interface (without
	// mask). It is derived from the configured subnet but not set on
	// the interface — the caller must configure the interface address
	// via `ip addr add` or netlink.
	addr net.IP

	// subnet is the CIDR subnet the TUN interface operates in.
	subnet *net.IPNet
}

// Config holds the parameters for creating a TUN device.
type Config struct {
	// Name is the desired interface name (e.g. "mesh0"). If empty or
	// shorter than IFNAMSIZ, the kernel assigns the next available name.
	// Names longer than IFNAMSIZ-1 are truncated.
	Name string

	// MTU is the maximum transmission unit. Must be > 0.
	// Typical values: 1280 (IPv6 minimum), 1400 (mesh-safe default), 1500 (Ethernet).
	MTU int

	// Subnet is the CIDR subnet for the TUN interface (e.g. "10.10.0.0/24").
	// The device's IP address is derived as the first usable address
	// (network address + 1). Required.
	Subnet string
}

// Create opens /dev/net/tun, creates a TUN device via TUNSETIFF ioctl,
// and returns a *Device wrapping the open file descriptor.
//
// The returned Device's File() can be used for read/write of IP packets.
// The caller is responsible for:
//   - Assigning the IP address to the interface (ip addr add)
//   - Setting the MTU (ip link set mtu)
//   - Bringing the interface up (ip link set up)
//   - Adding routes as needed (ip route add)
//
// If the process lacks CAP_NET_ADMIN (or is not root), Create returns
// an error wrapping EPERM so the caller can degrade gracefully.
func Create(cfg Config) (*Device, error) {
	// Validate the subnet.
	ip, ipNet, err := net.ParseCIDR(cfg.Subnet)
	if err != nil {
		return nil, fmt.Errorf("tun: invalid subnet %q: %w", cfg.Subnet, err)
	}
	if cfg.MTU <= 0 {
		return nil, errors.New("tun: MTU must be positive")
	}

	// Open the TUN character device.
	fd, err := unix.Open(tunDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		// Provide a clear error for the most common failure (no permissions).
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("tun: permission denied opening %s (need CAP_NET_ADMIN or root): %w",
				tunDevicePath, err)
		}
		// If the device node doesn't exist, guide the user.
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("tun: %s not found (ensure the tun kernel module is loaded: mknod /dev/net/tun c 10 200): %w",
				tunDevicePath, err)
		}
		return nil, fmt.Errorf("tun: open %s: %w", tunDevicePath, err)
	}

	// Prepare the ifreq for TUNSETIFF.
	var req ifreq
	req.Flags = IFF_TUN | IFF_NO_PI // Layer 3, no packet info prefix
	if cfg.Name != "" {
		// Copy the desired name, truncated to IFNAMSIZ-1 (leave room for null).
		nameBytes := []byte(cfg.Name)
		if len(nameBytes) > IFNAMSIZ-1 {
			nameBytes = nameBytes[:IFNAMSIZ-1]
		}
		copy(req.Name[:], nameBytes)
	}

	// Issue the TUNSETIFF ioctl. This creates the TUN interface and
	// writes the assigned name back into req.Name.
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(TUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		unix.Close(fd)
		if errno == unix.EPERM {
			return nil, fmt.Errorf("tun: TUNSETIFF failed — permission denied (need CAP_NET_ADMIN or root): %w", errno)
		}
		return nil, fmt.Errorf("tun: TUNSETIFF ioctl failed: %w", errno)
	}

	// Extract the assigned interface name (null-terminated C string).
	name := strings.TrimRight(string(req.Name[:]), "\x00")

	// Derive the device IP address: first usable address in the subnet
	// (network address + 1).
	deviceIP := make(net.IP, len(ip))
	copy(deviceIP, ip)
	// Increment to get the first usable host address.
	for i := len(deviceIP) - 1; i >= 0; i-- {
		deviceIP[i]++
		if deviceIP[i] != 0 {
			break
		}
	}

	// Wrap the fd in an *os.File for convenient read/write.
	file := os.NewFile(uintptr(fd), tunDevicePath)

	d := &Device{
		file:   file,
		name:   name,
		mtu:    cfg.MTU,
		addr:   deviceIP,
		subnet: ipNet,
	}

	return d, nil
}

// File returns the underlying *os.File for the TUN device. Reading from
// it yields inbound IP packets; writing to it injects packets into the
// kernel networking stack. The caller must not close the file — use
// Device.Close() instead.
func (d *Device) File() *os.File {
	return d.file
}

// Name returns the kernel-assigned interface name (e.g. "mesh0").
func (d *Device) Name() string {
	return d.name
}

// MTU returns the configured MTU.
func (d *Device) MTU() int {
	return d.mtu
}

// Addr returns the derived IPv4 address for the TUN interface.
// This is the first usable host address in the configured subnet.
func (d *Device) Addr() net.IP {
	return d.addr
}

// Subnet returns the CIDR subnet the TUN interface operates in.
func (d *Device) Subnet() *net.IPNet {
	return d.subnet
}

// Close closes the TUN device file descriptor. The kernel interface
// is automatically destroyed when the last fd referencing it is closed.
func (d *Device) Close() error {
	if d.file != nil {
		err := d.file.Close()
		d.file = nil
		return err
	}
	return nil
}
