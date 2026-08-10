package p2p

import "testing"

func TestIsVirtualInterfaceName(t *testing.T) {
	cases := map[string]bool{
		"tun0":    true,
		"tap1":    true,
		"mesh0":   true,
		"wg0":     true,
		"br-abc":  true,
		"docker0": true,
		"vethxyz": true,
		"wlan0":   false,
		"eth0":    false,
		"rmnet_data2": false,
		"enp3s0":  false,
		"ens3":    false,
	}
	for name, want := range cases {
		if got := isVirtualInterfaceName(name); got != want {
			t.Errorf("isVirtualInterfaceName(%q) = %v, want %v", name, got, want)
		}
	}
}
