//go:build ignore

package main

import (
	"fmt"
	"github.com/yzy806806/meshdesk/internal/handshake"
)

func main() {
	pub, priv, _ := handshake.GenerateRealityKeyPair()
	fmt.Printf("private_key: %s\npublic_key: %s\n", priv, pub)
}
