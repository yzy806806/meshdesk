//go:build ignore

package main

import (
	"fmt"
	"github.com/yzy806806/meshdesk/internal/identity"
)

func main() {
	id, _ := identity.GenerateIdentity()
	fmt.Printf("private: %s\npublic:  %s\n", id.PrivateKey, id.PublicKey)
}
