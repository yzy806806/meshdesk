//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/yzy806806/meshdesk/internal/identity"
)

func main() {
	for _, p := range []string{"/tmp/aliyun-identity.pem", "/tmp/txcloud-identity.pem", "/tmp/n1-identity.pem"} {
		data, _ := os.ReadFile(p)
		id, err := identity.IdentityFromPEM(data)
		if err != nil {
			fmt.Printf("%s: ERROR %v\n", p, err)
			continue
		}
		fmt.Printf("%s: public=%s\n", p, id.PublicKey)
	}
}
