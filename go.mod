module github.com/yzy806806/meshdesk

go 1.25.0

require (
	github.com/creack/pty v1.1.24
	github.com/gorilla/websocket v1.5.3
	github.com/hashicorp/go-sockaddr v1.0.7
	github.com/hashicorp/memberlist v0.6.0
	github.com/miekg/dns v1.1.72
	github.com/pion/stun/v3 v3.1.6
	github.com/refraction-networking/utls v1.8.2
	github.com/vmihailenco/msgpack/v5 v5.4.1
	github.com/xtls/reality v0.0.0-20260322125925-9234c772ba8f
	golang.org/x/crypto v0.54.0
	golang.org/x/sys v0.47.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/armon/go-metrics v0.4.1 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-metrics v0.6.0 // indirect
	github.com/hashicorp/go-msgpack/v2 v2.1.5 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/golang-lru v0.5.0 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/pion/dtls/v3 v3.1.4 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/pires/go-proxyproto v0.11.0 // indirect
	github.com/sean-/seed v0.0.0-20170313163322-e2103e2c3529 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
)

replace github.com/xtls/reality => ./third_party/reality-patched
