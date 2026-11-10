module github.com/yzy806806/meshdesk

go 1.27.0

require (
	github.com/creack/pty v1.1.24
	github.com/gorilla/websocket v1.5.3
	github.com/miekg/dns v1.1.72
	github.com/pion/stun/v3 v3.1.6
	github.com/refraction-networking/utls v1.8.2
	github.com/vmihailenco/msgpack/v5 v5.4.1
	github.com/xtls/reality v0.0.0-20261108102217-4a26e87788f5
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.20.4 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/molecule-man/go-brrr v1.2.0 // indirect
	github.com/pion/dtls/v3 v3.1.4 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/pires/go-proxyproto v0.15.0 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/xtls/utls v0.0.0-20261106062530-666e20f266ac // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/tools v0.51.0 // indirect
)

replace github.com/xtls/reality => ./third_party/reality-patched
