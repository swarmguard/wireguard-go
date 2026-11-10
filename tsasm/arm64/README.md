# Native ARM64 transport crypto

ARM64 builds select this implementation for transport packet AEAD by default.
Other architectures retain their existing implementations. The `purego` build
tag selects the portable Go fallback within these ARM64 packages.
This code uses Go assembly directly; it has no OpenSSL or CGO dependency.

The source is based on `golang.org/x/crypto` v0.55.0 under the BSD
license reproduced in the [repository-root LICENSE](../../LICENSE). ChaCha20 retains upstream ARM64 vector assembly. Its buffered XOR
uses `crypto/subtle.XORBytes`. Poly1305 adds an experimental ARM64 translation
of the upstream saturated-limb generic/Loong64 block update algorithm.
Partial blocks and finalization retain the reference Go implementation.
The AEAD wrapper retains upstream nonce, overlap, authentication and failure
handling. Local import paths connect these components. Compatibility files
preserve FIPS-only rejection on Go versions exposing that setting.

This is new, independently unreviewed Poly1305 assembly. Passing tests and
microbenchmarks do not establish production readiness or tunnel speed gains.
Architecture selection is enabled by default; independent review remains
outstanding. This implementation does not claim a standalone tunnel speed gain.

From this module:

```sh
GOWORK=off go test ./tsasm/arm64/... ./device
GOWORK=off go test -tags purego ./tsasm/arm64/... ./device
GOWORK=off go test -race ./tsasm/arm64/...
```

From the `sg-main` workspace root, use the workspace to select this local
submodule (the agent's `GOWORK=off` release build still uses its pinned module):

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags ui -o /tmp/swarmd-native-arm64 ./agent/go/cmd/swarmd
```

UI assets must already be built for the `ui` tag. No dependency version or
submodule pointer is changed by this experiment.

FD1800 measurements, test logs and provenance are under
`agent/go/doc/benchmarks-fd1800/05-optimization-2026-11-09/` in `sg-main`.
The 1280-byte AEAD microbenchmark improved from roughly 62 to 78 MB/s;
a matched three-run tunnel comparison showed no meaningful throughput gain
(321.84/219.16 Mbit/s native versus 322.03/221.87 Mbit/s control,
upload/download; both used the same 128 MiB Go memory limit).
