# Stet language bindings

The same runtime - journal every step, recover from any crash, replay
faithfully - from C++, Java, Go, and Node.js. Every binding sits on the one
C ABI exported by [`crates/pragmatic-ffi`](../crates/pragmatic-ffi)
([`pragmatic.h`](../crates/pragmatic-ffi/include/pragmatic.h)), so journals
are byte-compatible across every language here, plus Rust and Python, and
the CLI/console read them all.

**Status: stable, maintenance-only.** These bindings track the C ABI and
receive bug fixes and CI coverage, but new runtime surface lands in Rust,
Python, and (next) a first-class TypeScript SDK before it lands here - see
[docs/STRATEGY.md](../docs/STRATEGY.md). If a missing capability blocks a
real embedding use case, [open an issue](../CONTRIBUTING.md).

Build the shared library once, from the repo root:

```sh
cargo build -p pragmatic-ffi
```

| Binding | Mechanism | Extra deps | Test |
|---|---|---|---|
| [C](../crates/pragmatic-ffi/include/pragmatic.h) | the C ABI itself | none | `cargo test -p pragmatic-ffi` |
| [C++](cpp/pragmatic.hpp) | header-only RAII over the C ABI, C++17 | none | `bindings/cpp/test.sh` |
| [Java](java/pragmatic/Pragmatic.java) | pure Java via `java.lang.foreign` (JDK 22+), no JNI glue | none | `bindings/java/test.sh` |
| [Go](go/pragmatic.go) | cgo | none | `bindings/go/test.sh` |
| [Node.js](node/pragmatic.js) | [koffi](https://koffi.dev) (Node has no built-in FFI) | `koffi` | `bindings/node/test.sh` |

Each binding exposes the same surface:

- **`Runtime(dir, oracle, key?)`** - journals persist under `dir` (one
  append-only, hash-chained file per run); `oracle` is your model call,
  prompt in → completion out; `key` HMAC-signs the journals.
- **`run` / `resume` / `replay`** under a stable run id - record, crash-recover
  without re-sampling, and audit bit-for-bit with the model never consulted.
- **`ctx.oracle` / `ctx.effect` / `ctx.recv` / `ctx.now` / `ctx.contract` /
  `ctx.is_replaying`** inside the agent - every step journaled, effects under
  the write-ahead discipline.
- **`send` / `verify`** on the runtime, and a **run report** (output, trace,
  replayed/fresh step counts, chain head).

Faults cross the boundary typed (budget exhaustion stays budget exhaustion,
desync stays desync) and surface idiomatically: `FaultError` (C++/Node),
`FaultException` (Java), `*Fault` (Go), status codes (C).

Every `test.sh` runs the same scenario the Rust and Python suites run:
record → resume (zero model calls, no re-performed effects) → replay
(bit-for-bit trace parity) → chain verification → typed-fault and
exception-boundary checks.
