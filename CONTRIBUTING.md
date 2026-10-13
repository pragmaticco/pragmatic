# Contributing to Pragmatic

Thanks for your interest. Pragmatic is in **public beta**; the core replay
semantics are stable (they are the theorems), the API surface is not yet.

## Ground rules

1. **The core stays zero-dependency.** `crates/pragmatic` and
   `crates/pragmatic-macros` must build with no external crates. Anything
   that talks to the outside world (HTTP, model APIs, storage services)
   belongs in an adapter crate.
2. **Semantics follow the calculus.** The runtime implements the Agentical
   operational semantics - record/replay rules, the write-ahead effect
   discipline, cursor keys. A change that alters replay behavior needs an
   argument that it preserves T1 (replay soundness), not just passing tests.
   Reference the rule names (`[O-rec]`, `[Eff-intent]`, …) in comments the
   way the existing code does.
3. **Every claim is a test.** The E1/E2/E3 suites are the product's
   measured claims. New guarantees ship with the test that demonstrates
   them; changed guarantees update the README table.

## Workflow

```sh
cargo test --workspace          # all suites, including E1 1000/1000
cargo test --release            # headline numbers (E3 latency/speedup)
cargo fmt --all                 # rustfmt, enforced by CI
cargo clippy --all-targets -- -D warnings
cargo run -p pragmatic --example research_agent
```

- Branch from `main`, keep PRs focused, describe the *behavioral* change.
- New journal event kinds must extend `Event::encode`/`decode` with a fresh
  tag (never reuse or renumber - journals on disk are forever) and add a
  round-trip test.
- Breaking on-disk format changes bump the journal `VERSION` and require a
  migration story in the PR description.

## Reporting bugs

A replay divergence (same code, same journal, different trace) is the
highest-severity bug this project can have. If you find one, please attach
the journal file (`pragmatic export` output is ideal) and the exact crate
version. See [SECURITY.md](SECURITY.md) for anything security-sensitive.

## License

The project is licensed under the [Apache License 2.0](LICENSE). By
contributing you agree that your contribution is licensed under the same
terms (section 5 of the license).

Every commit must carry a `Signed-off-by:` line (`git commit -s`),
certifying the [Developer Certificate of Origin](https://developercertificate.org/):
that you wrote the change, or otherwise have the right to submit it under
this license.
