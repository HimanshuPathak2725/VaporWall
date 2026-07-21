# Contributing to VaporWall

Thanks for your interest in VaporWall — a low-level, async kernel-space/user-space eBPF packet filter and live exploit analyzer with localized tiny-ML threat classification. This project touches the kernel boundary, so contributions go through a slightly stricter bar than a typical CRUD app. That's not bureaucracy for its own sake — a bad eBPF program can wedge a host, and a bad classifier can create false confidence in a security tool.

## Before you start

1. **Search existing issues** before opening a new one — duplicate triage wastes reviewer time.
2. **Open an issue before a large PR.** For anything touching the eBPF program lifecycle (loading/attaching/verifier behavior), the user-space/kernel-space boundary, or the ML classification pipeline, discuss the approach first. Small fixes (docs, typos, clippy warnings, test coverage) can go straight to a PR.
3. **Check `good-first-issue` / `help-wanted` labels** if you're new to the codebase.

## Development setup

VaporWall is a Rust project built around Cargo. You'll need:

- A recent stable Rust toolchain (see `rust-toolchain.toml` once present, or `Cargo.toml` for MSRV)
- A Linux environment with kernel headers for eBPF compilation/testing (eBPF work cannot be meaningfully tested on macOS/Windows — use a Linux VM or container if you're on another OS)
- `bpf-linker` (or the equivalent toolchain the crate's build.rs expects) for compiling eBPF bytecode
- Root or `CAP_BPF`/`CAP_NET_ADMIN` capabilities locally to load and attach programs during testing

```bash
git clone https://github.com/HimanshuPathak2725/VaporWall.git
cd VaporWall
cargo build
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

If a command above doesn't yet exist in the repo (e.g. no tests yet), that's expected at this stage — add the scaffolding as you go rather than skipping it.

## Branching and commits

- Branch from `main`: `feature/<short-description>` or `fix/<short-description>`.
- Keep commits scoped and descriptive. Conventional Commit prefixes (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`) are preferred but not yet strictly enforced.
- Rebase on `main` before opening a PR; avoid merge commits in your branch history.

## Pull requests

- One logical change per PR. Split unrelated fixes.
- Fill out the PR template completely, especially the **kernel-impact** section if your change touches the eBPF program or attach points.
- Include tests for new behavior where feasible. For eBPF-adjacent code that's hard to unit test, describe how you manually verified it (verifier output, target kernel version, attach/detach behavior under load).
- CI must pass (build, clippy, fmt, tests) before review.
- A maintainer will review and may request changes — this is normal, not a rejection.

## Code style

- Idiomatic Rust; run `cargo fmt` and `cargo clippy` before pushing.
- No `unsafe` without a comment explaining the invariant it upholds — this matters more than usual given the kernel-space surface.
- Prefer explicit error handling (`Result`, `thiserror`/`anyhow` as appropriate) over `unwrap()`/`expect()` outside of tests and truly unrecoverable init paths.
- Avoid busy-waiting or blocking calls on the hot packet-processing path; this project cares about p99 latency in the filter path, not just average throughput.

## Reporting security issues

Do **not** open a public issue for a security vulnerability (e.g. verifier bypass, privilege escalation, panic-triggering packet input). See [SECURITY.md](SECURITY.md) for the disclosure process.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Participation implies agreement to its terms.

## License

By contributing, you agree that your contributions will be licensed under the project's [GPLv2 License](LICENSE).
