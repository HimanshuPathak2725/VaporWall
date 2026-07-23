## Summary

<!-- What does this PR do, and why? Link related issues with "Closes #123". -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation
- [ ] CI / tooling
- [ ] Refactor (no functional change)

## Kernel / eBPF impact

<!-- Required if this PR touches eBPF programs, attach/load logic, or the user-space/kernel-space boundary. Otherwise write "N/A". -->

- [ ] N/A — no eBPF or kernel-boundary changes
- [ ] Changes an existing eBPF program's logic
- [ ] Adds/changes an attach point (XDP, TC, kprobe, etc.)
- [ ] Changes map layout or shared user-space/kernel-space data structures
- [ ] Verified against the eBPF verifier on: <!-- kernel version + arch -->

## How was this tested?

<!-- Commands run, manual verification steps, target kernel version/arch if relevant. -->

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## Checklist

- [ ] `cargo fmt` and `cargo clippy` pass with no warnings
- [ ] I added/updated tests where feasible
- [ ] I updated relevant docs (README, CONTRIBUTING, inline comments)
- [ ] This PR does not introduce blocking calls on the hot packet-processing path
- [ ] I've reviewed my own diff before requesting review
