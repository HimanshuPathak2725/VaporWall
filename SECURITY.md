# Security Policy

VaporWall operates at the kernel/user-space boundary via eBPF. Vulnerabilities here have an unusually high blast radius — a flaw in the packet filter or the exploit analyzer can mean kernel panics, privilege escalation, or a bypassed threat detector giving a false sense of safety. We take reports seriously and ask you to report privately rather than filing a public issue.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| `main` (pre-release) | ✅ Yes — this project is pre-1.0; only the latest commit on `main` receives fixes |

Once tagged releases begin, this table will be updated to track supported release lines (typically latest major + previous major for a security-fix window).

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report privately using one of these channels:

1. **GitHub Private Vulnerability Reporting** (preferred): go to the repository's **Security** tab → **Report a vulnerability**. This creates a private advisory visible only to maintainers.
2. If that's unavailable, open a draft security advisory or contact the maintainer directly via the email listed on the [maintainer's GitHub profile](https://github.com/HimanshuPathak2725).

### What to include

- A clear description of the vulnerability and its impact (e.g. denial of service, privilege escalation, classifier evasion/poisoning, information disclosure).
- Steps to reproduce, including target kernel version, architecture, and any relevant eBPF verifier output.
- A minimal reproduction (crafted packet, PCAP, or program) if applicable.
- Whether you believe this is exploitable remotely, locally, or only by a process with elevated capabilities.

### What to expect

- **Acknowledgment** within 5 business days.
- **Initial assessment** (severity, affected scope) within 10 business days.
- We'll keep you updated as a fix is developed. We ask for coordinated disclosure — please don't publish details until a fix is released or 90 days have passed, whichever comes first, unless we agree on a different timeline together.
- Credit in the release notes/advisory, if you'd like it.

## Scope

In scope:
- The eBPF programs and their loading/attach logic
- The user-space control plane and its handling of untrusted network input
- The tiny-ML threat classification pipeline (including adversarial/evasion issues)
- Privilege and capability handling (anything that could escalate beyond the capabilities the process was granted)

Out of scope (for now, pre-1.0):
- Issues requiring physical access to the host
- Denial of service that requires already having root/`CAP_BPF` on the target
- Vulnerabilities in upstream dependencies — please report those upstream, though we appreciate a heads-up so we can pin/patch

## Disclosure Philosophy

This is a young, pre-1.0 project. We'd rather hear about a rough edge early and fix it than have it discovered in the wild after wider adoption. If you're unsure whether something rises to the level of a security issue, err on the side of reporting privately — we'd rather triage a false positive than miss a real one.
