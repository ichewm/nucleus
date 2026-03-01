# Nucleus

**Extremely lightweight Docker alternative for agents**

Nucleus is a minimalist container runtime designed specifically for AI agents running on Linux. It provides isolated execution environments using Linux kernel primitives without the overhead of traditional container runtimes.

## Why Nucleus?

AI agents need isolated, ephemeral execution environments with pre-populated context. Traditional containers are too heavyweight. Nucleus provides:

- **Zero-overhead isolation** — Direct use of cgroups, namespaces, chroot, capabilities, and seccomp
- **Memory-backed filesystems** — Container disk mapped to tmpfs/ramfs, pre-populated with agent context
- **gVisor integration** — Optional application kernel for enhanced security
- **Agent-optimized** — Fast startup, pre-seeded with files agents can read/grep
- **Linux-native** — Runs on standard Linux and NixOS

## Architecture

Nucleus leverages Linux kernel isolation primitives:

- **Namespaces** — PID, mount, network, UTS, IPC, user isolation
- **cgroups** — Resource limits (CPU, memory, I/O)
- **chroot** — Filesystem isolation
- **Capabilities** — Fine-grained privilege control
- **seccomp** — Syscall filtering
- **gVisor** — Optional application kernel (runsc)

Container filesystem is backed by tmpfs/ramfs and pre-populated with context files before agent execution, allowing agents to use standard tools (read, grep, find) on the provided context.

## Platform Support

- Linux (kernel 5.x+)
- NixOS
- **Not supported**: macOS, Windows, BSDs

This is a Linux-only tool by design — the isolation primitives are kernel-specific.

## gVisor Requirements

To use the `--runtime gvisor` option, you must have gVisor's `runsc` runtime installed:

1. **Install gVisor**: Follow the official installation guide at https://gvisor.dev/docs/user_guide/install/

2. **Verify installation**: Ensure `runsc` is in your PATH:
   ```bash
   which runsc
   ```

3. **Usage**:
   ```bash
   nucleus run --runtime gvisor --context ./ctx/ -- ./agent
   ```

**Notes:**
- gVisor uses the ptrace platform by default (no KVM required)
- Container state is stored in `/tmp/nucleus-runsc/`
- Set `NUCLEUS_GVISOR_DEBUG=1` environment variable for verbose runsc logging

## Installation

```bash
cargo install nucleus
```

## Usage

```bash
# Run agent in isolated container with pre-populated context
nucleus run --context ./agent-context/ -- /usr/bin/agent

# Specify resource limits
nucleus run --memory 512M --cpus 2 --context ./ctx/ -- ./agent

# Use gVisor for enhanced isolation
nucleus run --runtime gvisor --context ./ctx/ -- ./agent

# Set a custom hostname for the container
nucleus run --hostname my-container --context ./ctx/ -- ./agent

# Set I/O throttling limits (auto-detect root device)
nucleus run --io-limit auto:1000:1000:10M:10M --context ./ctx/ -- ./agent

# Set I/O limits for a specific device (major:minor format)
nucleus run --io-limit 8:0:5000:5000:50M:50M --context ./ctx/ -- ./agent
```

## Context Filtering

When copying context into the container, nucleus automatically excludes sensitive files to prevent accidental exposure of secrets:

**Excluded patterns:**
- VCS directories: `.git`, `.svn`
- Build artifacts: `target/`, `node_modules/`
- Editor files: `.*.swp`
- Environment files: `.env`, `.env.*`
- Credential files (case-insensitive): `*credential*`, `*secret*`, `*private*`
- Key/certificate files: `*.pem`, `*.key`, `*.p12`, `*.crt`