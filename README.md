# ssh-mcp-rs

A Rust MCP server that gives Claude Code SSH control over remote hosts — run commands, transfer files, and manage servers without leaving your editor.

## Features

- **Five tools** — `exec`, `sudo_exec`, `put_file`, `get_file`, `list_hosts`
- **Three auth methods** — SSH key (`~` expanded), SSH agent, password
- **Security layer** — `shellcheck` gate (default on), heuristic blocking of fork bombs / device writes / pipe-to-shell, per-host command allowlist, command length limit
- **Multiple hosts** — configure any number of SSH targets in one TOML file
- **Connection pooling** — lazy connect per host, sessions reused across calls

## Installation

```bash
cargo install --path .
```

## Claude Code Setup

**1. Install and register the server:**

```bash
cargo install --path .
claude mcp add ssh ~/.cargo/bin/ssh-mcp-rs
```

**2. Create `~/.config/ssh-mcp/config.toml`:**

```toml
[hosts.myserver]
host = "myserver.example.com"
user = "deploy"
auth = "key"
key_path = "~/.ssh/id_ed25519"     # ~ is expanded automatically
```

**3. Restart Claude Code.** The `ssh` MCP server loads at startup.

## Configuration Reference

Default config path: `~/.config/ssh-mcp/config.toml`. Override with `--config /path/to/config.toml`.

```toml
# shellcheck_path = "~/bin/shellcheck"   # optional; overrides PATH lookup

[hosts.prod]
host = "192.168.1.10"
port = 22                           # default: 22
user = "admin"
auth = "key"                        # "password" | "key" | "agent"
key_path = "~/.ssh/id_ed25519"      # required for auth = "key"; ~ expanded
sudo_password = "supersecret"       # optional; required for sudo_exec
timeout_ms = 60000                  # default: 60000
max_command_chars = 1000            # default: 1000; 0 = unlimited
shellcheck = true                   # default: true
allowed_commands = []               # optional regex allowlist

[hosts.dev]
host = "dev.example.com"
user = "ubuntu"
auth = "agent"                      # reads $SSH_AUTH_SOCK
shellcheck = false
```

## Tools

| Tool | Description |
|------|-------------|
| `exec` | Run a shell command on a named host |
| `sudo_exec` | Run a command via sudo on a named host |
| `put_file` | Upload a file (base64-encoded) via SFTP |
| `get_file` | Download a file as base64 via SFTP |
| `list_hosts` | List all configured host names |

## Security

`shellcheck` must be installed and in `$PATH` (or set `shellcheck_path` in config). The server refuses to start if shellcheck is enabled for any host and the binary is not found.

To disable per host: `shellcheck = false`.

## Development

```bash
cargo test                        # unit tests
cargo test --test integration     # integration tests (requires Docker)
cargo clippy -- -D warnings
cargo fmt --check
```
