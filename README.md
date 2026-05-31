# ssh-mcp-rs

A Rust MCP server that exposes SSH control over multiple named remote hosts via stdio transport.

## Features

- **Multiple hosts** — configure any number of SSH targets in a single TOML config
- **Five tools** — `exec`, `sudo_exec`, `put_file`, `get_file`, `list_hosts`
- **Three auth methods** — password, SSH key, SSH agent forwarding
- **Security layer** — fast heuristic blocking (fork bombs, device writes, pipe-to-shell), `shellcheck` gate (default on), per-host command allowlist, command length limit
- **Connection pooling** — lazy connect per host, sessions reused across calls

## Installation

```bash
cargo install --path .
```

## Configuration

Default path: `~/.config/ssh-mcp/config.toml`. Override with `--config /path/to/config.toml`.

```toml
[hosts.prod]
host = "192.168.1.10"
port = 22
user = "admin"
auth = "key"                        # "password" | "key" | "agent"
key_path = "~/.ssh/id_ed25519"
sudo_password = "supersecret"       # optional
timeout_ms = 60000                  # default: 60000
max_command_chars = 1000            # default: 1000; 0 = unlimited
shellcheck = true                   # default: true
allowed_commands = []               # optional regex allowlist

[hosts.dev]
host = "dev.example.com"
user = "ubuntu"
auth = "agent"                      # reads $SSH_AUTH_SOCK
```

## MCP Client Setup

```json
{
  "mcpServers": {
    "ssh": {
      "command": "ssh-mcp-rs",
      "args": ["--config", "/path/to/config.toml"]
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `exec` | Run a shell command on a named host |
| `sudo_exec` | Run a command via sudo on a named host |
| `put_file` | Upload a base64-encoded file via SFTP |
| `get_file` | Download a file as base64 via SFTP |
| `list_hosts` | List all configured host names |

## Security

`shellcheck` must be installed and in `$PATH` (or set `shellcheck_path` in config). The server will refuse to start if shellcheck is enabled for any host and the binary is not found.

To disable: set `shellcheck = false` per host.

## Development

```bash
cargo test                        # unit tests
cargo test --test integration     # integration tests (requires Docker)
cargo clippy -- -D warnings
cargo fmt --check
```
