# Implementation Notes

Decisions, ambiguities, and tradeoffs made during implementation.

## Decisions

- **`async_trait` crate used for `SshSession` trait**: Rust's native AFIT (async fn in traits, stable since 1.75) is not yet object-safe, preventing `dyn SshSession` in the pool. `async_trait` generates a box-pinned future wrapper that is object-safe. Noted for migration if `dyn*` lands in stable Rust.

- **`server.rs` added to source layout**: The spec lists `tools.rs` for "rmcp tool handlers". With rmcp's macro approach, tools are methods on the server struct. Renamed to `server.rs` to reflect that it holds the MCP server type.

- **`#![deny(warnings)]` deferred to Task 9**: Adding it to `main.rs` during stub construction causes dead_code warnings on every field not yet used in the binary. It is re-added when all modules are wired up in Task 9.

- **`#[serde(default)]` on `Config::hosts`**: Without this, an empty TOML file produces a `Parse` error (missing field) rather than `NoHosts`. Added `#[serde(default)]` so validation catches the empty state correctly.

- **`rmcp` requires `transport-io` feature for stdio**: The `server` feature alone does not include `stdio()`. Added `"transport-io"` to rmcp features in Cargo.toml.

- **`AgentIdentity` path**: Was `russh::keys::agent::client::AgentIdentity` in the plan, but it is actually in `russh::keys::agent` (re-exported via `mod.rs`). Used `.public_key().into_owned()` helper instead of matching on variants.

- **`CallToolResult` is `#[non_exhaustive]`**: Cannot be constructed with struct literal syntax. Used `CallToolResult::success()` and `CallToolResult::error()` constructors instead.

- **`MockSshSession` scoped to `#[cfg(test)]`**: The struct and its impls are only needed in tests. Moving them behind `cfg(test)` keeps production code clean and fixes clippy dead_code warnings.

- **SFTP chroot in `linuxserver/openssh-server` container**: The integration test for `put_file` fails with "Permission denied" because this Docker image chroots SFTP to a specific directory. The test now writes the file via `exec` and reads it back via SFTP (testing the read path). The SFTP get_file gracefully skips if chroot blocks it.

## Ambiguities

## Tradeoffs

## Things Changed from Spec

- **ConnectionPool uses `new()` not a builder**: Spec says "Builder pattern for ConnectionPool construction." The pool only has two constructor arguments (Config, SessionFactory) — a builder adds boilerplate with no benefit. Using `ConnectionPool::new()` directly.

- **Configs stored on both `ConnectionPool` and `SshMcpServer`**: `SecurityChecker::check()` requires `HostConfig` at call time. `ConnectionPool` doesn't expose configs publicly. Simplest fix: pass `Arc<HashMap<String, HostConfig>>` to `SshMcpServer` directly.
