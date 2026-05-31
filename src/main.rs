use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use rmcp::{transport::stdio, ServiceExt};
use tracing_subscriber::EnvFilter;

mod config;
mod error;
mod pool;
mod security;
mod server;
mod ssh;

use config::Config;
use pool::ConnectionPool;
use security::{resolve_shellcheck, SecurityChecker};
use server::SshMcpServer;
use ssh::RusshFactory;

#[derive(Parser, Debug)]
#[command(
    name = "ssh-mcp-rs",
    about = "SSH MCP server exposing multiple remote hosts"
)]
struct Cli {
    /// Path to config file (default: ~/.config/ssh-mcp/config.toml)
    #[arg(long, short)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let cli = Cli::parse();

    let config_path = cli
        .config
        .or_else(config::default_config_path)
        .ok_or_else(|| anyhow::anyhow!("could not determine config path; use --config"))?;

    tracing::info!(path = %config_path.display(), "loading config");
    let cfg = Config::load(&config_path)?;

    // Shellcheck preflight: if any non-Windows host has shellcheck enabled, verify the binary.
    let needs_shellcheck = cfg.hosts.values().any(|h| h.shellcheck && !h.windows);
    let shellcheck_bin = if needs_shellcheck {
        let bin = resolve_shellcheck(cfg.shellcheck_path.as_deref())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        tracing::info!(path = %bin.display(), "shellcheck resolved");
        Some(bin)
    } else {
        tracing::info!("shellcheck disabled for all hosts — skipping preflight");
        None
    };

    let security = Arc::new(SecurityChecker::new(shellcheck_bin));
    let configs = Arc::new(cfg.hosts.clone());
    let pool = Arc::new(ConnectionPool::new(
        cfg,
        Arc::new(RusshFactory) as Arc<dyn pool::SessionFactory>,
    ));
    let srv = SshMcpServer::new(pool, security, configs);

    tracing::info!("starting SSH MCP server on stdio");
    let service = srv.serve(stdio()).await?;
    service.waiting().await?;

    Ok(())
}
