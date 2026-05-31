use std::path::Path;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::config::{Config, ConfigError};
use crate::pool::ConnectionPool;

/// Reload config from `path`. On success, reconcile the pool and update the
/// shared config. On parse/validation error, keep the old config active and
/// return the error so callers can log it.
pub async fn reload_config(
    path: &Path,
    shared_config: &Arc<RwLock<Config>>,
    pool: &Arc<ConnectionPool>,
) -> Result<(), ConfigError> {
    let new_cfg = Config::load(path)?;
    pool.reconcile(&new_cfg).await;
    *shared_config.write().await = new_cfg;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMethod, HostConfig};
    use crate::error::ToolError;
    use crate::pool::SessionFactory;
    use crate::ssh::{MockSshSession, SshSession};
    use std::collections::HashMap;
    use std::io::Write as _;
    use std::sync::Mutex;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_host_config(host: &str) -> HostConfig {
        HostConfig {
            host: format!("{host}.example.com"),
            port: 22,
            user: "u".into(),
            auth: AuthMethod::Agent,
            key_path: None,
            password: None,
            sudo_password: None,
            timeout_ms: 60_000,
            max_command_chars: 1_000,
            shellcheck: false,
            windows: false,
            allowed_commands: vec![],
        }
    }

    fn make_config(host_names: &[&str]) -> Config {
        let mut hosts = HashMap::new();
        for &n in host_names {
            hosts.insert(n.to_string(), make_host_config(n));
        }
        Config {
            shellcheck_path: None,
            hosts,
        }
    }

    fn write_toml(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    struct NoopFactory;

    #[async_trait::async_trait]
    impl SessionFactory for NoopFactory {
        async fn connect(
            &self,
            _name: &str,
            _config: &HostConfig,
        ) -> Result<Arc<dyn SshSession>, ToolError> {
            Ok(Arc::new(MockSshSession::new()) as Arc<dyn SshSession>)
        }
    }

    fn make_pool(cfg: Config) -> Arc<ConnectionPool> {
        Arc::new(ConnectionPool::new(
            cfg,
            Arc::new(NoopFactory) as Arc<dyn SessionFactory>,
        ))
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    /// After reload_config with a valid new config that adds a host, the pool
    /// exposes the new host and the shared config reflects it.
    #[tokio::test]
    async fn reload_adds_new_host_to_pool_and_config() {
        let initial = make_config(&["prod"]);
        let shared = Arc::new(RwLock::new(initial.clone()));
        let pool = make_pool(initial);

        let f = write_toml(
            r#"
[hosts.prod]
host = "prod.example.com"
user = "u"
auth = "agent"

[hosts.dev]
host = "dev.example.com"
user = "u"
auth = "agent"
"#,
        );

        reload_config(f.path(), &shared, &pool).await.unwrap();

        // Pool now knows both hosts.
        let names = pool.host_names().await;
        assert!(names.contains(&"prod".to_string()));
        assert!(names.contains(&"dev".to_string()));

        // Shared config also reflects the addition.
        let cfg = shared.read().await;
        assert!(cfg.hosts.contains_key("dev"));
    }

    /// After reload_config where a host was removed, the pool no longer has it.
    #[tokio::test]
    async fn reload_removes_host_from_pool_and_config() {
        let initial = make_config(&["prod", "dev"]);
        let shared = Arc::new(RwLock::new(initial.clone()));
        let pool = make_pool(initial);

        let f = write_toml(
            r#"
[hosts.prod]
host = "prod.example.com"
user = "u"
auth = "agent"
"#,
        );

        reload_config(f.path(), &shared, &pool).await.unwrap();

        let names = pool.host_names().await;
        assert!(names.contains(&"prod".to_string()));
        assert!(!names.contains(&"dev".to_string()));

        let cfg = shared.read().await;
        assert!(!cfg.hosts.contains_key("dev"));
    }

    /// reload_config with an invalid TOML file returns an error and leaves the
    /// shared config and pool unchanged.
    #[tokio::test]
    async fn reload_invalid_config_keeps_old_state() {
        let initial = make_config(&["prod"]);
        let shared = Arc::new(RwLock::new(initial.clone()));
        let pool = make_pool(initial);

        // Write a config that fails validation (no hosts).
        let f = write_toml("shellcheck_path = \"/usr/bin/shellcheck\"");

        let result = reload_config(f.path(), &shared, &pool).await;

        // Should return an error.
        assert!(result.is_err());

        // Pool and config are untouched.
        assert_eq!(pool.host_names().await, vec!["prod"]);
        let cfg = shared.read().await;
        assert!(cfg.hosts.contains_key("prod"));
        assert!(!cfg.hosts.is_empty());
    }

    /// reload_config with a file that does not exist returns an error.
    #[tokio::test]
    async fn reload_missing_file_keeps_old_state() {
        let initial = make_config(&["prod"]);
        let shared = Arc::new(RwLock::new(initial.clone()));
        let pool = make_pool(initial);

        let result = reload_config(Path::new("/nonexistent/path.toml"), &shared, &pool).await;

        assert!(matches!(result, Err(ConfigError::NotFound(_))));
        assert_eq!(pool.host_names().await, vec!["prod"]);
    }

    /// reload_config when config is unchanged does not reconnect existing sessions.
    #[tokio::test]
    async fn reload_unchanged_config_no_reconnect() {
        // Use a counting factory.
        struct CountingFactory(Mutex<usize>);
        #[async_trait::async_trait]
        impl SessionFactory for CountingFactory {
            async fn connect(
                &self,
                _: &str,
                _: &HostConfig,
            ) -> Result<Arc<dyn SshSession>, ToolError> {
                *self.0.lock().unwrap() += 1;
                Ok(Arc::new(MockSshSession::new()) as Arc<dyn SshSession>)
            }
        }

        let factory = Arc::new(CountingFactory(Mutex::new(0)));
        let initial = make_config(&["prod"]);
        let shared = Arc::new(RwLock::new(initial.clone()));
        let pool = Arc::new(ConnectionPool::new(
            initial,
            Arc::clone(&factory) as Arc<dyn SessionFactory>,
        ));

        // Connect once.
        pool.get("prod").await.unwrap();
        assert_eq!(*factory.0.lock().unwrap(), 1);

        // Write config that matches exactly what make_host_config produces
        // (shellcheck = false, port = 22, timeout_ms = 60000, etc.).
        let f = write_toml(
            r#"
[hosts.prod]
host = "prod.example.com"
port = 22
user = "u"
auth = "agent"
timeout_ms = 60000
max_command_chars = 1000
shellcheck = false
windows = false
"#,
        );

        reload_config(f.path(), &shared, &pool).await.unwrap();

        // Still only one connection (session not dropped).
        pool.get("prod").await.unwrap();
        assert_eq!(*factory.0.lock().unwrap(), 1);
    }
}
