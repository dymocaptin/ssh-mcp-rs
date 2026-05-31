use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::config::{Config, HostConfig};
use crate::error::ToolError;
use crate::ssh::SshSession;

/// Factory for creating SSH sessions. Injected into ConnectionPool for testability.
#[async_trait]
pub trait SessionFactory: Send + Sync {
    async fn connect(
        &self,
        name: &str,
        config: &HostConfig,
    ) -> Result<Arc<dyn SshSession>, ToolError>;
}

/// Holds one persistent SSH session per named host, lazily connected on first use.
pub struct ConnectionPool {
    configs: HashMap<String, HostConfig>,
    sessions: Arc<RwLock<HashMap<String, Arc<dyn SshSession>>>>,
    factory: Arc<dyn SessionFactory>,
}

impl ConnectionPool {
    pub fn new(config: Config, factory: Arc<dyn SessionFactory>) -> Self {
        Self {
            configs: config.hosts,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            factory,
        }
    }

    /// Return the session for `host_name`, connecting lazily on first call.
    pub async fn get(&self, host_name: &str) -> Result<Arc<dyn SshSession>, ToolError> {
        // Fast path: already connected.
        {
            let sessions = self.sessions.read().await;
            if let Some(s) = sessions.get(host_name) {
                return Ok(Arc::clone(s));
            }
        }

        // Validate host exists before acquiring write lock.
        let host_config = self
            .configs
            .get(host_name)
            .ok_or_else(|| ToolError::UnknownHost(host_name.to_string()))?;

        // Slow path: connect and cache.
        let session = self.factory.connect(host_name, host_config).await?;
        let mut sessions = self.sessions.write().await;
        // Re-check after write lock: another task may have raced us.
        if let Some(s) = sessions.get(host_name) {
            return Ok(Arc::clone(s));
        }
        sessions.insert(host_name.to_string(), Arc::clone(&session));
        Ok(session)
    }

    /// Remove a cached session (forces reconnect on next `get`).
    pub async fn remove(&self, host_name: &str) {
        self.sessions.write().await.remove(host_name);
    }

    /// Return sorted list of all configured host names.
    pub fn host_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.configs.keys().cloned().collect();
        names.sort();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthMethod;
    use crate::ssh::{ExecOutput, MockSshSession};
    use std::sync::Mutex;

    fn make_config(host_names: &[&str]) -> Config {
        let mut hosts = HashMap::new();
        for &name in host_names {
            hosts.insert(
                name.to_string(),
                HostConfig {
                    host: format!("{name}.example.com"),
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
                },
            );
        }
        Config {
            shellcheck_path: None,
            hosts,
        }
    }

    struct MockFactory {
        sessions: Mutex<HashMap<String, Arc<MockSshSession>>>,
        connect_count: Mutex<usize>,
    }

    impl MockFactory {
        fn new() -> Self {
            Self {
                sessions: Mutex::new(HashMap::new()),
                connect_count: Mutex::new(0),
            }
        }

        fn add(&self, name: &str, session: Arc<MockSshSession>) {
            self.sessions
                .lock()
                .unwrap()
                .insert(name.to_string(), session);
        }
    }

    #[async_trait]
    impl SessionFactory for MockFactory {
        async fn connect(
            &self,
            name: &str,
            _config: &HostConfig,
        ) -> Result<Arc<dyn SshSession>, ToolError> {
            *self.connect_count.lock().unwrap() += 1;
            self.sessions
                .lock()
                .unwrap()
                .get(name)
                .map(|s| Arc::clone(s) as Arc<dyn SshSession>)
                .ok_or_else(|| ToolError::UnknownHost(name.to_string()))
        }
    }

    #[tokio::test]
    async fn get_unknown_host_returns_error() {
        let factory = Arc::new(MockFactory::new());
        let pool = ConnectionPool::new(make_config(&["prod"]), factory as Arc<dyn SessionFactory>);
        assert!(matches!(
            pool.get("nonexistent").await,
            Err(ToolError::UnknownHost(_))
        ));
    }

    #[tokio::test]
    async fn get_connects_lazily_on_first_call() {
        let factory = Arc::new(MockFactory::new());
        factory.add("prod", Arc::new(MockSshSession::new()));
        let pool = ConnectionPool::new(
            make_config(&["prod"]),
            Arc::clone(&factory) as Arc<dyn SessionFactory>,
        );

        assert_eq!(*factory.connect_count.lock().unwrap(), 0);
        pool.get("prod").await.unwrap();
        assert_eq!(*factory.connect_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn get_reuses_existing_session() {
        let factory = Arc::new(MockFactory::new());
        factory.add("prod", Arc::new(MockSshSession::new()));
        let pool = ConnectionPool::new(
            make_config(&["prod"]),
            Arc::clone(&factory) as Arc<dyn SessionFactory>,
        );

        pool.get("prod").await.unwrap();
        pool.get("prod").await.unwrap();
        assert_eq!(*factory.connect_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn remove_forces_reconnect() {
        let factory = Arc::new(MockFactory::new());
        factory.add("prod", Arc::new(MockSshSession::new()));
        let pool = ConnectionPool::new(
            make_config(&["prod"]),
            Arc::clone(&factory) as Arc<dyn SessionFactory>,
        );

        pool.get("prod").await.unwrap();
        pool.remove("prod").await;
        pool.get("prod").await.unwrap();
        assert_eq!(*factory.connect_count.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn host_names_returns_sorted_list() {
        let factory = Arc::new(MockFactory::new());
        let pool = ConnectionPool::new(
            make_config(&["zebra", "alpha", "mango"]),
            factory as Arc<dyn SessionFactory>,
        );
        assert_eq!(pool.host_names(), vec!["alpha", "mango", "zebra"]);
    }

    #[tokio::test]
    async fn exec_through_pool_uses_session() {
        let factory = Arc::new(MockFactory::new());
        let mock = Arc::new(MockSshSession::new());
        mock.set_exec(
            "whoami",
            ExecOutput {
                stdout: "root\n".into(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
        factory.add("prod", Arc::clone(&mock));
        let pool = ConnectionPool::new(
            make_config(&["prod"]),
            Arc::clone(&factory) as Arc<dyn SessionFactory>,
        );

        let session = pool.get("prod").await.unwrap();
        let out = session.exec("whoami").await.unwrap();
        assert_eq!(out.stdout, "root\n");
    }
}
