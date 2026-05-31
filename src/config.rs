use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Password,
    Key,
    Agent,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    pub key_path: Option<PathBuf>,
    pub password: Option<String>,
    pub sudo_password: Option<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_command_chars")]
    pub max_command_chars: usize,
    #[serde(default = "default_shellcheck")]
    pub shellcheck: bool,
    #[serde(default)]
    pub windows: bool,
    #[serde(default)]
    pub allowed_commands: Vec<String>,
}

fn default_port() -> u16 { 22 }
fn default_timeout_ms() -> u64 { 60_000 }
fn default_max_command_chars() -> usize { 1_000 }
fn default_shellcheck() -> bool { true }

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub shellcheck_path: Option<PathBuf>,
    #[serde(default)]
    pub hosts: std::collections::HashMap<String, HostConfig>,
}

/// Errors that can occur when loading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config file not found at {0}")]
    NotFound(PathBuf),
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("host '{0}': key_path required when auth = key")]
    MissingKeyPath(String),
    #[error("host '{0}': password required when auth = password")]
    MissingPassword(String),
    #[error("no hosts configured")]
    NoHosts,
}

impl Config {
    /// Load and validate config from the given path.
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_owned()));
        }
        let text = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&text)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.hosts.is_empty() {
            return Err(ConfigError::NoHosts);
        }
        for (name, host) in &self.hosts {
            match host.auth {
                AuthMethod::Key if host.key_path.is_none() => {
                    return Err(ConfigError::MissingKeyPath(name.clone()));
                }
                AuthMethod::Password if host.password.is_none() => {
                    return Err(ConfigError::MissingPassword(name.clone()));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Resolve the default XDG config path: ~/.config/ssh-mcp/config.toml
pub fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("ssh-mcp").join("config.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_toml(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn parses_minimal_password_host() {
        let f = write_toml(r#"
[hosts.myhost]
host = "1.2.3.4"
user = "admin"
auth = "password"
password = "secret"
"#);
        let cfg = Config::load(f.path()).unwrap();
        let h = &cfg.hosts["myhost"];
        assert_eq!(h.host, "1.2.3.4");
        assert_eq!(h.port, 22);
        assert_eq!(h.user, "admin");
        assert_eq!(h.auth, AuthMethod::Password);
        assert_eq!(h.password.as_deref(), Some("secret"));
        assert_eq!(h.timeout_ms, 60_000);
        assert_eq!(h.max_command_chars, 1_000);
        assert!(h.shellcheck);
        assert!(!h.windows);
    }

    #[test]
    fn parses_key_host_with_overrides() {
        let f = write_toml(r#"
[hosts.prod]
host = "prod.example.com"
port = 2222
user = "deploy"
auth = "key"
key_path = "/home/user/.ssh/id_ed25519"
timeout_ms = 30000
max_command_chars = 500
shellcheck = false
windows = false
allowed_commands = ["^systemctl\\s", "^journalctl\\s"]
"#);
        let cfg = Config::load(f.path()).unwrap();
        let h = &cfg.hosts["prod"];
        assert_eq!(h.port, 2222);
        assert_eq!(h.auth, AuthMethod::Key);
        assert_eq!(h.timeout_ms, 30_000);
        assert_eq!(h.max_command_chars, 500);
        assert!(!h.shellcheck);
        assert_eq!(h.allowed_commands.len(), 2);
    }

    #[test]
    fn parses_agent_host() {
        let f = write_toml(r#"
[hosts.dev]
host = "dev.example.com"
user = "ubuntu"
auth = "agent"
"#);
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.hosts["dev"].auth, AuthMethod::Agent);
    }

    #[test]
    fn parses_global_shellcheck_path() {
        let f = write_toml(r#"
shellcheck_path = "/usr/local/bin/shellcheck"

[hosts.h]
host = "1.2.3.4"
user = "u"
auth = "agent"
"#);
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(
            cfg.shellcheck_path.as_deref(),
            Some(std::path::Path::new("/usr/local/bin/shellcheck"))
        );
    }

    #[test]
    fn rejects_key_auth_without_key_path() {
        let f = write_toml(r#"
[hosts.h]
host = "1.2.3.4"
user = "u"
auth = "key"
"#);
        assert!(matches!(
            Config::load(f.path()),
            Err(ConfigError::MissingKeyPath(_))
        ));
    }

    #[test]
    fn rejects_password_auth_without_password() {
        let f = write_toml(r#"
[hosts.h]
host = "1.2.3.4"
user = "u"
auth = "password"
"#);
        assert!(matches!(
            Config::load(f.path()),
            Err(ConfigError::MissingPassword(_))
        ));
    }

    #[test]
    fn rejects_empty_hosts() {
        let f = write_toml("");
        assert!(matches!(Config::load(f.path()), Err(ConfigError::NoHosts)));
    }

    #[test]
    fn rejects_unknown_keys() {
        let f = write_toml(r#"
[hosts.h]
host = "1.2.3.4"
user = "u"
auth = "agent"
unknown_field = "oops"
"#);
        assert!(matches!(Config::load(f.path()), Err(ConfigError::Parse(_))));
    }

    #[test]
    fn not_found_returns_error() {
        let result = Config::load(std::path::Path::new("/nonexistent/path.toml"));
        assert!(matches!(result, Err(ConfigError::NotFound(_))));
    }

    #[test]
    fn default_config_path_is_some() {
        // Just verify it resolves without panicking; path may not exist.
        assert!(default_config_path().is_some());
    }
}
