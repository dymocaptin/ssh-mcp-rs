use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::error::ToolError;

/// Output from a remote command execution.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: u32,
}

/// Abstraction over an SSH connection's operations.
/// Uses async_trait for object safety so the pool can store `dyn SshSession`.
#[async_trait]
pub trait SshSession: Send + Sync {
    async fn exec(&self, command: &str) -> Result<ExecOutput, ToolError>;
    async fn put_file(&self, remote_path: &str, content: &[u8], mode: u32) -> Result<(), ToolError>;
    async fn get_file(&self, remote_path: &str) -> Result<Vec<u8>, ToolError>;
}

/// Configurable mock for unit tests — no network required.
#[derive(Clone, Default)]
pub struct MockSshSession {
    /// Maps command string → result. Returns Ok with empty output if not found.
    pub exec_responses: Arc<Mutex<HashMap<String, Result<ExecOutput, String>>>>,
    /// Maps remote_path → content for get_file.
    pub files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    /// Records all exec calls made.
    pub exec_calls: Arc<Mutex<Vec<String>>>,
    /// Records all put_file calls (path, mode).
    pub put_calls: Arc<Mutex<Vec<(String, u32)>>>,
}

impl MockSshSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_exec(&self, command: &str, output: ExecOutput) {
        self.exec_responses
            .lock()
            .unwrap()
            .insert(command.to_string(), Ok(output));
    }

    pub fn set_exec_error(&self, command: &str, message: &str) {
        self.exec_responses
            .lock()
            .unwrap()
            .insert(command.to_string(), Err(message.to_string()));
    }

    pub fn set_file(&self, path: &str, content: Vec<u8>) {
        self.files.lock().unwrap().insert(path.to_string(), content);
    }
}

#[async_trait]
impl SshSession for MockSshSession {
    async fn exec(&self, command: &str) -> Result<ExecOutput, ToolError> {
        self.exec_calls.lock().unwrap().push(command.to_string());
        let responses = self.exec_responses.lock().unwrap();
        match responses.get(command) {
            Some(Ok(out)) => Ok(out.clone()),
            Some(Err(msg)) => Err(ToolError::InvalidParam(msg.clone())),
            None => Ok(ExecOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            }),
        }
    }

    async fn put_file(&self, remote_path: &str, content: &[u8], mode: u32) -> Result<(), ToolError> {
        self.put_calls
            .lock()
            .unwrap()
            .push((remote_path.to_string(), mode));
        self.files
            .lock()
            .unwrap()
            .insert(remote_path.to_string(), content.to_vec());
        Ok(())
    }

    async fn get_file(&self, remote_path: &str) -> Result<Vec<u8>, ToolError> {
        self.files
            .lock()
            .unwrap()
            .get(remote_path)
            .cloned()
            .ok_or_else(|| ToolError::Sftp {
                host: "mock".into(),
                message: format!("file not found: {remote_path}"),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_exec_returns_configured_output() {
        let mock = MockSshSession::new();
        mock.set_exec(
            "ls",
            ExecOutput { stdout: "file.txt\n".into(), stderr: String::new(), exit_code: 0 },
        );
        let out = mock.exec("ls").await.unwrap();
        assert_eq!(out.stdout, "file.txt\n");
        assert_eq!(out.exit_code, 0);
    }

    #[tokio::test]
    async fn mock_exec_unknown_command_returns_empty_ok() {
        let mock = MockSshSession::new();
        let out = mock.exec("unknown").await.unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.is_empty());
    }

    #[tokio::test]
    async fn mock_exec_records_calls() {
        let mock = MockSshSession::new();
        mock.exec("cmd1").await.unwrap();
        mock.exec("cmd2").await.unwrap();
        let calls = mock.exec_calls.lock().unwrap();
        assert_eq!(*calls, vec!["cmd1", "cmd2"]);
    }

    #[tokio::test]
    async fn mock_put_and_get_file_roundtrip() {
        let mock = MockSshSession::new();
        let content = b"hello world";
        mock.put_file("/tmp/test.txt", content, 0o644).await.unwrap();
        let retrieved = mock.get_file("/tmp/test.txt").await.unwrap();
        assert_eq!(retrieved, content);
    }

    #[tokio::test]
    async fn mock_get_file_missing_returns_error() {
        let mock = MockSshSession::new();
        assert!(mock.get_file("/nonexistent").await.is_err());
    }

    #[tokio::test]
    async fn mock_put_records_mode() {
        let mock = MockSshSession::new();
        mock.put_file("/tmp/a.txt", b"data", 0o600).await.unwrap();
        let puts = mock.put_calls.lock().unwrap();
        assert_eq!(puts[0], ("/tmp/a.txt".to_string(), 0o600));
    }
}

// ─── Real SSH implementation via russh ───────────────────────────────────────

use std::borrow::Cow;
use std::sync::Arc as StdArc;
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::ChannelMsg;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::io::AsyncWriteExt as _;

use crate::config::{AuthMethod, HostConfig};
use crate::pool::SessionFactory;

/// russh client handler — accepts any server key (trust-on-first-use).
struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A live SSH session backed by a russh Handle.
pub struct RusshSession {
    handle: Handle<ClientHandler>,
    host_name: String,
    #[allow(dead_code)]
    timeout_ms: u64,
}

impl RusshSession {
    /// Establish a new SSH connection using the given host config.
    pub async fn connect(host_name: &str, config: &HostConfig) -> Result<Self, ToolError> {
        let russh_config = StdArc::new(client::Config {
            inactivity_timeout: Some(Duration::from_millis(config.timeout_ms)),
            preferred: russh::Preferred {
                kex: Cow::Owned(vec![
                    russh::kex::CURVE25519_PRE_RFC_8731,
                    russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
                ]),
                ..Default::default()
            },
            ..Default::default()
        });

        let addr = (config.host.as_str(), config.port);
        let mut handle = client::connect(russh_config, addr, ClientHandler)
            .await
            .map_err(|e| ToolError::SshConnect { host: host_name.to_string(), source: e })?;

        let auth_ok = Self::authenticate(&mut handle, host_name, config).await?;
        if !auth_ok {
            return Err(ToolError::SshAuth { host: host_name.to_string() });
        }

        Ok(Self { handle, host_name: host_name.to_string(), timeout_ms: config.timeout_ms })
    }

    async fn authenticate(
        handle: &mut Handle<ClientHandler>,
        host_name: &str,
        config: &HostConfig,
    ) -> Result<bool, ToolError> {
        let user = config.user.clone();
        let result = match &config.auth {
            AuthMethod::Password => {
                let password = config.password.as_deref().unwrap_or("");
                handle
                    .authenticate_password(user, password)
                    .await
                    .map_err(|e| ToolError::SshConnect { host: host_name.to_string(), source: e })?
            }
            AuthMethod::Key => {
                let path = config.key_path.as_deref().unwrap();
                let key_pair = load_secret_key(path, None).map_err(|e| {
                    ToolError::InvalidParam(format!("failed to load key {path:?}: {e}"))
                })?;
                let best_hash = handle
                    .best_supported_rsa_hash()
                    .await
                    .map_err(|e| ToolError::SshConnect { host: host_name.to_string(), source: e })?
                    .flatten();
                handle
                    .authenticate_publickey(
                        user,
                        PrivateKeyWithHashAlg::new(StdArc::new(key_pair), best_hash),
                    )
                    .await
                    .map_err(|e| ToolError::SshConnect { host: host_name.to_string(), source: e })?
            }
            AuthMethod::Agent => {
                use russh::keys::agent::client::AgentClient;
                let mut agent = AgentClient::connect_env().await.map_err(|_| {
                    ToolError::InvalidParam("SSH_AUTH_SOCK not set or agent unavailable".into())
                })?;
                let identities = agent.request_identities().await.map_err(|e| {
                    ToolError::InvalidParam(format!("agent request_identities failed: {e}"))
                })?;
                let mut authenticated = false;
                for identity in &identities {
                    // Use the .public_key() helper which works for both plain keys and certs.
                    let pubkey = identity.public_key().into_owned();
                    let best_hash = handle
                        .best_supported_rsa_hash()
                        .await
                        .map_err(|e| ToolError::SshConnect {
                            host: host_name.to_string(),
                            source: e,
                        })?
                        .flatten();
                    if let Ok(r) = handle
                        .authenticate_publickey_with(user.clone(), pubkey, best_hash, &mut agent)
                        .await
                    {
                        if r.success() {
                            authenticated = true;
                            break;
                        }
                    }
                }
                if authenticated {
                    russh::client::AuthResult::Success
                } else {
                    russh::client::AuthResult::Failure {
                        remaining_methods: russh::MethodSet::empty(),
                        partial_success: false,
                    }
                }
            }
        };
        Ok(result.success())
    }
}

#[async_trait]
impl SshSession for RusshSession {
    async fn exec(&self, command: &str) -> Result<ExecOutput, ToolError> {
        let mut channel = self.handle.channel_open_session().await.map_err(|e| {
            ToolError::SshConnect { host: self.host_name.clone(), source: e }
        })?;
        channel.exec(true, command).await.map_err(|e| {
            ToolError::SshConnect { host: self.host_name.clone(), source: e }
        })?;

        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut exit_code: u32 = 0;

        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { ref data }) => {
                    stdout.push_str(&String::from_utf8_lossy(data));
                }
                Some(ChannelMsg::ExtendedData { ref data, ext: 1 }) => {
                    stderr.push_str(&String::from_utf8_lossy(data));
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    exit_code = exit_status;
                }
                None => break,
                _ => {}
            }
        }

        Ok(ExecOutput { stdout, stderr, exit_code })
    }

    async fn put_file(
        &self,
        remote_path: &str,
        content: &[u8],
        mode: u32,
    ) -> Result<(), ToolError> {
        let channel = self.handle.channel_open_session().await.map_err(|e| {
            ToolError::SshConnect { host: self.host_name.clone(), source: e }
        })?;
        channel.request_subsystem(true, "sftp").await.map_err(|e| {
            ToolError::SshConnect { host: self.host_name.clone(), source: e }
        })?;
        let sftp = SftpSession::new(channel.into_stream()).await.map_err(|e| {
            ToolError::Sftp { host: self.host_name.clone(), message: e.to_string() }
        })?;

        let flags = OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE;
        let mut file = sftp.open_with_flags(remote_path, flags).await.map_err(|e| {
            ToolError::Sftp { host: self.host_name.clone(), message: e.to_string() }
        })?;

        // Set Unix permissions via SFTP file attributes.
        use russh_sftp::protocol::FileAttributes;
        let mut attrs = FileAttributes::default();
        attrs.permissions = Some(mode);
        file.set_metadata(attrs).await.map_err(|e| {
            ToolError::Sftp { host: self.host_name.clone(), message: e.to_string() }
        })?;

        file.write_all(content).await.map_err(|e| {
            ToolError::Sftp { host: self.host_name.clone(), message: e.to_string() }
        })?;
        file.flush().await.map_err(|e| {
            ToolError::Sftp { host: self.host_name.clone(), message: e.to_string() }
        })?;
        Ok(())
    }

    async fn get_file(&self, remote_path: &str) -> Result<Vec<u8>, ToolError> {
        let channel = self.handle.channel_open_session().await.map_err(|e| {
            ToolError::SshConnect { host: self.host_name.clone(), source: e }
        })?;
        channel.request_subsystem(true, "sftp").await.map_err(|e| {
            ToolError::SshConnect { host: self.host_name.clone(), source: e }
        })?;
        let sftp = SftpSession::new(channel.into_stream()).await.map_err(|e| {
            ToolError::Sftp { host: self.host_name.clone(), message: e.to_string() }
        })?;

        let flags = OpenFlags::READ;
        let mut file = sftp.open_with_flags(remote_path, flags).await.map_err(|e| {
            ToolError::Sftp { host: self.host_name.clone(), message: e.to_string() }
        })?;

        use tokio::io::AsyncReadExt as _;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await.map_err(|e| {
            ToolError::Sftp { host: self.host_name.clone(), message: e.to_string() }
        })?;
        Ok(buf)
    }
}

/// Production SessionFactory — creates real RusshSession connections.
pub struct RusshFactory;

#[async_trait]
impl SessionFactory for RusshFactory {
    async fn connect(
        &self,
        name: &str,
        config: &HostConfig,
    ) -> Result<Arc<dyn SshSession>, ToolError> {
        let session = RusshSession::connect(name, config).await?;
        Ok(Arc::new(session))
    }
}
