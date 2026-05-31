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
