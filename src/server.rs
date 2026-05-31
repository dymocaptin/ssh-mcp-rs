use std::collections::HashMap;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use serde::Deserialize;

use crate::config::HostConfig;
use crate::error::ToolError;
use crate::pool::ConnectionPool;
use crate::security::SecurityChecker;

/// Parameters for the `exec` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecParams {
    #[schemars(description = "Name of the configured SSH host")]
    pub host: String,
    #[schemars(description = "Shell command to execute")]
    pub command: String,
    #[schemars(description = "Optional description for the audit log")]
    pub description: Option<String>,
}

/// Parameters for the `sudo_exec` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SudoExecParams {
    #[schemars(description = "Name of the configured SSH host")]
    pub host: String,
    #[schemars(description = "Shell command to execute via sudo")]
    pub command: String,
    #[schemars(description = "Optional description for the audit log")]
    pub description: Option<String>,
}

/// Parameters for the `put_file` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PutFileParams {
    #[schemars(description = "Name of the configured SSH host")]
    pub host: String,
    #[schemars(description = "Absolute destination path on the remote host")]
    pub remote_path: String,
    #[schemars(description = "Base64-encoded file content")]
    pub content: String,
    #[schemars(description = "Unix permission bits as decimal (default: 420 = 0o644)")]
    pub mode: Option<u32>,
}

/// Parameters for the `get_file` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetFileParams {
    #[schemars(description = "Name of the configured SSH host")]
    pub host: String,
    #[schemars(description = "Absolute path of the file to retrieve")]
    pub remote_path: String,
}

/// The MCP server: holds pool, security checker, host configs, and tool router.
#[derive(Clone)]
pub struct SshMcpServer {
    pool: Arc<ConnectionPool>,
    security: Arc<SecurityChecker>,
    configs: Arc<HashMap<String, HostConfig>>,
    #[allow(dead_code)]
    tool_router: ToolRouter<SshMcpServer>,
}

#[tool_router]
impl SshMcpServer {
    /// Create a new server instance.
    pub fn new(
        pool: Arc<ConnectionPool>,
        security: Arc<SecurityChecker>,
        configs: Arc<HashMap<String, HostConfig>>,
    ) -> Self {
        Self {
            pool,
            security,
            configs,
            tool_router: Self::tool_router(),
        }
    }

    fn host_config(&self, host: &str) -> Result<&HostConfig, McpError> {
        self.configs
            .get(host)
            .ok_or_else(|| ToolError::UnknownHost(host.to_string()).into_mcp_error())
    }

    fn validate_command(command: &str) -> Result<(), McpError> {
        if command.trim().is_empty() {
            return Err(ToolError::EmptyCommand.into_mcp_error());
        }
        Ok(())
    }

    /// Execute a shell command on a named SSH host.
    #[tool(
        description = "Execute a shell command on a named SSH host. Returns stdout and stderr. Non-zero exit is returned as a tool-level error so the output is visible."
    )]
    async fn exec(
        &self,
        Parameters(p): Parameters<ExecParams>,
    ) -> Result<CallToolResult, McpError> {
        let cfg = self.host_config(&p.host)?;
        Self::validate_command(&p.command)?;
        self.security
            .check(&p.command, cfg)
            .map_err(|e| e.into_mcp_error())?;

        let session = self
            .pool
            .get(&p.host)
            .await
            .map_err(|e| e.into_mcp_error())?;
        tracing::info!(host = %p.host, command = %p.command, description = ?p.description, "exec");

        let out = session
            .exec(&p.command)
            .await
            .map_err(|e| e.into_mcp_error())?;
        tracing::info!(host = %p.host, exit_code = out.exit_code, "exec complete");
        Ok(format_exec_result(out))
    }

    /// Execute a shell command via sudo on a named SSH host.
    #[tool(
        description = "Execute a shell command via sudo on a named SSH host. Uses sudo_password from config if set, otherwise assumes passwordless sudo."
    )]
    async fn sudo_exec(
        &self,
        Parameters(p): Parameters<SudoExecParams>,
    ) -> Result<CallToolResult, McpError> {
        let cfg = self.host_config(&p.host)?;
        Self::validate_command(&p.command)?;
        self.security
            .check(&p.command, cfg)
            .map_err(|e| e.into_mcp_error())?;

        let sudo_cmd = build_sudo_command(&p.command, cfg.sudo_password.as_deref());
        let session = self
            .pool
            .get(&p.host)
            .await
            .map_err(|e| e.into_mcp_error())?;
        tracing::info!(host = %p.host, command = %p.command, description = ?p.description, "sudo_exec");

        let out = session
            .exec(&sudo_cmd)
            .await
            .map_err(|e| e.into_mcp_error())?;
        tracing::info!(host = %p.host, exit_code = out.exit_code, "sudo_exec complete");
        Ok(format_exec_result(out))
    }

    /// Upload a base64-encoded file to a named SSH host via SFTP.
    #[tool(description = "Upload a base64-encoded file to a named SSH host via SFTP.")]
    async fn put_file(
        &self,
        Parameters(p): Parameters<PutFileParams>,
    ) -> Result<CallToolResult, McpError> {
        self.host_config(&p.host)?;
        if p.remote_path.is_empty() {
            return Err(
                ToolError::InvalidParam("remote_path must not be empty".into()).into_mcp_error(),
            );
        }
        let content = BASE64.decode(&p.content).map_err(|e| {
            ToolError::InvalidParam(format!("invalid base64: {e}")).into_mcp_error()
        })?;
        let mode = p.mode.unwrap_or(0o644);
        let session = self
            .pool
            .get(&p.host)
            .await
            .map_err(|e| e.into_mcp_error())?;
        tracing::info!(host = %p.host, path = %p.remote_path, bytes = content.len(), "put_file");

        session
            .put_file(&p.remote_path, &content, mode)
            .await
            .map_err(|e| e.into_mcp_error())?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Uploaded {} bytes to {}",
            content.len(),
            p.remote_path
        ))]))
    }

    /// Download a file from a named SSH host via SFTP.
    #[tool(
        description = "Download a file from a named SSH host via SFTP. Returns JSON with 'bytes' count and base64 'content'."
    )]
    async fn get_file(
        &self,
        Parameters(p): Parameters<GetFileParams>,
    ) -> Result<CallToolResult, McpError> {
        self.host_config(&p.host)?;
        if p.remote_path.is_empty() {
            return Err(
                ToolError::InvalidParam("remote_path must not be empty".into()).into_mcp_error(),
            );
        }
        let session = self
            .pool
            .get(&p.host)
            .await
            .map_err(|e| e.into_mcp_error())?;
        tracing::info!(host = %p.host, path = %p.remote_path, "get_file");

        let bytes = session
            .get_file(&p.remote_path)
            .await
            .map_err(|e| e.into_mcp_error())?;
        let encoded = BASE64.encode(&bytes);
        Ok(CallToolResult::success(vec![Content::text(format!(
            "{{\"bytes\":{},\"content\":\"{}\"}}",
            bytes.len(),
            encoded
        ))]))
    }

    /// List all configured SSH host names.
    #[tool(description = "List the names of all configured SSH hosts.")]
    fn list_hosts(&self) -> Result<CallToolResult, McpError> {
        let names = self.pool.host_names();
        Ok(CallToolResult::success(vec![Content::text(
            names.join("\n"),
        )]))
    }
}

#[tool_handler]
impl ServerHandler for SshMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "SSH control server. Tools: exec, sudo_exec, put_file, get_file, list_hosts. \
                 All tools require a 'host' parameter matching a configured SSH host name."
                    .to_string(),
            )
    }
}

/// Build a sudo command string, piping the password via printf if provided.
pub fn build_sudo_command(command: &str, sudo_password: Option<&str>) -> String {
    let escaped_cmd = command.replace('\'', "'\"'\"'");
    match sudo_password {
        Some(pwd) => {
            let escaped_pwd = pwd.replace('\'', "'\"'\"'");
            format!("printf '%s\\n' '{escaped_pwd}' | sudo -p '' -S sh -c '{escaped_cmd}'")
        }
        None => format!("sudo -n sh -c '{escaped_cmd}'"),
    }
}

/// Format an ExecOutput as a CallToolResult.
/// Non-zero exits use is_error=true so the LLM can read the output and diagnose failures.
pub fn format_exec_result(out: crate::ssh::ExecOutput) -> CallToolResult {
    let text = if out.stderr.is_empty() {
        out.stdout.clone()
    } else {
        format!("stdout:\n{}\nstderr:\n{}", out.stdout, out.stderr)
    };

    if out.exit_code != 0 {
        CallToolResult::error(vec![Content::text(format!(
            "exit code: {}\n{text}",
            out.exit_code
        ))])
    } else {
        CallToolResult::success(vec![Content::text(text)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMethod, Config};
    use crate::pool::SessionFactory;
    use crate::ssh::{ExecOutput, MockSshSession, SshSession};

    fn make_host(name: &str) -> HostConfig {
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
        }
    }

    struct MockFactory(Arc<MockSshSession>);

    #[async_trait::async_trait]
    impl SessionFactory for MockFactory {
        async fn connect(&self, _: &str, _: &HostConfig) -> Result<Arc<dyn SshSession>, ToolError> {
            Ok(Arc::clone(&self.0) as Arc<dyn SshSession>)
        }
    }

    fn make_server(mock: Arc<MockSshSession>, host_name: &str) -> SshMcpServer {
        let mut hosts = HashMap::new();
        hosts.insert(host_name.to_string(), make_host(host_name));
        let config = Config {
            shellcheck_path: None,
            hosts: hosts.clone(),
        };
        let pool = Arc::new(ConnectionPool::new(
            config,
            Arc::new(MockFactory(mock)) as Arc<dyn SessionFactory>,
        ));
        let security = Arc::new(SecurityChecker::new(None));
        SshMcpServer::new(pool, security, Arc::new(hosts))
    }

    #[tokio::test]
    async fn exec_returns_stdout_on_success() {
        let mock = Arc::new(MockSshSession::new());
        mock.set_exec(
            "ls",
            ExecOutput {
                stdout: "file.txt\n".into(),
                stderr: String::new(),
                exit_code: 0,
            },
        );
        let server = make_server(mock, "prod");
        let result = server
            .exec(Parameters(ExecParams {
                host: "prod".into(),
                command: "ls".into(),
                description: None,
            }))
            .await
            .unwrap();
        assert_ne!(result.is_error, Some(true));
        match &result.content[0].raw {
            RawContent::Text(t) => assert!(t.text.contains("file.txt")),
            _ => panic!("expected text content"),
        }
    }

    #[tokio::test]
    async fn exec_unknown_host_returns_mcp_error() {
        let mock = Arc::new(MockSshSession::new());
        let server = make_server(mock, "prod");
        let err = server
            .exec(Parameters(ExecParams {
                host: "nonexistent".into(),
                command: "ls".into(),
                description: None,
            }))
            .await
            .unwrap_err();
        use rmcp::model::ErrorCode;
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn exec_empty_command_returns_mcp_error() {
        let mock = Arc::new(MockSshSession::new());
        let server = make_server(mock, "prod");
        let err = server
            .exec(Parameters(ExecParams {
                host: "prod".into(),
                command: "".into(),
                description: None,
            }))
            .await
            .unwrap_err();
        use rmcp::model::ErrorCode;
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn exec_non_zero_exit_sets_is_error() {
        let mock = Arc::new(MockSshSession::new());
        mock.set_exec(
            "false",
            ExecOutput {
                stdout: String::new(),
                stderr: "error\n".into(),
                exit_code: 1,
            },
        );
        let server = make_server(mock, "prod");
        let result = server
            .exec(Parameters(ExecParams {
                host: "prod".into(),
                command: "false".into(),
                description: None,
            }))
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
    }

    #[tokio::test]
    async fn put_file_invalid_base64_returns_error() {
        let mock = Arc::new(MockSshSession::new());
        let server = make_server(mock, "prod");
        let err = server
            .put_file(Parameters(PutFileParams {
                host: "prod".into(),
                remote_path: "/tmp/test.txt".into(),
                content: "not-valid-base64!!!!".into(),
                mode: None,
            }))
            .await
            .unwrap_err();
        use rmcp::model::ErrorCode;
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn put_file_empty_path_returns_error() {
        let mock = Arc::new(MockSshSession::new());
        let server = make_server(mock, "prod");
        let err = server
            .put_file(Parameters(PutFileParams {
                host: "prod".into(),
                remote_path: "".into(),
                content: BASE64.encode(b"data"),
                mode: None,
            }))
            .await
            .unwrap_err();
        use rmcp::model::ErrorCode;
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn list_hosts_returns_sorted_names() {
        let mock = Arc::new(MockSshSession::new());
        let mut hosts = HashMap::new();
        hosts.insert("zebra".to_string(), make_host("zebra"));
        hosts.insert("alpha".to_string(), make_host("alpha"));
        let config = Config {
            shellcheck_path: None,
            hosts: hosts.clone(),
        };
        let pool = Arc::new(ConnectionPool::new(
            config,
            Arc::new(MockFactory(Arc::clone(&mock))) as Arc<dyn SessionFactory>,
        ));
        let security = Arc::new(SecurityChecker::new(None));
        let server = SshMcpServer::new(pool, security, Arc::new(hosts));
        let result = server.list_hosts().unwrap();
        match &result.content[0].raw {
            RawContent::Text(t) => assert_eq!(t.text, "alpha\nzebra"),
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn build_sudo_command_with_password() {
        let cmd = build_sudo_command("ls -la", Some("mypass"));
        assert!(cmd.contains("printf"));
        assert!(cmd.contains("sudo -p '' -S"));
        assert!(cmd.contains("ls -la"));
    }

    #[test]
    fn build_sudo_command_without_password() {
        let cmd = build_sudo_command("ls -la", None);
        assert!(cmd.contains("sudo -n"));
        assert!(cmd.contains("ls -la"));
    }
}
