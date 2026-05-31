use rmcp::model::ErrorData;

/// All errors that tool handlers can produce.
#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("unknown host '{0}' — not in config")]
    UnknownHost(String),

    #[error("SSH connection failed for '{host}': {source}")]
    SshConnect {
        host: String,
        #[source]
        source: russh::Error,
    },

    #[error("SSH authentication failed for '{host}'")]
    SshAuth { host: String },

    #[error("command timed out on '{host}' after {after_ms}ms")]
    Timeout { host: String, after_ms: u64 },

    #[error("shellcheck failed: {0}")]
    ShellCheckFailed(String),

    #[error("dangerous command blocked: {0}")]
    DangerousCommand(String),

    #[error("command too long: {len} chars (max {max})")]
    CommandTooLong { len: usize, max: usize },

    #[error("command denied by allowlist: {0}")]
    CommandDenied(String),

    #[error("command must not be empty")]
    EmptyCommand,

    #[error("SFTP error on '{host}': {message}")]
    Sftp { host: String, message: String },

    #[error("SSH exec on '{host}' exited {exit_code}")]
    SshExec {
        host: String,
        exit_code: u32,
        stdout: String,
        stderr: String,
    },

    #[error("shellcheck binary not found: {0}")]
    ShellCheckNotFound(String),

    #[error("invalid parameter: {0}")]
    InvalidParam(String),
}

impl ToolError {
    /// Convert to an MCP protocol error.
    /// Validation failures → InvalidParams (-32602); everything else → InternalError (-32603).
    pub fn into_mcp_error(self) -> ErrorData {
        match &self {
            ToolError::UnknownHost(_)
            | ToolError::EmptyCommand
            | ToolError::CommandTooLong { .. }
            | ToolError::CommandDenied(_)
            | ToolError::InvalidParam(_) => ErrorData::invalid_params(self.to_string(), None),
            _ => ErrorData::internal_error(self.to_string(), None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ErrorCode;

    #[test]
    fn unknown_host_maps_to_invalid_params() {
        let e = ToolError::UnknownHost("prod".into());
        assert_eq!(e.into_mcp_error().code, ErrorCode::INVALID_PARAMS);
    }

    #[test]
    fn timeout_maps_to_internal_error() {
        let e = ToolError::Timeout { host: "prod".into(), after_ms: 60_000 };
        assert_eq!(e.into_mcp_error().code, ErrorCode::INTERNAL_ERROR);
    }

    #[test]
    fn empty_command_maps_to_invalid_params() {
        assert_eq!(ToolError::EmptyCommand.into_mcp_error().code, ErrorCode::INVALID_PARAMS);
    }

    #[test]
    fn command_too_long_maps_to_invalid_params() {
        assert_eq!(
            ToolError::CommandTooLong { len: 1001, max: 1000 }.into_mcp_error().code,
            ErrorCode::INVALID_PARAMS
        );
    }
}
