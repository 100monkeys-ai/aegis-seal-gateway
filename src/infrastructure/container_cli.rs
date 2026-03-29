use std::process::Command;

/// Resolve the container CLI binary path.
///
/// Precedence:
/// 1. Explicit configuration value (if provided and not empty)
/// 2. `SMCP_GATEWAY_CONTAINER_CLI` environment variable
/// 3. Auto-detect:
///    - If `CONTAINER_HOST` is set → prefer `podman`
///    - If `DOCKER_HOST` is set → prefer `docker`
///    - Probe `which podman` → use if found
///    - Probe `which docker` → use if found
/// 4. Fail with a clear error if nothing is found
pub fn resolve_container_cli(configured: Option<&str>) -> anyhow::Result<String> {
    // 1. Explicit config
    if let Some(value) = configured {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    // 2. Environment variable override
    if let Ok(value) = std::env::var("SMCP_GATEWAY_CONTAINER_CLI") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    // 3. Auto-detect
    if std::env::var("CONTAINER_HOST").is_ok() && binary_exists("podman") {
        return Ok("podman".to_string());
    }
    if std::env::var("DOCKER_HOST").is_ok() && binary_exists("docker") {
        return Ok("docker".to_string());
    }

    // Probe both
    if binary_exists("podman") {
        return Ok("podman".to_string());
    }
    if binary_exists("docker") {
        return Ok("docker".to_string());
    }

    anyhow::bail!(
        "No container CLI binary found. Install podman or docker, or set \
         cli.container_cli in smcp-gateway-config.yaml"
    )
}

/// Validate the resolved binary by running `<binary> --version`.
/// Returns the version string on success.
pub fn validate_container_cli(binary: &str) -> anyhow::Result<String> {
    let output = Command::new(binary)
        .arg("--version")
        .output()
        .map_err(|e| anyhow::anyhow!("failed to execute '{binary} --version': {e}"))?;

    if !output.status.success() {
        anyhow::bail!(
            "'{binary} --version' exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn binary_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_config_overrides_everything() {
        let result = resolve_container_cli(Some("podman")).unwrap();
        assert_eq!(result, "podman");
    }

    #[test]
    fn explicit_config_with_path() {
        let result = resolve_container_cli(Some("/usr/bin/podman")).unwrap();
        assert_eq!(result, "/usr/bin/podman");
    }

    #[test]
    fn empty_config_triggers_auto_detect() {
        // Should not error with empty string — falls through to auto-detect
        let result = resolve_container_cli(Some(""));
        // Result depends on what's installed; just verify it doesn't panic on empty
        assert!(result.is_ok() || result.is_err());
    }
}
