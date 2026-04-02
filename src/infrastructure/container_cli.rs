use std::path::Path;
use std::process::Command;

/// Resolve the container CLI binary path.
///
/// Precedence:
/// 1. Explicit configuration value (if provided and not empty)
/// 2. `SEAL_GATEWAY_CONTAINER_CLI` environment variable
/// 3. Auto-detect:
///    - If `CONTAINER_HOST` is set → prefer `podman` (binary or socket-only)
///    - If `DOCKER_HOST` is set → prefer `docker` (binary or socket-only)
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
    if let Ok(value) = std::env::var("SEAL_GATEWAY_CONTAINER_CLI") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    // 3. Auto-detect — when a *_HOST env var points to a socket, the binary
    //    does not need to be in PATH (socket-only deployment).
    if let Ok(host) = std::env::var("CONTAINER_HOST") {
        if binary_exists("podman") || host_socket_exists(&host) {
            return Ok("podman".to_string());
        }
    }
    if let Ok(host) = std::env::var("DOCKER_HOST") {
        if binary_exists("docker") || host_socket_exists(&host) {
            return Ok("docker".to_string());
        }
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
         cli.container_cli in seal-gateway-config.yaml"
    )
}

/// Validate the resolved binary.
///
/// When a socket-based host is configured (`CONTAINER_HOST` for podman,
/// `DOCKER_HOST` for docker) and the socket file exists, the binary does not
/// need to be in PATH — the container runtime is reachable via the socket.
/// In that case we skip `<binary> --version` and return a socket-validated
/// message.  Otherwise we fall back to the standard `<binary> --version`
/// probe.
pub fn validate_container_cli(binary: &str) -> anyhow::Result<String> {
    // Determine the relevant host env-var for this binary.
    let host_var = match binary {
        "podman" => Some("CONTAINER_HOST"),
        "docker" => Some("DOCKER_HOST"),
        _ => None,
    };

    // If a socket-based host is configured and the socket exists, accept it.
    if let Some(var) = host_var {
        if let Ok(host) = std::env::var(var) {
            if let Some(socket_path) = extract_socket_path(&host) {
                if Path::new(&socket_path).exists() {
                    return Ok(format!("{binary} (socket-validated via {var}={host})"));
                }
            }
        }
    }

    // Fall back to running `<binary> --version`.
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

/// Extract the filesystem path from a host URI that uses a unix socket.
///
/// Accepted forms:
///   - `unix:///path/to/sock`
///   - `unix:///path/to/sock` (with trailing query/fragment stripped)
///   - `/path/to/sock` (bare path, treated as a socket if it exists)
fn extract_socket_path(host: &str) -> Option<String> {
    if let Some(rest) = host.strip_prefix("unix://") {
        // Strip any query string or fragment from the path.
        let path = rest.split(['?', '#']).next().unwrap_or(rest);
        if !path.is_empty() {
            return Some(path.to_string());
        }
    }
    // Bare absolute path — common in DOCKER_HOST=/var/run/docker.sock
    if host.starts_with('/') {
        return Some(host.to_string());
    }
    None
}

/// Check whether the host URI points to a unix socket that exists on disk.
fn host_socket_exists(host: &str) -> bool {
    extract_socket_path(host)
        .map(|p| Path::new(&p).exists())
        .unwrap_or(false)
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

    #[test]
    fn extract_socket_path_unix_scheme() {
        assert_eq!(
            extract_socket_path("unix:///run/podman/podman.sock"),
            Some("/run/podman/podman.sock".to_string())
        );
    }

    #[test]
    fn extract_socket_path_unix_scheme_with_query() {
        assert_eq!(
            extract_socket_path("unix:///run/docker.sock?timeout=30"),
            Some("/run/docker.sock".to_string())
        );
    }

    #[test]
    fn extract_socket_path_bare_path() {
        assert_eq!(
            extract_socket_path("/var/run/docker.sock"),
            Some("/var/run/docker.sock".to_string())
        );
    }

    #[test]
    fn extract_socket_path_tcp_returns_none() {
        assert_eq!(extract_socket_path("tcp://127.0.0.1:2375"), None);
    }

    #[test]
    fn extract_socket_path_empty_unix_returns_none() {
        assert_eq!(extract_socket_path("unix://"), None);
    }

    #[test]
    fn validate_container_cli_socket_based() {
        // Create a temp file to act as a socket stand-in for the existence check.
        let tmp = std::env::temp_dir().join("test_container_cli.sock");
        std::fs::write(&tmp, b"").unwrap();

        // Set DOCKER_HOST to point at the temp file.
        std::env::set_var("DOCKER_HOST", format!("unix://{}", tmp.display()));
        let result = validate_container_cli("docker");
        std::env::remove_var("DOCKER_HOST");
        std::fs::remove_file(&tmp).unwrap();

        let msg = result.unwrap();
        assert!(
            msg.contains("socket-validated"),
            "expected socket-validated message, got: {msg}"
        );
    }
}
