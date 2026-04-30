// Copyright (c) 2026 100monkeys.ai
// SPDX-License-Identifier: AGPL-3.0
//! Prometheus metrics exporter and shared metric helpers (ADR-058).
//!
//! # Code Quality Principles
//!
//! - Keep metric names stable and label cardinality bounded.
//! - **Never** label metrics with `tenant_id`, `agent_id`, `execution_id`,
//!   `workflow_id`, or `iteration_id` — these are unbounded identifiers and
//!   would explode Prometheus cardinality.
//! - The `tool_name` label MUST be the canonical registered name resolved
//!   from the tool registry, never user-supplied input.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

use crate::domain::{PolicyViolation, SealSessionRepository};

/// Default bind address for the Prometheus scrape endpoint (loopback only).
///
/// Binding `0.0.0.0` would expose the unauthenticated scrape endpoint to the
/// network and requires an external authenticating reverse proxy.
const DEFAULT_METRICS_BIND: &str = "127.0.0.1";
const DEFAULT_METRICS_PORT: u16 = 9092;

/// Initialize the Prometheus exporter and install the global recorder.
///
/// Binds an HTTP listener at `${METRICS_BIND:-127.0.0.1}:${METRICS_PORT:-9092}`
/// and configures histogram buckets for any metric whose name ends in
/// `_duration_seconds`.
pub fn init_metrics() -> anyhow::Result<()> {
    let bind = std::env::var("METRICS_BIND").unwrap_or_else(|_| DEFAULT_METRICS_BIND.to_string());
    let port: u16 = match std::env::var("METRICS_PORT") {
        Ok(value) => value
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid METRICS_PORT={value}: {e}"))?,
        Err(_) => DEFAULT_METRICS_PORT,
    };

    let addr: SocketAddr = format!("{bind}:{port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid metrics bind address {bind}:{port}: {e}"))?;

    PrometheusBuilder::new()
        .with_http_listener(addr)
        .set_buckets_for_metric(
            Matcher::Suffix("_duration_seconds".to_string()),
            &[
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
            ],
        )?
        .install()?;

    register_descriptors();

    tracing::info!("Prometheus metrics exporter listening on {}", addr);
    Ok(())
}

/// Pre-register metric descriptors so they appear in scrapes before the first
/// event is recorded. The `metrics` crate deduplicates registrations by name,
/// so subsequent emissions reuse the same handles.
fn register_descriptors() {
    metrics::counter!("aegis_seal_attestations_total", "outcome" => "ok").absolute(0);
    metrics::counter!("aegis_seal_signature_failures_total").absolute(0);
    metrics::gauge!("aegis_seal_sessions_active").set(0.0);
}

/// Spawn a background task that polls the active SEAL session count from the
/// repository and exports it as the `aegis_seal_sessions_active` gauge.
///
/// Polling is used (instead of incrementing/decrementing on
/// upsert/delete) so the gauge remains accurate across restarts, expirations,
/// and direct database modifications.
pub fn spawn_session_gauge_task(repo: Arc<dyn SealSessionRepository>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            interval.tick().await;
            match repo.list_active_for_tenant(None).await {
                Ok(sessions) => {
                    metrics::gauge!("aegis_seal_sessions_active").set(sessions.len() as f64);
                }
                Err(e) => {
                    tracing::warn!("active session gauge refresh failed: {e}");
                }
            }
        }
    });
}

/// Map a [`PolicyViolation`] to a stable, low-cardinality `violation_type` label
/// value for the `aegis_tool_policy_violations_total` counter.
pub fn policy_violation_type(violation: &PolicyViolation) -> &'static str {
    match violation {
        PolicyViolation::ToolNotAllowed { .. } => "tool_not_allowed",
        PolicyViolation::ToolDenied { .. } => "tool_denied",
        PolicyViolation::PathOutsideBoundary { .. } => "path_outside_boundary",
        PolicyViolation::DomainNotAllowed { .. } => "domain_not_allowed",
        PolicyViolation::CommandNotAllowed { .. } => "command_not_allowed",
        PolicyViolation::SubcommandNotAllowed { .. } => "subcommand_not_allowed",
        PolicyViolation::ConcurrentExecLimitExceeded { .. } => "concurrent_exec_limit_exceeded",
        PolicyViolation::OutputSizeLimitExceeded { .. } => "output_size_limit_exceeded",
    }
}

/// Record a `aegis_tool_policy_violations_total` event.
pub fn record_policy_violation(violation: &PolicyViolation) {
    metrics::counter!(
        "aegis_tool_policy_violations_total",
        "violation_type" => policy_violation_type(violation)
    )
    .increment(1);
}

/// Record an attestation outcome.
///
/// `outcome` MUST be one of: `"ok"`, `"signature_invalid"`, `"replay"`,
/// `"expired"`, `"unauthorized"`, `"context_mismatch"`, `"tool_not_allowed"`,
/// `"forbidden"`, `"malformed"`. Use stable strings only.
pub fn record_attestation(outcome: &'static str) {
    metrics::counter!(
        "aegis_seal_attestations_total",
        "outcome" => outcome
    )
    .increment(1);
}

/// Record a SEAL signature verification failure.
pub fn record_signature_failure() {
    metrics::counter!("aegis_seal_signature_failures_total").increment(1);
}

/// Record a tool invocation outcome and duration.
///
/// `tool_name` MUST be the canonical registered tool name (never raw user
/// input). `path` distinguishes the dispatch path: `"native"`, `"cli"`, or
/// `"workflow"`. `status` is `"ok"` or `"error"`.
pub fn record_tool_invocation(
    tool_name: &str,
    path: &'static str,
    status: &'static str,
    duration_secs: f64,
) {
    metrics::counter!(
        "aegis_tool_invocations_total",
        "tool_name" => tool_name.to_string(),
        "path" => path,
        "status" => status
    )
    .increment(1);

    metrics::histogram!(
        "aegis_tool_invocation_duration_seconds",
        "tool_name" => tool_name.to_string(),
        "path" => path
    )
    .record(duration_secs);
}
