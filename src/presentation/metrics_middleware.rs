// Copyright (c) 2026 100monkeys.ai
// SPDX-License-Identifier: AGPL-3.0
//! HTTP and gRPC metrics middleware for the SEAL gateway (ADR-058).
//!
//! Emits:
//!   - `aegis_seal_http_requests_total{method,path_template,status_code}`
//!   - `aegis_seal_http_request_duration_seconds{method,path_template}`
//!   - `aegis_seal_grpc_requests_total{method,code}`
//!   - `aegis_seal_grpc_request_duration_seconds{method}`
//!
//! The HTTP middleware uses Axum's [`MatchedPath`] to derive a low-cardinality
//! route template (e.g. `/v1/specs/{id}` rather than the raw URI) — this is
//! REQUIRED to bound Prometheus label cardinality.

use std::task::{Context, Poll};
use std::time::Instant;

use axum::{
    extract::MatchedPath,
    http::{Request, Response},
    middleware::Next,
    response::Response as AxumResponse,
};
use futures::future::BoxFuture;
use tower::{Layer, Service};

/// Normalize a gRPC method path (`/package.Service/Method`) into a stable,
/// low-cardinality label value.
fn normalize_grpc_method(path: &str) -> String {
    path.trim_matches('/').replace('/', ".").replace(':', "_")
}

/// Axum middleware emitting HTTP request metrics for the SEAL gateway.
pub async fn http_metrics_middleware(req: Request<axum::body::Body>, next: Next) -> AxumResponse {
    let start = Instant::now();
    let method = req.method().to_string();

    // Use the matched route template — never the raw URI — to bound cardinality.
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str())
        .unwrap_or("unknown_path")
        .to_string();

    let response = next.run(req).await;

    let latency = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    metrics::counter!(
        "aegis_seal_http_requests_total",
        "method" => method.clone(),
        "path_template" => path.clone(),
        "status_code" => status
    )
    .increment(1);

    metrics::histogram!(
        "aegis_seal_http_request_duration_seconds",
        "method" => method,
        "path_template" => path
    )
    .record(latency);

    response
}

/// Tower [`Layer`] that wraps a gRPC service with metrics instrumentation.
#[derive(Clone, Default)]
pub struct GrpcMetricsLayer;

impl<S> Layer<S> for GrpcMetricsLayer {
    type Service = GrpcMetricsService<S>;

    fn layer(&self, service: S) -> Self::Service {
        GrpcMetricsService { service }
    }
}

/// Tower [`Service`] that records gRPC method counts and durations.
#[derive(Clone)]
pub struct GrpcMetricsService<S> {
    service: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for GrpcMetricsService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let start = Instant::now();
        let method = normalize_grpc_method(req.uri().path());

        let mut next_service = self.service.clone();
        Box::pin(async move {
            let response = next_service.call(req).await?;

            let latency = start.elapsed().as_secs_f64();

            // gRPC status lands in headers (for header-only error responses) or
            // trailers (typical happy-path). Header inspection captures the
            // common error case; absent headers default to "0" (OK).
            let grpc_status = response
                .headers()
                .get("grpc-status")
                .and_then(|s| s.to_str().ok())
                .unwrap_or("0")
                .to_string();

            metrics::counter!(
                "aegis_seal_grpc_requests_total",
                "method" => method.clone(),
                "code" => grpc_status
            )
            .increment(1);

            metrics::histogram!(
                "aegis_seal_grpc_request_duration_seconds",
                "method" => method
            )
            .record(latency);

            Ok(response)
        })
    }
}
