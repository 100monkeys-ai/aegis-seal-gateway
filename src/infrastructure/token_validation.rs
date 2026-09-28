// Copyright (c) 2026 100monkeys.ai
// SPDX-License-Identifier: AGPL-3.0
//! The claim checks every token the gateway accepts must pass, on both of its
//! verification paths: operator tokens from the identity provider
//! (`jwks_validator`) and SEAL security tokens (`seal`).
//!
//! A token is accepted only if it is signed with RS256 by a key the path
//! trusts, and carries `exp`, `iss` and `aud`, with `iss` exactly the
//! configured issuer and `aud` (a string, or an array of strings) naming the
//! configured audience. `jsonwebtoken` compares `iss` and `aud` only when the
//! claim is present and well-typed unless they are listed as required, so a
//! validation that only sets the expected values accepts a token that omits
//! them. `nbf`, when present, is honoured (RFC 7519 §4.1.5).

use jsonwebtoken::{Algorithm, Validation};

/// Registered claims every accepted token must carry.
pub const REQUIRED_CLAIMS: [&str; 3] = ["exp", "iss", "aud"];

/// The validation for a path that trusts exactly `trusted_issuer` and accepts
/// exactly `accepted_audience`. Both are compared as exact strings.
pub fn rs256_validation(trusted_issuer: &str, accepted_audience: &str) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(&REQUIRED_CLAIMS);
    validation.set_issuer(&[trusted_issuer]);
    validation.set_audience(&[accepted_audience]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = true;
    validation
}
