// Copyright (c) 2026 100monkeys.ai
// SPDX-License-Identifier: AGPL-3.0
//! Test support: RSA keys generated in the test process, and tokens signed with them.
//!
//! Every token the claim tests present is really signed, so a refusal can only
//! come from the claim checks under test and never from a signature that does
//! not verify.

use std::sync::OnceLock;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::KeyPair as _;
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::Value;

/// The issuer every claim test configures as trusted. URL-shaped, like a
/// Keycloak realm, so the scheme, host-case and trailing-slash cases mean
/// something.
pub const TRUSTED_ISSUER: &str = "https://auth.example.test/realms/aegis-system";
/// The audience every claim test configures as accepted.
pub const ACCEPTED_AUDIENCE: &str = "aegis-seal-gateway";
/// The `kid` the trusted key is published under in the test JWKS.
pub const TRUSTED_KID: &str = "trusted-test-key";

/// An RSA key pair generated for this test process.
pub struct TestKey {
    pub private_pem: String,
    pub public_pem: String,
    /// JWK modulus, base64url without padding.
    pub n: String,
    /// JWK exponent, base64url without padding.
    pub e: String,
}

fn pem(label: &str, der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn generate() -> TestKey {
    let pair = KeyPair::generate(KeySize::Rsa2048).expect("generate RSA key");
    let private_der = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&pair)
        .expect("PKCS#8 DER of the private key");
    let public = pair.public_key();
    let public_der = AsDer::<aws_lc_rs::encoding::PublicKeyX509Der>::as_der(public)
        .expect("SPKI DER of the public key");
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    TestKey {
        private_pem: pem("PRIVATE KEY", private_der.as_ref()),
        public_pem: pem("PUBLIC KEY", public_der.as_ref()),
        n: b64url.encode(public.modulus().big_endian_without_leading_zero()),
        e: b64url.encode(public.exponent().big_endian_without_leading_zero()),
    }
}

/// The key the gateway under test trusts.
pub fn trusted_key() -> &'static TestKey {
    static KEY: OnceLock<TestKey> = OnceLock::new();
    KEY.get_or_init(generate)
}

/// A key the gateway under test has never been told about.
pub fn untrusted_key() -> &'static TestKey {
    static KEY: OnceLock<TestKey> = OnceLock::new();
    KEY.get_or_init(generate)
}

/// The JWKS document that publishes the trusted key.
pub fn trusted_jwks() -> Value {
    let key = trusted_key();
    serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "kid": TRUSTED_KID,
            "alg": "RS256",
            "use": "sig",
            "n": key.n,
            "e": key.e,
        }]
    })
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Sign `claims` with RS256 under `key`, with `kid` set to [`TRUSTED_KID`].
pub fn sign_rs256(key: &TestKey, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TRUSTED_KID.to_string());
    let encoding_key =
        EncodingKey::from_rsa_pem(key.private_pem.as_bytes()).expect("encoding key from PEM");
    encode(&header, claims, &encoding_key).expect("sign RS256 token")
}

/// An HS256 token whose HMAC secret is the trusted public key's PEM: the
/// classic RS256/HS256 algorithm-confusion forgery.
pub fn sign_hs256_with_public_key_as_secret(claims: &Value) -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(TRUSTED_KID.to_string());
    let secret = EncodingKey::from_secret(trusted_key().public_pem.as_bytes());
    encode(&header, claims, &secret).expect("sign HS256 token")
}

/// An unsigned token with `"alg": "none"`.
pub fn unsigned_alg_none(claims: &Value) -> String {
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = b64url.encode(format!(
        r#"{{"alg":"none","typ":"JWT","kid":"{TRUSTED_KID}"}}"#
    ));
    let payload = b64url.encode(serde_json::to_vec(claims).expect("serialize claims"));
    format!("{header}.{payload}.")
}

/// How a case's token is produced.
pub enum Signing {
    Trusted,
    Untrusted,
    Hs256PublicKeyAsSecret,
    AlgNone,
}

/// One row of the claim matrix both verification paths are driven through.
pub struct ClaimCase {
    pub name: &'static str,
    /// Applied to a claim set that is valid in every respect.
    pub mutate: fn(&mut serde_json::Map<String, Value>),
    pub signing: Signing,
    pub accepted: bool,
}

/// The claim matrix. `base` is a claim set valid in every respect for the path
/// under test; each case changes one thing about it.
pub fn claim_cases() -> Vec<ClaimCase> {
    fn set(claims: &mut serde_json::Map<String, Value>, name: &str, value: Value) {
        claims.insert(name.to_string(), value);
    }
    vec![
        ClaimCase {
            name: "valid in every respect",
            mutate: |_| {},
            signing: Signing::Trusted,
            accepted: true,
        },
        ClaimCase {
            name: "no iss",
            mutate: |c| {
                c.remove("iss");
            },
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "no aud",
            mutate: |c| {
                c.remove("aud");
            },
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "numeric aud",
            mutate: |c| set(c, "aud", serde_json::json!(7)),
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "aud array containing the accepted audience",
            mutate: |c| set(c, "aud", serde_json::json!(["account", ACCEPTED_AUDIENCE])),
            signing: Signing::Trusted,
            accepted: true,
        },
        ClaimCase {
            name: "aud array not containing the accepted audience",
            mutate: |c| {
                set(
                    c,
                    "aud",
                    serde_json::json!(["account", "aegis-orchestrator"]),
                )
            },
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "aud for another audience",
            mutate: |c| set(c, "aud", serde_json::json!("aegis-orchestrator")),
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "iss with a trailing slash",
            mutate: |c| set(c, "iss", serde_json::json!(format!("{TRUSTED_ISSUER}/"))),
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "iss differing by case in the host",
            mutate: |c| {
                set(
                    c,
                    "iss",
                    serde_json::json!("https://AUTH.example.test/realms/aegis-system"),
                )
            },
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "iss differing by scheme",
            mutate: |c| {
                set(
                    c,
                    "iss",
                    serde_json::json!("http://auth.example.test/realms/aegis-system"),
                )
            },
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "iss with the trusted issuer as its prefix",
            mutate: |c| {
                set(
                    c,
                    "iss",
                    serde_json::json!(format!("{TRUSTED_ISSUER}-other")),
                )
            },
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "numeric iss",
            mutate: |c| set(c, "iss", serde_json::json!(7)),
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "no exp",
            mutate: |c| {
                c.remove("exp");
            },
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "exp as a string",
            mutate: |c| set(c, "exp", serde_json::json!((now() + 3600).to_string())),
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "exp in the past",
            mutate: |c| set(c, "exp", serde_json::json!(now() - 3600)),
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "nbf in the future",
            mutate: |c| set(c, "nbf", serde_json::json!(now() + 3600)),
            signing: Signing::Trusted,
            accepted: false,
        },
        ClaimCase {
            name: "nbf in the past",
            mutate: |c| set(c, "nbf", serde_json::json!(now() - 60)),
            signing: Signing::Trusted,
            accepted: true,
        },
        ClaimCase {
            name: "signed by an untrusted key, claims correct",
            mutate: |_| {},
            signing: Signing::Untrusted,
            accepted: false,
        },
        ClaimCase {
            name: "alg none",
            mutate: |_| {},
            signing: Signing::AlgNone,
            accepted: false,
        },
        ClaimCase {
            name: "HS256 signed with the public key as the secret",
            mutate: |_| {},
            signing: Signing::Hs256PublicKeyAsSecret,
            accepted: false,
        },
    ]
}

/// Produce the token for `case` from a claim set valid in every respect.
pub fn token_for(case: &ClaimCase, base: &Value) -> String {
    let mut claims = base.as_object().expect("claims object").clone();
    (case.mutate)(&mut claims);
    let claims = Value::Object(claims);
    match case.signing {
        Signing::Trusted => sign_rs256(trusted_key(), &claims),
        Signing::Untrusted => sign_rs256(untrusted_key(), &claims),
        Signing::Hs256PublicKeyAsSecret => sign_hs256_with_public_key_as_secret(&claims),
        Signing::AlgNone => unsigned_alg_none(&claims),
    }
}

/// Drive every case through `verify`, which answers whether the path under
/// test accepted the token, and fail listing every case that answered wrongly.
pub async fn assert_claim_matrix<F, Fut>(path: &str, base: Value, verify: F)
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let mut wrong = Vec::new();
    let cases = claim_cases();
    for case in &cases {
        let token = token_for(case, &base);
        let accepted = verify(token).await;
        if accepted != case.accepted {
            wrong.push(format!(
                "{path}: \"{}\" was {} but must be {}",
                case.name,
                if accepted { "ACCEPTED" } else { "refused" },
                if case.accepted { "accepted" } else { "refused" },
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} claim cases answered wrongly:\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n")
    );
}
