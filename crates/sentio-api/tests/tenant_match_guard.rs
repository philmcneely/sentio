//! Handler-layer tenant guard, pinned at unit level (review finding: the
//! repo-layer isolation tests cannot catch a handler reverting to the
//! client-controlled path tenant). Full axum wiring requires live
//! infrastructure (pool + nats + s3), so the guard's contract is asserted
//! here, and end-to-end two-tenant behavior is verified against the deployed
//! service (see PR description: cross-tenant = 404, own tenant = 200).

use axum::http::StatusCode;
use axum::response::IntoResponse;
use sentio_api::auth::{AuthContext, PLATFORM_ADMIN_SCOPE};
use sentio_api::routes::ensure_tenant_match;
use sentio_core::tenant::TenantId;

fn ctx_for(tenant: uuid::Uuid) -> AuthContext {
    AuthContext {
        tenant_id: TenantId(tenant),
        scopes: vec![],
    }
}

fn ctx_with(tenant: uuid::Uuid, scopes: &[&str]) -> AuthContext {
    AuthContext {
        tenant_id: TenantId(tenant),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn guard_passes_when_path_tenant_matches_session() {
    let t = uuid::Uuid::new_v4();
    assert!(ensure_tenant_match(&ctx_for(t), t).is_ok());
}

#[test]
fn guard_rejects_mismatched_path_tenant_with_not_found() {
    let session = uuid::Uuid::new_v4();
    let attacker_path = uuid::Uuid::new_v4();
    let err = ensure_tenant_match(&ctx_for(session), attacker_path)
        .expect_err("mismatched path tenant must be rejected");
    // Must serialize as 404 (not 403): the existence of another tenant's
    // resources must not leak through the error code.
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ──────────────────────────────────────────────────────────────────────────────
// The platform scope. Giving a new tenant its first API key means acting
// on a tenant that is not your own, so the guard has an exception - and
// the exception has to be one a tenant cannot grant itself.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn platform_admin_passes_a_foreign_path_tenant() {
    let session = uuid::Uuid::new_v4();
    let other = uuid::Uuid::new_v4();
    let ctx = ctx_with(session, &[PLATFORM_ADMIN_SCOPE]);
    assert!(ensure_tenant_match(&ctx, other).is_ok());
}

#[test]
fn wildcard_alone_does_not_pass_a_foreign_path_tenant() {
    let session = uuid::Uuid::new_v4();
    let other = uuid::Uuid::new_v4();
    let ctx = ctx_with(session, &["*"]);
    let err = ensure_tenant_match(&ctx, other).expect_err("`*` must stay inside its tenant");
    assert_eq!(err.into_response().status(), StatusCode::NOT_FOUND);
}

#[test]
fn wildcard_does_not_cover_the_platform_scope() {
    let ctx = ctx_with(uuid::Uuid::new_v4(), &["*"]);
    assert!(ctx.require_scope("admin:tenants:write").is_ok());
    assert!(ctx.require_scope(PLATFORM_ADMIN_SCOPE).is_err());
    assert!(!ctx.is_platform_admin());
}

#[test]
fn the_platform_scope_is_honoured_when_written_out() {
    let ctx = ctx_with(uuid::Uuid::new_v4(), &[PLATFORM_ADMIN_SCOPE]);
    assert!(ctx.require_scope(PLATFORM_ADMIN_SCOPE).is_ok());
    assert!(ctx.is_platform_admin());
}

#[test]
fn a_tenant_cannot_grant_itself_the_platform_scope() {
    let ctx = ctx_with(uuid::Uuid::new_v4(), &["*"]);
    // Ordinary scopes are its own business.
    assert!(ctx
        .require_grantable(&["messages:read".into(), "*".into()])
        .is_ok());
    // Reaching out of the tenant is not.
    let err = ctx
        .require_grantable(&["messages:read".into(), PLATFORM_ADMIN_SCOPE.into()])
        .expect_err("a session without the platform scope must not hand it out");
    assert_eq!(err.into_response().status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn platform_admin_can_grant_the_platform_scope() {
    let ctx = ctx_with(uuid::Uuid::new_v4(), &[PLATFORM_ADMIN_SCOPE]);
    assert!(ctx
        .require_grantable(&[PLATFORM_ADMIN_SCOPE.into()])
        .is_ok());
}
