use super::tests::TempRepo;
use super::*;

#[test]
fn nested_callback_declarations_do_not_duplicate_concrete_mounts() {
    let source = r#"
async fn handler() {}
fn inner(cfg: &mut Config) { cfg.route("/item",web::get().to(handler)); }
fn outer(cfg: &mut Config) { cfg.service(web::scope("/api").configure(inner)); }
fn first() { App::new().configure(outer); }
fn second() { App::new().configure(outer); }
"#;
    let report = TempRepo::new("nested-app-context", &[("main.rs", source)]).analyze();
    assert_eq!(report.routes.len(), 2);
    assert!(
        report.routes.iter().all(|r| r.path == "/api/item"
            && !r.application.as_ref().unwrap().starts_with("declaration:"))
    );
    assert_ne!(report.routes[0].application, report.routes[1].application);
}

#[test]
fn test_apps_are_excluded_and_distinct_production_apps_are_preserved() {
    let source = r#"
async fn item() {}
fn configure(cfg: &mut Config) { cfg.route("/item", web::get().to(item)); }
fn first() { App::new().configure(configure); }
fn second() { App::new().configure(configure); }
#[cfg(test)] mod tests { fn harness() { App::new().configure(super::configure); } }
#[actix_web::test] async fn request_test() { App::new().configure(configure); }
"#;
    let report = TempRepo::new(
        "production-context",
        &[
            ("main.rs", source),
            (
                "tests/integration.rs",
                "fn test_app() { App::new().route(\"/test\", web::get().to(handler)); }",
            ),
            (
                "examples/demo.rs",
                "fn demo() { App::new().route(\"/example\", web::get().to(handler)); }",
            ),
        ],
    )
    .analyze();
    assert_eq!(report.routes.len(), 2);
    assert_ne!(report.routes[0].application, report.routes[1].application);
    assert!(report.routes.iter().all(|r| r.application.is_some()));
    assert!(report.candidate_relationships.is_empty());
}

#[test]
fn standard_middleware_binding_does_not_hide_a_shadowed_opaque_layer() {
    let repo = TempRepo::new(
        "p2-middleware-bindings",
        &[(
            "main.rs",
            r#"
async fn handler() {}
fn app() {
 let layer = Cors::default().supports_credentials();
 App::new().wrap(layer).route("/public", web::get().to(handler));
 {
   let layer = custom_layer();
   App::new().wrap(layer).route("/opaque", web::get().to(handler));
 }
}
"#,
        )],
    );
    let report = repo.analyze();
    assert_eq!(
        report
            .routes
            .iter()
            .find(|r| r.path == "/public")
            .unwrap()
            .security_status(),
        RouteSecurityStatus::Unprotected
    );
    assert!(matches!(
        report
            .routes
            .iter()
            .find(|r| r.path == "/opaque")
            .unwrap()
            .security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));
}

#[test]
fn unknown_middleware_propagates_only_to_its_mount() {
    let repo = TempRepo::new(
        "p2-opaque",
        &[(
            "main.rs",
            r#"
async fn handler() {}
fn app(c: &mut Config) {
 c.service(web::scope("/opaque").wrap(custom_layer()).route("/item", web::get().to(handler)))
 .service(web::scope("/public").route("/item", web::get().to(handler)));
}
"#,
        )],
    );
    let report = repo.analyze();
    assert!(matches!(
        report
            .routes
            .iter()
            .find(|r| r.path == "/opaque/item")
            .unwrap()
            .security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));
    assert_eq!(
        report
            .routes
            .iter()
            .find(|r| r.path == "/public/item")
            .unwrap()
            .security_status(),
        RouteSecurityStatus::Unprotected
    );
}

#[test]
fn role_constructor_value_is_read_instead_of_assumed_from_its_name() {
    let repo = TempRepo::new(
        "p2-constructor",
        &[(
            "main.rs",
            r#"
impl RoleGuard { fn admin() -> Self { Self { role: Role::Editor } } }
impl Service for RoleGuardMiddleware {
 fn call(&self, req: Request) { if req.role == self.role { self.service.call(req) } else { Err(denied()) } }
}
async fn handler() {}
fn app(c: &mut Config) { c.route("/item", web::get().to(handler).wrap(RoleGuard::admin())); }
"#,
        )],
    );
    let report = repo.analyze();
    assert!(
        report.security_assessments[0]
            .requirements
            .iter()
            .any(|r| r.dimension == "roles" && r.values == ["Role::Editor"])
    );
}

#[test]
fn ownership_predicate_controlling_rejection_is_observed() {
    let repo = TempRepo::new(
        "p2-control",
        &[(
            "main.rs",
            r#"
fn is_owner(user: User, id: Id) -> bool { user.id == id }
async fn handler(user: User, id: Id) { if !is_owner(user, id) { return Err(denied()); } serve(); }
fn app(c: &mut Config) { c.route("/item/{id}", web::get().to(handler)); }
"#,
        )],
    );
    let report = repo.analyze();
    assert!(report.routes[0].is_authorized());
    assert_eq!(
        report.security_assessments[0].requirements[0].enforcement,
        security::Enforcement::Observed
    );
}

#[test]
fn fallible_permission_helper_must_propagate_result() {
    let repo = TempRepo::new(
        "p2-propagation",
        &[(
            "main.rs",
            r#"
fn check_permission(p: &str) -> Result<(), Error> { if !allowed(p) { return Err(denied()); } Ok(()) }
async fn checked() { check_permission("invoice.read")?; serve(); }
async fn ignored() { check_permission("invoice.read"); serve(); }
fn app(c: &mut Config) { c.route("/checked", web::get().to(checked)).route("/ignored", web::get().to(ignored)); }
"#,
        )],
    );
    let report = repo.analyze();
    assert!(
        report
            .routes
            .iter()
            .find(|r| r.path == "/checked")
            .unwrap()
            .is_authorized()
    );
    assert!(matches!(
        report
            .routes
            .iter()
            .find(|r| r.path == "/ignored")
            .unwrap()
            .security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));
}

#[test]
fn cross_file_resources_repeated_mounts_keep_context() {
    let repo = TempRepo::new(
        "p1-mounts",
        &[
            ("Cargo.toml", "[package]\nname='fixture'\nversion='0.1.0'\n"),
            (
                "src/main.rs",
                r#"mod api;
fn main() { App::new()
 .service(web::scope("/one").wrap(AdminGuard).configure(api::configure))
 .service(web::scope("/two").configure(|c| api::configure(c))); }
"#,
            ),
            (
                "src/api.rs",
                r#"pub fn configure(c: &mut web::ServiceConfig) {
 c.service(web::resource("/{id}").get(read).put(update));
} async fn read() {} async fn update() {}"#,
            ),
        ],
    );
    let report = repo.analyze();
    assert_eq!(report.routes.len(), 4);
    for route in &report.routes {
        assert_eq!(
            !route.authorization.is_empty(),
            route.path.starts_with("/one/")
        );
        assert!(route.path == "/one/{id}" || route.path == "/two/{id}");
    }
}

#[test]
fn attribute_services_receive_mount_prefix() {
    let repo = TempRepo::new(
        "p1-attributes",
        &[(
            "main.rs",
            r#"
#[actix_web::get("/item")] async fn item() {}
fn app() { App::new().service(web::scope("/api").service(item)); }
"#,
        )],
    );
    let report = repo.analyze();
    assert_eq!(report.routes.len(), 1);
    assert_eq!(report.routes[0].path, "/api/item");
}

#[test]
fn unsupported_callback_and_dynamic_path_are_diagnostic() {
    let repo = TempRepo::new(
        "p0-diagnostics",
        &[(
            "main.rs",
            r#"
fn app(c: &mut Config) { c.configure(external::configure).route(PATH, web::get().to(handler)); }
"#,
        )],
    );
    let report = repo.analyze();
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == "unresolved_callback")
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == "unsupported_registration")
    );
}

#[test]
fn unused_local_security_predicate_is_not_protection() {
    let repo = TempRepo::new(
        "p2-unused",
        &[(
            "main.rs",
            r#"
fn is_owner() -> bool { true }
async fn handler() { is_owner(); }
fn app(c: &mut Config) { c.route("/item", web::get().to(handler)); }
"#,
        )],
    );
    let report = repo.analyze();
    assert!(!report.routes[0].is_authorized());
    assert!(matches!(
        report.routes[0].security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));
    assert_eq!(
        report.security_assessments[0].requirements[0].dimension,
        "ownership"
    );
}

#[test]
fn typed_identity_and_permission_arguments_are_preserved() {
    let repo = TempRepo::new(
        "p2-values",
        &[(
            "main.rs",
            r#"
async fn handler(user: web::ReqData<Claims>) { check_permission("invoice.read"); }
fn app(c: &mut Config) { c.route("/item", web::get().to(handler)); }
"#,
        )],
    );
    let report = repo.analyze();
    let requirements = &report.security_assessments[0].requirements;
    assert!(
        requirements
            .iter()
            .any(|r| r.dimension == "authentication" && r.mechanism == "extractor")
    );
    assert!(
        requirements
            .iter()
            .any(|r| r.dimension == "permissions" && r.values == ["invoice.read"])
    );
}

#[test]
fn middleware_name_without_implementation_does_not_prove_role_policy() {
    let repo = TempRepo::new(
        "p2-model-negative",
        &[(
            "main.rs",
            r#"
async fn handler() {}
fn app(c: &mut Config) { c.route("/item", web::get().to(handler).wrap(RequireAuth::allowed_roles(vec![Role::Admin]))); }
"#,
        )],
    );
    let report = repo.analyze();
    assert!(!report.routes[0].is_authorized());
    assert!(matches!(
        report.routes[0].security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));
}

#[test]
fn role_sets_remain_distinct_and_public_route_does_not_inherit() {
    let repo = TempRepo::new(
        "p2-roles",
        &[(
            "main.rs",
            r#"
impl Service for AuthMiddleware {
 fn call(&self, req: Request) { if self.allowed_roles.contains(&req.role) { self.service.call(req) } else { Err(denied()) } }
}
async fn handler() {}
fn app(c: &mut Config) {
 c.route("/admin", web::get().to(handler).wrap(RequireAuth::allowed_roles(vec![Role::Admin])))
 .route("/self", web::get().to(handler).wrap(RequireAuth::allowed_roles(vec![Role::User, Role::Admin])))
 .route("/public", web::get().to(handler));
}
"#,
        )],
    );
    let report = repo.analyze();
    assert_eq!(
        report.routes.iter().filter(|r| r.is_authorized()).count(),
        2
    );
    let roles: Vec<_> = report
        .security_assessments
        .iter()
        .flat_map(|a| &a.requirements)
        .filter(|r| r.dimension == "roles")
        .collect();
    assert!(roles.iter().any(|r| r.values == ["Role::Admin"]));
    assert!(
        roles
            .iter()
            .any(|r| r.values == ["Role::User", "Role::Admin"])
    );
}

#[test]
fn workspace_security_aliases_and_ignored_wrapper_results() {
    for (body, observed) in [
        ("demand(\"manage\")?;", true),
        ("demand(\"manage\");", false),
        ("wrapper(\"manage\")?;", false),
        ("recursive(\"manage\")?;", false),
    ] {
        let app = format!(
            r#"
use guards::check_permission as demand;
use guards::check_permission_wrapper as wrapper;
use guards::check_permission_recursive as recursive;
async fn handler() {{ {body} }}
fn app(c: &mut Config) {{ c.route("/item", web::get().to(handler)); }}
"#
        );
        let repo = TempRepo::new(
            "workspace-security-controls",
            &[
                (
                    "Cargo.toml",
                    "[workspace]\nmembers=[\"app\",\"guards\"]\nresolver=\"2\"",
                ),
                (
                    "app/Cargo.toml",
                    "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nguards={path=\"../guards\"}",
                ),
                (
                    "guards/Cargo.toml",
                    "[package]\nname=\"guards\"\nversion=\"0.1.0\"\nedition=\"2021\"",
                ),
                ("app/src/lib.rs", &app),
                (
                    "guards/src/lib.rs",
                    r#"
pub fn check_permission(p: &str) -> Result<(), Error> { if allowed(p) { Ok(()) } else { Err(denied()) } }
pub fn check_permission_wrapper(p: &str) -> Result<(), Error> { check_permission(p); Ok(()) }
pub fn check_permission_recursive(p: &str) -> Result<(), Error> { check_permission_recursive(p) }
"#,
                ),
            ],
        );
        let report = repo.analyze();
        let assessment = &report.security_assessments[0];
        assert_eq!(
            assessment
                .requirements
                .iter()
                .any(|r| r.enforcement == security::Enforcement::Observed),
            observed,
            "{body}: {assessment:?}"
        );
        if observed {
            assert!(
                assessment.route.authorization[0]
                    .file
                    .ends_with("app/src/lib.rs")
            );
        } else {
            assert!(matches!(
                assessment.route.status,
                RouteSecurityStatus::Unknown { .. }
            ));
        }
    }
}

#[test]
fn workspace_role_middleware_alias_and_placement_preserve_mount_boundaries() {
    for placement in ["route", "scope", "sibling"] {
        let builder = match placement {
            "route" => {
                r#"c.route("/items", web::get().to(handler).wrap(Gate::allowed_roles(vec![Role::Editor])));"#
            }
            "scope" => {
                r#"c.service(web::scope("/items").wrap(Gate::allowed_roles(vec![Role::Editor])).route("", web::get().to(handler)));"#
            }
            _ => {
                r#"c.service(web::scope("/protected").wrap(Gate::allowed_roles(vec![Role::Editor])).route("", web::get().to(handler))).route("/items", web::get().to(handler));"#
            }
        };
        let source = format!(
            "use guards::RequireAuth as Gate; async fn handler() {{ serve(); }} fn app(c: &mut Config) {{ {builder} }}"
        );
        let report = TempRepo::new("workspace-middleware-placement", &[
            ("Cargo.toml", "[workspace]\nmembers=[\"app\",\"guards\"]\nresolver=\"2\""),
            ("app/Cargo.toml", "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nguards={path=\"../guards\"}"),
            ("guards/Cargo.toml", "[package]\nname=\"guards\"\nversion=\"0.1.0\"\nedition=\"2021\""),
            ("app/src/lib.rs", &source),
            ("guards/src/lib.rs", r#"
pub struct RequireAuth;
impl RequireAuth { pub fn allowed_roles(roles: Vec<Role>) -> Self { Self } }
impl Service for AuthMiddleware { fn call(&self, req: Request) { if self.allowed_roles.contains(&req.role) { self.service.call(req) } else { Err(denied()) } } }
"#),
        ]).analyze();
        let assessment = report
            .security_assessments
            .iter()
            .find(|a| a.route.path == "/items")
            .unwrap();
        assert_eq!(assessment.requirements.iter().any(|r| r.dimension == "roles" && r.enforcement == security::Enforcement::Observed), placement != "sibling", "{placement}: {assessment:?}");
    }
}

#[test]
fn unresolved_import_does_not_borrow_a_local_middleware_model() {
    let source = r#"
use absent_dependency::RequireAuth;
impl Service for AuthMiddleware {
 fn call(&self, req: Request) { if self.allowed_roles.contains(&req.role) { self.service.call(req) } else { Err(denied()) } }
}
async fn handler() { serve(); }
fn app(c: &mut Config) { c.route("/item", web::get().to(handler).wrap(RequireAuth::allowed_roles(vec![Role::Admin]))); }
"#;
    let report = TempRepo::new("unresolved-middleware-decoy", &[("main.rs", source)]).analyze();
    assert!(
        !report.security_assessments[0]
            .requirements
            .iter()
            .any(|r| r.enforcement == security::Enforcement::Observed)
    );
    assert!(matches!(
        report.security_assessments[0].route.status,
        RouteSecurityStatus::Unknown { .. }
    ));
}

#[test]
fn qualified_public_type_reexport_keeps_role_middleware_evidence() {
    let report = TempRepo::new("qualified-type-reexport", &[("main.rs", r#"
mod security {
 mod implementation {
  pub struct RequireAuth;
  impl RequireAuth { pub fn allowed_roles(roles: Vec<Role>) -> Self { Self } }
  impl Service for AuthMiddleware { fn call(&self, req: Request) { if self.allowed_roles.contains(&req.role) { self.service.call(req) } else { Err(denied()) } } }
 }
 pub use implementation::RequireAuth;
}
use crate::security::RequireAuth;
async fn handler() { serve(); }
fn app(c: &mut Config) { c.route("/item", web::get().to(handler).wrap(RequireAuth::allowed_roles(vec![Role::Admin]))); }
"#)]).analyze();
    assert!(
        report.security_assessments[0]
            .requirements
            .iter()
            .any(|r| r.dimension == "roles" && r.enforcement == security::Enforcement::Observed)
    );
}
