use super::tests::TempRepo;
use super::*;

#[test]
fn conflicting_overlapping_contracts_abstain_instead_of_choosing_first() {
    let report = analyze_bodies(
        "conflicting-contracts",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(\"Editor\")?;",
        ],
    );
    let mut assessments = report.security_assessments.clone();
    let target = assessments
        .iter()
        .find(|a| a.route.handler.as_deref() == Some("three"))
        .unwrap()
        .clone();
    let admin: Vec<_> = assessments
        .iter()
        .filter(|a| a.route.handler.as_deref() != Some("three"))
        .cloned()
        .collect();
    let mut other = admin.clone();
    for (i, a) in other.iter_mut().enumerate() {
        a.route.path = format!("/other/{i}");
        a.requirements
            .iter_mut()
            .find(|r| r.dimension == "roles")
            .unwrap()
            .values = vec!["User".into()];
    }
    let first = PeerGroup {
        id: "first".into(),
        description: "test".into(),
        routes: admin
            .iter()
            .map(|a| a.route.clone())
            .chain([target.route.clone()])
            .collect(),
    };
    let second = PeerGroup {
        id: "second".into(),
        description: "test".into(),
        routes: other
            .iter()
            .map(|a| a.route.clone())
            .chain([target.route.clone()])
            .collect(),
    };
    assessments.extend(other);
    let mut details = Vec::new();
    let mut findings = Vec::new();
    policy_drift::extend(&[first.clone()], &assessments, &mut details, &mut findings);
    assert_eq!(details.len(), 1);
    details.clear();
    findings.clear();
    policy_drift::extend(&[second, first], &assessments, &mut details, &mut findings);
    assert!(details.is_empty());
}

#[test]
fn database_operations_and_security_helpers_do_not_create_spurious_contracts() {
    let source = r#"
fn check_role() { sqlx::query("SELECT * FROM identities"); }
async fn read() { check_role(); sqlx::query("SELECT * FROM objects"); }
async fn write() { check_role(); sqlx::query("DELETE FROM objects"); }
async fn unrelated() { check_role(); sqlx::query("SELECT * FROM invoices"); }
fn app(cfg: &mut Config) { cfg.route("/read",web::get().to(read)).route("/write",web::get().to(write)).route("/invoice",web::get().to(unrelated)); }
"#;
    let report = TempRepo::new("resource-conflicts", &[("main.rs", source)]).analyze();
    assert_eq!(report.candidate_relationships.len(), 1);
    assert!(!report.candidate_relationships[0].contract_eligible);
    assert!(
        report.candidate_relationships[0]
            .conflicts
            .iter()
            .any(|c| c.contains("database operations"))
    );
    assert!(report.finding_details.is_empty());
}

#[test]
fn overlapping_families_do_not_merge_transitively_or_duplicate_findings() {
    let report = analyze_bodies(
        "overlap-base",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(\"User\")?;",
        ],
    );
    let group = report.peer_groups[0].clone();
    let mut details = Vec::new();
    let mut findings = Vec::new();
    policy_drift::extend(
        &[group.clone(), group],
        &report.security_assessments,
        &mut details,
        &mut findings,
    );
    assert_eq!(details.len(), 1);
    let edge = |a, b| policy_drift::Relationship {
        left: a,
        right: b,
        kind: "test".into(),
        evidence: vec![],
        conflicts: vec![],
        evidence_score: 0,
        confidence: "test".into(),
        contract_eligible: true,
    };
    let families = policy_drift::families(&report.routes, &[edge(0, 1), edge(1, 2)]);
    assert_eq!(families.len(), 2);
    assert!(families.iter().all(|g| g.routes.len() == 2));
}

#[test]
fn candidates_survive_removal_of_all_authorization() {
    let source = r#"
fn check_role(role: &str) -> Result<(), Error> { if !allowed(role) { return Err(denied()); } Ok(()) }
async fn item() { check_role("Admin")?; }
async fn collection() { check_role("Admin")?; }
fn app(c: &mut Config) { c.service(web::scope("/objects")
 .route("", web::get().to(collection)).route("/{id}", web::get().to(item))); }
"#;
    let baseline = TempRepo::new("candidate-before", &[("main.rs", source)]).analyze();
    let mutation = source.replace("check_role(\"Admin\")?;", "");
    let after = TempRepo::new("candidate-after", &[("main.rs", &mutation)]).analyze();
    assert_eq!(baseline.candidate_relationships.len(), 1);
    assert_eq!(after.candidate_relationships.len(), 1);
    assert_eq!(after.candidate_relationships[0].kind, "collection_item");
    assert!(!after.candidate_relationships[0].contract_eligible);
    assert!(after.finding_details.is_empty());
}

#[test]
fn generic_shared_utilities_do_not_establish_peer_membership() {
    let source = r#"
mod storage { pub fn load() {} pub fn list() {} }
async fn a() { storage::load(); }
async fn b() { storage::list(); }
fn app(c: &mut Config) { c.route("/single/{id}", web::get().to(a))
 .route("/catalog", web::get().to(b)); }
"#;
    let report = TempRepo::new("candidate-dependency", &[("main.rs", source)]).analyze();
    assert!(report.candidate_relationships.is_empty());
}

// Source-level mutations: each case changes exactly one handler, in every
// route position, and checks the exact target/category (not just a count).
#[test]
fn source_mutation_matrix() {
    let base = "check_role(\"Admin\")?; check_permission(\"write\")?; if !is_owner(user, id) { return Err(denied()); }";
    let cases = [
        (
            "wrong-role",
            "check_role(\"User\")?; check_permission(\"write\")?; if !is_owner(user, id) { return Err(denied()); }",
            Some(DriftCategory::InconsistentRoleOrPermission),
        ),
        (
            "wrong-permission",
            "check_role(\"Admin\")?; check_permission(\"read\")?; if !is_owner(user, id) { return Err(denied()); }",
            Some(DriftCategory::InconsistentRoleOrPermission),
        ),
        (
            "missing-role",
            "check_permission(\"write\")?; if !is_owner(user, id) { return Err(denied()); }",
            Some(DriftCategory::InconsistentRoleOrPermission),
        ),
        (
            "missing-permission",
            "check_role(\"Admin\")?; if !is_owner(user, id) { return Err(denied()); }",
            Some(DriftCategory::InconsistentRoleOrPermission),
        ),
        (
            "missing-owner",
            "check_role(\"Admin\")?; check_permission(\"write\")?;",
            Some(DriftCategory::MissingOwnershipValidation),
        ),
        (
            "missing-all",
            "serve();",
            Some(DriftCategory::MissingOwnershipValidation),
        ),
        (
            "ignored",
            "check_role(\"Admin\"); check_permission(\"write\"); is_owner(user, id);",
            None,
        ),
        (
            "equivalent-predicate",
            "if !check_role(\"Admin\").is_ok() { return Err(denied()); } check_permission(\"write\")?; if !is_owner(user, id) { return Err(denied()); }",
            None,
        ),
        (
            "reordered",
            "if !is_owner(user, id) { return Err(denied()); } check_permission(\"write\")?; check_role(\"Admin\")?;",
            None,
        ),
        ("unchanged", base, None),
    ];
    for (name, mutation, expected) in cases {
        for position in 0..3 {
            let mut bodies = [base; 3];
            bodies[position] = mutation;
            let report = analyze_bodies(&format!("mutation-{name}-{position}"), bodies);
            assert!(report.parse_errors.is_empty());
            assert_eq!(report.routes.len(), 3);
            assert_eq!(report.peer_groups.len(), 1);
            assert_eq!(
                report.finding_details.len(),
                if name == "missing-all" {
                    3
                } else {
                    usize::from(expected.is_some())
                },
                "{name}, position {position}: {:?}",
                report.finding_details
            );
            if let Some(category) = &expected {
                let finding = &report.finding_details[0];
                if name != "missing-all" {
                    assert_eq!(&finding.category, category, "{name}");
                }
                assert_eq!(
                    finding.suspicious_route.handler.as_deref(),
                    Some(["one", "two", "three"][position])
                );
            }
            if name == "ignored" {
                assert_eq!(report.summary.unwrap().unknown_routes, 1);
            }
        }
    }
}

#[test]
fn mounted_allowlist_mutations() {
    for (name, baseline, mutated, count) in [
        ("broaden", "Role::Admin", "Role::Admin, Role::User", 1),
        ("replace", "Role::Admin", "Role::User", 1),
        ("narrow", "Role::Admin, Role::User", "Role::Admin", 0),
        (
            "reorder",
            "Role::Admin, Role::User",
            "Role::User, Role::Admin",
            0,
        ),
        ("duplicate", "Role::Admin", "Role::Admin, Role::Admin", 0),
    ] {
        for position in 0..3 {
            let mut policies = [baseline; 3];
            policies[position] = mutated;
            let source = format!(
                r#"
impl Service for AuthMiddleware {{
 fn call(&self, req: Request) {{ if self.allowed_roles.contains(&req.role) {{ self.service.call(req) }} else {{ Err(denied()) }} }}
}}
async fn one() {{ sqlx::query("SELECT * FROM records"); }} async fn two() {{ sqlx::query("SELECT * FROM records"); }} async fn three() {{ sqlx::query("SELECT * FROM records"); }}
fn app(c: &mut Config) {{ c.service(web::scope("/records")
 .route("/one", web::get().to(one).wrap(RequireAuth::allowed_roles(vec![{}])))
 .route("/two", web::get().to(two).wrap(RequireAuth::allowed_roles(vec![{}])))
 .route("/three", web::get().to(three).wrap(RequireAuth::allowed_roles(vec![{}])))); }}
"#,
                policies[0], policies[1], policies[2]
            );
            let report = TempRepo::new(
                &format!("allowlist-{name}-{position}"),
                &[("main.rs", &source)],
            )
            .analyze();
            assert_eq!(report.summary.as_ref().unwrap().protected_routes, 3);
            assert_eq!(
                report.finding_details.len(),
                count,
                "{name}: {:?}",
                report.finding_details
            );
            if count == 1 {
                assert_eq!(
                    report.finding_details[0]
                        .suspicious_route
                        .handler
                        .as_deref(),
                    Some(["one", "two", "three"][position])
                );
            }
        }
    }
}

#[test]
fn multiple_omissions_produce_distinct_requirement_findings() {
    let report = analyze_bodies(
        "mutation-two-omissions",
        [
            "check_role(\"Admin\")?; check_permission(\"write\")?; if !is_owner(user,id) { return Err(denied()); }",
            "check_role(\"Admin\")?; check_permission(\"write\")?; if !is_owner(user,id) { return Err(denied()); }",
            "check_role(\"Admin\")?;",
        ],
    );
    assert_eq!(report.finding_details.len(), 2);
    assert!(
        report
            .finding_details
            .iter()
            .any(|f| f.category == DriftCategory::MissingOwnershipValidation)
    );
    assert!(
        report
            .finding_details
            .iter()
            .any(|f| f.category == DriftCategory::InconsistentRoleOrPermission)
    );
    assert!(
        report
            .finding_details
            .iter()
            .all(|f| f.suspicious_route.handler.as_deref() == Some("three"))
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["summary"]["drift_findings_count"], 2);
    assert_eq!(json["finding_details"].as_array().unwrap().len(), 2);
}

#[test]
fn unsupported_values_and_insufficient_support_abstain() {
    let cases = [
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(required_role)?;",
        ],
        ["check_role(\"Admin\")?;", "serve();", "serve();"],
        ["serve();", "serve();", "serve();"],
        [
            "check_role(\"Admin\")?;",
            "check_role(required_role)?;",
            "check_role(\"User\")?;",
        ],
    ];
    for (i, bodies) in cases.into_iter().enumerate() {
        let report = analyze_bodies(&format!("mutation-abstain-{i}"), bodies);
        assert!(report.finding_details.is_empty(), "case {i}");
    }
}

#[test]
fn unknown_members_count_against_policy_consensus() {
    let source = r#"
fn check_role(role: &str) -> Result<(), Error> { if !allowed(role) { return Err(denied()); } Ok(()) }
async fn a() { sqlx::query("SELECT * FROM records"); check_role("Admin")?; }
async fn b() { sqlx::query("SELECT * FROM records"); check_role("Admin")?; }
async fn c() { sqlx::query("SELECT * FROM records"); check_role("User")?; }
async fn d() { sqlx::query("SELECT * FROM records"); check_role(dynamic_role)?; }
async fn e() { sqlx::query("SELECT * FROM records"); check_role(dynamic_role)?; }
fn app(cfg: &mut Config) { cfg.service(web::scope("/records")
 .route("/a", web::get().to(a)).route("/b", web::get().to(b))
 .route("/c", web::get().to(c)).route("/d", web::get().to(d))
 .route("/e", web::get().to(e))); }
"#;
    let report = TempRepo::new("mutation-unknown-consensus", &[("main.rs", source)]).analyze();
    assert_eq!(report.peer_groups.len(), 1);
    assert_eq!(
        report.peer_groups[0].routes.len(),
        5,
        "{:?} {:?}",
        report.routes,
        report.candidate_relationships
    );
    assert!(report.finding_details.is_empty());
}

fn analyze_bodies(name: &str, bodies: [&str; 3]) -> Report {
    let source = format!(
        r#"
fn check_role(role: &str) -> Result<(), Error> {{ if !allowed(role) {{ return Err(denied()); }} Ok(()) }}
fn check_permission(p: &str) -> Result<(), Error> {{ if !allowed(p) {{ return Err(denied()); }} Ok(()) }}
fn is_owner(user: User, id: Id) -> bool {{ user.id == id }}
async fn one() {{ {} sqlx::query("SELECT * FROM records"); }}
async fn two() {{ {} sqlx::query("SELECT * FROM records"); }}
async fn three() {{ {} sqlx::query("SELECT * FROM records"); }}
fn app(c: &mut Config) {{ c.service(web::scope("/records")
 .route("/one/{{id}}", web::get().to(one))
 .route("/two/{{id}}", web::get().to(two))
 .route("/three/{{id}}", web::get().to(three))); }}
"#,
        bodies[0], bodies[1], bodies[2]
    );
    TempRepo::new(name, &[("main.rs", &source)]).analyze()
}

#[test]
fn protected_wrong_role_is_reported_with_requirement_evidence() {
    let report = analyze_bodies(
        "p3-role",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(\"User\")?;",
        ],
    );
    assert_eq!(report.summary.as_ref().unwrap().protected_routes, 3);
    assert_eq!(report.finding_details.len(), 1);
    let finding = &report.finding_details[0];
    assert_eq!(
        finding.category,
        DriftCategory::InconsistentRoleOrPermission
    );
    assert_eq!(finding.suspicious_route.handler.as_deref(), Some("three"));
    assert_eq!(finding.authorized_peer_routes.len(), 2);
    assert!(finding.explanation.contains("Admin"));
    assert!(finding.explanation.contains("User"));
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.summary.as_ref().unwrap().drift_findings_count, 1);
    assert_eq!(report.summary.as_ref().unwrap().peer_compared_routes, 1);
    assert!(
        report
            .graph
            .unwrap()
            .nodes
            .iter()
            .any(|n| n.kind == NodeKind::Finding)
    );
}

#[test]
fn permission_drift_is_checked_independently_of_role_protection() {
    let report = analyze_bodies(
        "p3-permission",
        [
            "check_permission(\"record.write\")?;",
            "check_permission(\"record.write\")?;",
            "check_role(\"Admin\")?;",
        ],
    );
    assert_eq!(report.finding_details.len(), 1);
    assert_eq!(
        report.finding_details[0].category,
        DriftCategory::InconsistentRoleOrPermission
    );
    assert!(
        report.finding_details[0]
            .explanation
            .contains("permissions")
    );
}

#[test]
fn protected_route_can_lack_peer_ownership_requirement() {
    let report = analyze_bodies(
        "p3-ownership",
        [
            "check_role(\"User\")?; if !is_owner(user, id) { return Err(denied()); }",
            "check_role(\"User\")?; if !is_owner(other, key) { return Err(denied()); }",
            "check_role(\"User\")?;",
        ],
    );
    assert_eq!(report.finding_details.len(), 1);
    assert_eq!(
        report.finding_details[0].category,
        DriftCategory::MissingOwnershipValidation
    );
}

#[test]
fn matching_policies_do_not_create_drift() {
    let report = analyze_bodies(
        "p3-match",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
        ],
    );
    assert!(report.finding_details.is_empty());
}

#[test]
fn different_permission_value_is_reported() {
    let report = analyze_bodies(
        "p3-wrong-permission",
        [
            "check_permission(\"record.write\")?;",
            "check_permission(\"record.write\")?;",
            "check_permission(\"record.read\")?;",
        ],
    );
    assert_eq!(report.finding_details.len(), 1);
    assert!(
        report.finding_details[0]
            .explanation
            .contains("record.read")
    );
}

#[test]
fn narrower_role_allowlist_does_not_weaken_peer_policy() {
    let mut report = analyze_bodies(
        "p3-narrower",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
        ],
    );
    for assessment in &mut report.security_assessments {
        if assessment.route.handler.as_deref() != Some("three") {
            assessment
                .requirements
                .iter_mut()
                .find(|r| r.dimension == "roles")
                .unwrap()
                .values
                .push("Editor".into());
        }
    }
    let mut details = Vec::new();
    let mut findings = Vec::new();
    policy_drift::extend(
        &report.peer_groups,
        &report.security_assessments,
        &mut details,
        &mut findings,
    );
    assert!(details.is_empty());
}

#[test]
fn multiple_role_checks_are_not_flattened_into_an_allowlist() {
    let report = analyze_bodies(
        "p3-multiple",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(\"User\")?; check_role(\"Editor\")?;",
        ],
    );
    assert!(report.finding_details.is_empty());
}

#[test]
fn operation_policy_difference_outside_peer_family_is_not_flagged() {
    let source = r#"
fn check_role(role: &str) -> Result<(), Error> { if !allowed(role) { return Err(denied()); } Ok(()) }
async fn one() { check_role("Admin")?; }
async fn two() { check_role("Admin")?; }
async fn self_profile() { check_role("User")?; }
fn app(c: &mut Config) { c.service(web::scope("/users")
 .route("/one", web::get().to(one)).route("/two", web::get().to(two)))
 .service(web::scope("/self").route("/profile", web::get().to(self_profile))); }
"#;
    let report = TempRepo::new("p3-exception", &[("main.rs", source)]).analyze();
    assert!(report.finding_details.is_empty());
    let summary = report.summary.unwrap();
    assert_eq!(summary.peer_compared_routes, 0);
    assert_eq!(summary.routes_without_peer_comparison, 3);
}

#[test]
fn mixed_policies_without_two_supporters_do_not_invent_a_contract() {
    let report = analyze_bodies(
        "p3-mixed",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Editor\")?;",
            "check_role(\"User\")?;",
        ],
    );
    assert!(report.finding_details.is_empty());
}

#[test]
fn ignored_check_is_uncertain_rather_than_missing_policy() {
    let report = analyze_bodies(
        "p3-ignored",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_permission(\"record.read\")?; check_role(\"Admin\");",
        ],
    );
    assert!(report.finding_details.is_empty());
}

#[test]
fn missing_all_enforcement_still_uses_existing_finding_without_duplicates() {
    let report = analyze_bodies(
        "p3-missing",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "serve();",
        ],
    );
    assert_eq!(report.finding_details.len(), 1);
    assert_eq!(
        report.finding_details[0].category,
        DriftCategory::InconsistentRoleOrPermission
    );
}

#[test]
fn cross_operation_resources_keep_membership_under_policy_mutation() {
    for resource in ["invoices", "projects", "messages"] {
        for mutation in [
            "check_role(\"Admin\")?;",
            "check_role(\"Visitor\")?;",
            "serve();",
        ] {
            let source = format!(
                r#"
fn check_role(role: &str) -> Result<(), Error> {{ if !allowed(role) {{ return Err(denied()); }} Ok(()) }}
async fn read() {{ check_role("Admin")?; }}
async fn update() {{ check_role("Admin")?; }}
async fn delete() {{ {mutation} }}
fn app(cfg: &mut Config) {{ cfg.route("/{resource}/{{id}}",web::get().to(read))
.route("/{resource}/{{id}}",web::put().to(update))
.route("/{resource}/{{id}}",web::delete().to(delete)); }}
"#
            );
            let report = TempRepo::new("cross-operation", &[("main.rs", &source)]).analyze();
            assert_eq!(report.peer_groups.len(), 1);
            assert_eq!(report.peer_groups[0].routes.len(), 3);
            assert!(!report.invariants.is_empty());
            assert_eq!(
                report.finding_details.len(),
                usize::from(mutation != "check_role(\"Admin\")?;")
            );
        }
    }
}

#[test]
fn two_peers_establish_an_invariant_without_inventing_a_drift() {
    let source = r#"
fn check_permission(value: &str) -> Result<(), Error> { if !allowed(value) { return Err(denied()); } Ok(()) }
async fn archive() { check_permission("manage")?; }
async fn restore() { check_permission("manage")?; }
fn app(cfg: &mut Config) { cfg.route("/records/{id}/archive",web::post().to(archive))
.route("/records/{id}/restore",web::patch().to(restore)); }
"#;
    let report = TempRepo::new("two-member-invariant", &[("main.rs", source)]).analyze();
    assert_eq!(report.peer_groups.len(), 1);
    assert_eq!(report.invariants.len(), 1);
    assert!(report.finding_details.is_empty());
}

#[test]
fn unrelated_siblings_do_not_inherit_policy_from_mount_alone() {
    let source = r#"
async fn one() { check_role("Admin")?; }
async fn two() { check_role("Admin")?; }
async fn three() { serve(); }
fn app(cfg: &mut Config) { cfg.route("/api/invoices",web::get().to(one))
.route("/api/messages",web::get().to(two)).route("/api/weather",web::get().to(three)); }
"#;
    let report = TempRepo::new("unrelated-siblings", &[("main.rs", source)]).analyze();
    assert!(report.peer_groups.is_empty());
    assert!(report.invariants.is_empty());
    assert!(report.finding_details.is_empty());
}

#[test]
fn resolved_data_models_support_collection_item_and_self_without_named_paths() {
    for endpoint in ["current", "owned", "selected"] {
        for missing_auth in [false, true] {
            let auth = if missing_auth {
                ""
            } else {
                "require_auth(\"session\")?;"
            };
            let source = format!(
                r#"
struct Record {{ id: u64 }}
struct View {{ id: u64 }}
impl View {{
 pub fn one(record: &Record) -> Self {{ View {{ id: record.id }} }}
 pub fn many(records: &[Record]) -> Vec<View> {{ records.iter().map(View::one).collect() }}
}}
fn require_auth(kind: &str) -> Result<(), Error> {{ if allowed(kind) {{ Ok(()) }} else {{ Err(denied()) }} }}
fn check_role(role: &str) -> Result<(), Error> {{ if allowed(role) {{ Ok(()) }} else {{ Err(denied()) }} }}
async fn collection() {{ require_auth("session")?; check_role("Admin")?; HttpResponse::Ok().json(View::many(&records)); }}
async fn item() {{ require_auth("session")?; check_role("Member")?; HttpResponse::Ok().json(View::one(&record)); }}
async fn selected() {{ {auth} check_role("Member")?; HttpResponse::Ok().json(View::one(&record)); }}
fn app(c: &mut Config) {{ c.service(web::scope("/records")
 .route("",web::get().to(collection)).route("/{{id}}",web::get().to(item)).route("/{endpoint}",web::get().to(selected))); }}
"#
            );
            let report =
                TempRepo::new("resource-selector-controls", &[("main.rs", &source)]).analyze();
            assert_eq!(report.peer_groups.len(), 1, "{endpoint}");
            assert_eq!(report.peer_groups[0].routes.len(), 3);
            assert!(
                report
                    .invariants
                    .iter()
                    .any(|i| i.description.starts_with("Supported authentication"))
            );
            assert!(
                !report
                    .invariants
                    .iter()
                    .any(|i| i.description.starts_with("Supported roles"))
            );
            assert_eq!(report.finding_details.len(), usize::from(missing_auth));
            if missing_auth {
                assert_eq!(
                    report.finding_details[0]
                        .suspicious_route
                        .handler
                        .as_deref(),
                    Some("selected")
                );
            }
            assert!(
                report
                    .analysis_evidence
                    .iter()
                    .any(|e| e.stage == "invariant"
                        && e.dimension.as_deref() == Some("roles")
                        && !e.abstention_reasons.is_empty())
            );
        }
    }
}

#[test]
fn shared_unit_returning_utilities_are_not_data_models() {
    let source = r#"
struct Context { id: u64 }
struct Logger;
impl Logger { pub fn event(ctx: &Context) { log(ctx.id); } }
async fn one() { Logger::event(&ctx); }
async fn two() { Logger::event(&ctx); }
fn app(c: &mut Config) { c.route("/inventory", web::get().to(one)).route("/forecast", web::get().to(two)); }
"#;
    let report = TempRepo::new("typed-utility-negative", &[("main.rs", source)]).analyze();
    assert!(report.peer_groups.is_empty());
    assert!(report.finding_details.is_empty());
}

#[test]
fn concrete_cross_crate_methods_trait_defaults_and_alias_returns_share_resources() {
    for resource in ["invoices", "tickets", "assets"] {
        let storage = format!(
            r#"
pub mod schema {{ pub mod {resource} {{}} }}
pub mod models {{
 use crate::schema::{resource};
 #[diesel(table_name = {resource})] pub struct Entry {{ pub id: u64 }}
}}
pub type StoreResult<T> = Result<T, Error>;
pub mod repository {{
 use crate::models::Entry;
 use crate::schema::{resource};
 pub trait ReadStore {{ fn load(&self) -> Entry {{ {resource}::table.first(conn); Entry {{ id: 1 }} }} }}
 impl ReadStore for Entry {{}}
 impl Entry {{ pub fn fetch() -> Self {{ {resource}::table.first(conn); Entry {{ id: 1 }} }} }}
 pub struct Query;
 impl Query {{ pub fn list(&self) -> Vec<Entry> {{ {resource}::table.load(conn); vec![] }} }}
}}
"#
        );
        let app = format!(
            r#"
use storage::{{models::Entry, repository::{{Query, ReadStore}}, StoreResult}};
fn service() -> StoreResult<Entry> {{ Ok(Entry::fetch()) }}
async fn collection() {{ let rows = Query {{}}.list(); respond(rows); }}
async fn item(repo: Entry) {{ let row = repo.load(); respond(row); }}
async fn selected() {{ let row = service()?; respond(row); }}
fn app(c: &mut Config) {{ c.route("/{resource}", web::get().to(collection))
.service(web::scope("/{resource}").route("/{{id}}", web::get().to(item)).route("/selected", web::get().to(selected))); }}
"#
        );
        let report = TempRepo::new("typed-resource-workspace", &[
            ("Cargo.toml", "[workspace]\nmembers=[\"app\",\"storage\"]\nresolver=\"2\""),
            ("app/Cargo.toml", "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nstorage={path=\"../storage\"}"),
            ("storage/Cargo.toml", "[package]\nname=\"storage\"\nversion=\"0.1.0\"\nedition=\"2021\""),
            ("app/src/lib.rs", &app), ("storage/src/lib.rs", &storage),
        ]).analyze();
        assert_eq!(
            report.peer_groups.len(),
            1,
            "{resource}: {:?}",
            report.peer_groups
        );
        assert_eq!(report.peer_groups[0].routes.len(), 3);
        assert!(report.finding_details.is_empty());
        assert!(report.resource_evidence.iter().any(|r| {
            r.call_chain_evidence
                .iter()
                .any(|call| call.contains("::Query::list"))
        }));
        assert!(report.resource_evidence.iter().any(|r| {
            r.call_chain_evidence
                .iter()
                .any(|call| call.contains("::Entry::load"))
        }));
    }
}

#[test]
fn competing_traits_unknown_receivers_and_shadowing_never_guess_a_method() {
    for body in [
        "let value = receiver.load();",
        "let receiver = opaque(); let value = receiver.load();",
        "{ let receiver = opaque(); let value = receiver.load(); }",
    ] {
        let source = format!(
            r#"
mod schema {{ pub mod invoices {{}} pub mod weather {{}} }}
struct Row;
trait A {{ fn load(&self) -> Row {{ schema::invoices::table.first(conn); Row }} }}
trait B {{ fn load(&self) -> Row {{ schema::weather::table.first(conn); Row }} }}
impl A for Row {{}} impl B for Row {{}}
async fn one(receiver: Row) {{ {body} }}
async fn two() {{ let row = schema::invoices::table.first(conn); }}
fn app(c: &mut Config) {{ c.route("/a",web::get().to(one)).route("/b",web::get().to(two)); }}
"#
        );
        let report =
            TempRepo::new("ambiguous-receiver-negative", &[("main.rs", &source)]).analyze();
        assert!(report.peer_groups.is_empty(), "{body}");
    }
}

#[test]
fn generic_auxiliary_helpers_do_not_independently_make_peers() {
    let source = r#"
struct Settings;
impl Settings { pub fn read() -> Self { sqlx::query("SELECT * FROM settings"); Self } }
fn log_request() { sqlx::query("INSERT INTO audit_log VALUES (1)"); }
struct Audit;
impl Audit { pub fn record(&self) -> Result<(), Error> { sqlx::query("INSERT INTO audit_log VALUES (1)"); Ok(()) } }
async fn one() { Settings::read(); let _ = Settings::read(); log_request(); Audit {}.record(); respond(); }
async fn two() { Settings::read(); let _ = Settings::read(); log_request(); Audit {}.record(); respond(); }
fn app(c: &mut Config) { c.route("/inventory",web::get().to(one)).route("/forecast",web::get().to(two)); }
"#;
    let report = TempRepo::new("auxiliary-data-negative", &[("main.rs", source)]).analyze();
    assert!(report.peer_groups.is_empty());
}

#[test]
fn resource_overlap_is_not_transitive_and_method_names_do_not_identify_resources() {
    let source = r#"
struct Invoices; struct Weather;
impl Invoices { pub fn load() -> Self { sqlx::query("SELECT * FROM invoices"); Self } }
impl Weather { pub fn load() -> Self { sqlx::query("SELECT * FROM weather"); Self } }
async fn one() { let row = Invoices::load(); respond(row); }
async fn bridge() { let a = Invoices::load(); let b = Weather::load(); respond((a,b)); }
async fn three() { let row = Weather::load(); respond(row); }
fn app(c: &mut Config) { c.route("/one",web::get().to(one)).route("/bridge",web::get().to(bridge)).route("/three",web::get().to(three)); }
"#;
    let report = TempRepo::new("typed-overlap-not-transitive", &[("main.rs", source)]).analyze();
    assert_eq!(report.peer_groups.len(), 2);
    assert!(report.peer_groups.iter().all(|g| g.routes.len() == 2));
    assert!(!report.peer_groups.iter().any(|g| {
        g.routes.iter().any(|r| r.handler.as_deref() == Some("one"))
            && g.routes
                .iter()
                .any(|r| r.handler.as_deref() == Some("three"))
    }));
}

#[test]
fn nested_resource_mount_membership_does_not_transfer_public_creation_policy() {
    let source = r#"
mod schema { pub mod invoices {} }
use crate::schema::invoices;
#[diesel(table_name = invoices)] struct Entry;
impl Entry { pub fn fetch() -> Self { invoices::table.first(conn); Self } }
fn check_role(role: &str) -> Result<(), Error> { if allowed(role) { Ok(()) } else { Err(denied()) } }
async fn public() { let row = Entry::fetch(); respond(row); }
async fn one() { check_role("Admin")?; let row = Entry::fetch(); respond(row); }
async fn two() { check_role("Admin")?; let row = Entry::fetch(); respond(row); }
async fn three() { check_role("Admin")?; let row = Entry::fetch(); respond(row); }
fn app(c: &mut Config) { c.service(web::scope("/api")
 .route("/invoices",web::post().to(public))
 .service(web::scope("/invoices")
  .route("/{id}/one",web::get().to(one)).route("/{id}/two",web::get().to(two)).route("/{id}/three",web::get().to(three)))); }
"#;
    let report = TempRepo::new("nested-resource-policy-contexts", &[("main.rs", source)]).analyze();
    assert!(report.peer_groups.iter().any(|g| g.routes.len() == 4));
    assert!(report.finding_details.is_empty());
    assert!(
        report
            .analysis_evidence
            .iter()
            .filter(|e| e.stage == "drift"
                && e.route
                    .as_ref()
                    .is_some_and(|r| r.handler.as_deref() == Some("public")))
            .all(|e| !e.abstention_reasons.is_empty())
    );
}

#[test]
fn shadowed_pattern_and_shared_cache_reads_cannot_create_resource_peers() {
    for branch in [
        "if let Some(receiver) = opaque() { let row = receiver.load(); }",
        "match opaque() { Some(receiver) => { let row = receiver.load(); }, _ => {} }",
        "while let Some(receiver) = opaque() { let row = receiver.load(); }",
    ] {
        let source = format!(
            r#"
struct Invoices;
impl Invoices {{ pub fn load(&self) -> Self {{ sqlx::query("SELECT * FROM invoices"); Self }} }}
async fn one(receiver: Invoices) {{ {branch} }}
async fn two() {{ let row = sqlx::query("SELECT * FROM invoices"); respond(row); }}
fn app(c: &mut Config) {{ c.route("/one",web::get().to(one)).route("/two",web::get().to(two)); }}
"#
        );
        let report =
            TempRepo::new("pattern-shadow-resource-negative", &[("main.rs", &source)]).analyze();
        assert!(report.peer_groups.is_empty());
    }
}

#[test]
fn consumed_opaque_record_wrappers_and_private_query_factories_keep_resource_evidence() {
    let source = r#"
mod schema { pub mod invoices {} }
struct View;
impl View {
 fn query() -> OpaqueQuery { schema::invoices::table.select(columns) }
 pub fn read() -> Self { let row = Self::query().first(conn); Self }
}
fn service() -> ExternalResult<View> { Ok(View::read()) }
async fn one() { let result = service(); respond(result); }
async fn two() { let result = View::read(); respond(result); }
fn app(c: &mut Config) { c.route("/one",web::get().to(one)).route("/two",web::get().to(two)); }
"#;
    let report = TempRepo::new("private-query-factory", &[("main.rs", source)]).analyze();
    assert_eq!(report.peer_groups.len(), 1);
    assert_eq!(report.peer_groups[0].routes.len(), 2);
}

#[test]
fn containers_are_not_their_payload_receivers() {
    for parameter in ["Option<Row>", "Vec<Row>", "Result<Row, Error>"] {
        let source = format!(
            r#"
struct Row;
impl Row {{ pub fn load(&self) -> Self {{ sqlx::query("SELECT * FROM records"); Self }} }}
async fn one(receiver: {parameter}) {{ let value = receiver.load(); respond(value); }}
async fn two() {{ let value = sqlx::query("SELECT * FROM records"); respond(value); }}
fn app(c: &mut Config) {{ c.route("/one",web::get().to(one)).route("/two",web::get().to(two)); }}
"#
        );
        let report = TempRepo::new("container-payload-negative", &[("main.rs", &source)]).analyze();
        assert!(report.peer_groups.is_empty(), "{parameter}");
    }
}

#[test]
fn global_unique_name_fallback_does_not_supply_resource_proof() {
    let source = r#"
struct Row;
mod not_imported { pub fn fetch() -> super::Row { sqlx::query("SELECT * FROM records"); super::Row } }
async fn one() { let row = fetch(); respond(row); }
async fn two() { let row = sqlx::query("SELECT * FROM records"); respond(row); }
fn app(c: &mut Config) { c.route("/one",web::get().to(one)).route("/two",web::get().to(two)); }
"#;
    let report = TempRepo::new("unique-name-resource-negative", &[("main.rs", source)]).analyze();
    assert!(report.peer_groups.is_empty());
}

#[test]
fn same_line_trait_implementations_have_distinct_resource_cache_entries() {
    let source = r#"
struct Row; trait A { fn load(&self) -> Row { sqlx::query("SELECT * FROM alpha"); Row } } trait B { fn load(&self) -> Row { sqlx::query("SELECT * FROM beta"); Row } } impl A for Row {} impl B for Row {}
mod one { use crate::{Row,A}; pub fn read(row: Row) -> Row { row.load() } }
mod two { use crate::{Row,B}; pub fn read(row: Row) -> Row { row.load() } }
async fn handler() { let a = one::read(Row); let b = two::read(Row); respond((a,b)); }
fn app(c: &mut Config) { c.route("/records",web::get().to(handler)); }
"#;
    let report = TempRepo::new("distinct-trait-resource-cache", &[("main.rs", source)]).analyze();
    assert!(
        report.resource_evidence[0]
            .resources
            .iter()
            .any(|r| r == "sql:alpha")
    );
    assert!(
        report.resource_evidence[0]
            .resources
            .iter()
            .any(|r| r == "sql:beta")
    );
}

#[test]
fn receiver_autoref_conflicts_abstain_instead_of_preferring_an_inherent_guess() {
    let source = r#"
struct Row;
impl Row { pub fn load(&mut self) -> Self { sqlx::query("SELECT * FROM invoices"); Self } }
trait Alternate { fn load(&self) -> Row { sqlx::query("SELECT * FROM weather"); Row } }
impl Alternate for Row {}
async fn one(receiver: Row) { let row = receiver.load(); respond(row); }
async fn two() { let row = sqlx::query("SELECT * FROM invoices"); respond(row); }
fn app(c: &mut Config) { c.route("/one",web::get().to(one)).route("/two",web::get().to(two)); }
"#;
    let report = TempRepo::new("receiver-autoref-negative", &[("main.rs", source)]).analyze();
    assert!(report.peer_groups.is_empty());
    assert!(
        report
            .resource_evidence
            .iter()
            .find(|r| r.route.handler.as_deref() == Some("one"))
            .unwrap()
            .abstention_reasons
            .iter()
            .any(|r| r.contains("No unique applicable implementation"))
    );
}
