//! Framework-neutral security observations, separate from peer inference.
use super::*;

pub(super) fn known_nonsecurity_constructor(expr: &Expr) -> bool {
    let mut root = expr;
    while let Expr::MethodCall(call) = root {
        root = &call.receiver;
    }
    matches!(root, Expr::Call(call) if matches!(&*call.func, Expr::Path(path) if path.path.segments.iter().any(|s| ["Cors", "Logger", "Compress", "NormalizePath", "DefaultHeaders"].contains(&s.ident.to_string().as_str()))))
}

pub(super) fn unknown_middleware(node: &ExprMethodCall, file: &Path) -> Vec<AuthEvidence> {
    let mut current = node;
    let mut evidence = Vec::new();
    loop {
        if current.method == "wrap" {
            for arg in &current.args {
                struct Names(Vec<String>);
                impl<'ast> Visit<'ast> for Names {
                    fn visit_expr_path(&mut self, p: &'ast ExprPath) {
                        self.0
                            .extend(p.path.segments.iter().map(|s| s.ident.to_string()));
                    }
                }
                let mut names = Names(Vec::new());
                names.visit_expr(arg);
                let known_nonsecurity = names.0.iter().any(|n| {
                    [
                        "Cors",
                        "Logger",
                        "Compress",
                        "NormalizePath",
                        "DefaultHeaders",
                    ]
                    .contains(&n.as_str())
                });
                if route_configuration_name_in_expr(arg).is_none() && !known_nonsecurity {
                    evidence.push(AuthEvidence {
                        kind: AuthEvidenceKind::Unknown,
                        mechanism: "UnresolvedMiddleware".into(),
                        symbol: Some(arg.to_token_stream().to_string()),
                        file: file.to_path_buf(),
                        line: arg.span().start().line,
                        handler: None,
                        strength: AuthStrength::Weak,
                    });
                }
            }
        }
        match &*current.receiver {
            Expr::MethodCall(next) => current = next,
            _ => break,
        }
    }
    evidence
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum Enforcement {
    Observed,
    Potential,
    Unresolved,
}

#[derive(Debug, Clone, Serialize)]
pub struct Requirement {
    pub dimension: String,
    pub values: Vec<String>,
    pub mechanism: String,
    pub enforcement: Enforcement,
    pub confidence: AuthStrength,
    pub file: PathBuf,
    pub line: usize,
    pub symbol: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    pub route: RouteReference,
    pub requirements: Vec<Requirement>,
    pub uncertainty: Vec<String>,
}

struct ConstructorVisitor {
    calls: Vec<(usize, String, Vec<String>, Vec<String>)>,
}
impl<'ast> Visit<'ast> for ConstructorVisitor {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(path) = &*node.func {
            let segments: Vec<_> = path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if segments.len() >= 2 && segments.last().is_some_and(|s| s == "allowed_roles") {
                let mut values = Vec::new();
                for arg in &node.args {
                    // vec! is an opaque macro in syn; parse its expression list explicitly.
                    if let Expr::Macro(m) = arg {
                        use syn::parse::Parser;
                        if m.mac.path.is_ident("vec") {
                            let parser = syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated;
                            if let Ok(items) = parser.parse2(m.mac.tokens.clone()) {
                                for item in items {
                                    if let Expr::Path(p) = item {
                                        values.push(
                                            p.path.to_token_stream().to_string().replace(' ', ""),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                self.calls.push((
                    node.span().start().line,
                    segments[segments.len() - 2].clone(),
                    values,
                    segments,
                ));
            } else if segments.len() >= 2 && segments.last().is_some_and(|s| s == "admin") {
                self.calls.push((
                    node.span().start().line,
                    segments[segments.len() - 2].clone(),
                    vec!["Admin".into()],
                    segments,
                ));
            }
        }
        visit::visit_expr_call(self, node);
    }
}

pub(super) fn assess(
    routes: &mut [Route],
    files: &[(ModuleKey, PathBuf, syn::File)],
    index: &HandlerIndex,
) -> Vec<Assessment> {
    let constructors: HashMap<_, _> = files
        .iter()
        .map(|(_, path, ast)| {
            let mut visitor = ConstructorVisitor { calls: Vec::new() };
            visitor.visit_file(ast);
            (path.clone(), visitor.calls)
        })
        .collect();
    routes.iter_mut().map(|route| {
        let mut requirements = Vec::new();
        let mut uncertainty = Vec::new();
        let handler = index.route_handler(route);
        if let Some(handler) = handler {
            // Resolve aliases before classifying helper names. Evidence retains
            // the spelling at the call site so control-flow checks still match.
            struct Calls(Vec<(String, usize)>);
            impl<'ast> Visit<'ast> for Calls {
                fn visit_expr_call(&mut self, call: &'ast ExprCall) {
                    if let Expr::Path(path) = &*call.func {
                        self.0.push((path.path.to_token_stream().to_string().replace(' ', ""), call.span().start().line));
                    }
                    visit::visit_expr_call(self, call);
                }
                fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
            }
            let mut calls = Calls(Vec::new()); calls.visit_block(&handler.function.block);
            for (symbol, line) in calls.0 {
                if route.authorization.iter().any(|e| e.symbol.as_ref() == Some(&symbol) && e.line == line) { continue; }
                let target = HandlerTarget::Path { segments: symbol.trim_start_matches("::").split("::").map(str::to_owned).collect(), leading_colon: symbol.starts_with("::") };
                if let (Some(helper), _) = index.resolve_handler(&handler.crate_key, &handler.module, &target) {
                    if let Some(mut evidence) = evidence_for_handler_method(&helper.name, line, &handler.file, &handler.name) {
                        evidence.symbol = Some(symbol); route.authorization.push(evidence);
                    }
                }
            }
            for input in &handler.function.sig.inputs {
                if let FnArg::Typed(arg) = input {
                    let ty = arg.ty.to_token_stream().to_string();
                    if ["Authenticated", "Claims", "Identity", "ReqData"].iter().any(|name| ty.contains(name)) {
                        requirements.push(Requirement {
                            dimension: "authentication".into(), values: vec![ty.clone()], mechanism: "extractor".into(),
                            enforcement: Enforcement::Potential, confidence: AuthStrength::Weak,
                            file: handler.file.clone(), line: arg.span().start().line, symbol: ty,
                            explanation: "Security-relevant typed parameter; extractor rejection semantics require verification".into(),
                        });
                    }
                }
            }
        }
        for evidence in &mut route.authorization {
            let constructor = constructors.get(&evidence.file).and_then(|calls| calls.iter().find(|(line, symbol, _, path)| *line == evidence.line && (symbol == &evidence.mechanism || evidence.symbol.as_ref().is_some_and(|s| s.replace(' ', "").contains(&path.join("::"))))));
            if let Some((_, symbol, roles, path)) = constructor {
                let location = index.file_modules.get(&evidence.file);
                let resolved = location.and_then(|(key, module)| index.resolve_handler(key, module, &HandlerTarget::Path { segments: path.clone(), leading_colon: false }).0);
                let canonical = resolved.and_then(|d| d.owner.as_ref().and_then(|k| k.1.last()).or_else(|| d.module.last())).map(String::as_str).unwrap_or(symbol);
                let explicit_origin = path.len() > 2 || location.is_some_and(|(key, module)|
                    path.first().is_some_and(|name| index.scope(key, module).is_some_and(|scope| scope.imports.contains_key(name))));
                let crate_key = resolved.map(|d| &d.crate_key).or_else(||
                    if explicit_origin { None } else { location.map(|(key, _)| key) });
                // Existing named models are reused only in the resolved constructor's
                // crate. An identically named implementation elsewhere is not evidence.
                let model_module = resolved.map(|d| d.module.as_slice());
                let implementations: Vec<_> = files.iter().filter(|(key, _, _)| Some(&key.0) == crate_key)
                    .filter_map(|(key, _, ast)| {
                        let relative = if let Some(module) = model_module { module.strip_prefix(key.1.as_slice())? } else { &[] };
                        module_items(&ast.items, relative)
                    }).collect();
                let roles = if canonical == "RoleGuard" {
                    implementations.iter().flat_map(|items| constructor_roles(items)).collect::<Vec<_>>()
                } else { roles.clone() };
                let validated = implementations.iter().any(|items| middleware_has_role_gate(items, canonical));
                if !roles.is_empty() && validated {
                    // Explicit API model. This records the model's scope instead of
                    // promoting arbitrary Auth/Role identifiers to authorization.
                    evidence.kind = AuthEvidenceKind::RoleCheck;
                    evidence.strength = AuthStrength::Medium;
                    requirements.push(Requirement {
                        dimension: "roles".into(), values: roles.clone(), mechanism: "middleware".into(),
                        enforcement: Enforcement::Observed, confidence: AuthStrength::Medium,
                        file: evidence.file.clone(), line: evidence.line, symbol: symbol.clone(),
                        explanation: "Parameterized middleware model with a local role-dependent service-call/rejection branch; role arguments retained. Not a whole-program proof.".into(),
                    });
                    requirements.push(Requirement {
                        dimension: "authentication".into(), values: Vec::new(), mechanism: "middleware".into(),
                        enforcement: Enforcement::Observed, confidence: AuthStrength::Medium,
                        file: evidence.file.clone(), line: evidence.line, symbol: symbol.clone(),
                        explanation: "Identity prerequisite of modeled role middleware".into(),
                    });
                    continue;
                }
                evidence.kind = AuthEvidenceKind::Unknown;
                uncertainty.push("Role middleware arguments or local enforcement implementation could not be verified".into());
            }
            let dimension = match evidence.kind {
                AuthEvidenceKind::IdentityExtraction => "authentication",
                AuthEvidenceKind::RoleCheck => "roles",
                AuthEvidenceKind::PermissionCheck => "permissions",
                AuthEvidenceKind::OwnershipCheck => "ownership",
                AuthEvidenceKind::Unknown => "unresolved",
                _ => "authorization",
            };
            let mechanism = match evidence.kind {
                AuthEvidenceKind::AuthorizationGuard => "route_guard",
                AuthEvidenceKind::AuthorizationMiddleware => "middleware",
                _ if evidence.mechanism.ends_with("Middleware") || evidence.mechanism == "RequireAuth" => "middleware",
                _ => "helper",
            };
            let mut values = Vec::new();
            let mut observed = false;
            if let Some(handler) = handler {
                let mut arguments = CallArguments { symbol: evidence.symbol.as_deref().unwrap_or(""), values: Vec::new() };
                arguments.visit_block(&handler.function.block);
                values = arguments.values;
                let mut control = ControlledCalls::default();
                control.visit_block(&handler.function.block);
                if let Some(symbol) = &evidence.symbol {
                    let target = HandlerTarget::Path { segments: symbol.split("::").map(str::to_owned).collect(), leading_colon: false };
                    let (helper, _) = index.resolve_handler(&handler.crate_key, &handler.module, &target);
                    if let Some(helper) = helper {
                        observed = control.predicates.contains(symbol) || (control.propagated.contains(symbol) && helper_may_reject(index, helper, 0, &mut HashSet::new()));
                        if !observed && !helper_may_reject(index, helper, 0, &mut HashSet::new()) && evidence.is_authorization() {
                            evidence.kind = AuthEvidenceKind::Unknown;
                            uncertainty.push(format!("Local helper {symbol} has no supported rejection path; its name is not enforcement proof"));
                        }
                    }
                }
            }
            if evidence.is_authorization() && !observed {
                evidence.kind = AuthEvidenceKind::Unknown;
                uncertainty.push("Lexical authorization evidence lacks a verified local enforcement path".into());
            }
            requirements.push(Requirement {
                dimension: dimension.into(), values, mechanism: mechanism.into(),
                enforcement: if observed { Enforcement::Observed } else if evidence.kind == AuthEvidenceKind::Unknown { Enforcement::Unresolved } else { Enforcement::Potential },
                confidence: if observed { evidence.strength.clone() } else { AuthStrength::Weak }, file: evidence.file.clone(), line: evidence.line,
                symbol: evidence.symbol.clone().unwrap_or_default(),
                explanation: if observed { "Local predicate controls a rejection branch, or a local fallible helper propagates rejection".into() } else { "Lexical evidence; acceptance/rejection control flow has not been proven".into() },
            });
        }
        if requirements.iter().any(|r| r.enforcement == Enforcement::Potential) {
            uncertainty.push("Potential evidence is retained separately from observed enforcement".into());
        }
        if let RouteSecurityStatus::Unknown { reason } = route.security_status() {
            if !uncertainty.contains(&reason) { uncertainty.push(reason); }
        }
        Assessment { route: RouteReference::from(&*route), requirements, uncertainty }
    }).collect()
}

fn module_items<'a>(items: &'a [Item], path: &[String]) -> Option<&'a [Item]> {
    let Some((name, rest)) = path.split_first() else {
        return Some(items);
    };
    items.iter().find_map(|item| match item {
        Item::Mod(module) if module.ident == name.as_str() => module
            .content
            .as_ref()
            .and_then(|(_, items)| module_items(items, rest)),
        _ => None,
    })
}

fn constructor_roles(items: &[Item]) -> Vec<String> {
    struct Values(Vec<String>);
    impl<'ast> Visit<'ast> for Values {
        fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
            for field in &node.fields {
                if matches!(&field.member, syn::Member::Named(name) if name == "role") {
                    if let Expr::Path(value) = &field.expr {
                        self.0
                            .push(value.path.to_token_stream().to_string().replace(' ', ""));
                    }
                }
            }
        }
    }
    let mut values = Values(Vec::new());
    for item in items {
        if let Item::Impl(item) = item {
            if matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.is_ident("RoleGuard")) {
                for method in &item.items {
                    if let syn::ImplItem::Fn(method) = method {
                        if method.sig.ident == "admin" {
                            values.visit_block(&method.block);
                        }
                    }
                }
            }
        }
    }
    values.0
}

#[derive(Default)]
struct ControlledCalls {
    predicates: HashSet<String>,
    propagated: HashSet<String>,
}
impl<'ast> Visit<'ast> for ControlledCalls {
    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        if let Expr::Call(call) = &*node.expr {
            self.propagated
                .insert(call.func.to_token_stream().to_string().replace(' ', ""));
        }
        visit::visit_expr_try(self, node);
    }
    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        struct Calls {
            names: HashSet<String>,
            rejects: bool,
        }
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
                self.rejects |= node.expr.as_deref().is_some_and(|expr| matches!(expr, Expr::Call(call) if matches!(&*call.func, Expr::Path(p) if p.path.is_ident("Err"))));
                visit::visit_expr_return(self, node);
            }
            fn visit_expr_call(&mut self, call: &'ast ExprCall) {
                let name = call.func.to_token_stream().to_string().replace(' ', "");
                self.names.insert(name);
                visit::visit_expr_call(self, call);
            }
        }
        let mut branches = Calls {
            names: HashSet::new(),
            rejects: false,
        };
        branches.visit_block(&node.then_branch);
        if let Some((_, other)) = &node.else_branch {
            branches.visit_expr(other);
        }
        if branches.rejects {
            let mut condition = Calls {
                names: HashSet::new(),
                rejects: false,
            };
            condition.visit_expr(&node.cond);
            self.predicates.extend(condition.names);
        }
        visit::visit_expr_if(self, node);
    }
}

fn middleware_has_role_gate(items: &[Item], symbol: &str) -> bool {
    let expected = if symbol == "RequireAuth" {
        "AuthMiddleware"
    } else {
        "RoleGuardMiddleware"
    };
    #[derive(Default)]
    struct Gate {
        role: bool,
        forwards: bool,
        rejects: bool,
        bindings: HashSet<String>,
        conditional: bool,
    }
    impl<'ast> Visit<'ast> for Gate {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let (Pat::Ident(name), Some(init)) = (&node.pat, &node.init) {
                let mut value = Gate::default();
                value.visit_expr(&init.expr);
                if value.role {
                    self.bindings.insert(name.ident.to_string());
                }
            }
            visit::visit_local(self, node);
        }
        fn visit_expr_if(&mut self, node: &'ast ExprIf) {
            let mut condition = Gate::default();
            condition.visit_expr(&node.cond);
            let bound = matches!(&*node.cond, Expr::Path(p) if p.path.get_ident().is_some_and(|n| self.bindings.contains(&n.to_string())));
            if condition.role || bound {
                let mut branches = Gate::default();
                branches.visit_block(&node.then_branch);
                if let Some((_, other)) = &node.else_branch {
                    branches.visit_expr(other);
                }
                self.conditional |= branches.forwards && branches.rejects;
            }
            visit::visit_expr_if(self, node);
        }
        fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
            self.role |= matches!(&node.member, syn::Member::Named(name) if name == "role" || name == "allowed_roles");
            visit::visit_expr_field(self, node);
        }
        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            self.forwards |= node.method == "call";
            visit::visit_expr_method_call(self, node);
        }
        fn visit_expr_call(&mut self, node: &'ast ExprCall) {
            if let Expr::Path(p) = &*node.func {
                self.rejects |= p.path.is_ident("Err");
            }
            visit::visit_expr_call(self, node);
        }
    }
    items.iter().any(|item| {
        let Item::Impl(item) = item else { return false };
        let syn::Type::Path(ty) = &*item.self_ty else {
            return false;
        };
        if ty.path.segments.last().is_none_or(|s| s.ident != expected) {
            return false;
        }
        item.items.iter().any(|member| {
            let syn::ImplItem::Fn(method) = member else {
                return false;
            };
            if method.sig.ident != "call" {
                return false;
            }
            let mut gate = Gate::default();
            gate.visit_block(&method.block);
            gate.conditional
        })
    })
}

struct CallArguments<'a> {
    symbol: &'a str,
    values: Vec<String>,
}
impl<'ast> Visit<'ast> for CallArguments<'_> {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if node.func.to_token_stream().to_string().replace(' ', "") == self.symbol {
            for arg in &node.args {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Str(value),
                    ..
                }) = arg
                {
                    self.values.push(value.value());
                }
            }
        }
        visit::visit_expr_call(self, node);
    }
}

// Inspect returned expressions, not every Err constructor anywhere in a body.
fn returned_calls(expr: &Expr, calls: &mut Vec<String>) -> bool {
    match expr {
        Expr::Call(call) => {
            if let Expr::Path(path) = &*call.func {
                let name = path.path.to_token_stream().to_string().replace(' ', "");
                if name == "Err" {
                    return true;
                }
                calls.push(name);
            }
            false
        }
        Expr::Return(r) => r.expr.as_deref().is_some_and(|e| returned_calls(e, calls)),
        Expr::Block(b) => returned_block(&b.block, calls),
        Expr::If(i) => {
            let a = returned_block(&i.then_branch, calls);
            let b = i
                .else_branch
                .as_ref()
                .is_some_and(|(_, e)| returned_calls(e, calls));
            a || b
        }
        Expr::Match(m) => m.arms.iter().fold(false, |rejects, arm| {
            returned_calls(&arm.body, calls) || rejects
        }),
        _ => false,
    }
}

fn returned_block(block: &Block, calls: &mut Vec<String>) -> bool {
    match block.stmts.last() {
        Some(Stmt::Expr(expr, None)) => returned_calls(expr, calls),
        _ => false,
    }
}

// Bounded local call summaries establish only a possible rejection path.
// They deliberately do not claim dominance or prove an arbitrary predicate.
fn helper_may_reject(
    index: &HandlerIndex,
    definition: &HandlerDefinition,
    depth: usize,
    visited: &mut HashSet<String>,
) -> bool {
    if depth >= 8
        || !visited.insert(format!(
            "{}:{}",
            definition.crate_key.display(),
            definition.rust_path()
        ))
    {
        return false;
    }
    struct Calls {
        names: Vec<String>,
        rejects: bool,
    }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
            self.rejects |= node
                .expr
                .as_deref()
                .is_some_and(|e| returned_calls(e, &mut self.names));
            visit::visit_expr_return(self, node);
        }
        fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
            self.rejects |= returned_calls(&node.expr, &mut self.names);
            visit::visit_expr_try(self, node);
        }
        fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
        fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
    }
    let mut calls = Calls {
        names: Vec::new(),
        rejects: false,
    };
    calls.visit_block(&definition.function.block);
    calls.rejects |= returned_block(&definition.function.block, &mut calls.names);
    if calls.rejects {
        return true;
    }
    calls.names.into_iter().any(|name| {
        let target = HandlerTarget::Path {
            segments: name.split("::").map(str::to_owned).collect(),
            leading_colon: false,
        };
        let (helper, _) = index.resolve_handler(&definition.crate_key, &definition.module, &target);
        helper.is_some_and(|helper| helper_may_reject(index, helper, depth + 1, visited))
    })
}
