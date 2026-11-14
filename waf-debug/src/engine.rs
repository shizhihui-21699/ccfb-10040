//! Rule evaluation engine: variables, transform chains, operators, chains,
//! TX collection, captures, ctl actions, anomaly scoring. Produces a JSON
//! trace for the debug UI. Everything is fault-tolerant: no panics, all
//! limits bounded.

use crate::http;
use crate::json::{q, Arr, Obj};
use crate::operators;
use crate::seclang::{self, Ctl, Entry, Rule, Selector, VarSpec};
use crate::transforms;
use std::collections::BTreeMap;

const MAX_TARGETS_PER_RULE: usize = 512;
const MAX_VALUE_PREVIEW: usize = 4096;

pub struct EngineConfig {
    pub mode: String, // "anomaly" | "selfcontained"
    pub threshold: i64,
    pub remote_addr: String,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            mode: "anomaly".into(),
            threshold: 5,
            remote_addr: "127.0.0.1".into(),
        }
    }
}

struct Ctx<'a> {
    req: &'a http::Request,
    tx: BTreeMap<String, String>,
    matched_var: Option<(String, String)>,
    remote_addr: String,
}

impl<'a> Ctx<'a> {
    fn lookup(&self, name: &str) -> String {
        let n = name.trim().to_ascii_lowercase();
        if let Some(rest) = n.strip_prefix("tx.") {
            return self.tx.get(rest).cloned().unwrap_or_default();
        }
        match n.as_str() {
            "matched_var" => self
                .matched_var
                .as_ref()
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
            "matched_var_name" => self
                .matched_var
                .as_ref()
                .map(|(k, _)| k.clone())
                .unwrap_or_default(),
            "remote_addr" => self.remote_addr.clone(),
            "request_method" => self.req.method.clone(),
            "request_uri" => self.req.uri_raw.clone(),
            "query_string" => self.req.query.clone(),
            other => {
                // try tx.<other> and captures %{0}..%{9}
                if let Some(v) = self.tx.get(other) {
                    return v.clone();
                }
                if other.chars().all(|c| c.is_ascii_digit()) && !other.is_empty() {
                    return self.tx.get(other).cloned().unwrap_or_default();
                }
                String::new()
            }
        }
    }
}

fn severity_weight(sev: &Option<String>) -> i64 {
    match sev.as_deref().map(|s| s.to_ascii_uppercase()) {
        Some(s) if s == "CRITICAL" => 5,
        Some(s) if s == "ERROR" => 4,
        Some(s) if s == "WARNING" => 3,
        Some(s) if s == "NOTICE" => 2,
        // no severity set: default to CRITICAL weight so a plain `deny` rule
        // still scores in anomaly mode (console convenience)
        None => 5,
        Some(_) => 0,
    }
}

/// Resolve one variable spec to (display_name, value) pairs.
fn resolve(spec: &VarSpec, ctx: &Ctx) -> Vec<(String, String)> {
    let req = ctx.req;
    let name = spec.name.as_str();

    let selector_match = |item_name: &str, case_insensitive: bool| -> bool {
        match &spec.selector {
            None => true,
            Some(Selector::Name(want)) => {
                if case_insensitive {
                    item_name.eq_ignore_ascii_case(want)
                } else {
                    item_name == want
                }
            }
            Some(Selector::Regex(pat)) => match crate::regex::compile(pat) {
                Ok(re) => matches!(re.search(item_name), crate::regex::SearchResult::Match(_)),
                Err(_) => false,
            },
        }
    };

    let collect = |items: &[(String, String)], prefix: &str, ci: bool| -> Vec<(String, String)> {
        items
            .iter()
            .filter(|(k, _)| selector_match(k, ci))
            .map(|(k, v)| (format!("{}:{}", prefix, k), v.clone()))
            .collect()
    };

    let out: Vec<(String, String)> = match name {
        "ARGS" => {
            let mut all = req.args_get.clone();
            all.extend(req.args_post.clone());
            collect(&all, "ARGS", false)
        }
        "ARGS_GET" => collect(&req.args_get, "ARGS_GET", false),
        "ARGS_POST" => collect(&req.args_post, "ARGS_POST", false),
        "ARGS_NAMES" | "ARGS_GET_NAMES" | "ARGS_POST_NAMES" => {
            let src: &[(String, String)] = match name {
                "ARGS_GET_NAMES" => &req.args_get,
                "ARGS_POST_NAMES" => &req.args_post,
                _ => {
                    let mut all = req.args_get.clone();
                    all.extend(req.args_post.clone());
                    // leak-free trick: build directly
                    return all
                        .iter()
                        .filter(|(k, _)| selector_match(k, false))
                        .map(|(k, _)| (format!("{}:{}", name, k), k.clone()))
                        .collect();
                }
            };
            src.iter()
                .filter(|(k, _)| selector_match(k, false))
                .map(|(k, _)| (format!("{}:{}", name, k), k.clone()))
                .collect()
        }
        "REQUEST_HEADERS" => collect(&req.headers, "REQUEST_HEADERS", true),
        "REQUEST_HEADERS_NAMES" => req
            .headers
            .iter()
            .filter(|(k, _)| selector_match(k, true))
            .map(|(k, _)| (format!("REQUEST_HEADERS_NAMES:{}", k), k.clone()))
            .collect(),
        "REQUEST_COOKIES" => collect(&req.cookies, "REQUEST_COOKIES", false),
        "REQUEST_COOKIES_NAMES" => req
            .cookies
            .iter()
            .filter(|(k, _)| selector_match(k, false))
            .map(|(k, _)| (format!("REQUEST_COOKIES_NAMES:{}", k), k.clone()))
            .collect(),
        "FILES" | "FILES_NAMES" => collect(&req.files, name, false),
        "TX" => match &spec.selector {
            Some(Selector::Name(want)) => {
                let key = want.to_ascii_lowercase();
                match ctx.tx.get(&key) {
                    Some(v) => vec![(format!("TX:{}", key), v.clone())],
                    None => vec![(format!("TX:{}", key), String::new())],
                }
            }
            _ => ctx
                .tx
                .iter()
                .filter(|(k, _)| selector_match(k, false))
                .map(|(k, v)| (format!("TX:{}", k), v.clone()))
                .collect(),
        },
        "MATCHED_VAR" => vec![(
            "MATCHED_VAR".into(),
            ctx.matched_var.clone().map(|(_, v)| v).unwrap_or_default(),
        )],
        "MATCHED_VARS" => vec![(
            "MATCHED_VARS".into(),
            ctx.matched_var.clone().map(|(_, v)| v).unwrap_or_default(),
        )],
        "MATCHED_VAR_NAME" => vec![(
            "MATCHED_VAR_NAME".into(),
            ctx.matched_var.clone().map(|(k, _)| k).unwrap_or_default(),
        )],
        _ => {
            let (disp, val) = single_value(name, ctx);
            vec![(disp, val)]
        }
    };

    if spec.count {
        vec![(format!("&{}", spec_display(spec)), out.len().to_string())]
    } else {
        out
    }
}

fn single_value(name: &str, ctx: &Ctx) -> (String, String) {
    let req = ctx.req;
    let v = match name {
        "REQUEST_METHOD" => req.method.clone(),
        "REQUEST_URI" => req.uri_raw.clone(),
        "REQUEST_URI_RAW" => req.uri_raw.clone(),
        "REQUEST_FILENAME" => req.path.clone(),
        "QUERY_STRING" => req.query.clone(),
        "REQUEST_LINE" => format!("{} {} {}", req.method, req.uri_raw, req.version),
        "REQUEST_PROTOCOL" => req.version.clone(),
        "REQUEST_BODY" => req.body_string(),
        "REQUEST_CONTENT_TYPE" => req.content_type.clone(),
        "REQUEST_CONTENT_LENGTH" => req.body.len().to_string(),
        "REMOTE_ADDR" => ctx.remote_addr.clone(),
        "SERVER_NAME" => req.header("host").unwrap_or("").to_string(),
        "MULTIPART_STRICT_ERROR" => {
            if req.multipart_strict_error {
                "1".into()
            } else {
                "0".into()
            }
        }
        "REQBODY_ERROR" => {
            if req.reqbody_error {
                "1".into()
            } else {
                "0".into()
            }
        }
        _ => String::new(),
    };
    (name.to_string(), v)
}

fn spec_display(spec: &VarSpec) -> String {
    let mut s = String::new();
    if spec.excluded {
        s.push('!');
    }
    if spec.count {
        s.push('&');
    }
    s.push_str(&spec.name);
    if let Some(sel) = &spec.selector {
        s.push(':');
        match sel {
            Selector::Name(n) => s.push_str(n),
            Selector::Regex(r) => {
                s.push('/');
                s.push_str(r);
                s.push('/');
            }
        }
    }
    s
}

struct VarEval {
    json: String,
    matched: bool,
    match_value: String,
    captures: Vec<Option<String>>,
    var_name: String,
}

fn eval_target(
    var_name: &str,
    value: &str,
    rule: &Rule,
    ctx: &Ctx,
) -> VarEval {
    let mut o = Obj::new();
    o.str("var", var_name);
    o.str("value", &truncate(value));

    // transform chain
    let mut tarr = Arr::new();
    let mut cur = value.to_string();
    for t in &rule.actions.transforms {
        match transforms::apply(t, &cur) {
            Ok(next) => {
                let mut to = Obj::new();
                to.str("t", t);
                to.str("out", &truncate(&next));
                tarr.push(to.build());
                cur = next;
            }
            Err(()) => {
                let mut to = Obj::new();
                to.str("t", t);
                to.str("error", "unknown transform (treated as identity)");
                tarr.push(to.build());
            }
        }
    }
    o.set("transforms", tarr.build());
    o.str("final", &truncate(&cur));

    // operator
    let expand = |name: &str| ctx.lookup(name);
    let res = operators::eval(&rule.operator, &cur, &expand);
    o.str("op", &rule.operator);
    o.boolean("matched", res.matched);
    if res.matched {
        o.str("match", &truncate(&res.match_value));
    }
    if let Some(note) = &res.note {
        o.str("note", note);
    }
    if !res.captures.is_empty() {
        let mut c = Arr::new();
        for cap in &res.captures {
            match cap {
                Some(s) => c.push(q(s)),
                None => c.push("null".into()),
            };
        }
        o.set("captures", c.build());
    }
    VarEval {
        json: o.build(),
        matched: res.matched,
        match_value: res.match_value,
        captures: res.captures,
        var_name: var_name.to_string(),
    }
}

fn truncate(s: &str) -> String {
    if s.chars().count() > MAX_VALUE_PREVIEW {
        let t: String = s.chars().take(MAX_VALUE_PREVIEW).collect();
        format!("{}…[truncated]", t)
    } else {
        s.to_string()
    }
}

struct RuleOutcome {
    matched: bool,
    targets_json: Arr,
    chain_json: Arr,
    first_match: Option<(String, String, Vec<Option<String>>)>, // var, match, captures
}

fn eval_rule(
    rule: &Rule,
    ctx: &Ctx,
    removed_targets: &[(i64, String)],
    depth: usize,
) -> RuleOutcome {
    let mut outcome = RuleOutcome {
        matched: false,
        targets_json: Arr::new(),
        chain_json: Arr::new(),
        first_match: None,
    };
    if depth > 8 {
        return outcome;
    }

    if rule.is_action {
        outcome.matched = true;
    } else {
        // build target list
        let mut targets: Vec<(String, String)> = Vec::new();
        for spec in &rule.vars {
            if spec.excluded {
                continue;
            }
            for (n, v) in resolve(spec, ctx) {
                targets.push((n, v));
                if targets.len() >= MAX_TARGETS_PER_RULE {
                    break;
                }
            }
        }
        // exclusions from the rule itself
        let mut excluded: Vec<String> = Vec::new();
        for spec in &rule.vars {
            if !spec.excluded {
                continue;
            }
            for (n, _) in resolve(spec, ctx) {
                excluded.push(n.to_ascii_lowercase());
            }
        }
        // exclusions from ctl:ruleRemoveTargetById
        if let Some(id) = rule.actions.id {
            for (rid, target) in removed_targets {
                if *rid == id {
                    excluded.push(target.to_ascii_lowercase());
                }
            }
        }
        targets.retain(|(n, _)| !excluded.contains(&n.to_ascii_lowercase()));
        // dedupe by name, keep first
        let mut seen = std::collections::HashSet::new();
        targets.retain(|(n, _)| seen.insert(n.clone()));

        for (n, v) in &targets {
            let ev = eval_target(n, v, rule, ctx);
            if ev.matched && outcome.first_match.is_none() {
                outcome.first_match = Some((ev.var_name.clone(), ev.match_value.clone(), ev.captures.clone()));
            }
            outcome.targets_json.push(ev.json);
        }
        outcome.matched = outcome.first_match.is_some();
    }

    // chain: all children must match
    if outcome.matched && !rule.chained.is_empty() {
        for child in &rule.chained {
            let co = eval_rule(child, ctx, removed_targets, depth + 1);
            let mut cj = Obj::new();
            cj.num("line", child.line_no as i64);
            if let Some(id) = child.actions.id {
                cj.num("id", id);
            }
            cj.str("raw", &child.raw);
            cj.boolean("matched", co.matched);
            cj.set("targets", co.targets_json.build());
            cj.set("chain", co.chain_json.build());
            outcome.chain_json.push(cj.build());
            if !co.matched {
                outcome.matched = false;
                break;
            }
        }
    }
    outcome
}

struct EngineState {
    removed_ids: Vec<(i64, i64)>,
    removed_tags: Vec<String>,
    removed_targets: Vec<(i64, String)>,
    rule_engine: String,
    skip_n: usize,
    skip_after: Option<String>,
}

pub fn run(rules_text: &str, request_text: &str, cfg: &EngineConfig) -> String {
    let req = http::parse(request_text);
    let parsed = seclang::parse(rules_text);

    let mut out = Obj::new();

    // ---- request summary ----
    let mut rq = Obj::new();
    rq.str("method", &req.method);
    rq.str("uri", &req.uri_raw);
    rq.str("path", &req.path);
    rq.str("query", &req.query);
    rq.str("version", &req.version);
    let mut hs = Arr::new();
    for (k, v) in &req.headers {
        let mut h = Obj::new();
        h.str("name", k);
        h.str("value", v);
        hs.push(h.build());
    }
    rq.set("headers", hs.build());
    rq.num("body_len", req.body.len() as i64);
    rq.str("body_preview", &truncate(&req.body_string()));
    let mut errs = Arr::new();
    for e in &req.errors {
        errs.push_str(e);
    }
    rq.set("errors", errs.build());
    let args_json = |items: &[(String, String)]| {
        let mut a = Arr::new();
        for (k, v) in items {
            let mut o = Obj::new();
            o.str("name", k);
            o.str("value", v);
            a.push(o.build());
        }
        a.build()
    };
    rq.set("args_get", args_json(&req.args_get));
    rq.set("args_post", args_json(&req.args_post));
    rq.set("cookies", args_json(&req.cookies));
    out.set("request", rq.build());

    // ---- parse errors ----
    let mut pe = Arr::new();
    for e in &parsed.errors {
        pe.push_str(e);
    }
    out.set("parse_errors", pe.build());

    let mut state = EngineState {
        removed_ids: Vec::new(),
        removed_tags: Vec::new(),
        removed_targets: Vec::new(),
        rule_engine: parsed.config.rule_engine.clone(),
        skip_n: 0,
        skip_after: None,
    };

    let mut ctx = Ctx {
        req: &req,
        tx: BTreeMap::new(),
        matched_var: None,
        remote_addr: cfg.remote_addr.clone(),
    };
    // CRS-compatible defaults
    ctx.tx.insert("anomaly_score".into(), "0".into());
    ctx.tx.insert("critical_anomaly_score".into(), "5".into());
    ctx.tx.insert("error_anomaly_score".into(), "4".into());
    ctx.tx.insert("warning_anomaly_score".into(), "3".into());
    ctx.tx.insert("notice_anomaly_score".into(), "2".into());
    ctx.tx.insert(
        "inbound_anomaly_threshold".into(),
        cfg.threshold.to_string(),
    );

    let anomaly_mode = cfg.mode.eq_ignore_ascii_case("anomaly");
    let mut verdict = "PASS".to_string();
    let mut verdict_reason = String::new();
    let mut halted = false;

    let mut steps = Arr::new();
    let mut rules_loaded = 0i64;

    for phase in [1u8, 2u8] {
        if halted {
            break;
        }
        // skip/skipAfter state is per-phase (ModSecurity semantics)
        state.skip_n = 0;
        state.skip_after = None;
        for entry in &parsed.entries {
            if halted {
                break;
            }
            match entry {
                Entry::Marker(name) => {
                    if state.skip_after.as_deref() == Some(name.as_str()) {
                        state.skip_after = None;
                        let mut s = Obj::new();
                        s.str("kind", "marker");
                        s.str("name", name);
                        s.str("status", "reached (skipAfter cleared)");
                        steps.push(s.build());
                    }
                }
                Entry::Rule(rule) => {
                    let phase_of = rule
                        .actions
                        .phase
                        .or(parsed.config.default_phase)
                        .unwrap_or(2);
                    if phase_of != phase {
                        continue;
                    }
                    rules_loaded += 1;
                    let mut s = Obj::new();
                    s.str("kind", if rule.is_action { "action" } else { "rule" });
                    s.num("line", rule.line_no as i64);
                    if let Some(id) = rule.actions.id {
                        s.num("id", id);
                    }
                    s.num("phase", phase_of as i64);
                    s.str("raw", &rule.raw);

                    // skip logic
                    if state.skip_n > 0 {
                        state.skip_n -= 1;
                        s.str("status", "skipped");
                        s.str("skip_reason", "skip action from a previous rule");
                        steps.push(s.build());
                        continue;
                    }
                    if state.skip_after.is_some() {
                        s.str("status", "skipped");
                        s.str(
                            "skip_reason",
                            &format!("skipAfter:{} pending", state.skip_after.clone().unwrap_or_default()),
                        );
                        steps.push(s.build());
                        continue;
                    }
                    // ctl removals
                    if let Some(id) = rule.actions.id {
                        if state.removed_ids.iter().any(|(lo, hi)| id >= *lo && id <= *hi) {
                            s.str("status", "skipped");
                            s.str("skip_reason", "removed by ctl:ruleRemoveById");
                            steps.push(s.build());
                            continue;
                        }
                    }
                    if rule
                        .actions
                        .tags
                        .iter()
                        .any(|t| state.removed_tags.contains(t))
                    {
                        s.str("status", "skipped");
                        s.str("skip_reason", "removed by ctl:ruleRemoveByTag");
                        steps.push(s.build());
                        continue;
                    }
                    if state.rule_engine.eq_ignore_ascii_case("off") {
                        s.str("status", "skipped");
                        s.str("skip_reason", "SecRuleEngine Off");
                        steps.push(s.build());
                        continue;
                    }

                    let outcome = eval_rule(rule, &ctx, &state.removed_targets, 0);
                    s.set("targets", outcome.targets_json.build());
                    s.set("chain", outcome.chain_json.build());

                    if !outcome.matched {
                        s.str("status", "no_match");
                        steps.push(s.build());
                        continue;
                    }

                    s.str("status", "matched");

                    // matched: update matched var
                    if let Some((vn, mv, captures)) = &outcome.first_match {
                        ctx.matched_var = Some((vn.clone(), mv.clone()));
                        // capture action
                        if rule.actions.capture {
                            let mut changes = Arr::new();
                            for (i, c) in captures.iter().enumerate() {
                                if i > 9 {
                                    break;
                                }
                                let key = i.to_string();
                                let val = c.clone().unwrap_or_default();
                                let old = ctx.tx.get(&key).cloned().unwrap_or_default();
                                ctx.tx.insert(key.clone(), val.clone());
                                let mut ch = Obj::new();
                                ch.str("name", &format!("tx.{}", key));
                                ch.str("from", &old);
                                ch.str("to", &val);
                                changes.push(ch.build());
                            }
                            s.set("capture", changes.build());
                        }
                    }

                    let mut actions_run = Arr::new();
                    let mut tx_changes = Arr::new();

                    // msg
                    if let Some(msg) = &rule.actions.msg {
                        let expand = |n: &str| ctx.lookup(n);
                        s.str("msg", &operators::expand_macros(msg, &expand));
                    }

                    // setvar
                    for sv in &rule.actions.setvars {
                        if !sv.name.starts_with("tx.") {
                            actions_run.push_str(&format!("setvar:{} (only tx.* supported, ignored)", sv.name));
                            continue;
                        }
                        let key = sv.name[3..].to_string();
                        let expand = |n: &str| ctx.lookup(n);
                        let val = operators::expand_macros(&sv.value, &expand);
                        let old = ctx.tx.get(&key).cloned().unwrap_or_else(|| "0".into());
                        let newv = match sv.inc {
                            1 => {
                                let a: i64 = old.trim().parse().unwrap_or(0);
                                let b: i64 = val.trim().parse().unwrap_or(0);
                                (a + b).to_string()
                            }
                            -1 => {
                                let a: i64 = old.trim().parse().unwrap_or(0);
                                let b: i64 = val.trim().parse().unwrap_or(0);
                                (a - b).to_string()
                            }
                            _ => val.clone(),
                        };
                        ctx.tx.insert(key.clone(), newv.clone());
                        let mut ch = Obj::new();
                        ch.str("name", &format!("tx.{}", key));
                        ch.str("from", &old);
                        ch.str("to", &newv);
                        tx_changes.push(ch.build());
                        actions_run.push_str(&format!(
                            "setvar:{} = {} -> {}",
                            sv.name, old, newv
                        ));
                    }

                    // ctl
                    for ctl in &rule.actions.ctls {
                        match ctl {
                            Ctl::RuleRemoveById(lo, hi) => {
                                state.removed_ids.push((*lo, *hi));
                                actions_run.push_str(&format!("ctl:ruleRemoveById={}-{}", lo, hi));
                            }
                            Ctl::RuleRemoveByTag(t) => {
                                state.removed_tags.push(t.clone());
                                actions_run.push_str(&format!("ctl:ruleRemoveByTag={}", t));
                            }
                            Ctl::RuleRemoveTargetById(id, target) => {
                                state.removed_targets.push((*id, target.clone()));
                                actions_run
                                    .push_str(&format!("ctl:ruleRemoveTargetById={};{}", id, target));
                            }
                            Ctl::RuleEngine(mode) => {
                                state.rule_engine = mode.clone();
                                actions_run.push_str(&format!("ctl:ruleEngine={}", mode));
                            }
                        }
                    }

                    // skip / skipAfter
                    if let Some(n) = rule.actions.skip {
                        state.skip_n = n;
                        actions_run.push_str(&format!("skip:{}", n));
                    }
                    if let Some(m) = &rule.actions.skip_after {
                        state.skip_after = Some(m.clone());
                        actions_run.push_str(&format!("skipAfter:{}", m));
                    }

                    // disruptive / scoring
                    let disruptive = rule
                        .actions
                        .disruptive
                        .clone()
                        .or(parsed.config.default_disruptive.clone())
                        .unwrap_or_else(|| "pass".into());
                    let weight = severity_weight(&rule.actions.severity);
                    let has_explicit_score = rule
                        .actions
                        .setvars
                        .iter()
                        .any(|sv| sv.name.starts_with("tx.anomaly_score"));

                    match disruptive.as_str() {
                        "block" | "deny" | "drop" => {
                            if anomaly_mode {
                                // Auto severity scoring (console convenience):
                                // skipped when the rule does its own
                                // setvar:tx.anomaly_score (CRS style) or
                                // examines TX (meta/scoring rules like 949).
                                let references_tx =
                                    rule.vars.iter().any(|v| v.name == "TX");
                                let delta = if has_explicit_score || references_tx {
                                    0
                                } else {
                                    weight
                                };
                                if delta > 0 {
                                    let old: i64 = ctx
                                        .tx
                                        .get("anomaly_score")
                                        .and_then(|v| v.trim().parse().ok())
                                        .unwrap_or(0);
                                    let newv = old + delta;
                                    ctx.tx.insert(
                                        "anomaly_score".into(),
                                        newv.to_string(),
                                    );
                                    let mut ch = Obj::new();
                                    ch.str("name", "tx.anomaly_score");
                                    ch.str("from", &old.to_string());
                                    ch.str("to", &newv.to_string());
                                    tx_changes.push(ch.build());
                                    actions_run.push_str(&format!(
                                        "anomaly score +{} (severity {})",
                                        delta,
                                        rule.actions
                                            .severity
                                            .clone()
                                            .unwrap_or_else(|| "(default)".into())
                                    ));
                                }
                                s.num("score_delta", delta);
                            } else {
                                let status = rule.actions.status.unwrap_or(403);
                                if state.rule_engine.eq_ignore_ascii_case("detectiononly") {
                                    actions_run.push_str(&format!(
                                        "would {} with status {} (DetectionOnly)",
                                        disruptive, status
                                    ));
                                } else {
                                    verdict = "BLOCK".into();
                                    verdict_reason = format!(
                                        "rule id {} (line {}) {}",
                                        rule.actions.id.unwrap_or(0),
                                        rule.line_no,
                                        rule.actions.msg.clone().unwrap_or_default()
                                    );
                                    actions_run
                                        .push_str(&format!("{} with status {}", disruptive, status));
                                    halted = true;
                                }
                            }
                        }
                        "allow" => {
                            actions_run.push_str("allow (remaining rules skipped)".into());
                            halted = true;
                        }
                        _ => {}
                    }

                    s.set("actions_run", actions_run.build());
                    s.set("tx_changes", tx_changes.build());
                    s.str("disruptive", &disruptive);
                    if !rule.actions.unknown.is_empty() {
                        let mut u = Arr::new();
                        for x in &rule.actions.unknown {
                            u.push_str(x);
                        }
                        s.set("unsupported_actions", u.build());
                    }
                    steps.push(s.build());
                }
            }
        }
    }

    // ---- verdict ----
    let detection_only = state.rule_engine.eq_ignore_ascii_case("detectiononly");
    let mut anomaly_score: i64 = 0;
    if anomaly_mode && verdict == "PASS" {
        // tx.anomaly_score already includes both auto severity scoring and
        // explicit setvar increments
        let total: i64 = ctx
            .tx
            .get("anomaly_score")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        if total >= cfg.threshold {
            if detection_only || state.rule_engine.eq_ignore_ascii_case("off") {
                verdict_reason = format!(
                    "anomaly score {} >= threshold {} (would block; {})",
                    total, cfg.threshold, state.rule_engine
                );
            } else {
                verdict = "BLOCK".into();
                verdict_reason = format!(
                    "anomaly score {} >= threshold {}",
                    total, cfg.threshold
                );
            }
        } else {
            verdict_reason = format!("anomaly score {} < threshold {}", total, cfg.threshold);
        }
        anomaly_score = total;
    }

    out.num("rules_evaluated", rules_loaded);
    out.set("steps", steps.build());
    out.str("rule_engine", &state.rule_engine);
    out.str("mode", &cfg.mode);
    out.num("anomaly_score", anomaly_score);
    out.num("threshold", cfg.threshold);
    out.str("verdict", &verdict);
    out.str("verdict_reason", &verdict_reason);

    let mut txj = Obj::new();
    for (k, v) in &ctx.tx {
        txj.str(k, v);
    }
    out.set("tx", txj.build());

    out.build()
}

/// Wire entry: parse the length-prefixed input and run.
/// Format: [u32 LE rules_len][rules][u32 req_len][req][u32 cfg_len][cfg]
/// cfg lines: key=value (mode, threshold, remote_addr)
pub fn run_from_wire(input: &[u8]) -> Vec<u8> {
    let read_u32 = |b: &[u8], off: usize| -> Option<usize> {
        let s = b.get(off..off + 4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
    };
    let result = (|| -> String {
        let mut off = 0usize;
        let rl = match read_u32(input, off) {
            Some(v) => v,
            None => return err_json("bad wire format (rules len)"),
        };
        off += 4;
        let rules = match input.get(off..off + rl) {
            Some(b) => String::from_utf8_lossy(b).into_owned(),
            None => return err_json("bad wire format (rules)"),
        };
        off += rl;
        let ql = match read_u32(input, off) {
            Some(v) => v,
            None => return err_json("bad wire format (request len)"),
        };
        off += 4;
        let req = match input.get(off..off + ql) {
            Some(b) => String::from_utf8_lossy(b).into_owned(),
            None => return err_json("bad wire format (request)"),
        };
        off += ql;
        let cl = match read_u32(input, off).unwrap_or(0) {
            v => v,
        };
        off += 4;
        let cfgs = match input.get(off..off + cl) {
            Some(b) => String::from_utf8_lossy(b).into_owned(),
            None => String::new(),
        };
        let mut cfg = EngineConfig::default();
        for line in cfgs.lines() {
            if let Some((k, v)) = line.split_once('=') {
                match k.trim() {
                    "mode" => cfg.mode = v.trim().to_string(),
                    "threshold" => cfg.threshold = v.trim().parse().unwrap_or(5),
                    "remote_addr" => cfg.remote_addr = v.trim().to_string(),
                    _ => {}
                }
            }
        }
        run(&rules, &req, &cfg)
    })();
    result.into_bytes()
}

fn err_json(msg: &str) -> String {
    let mut o = Obj::new();
    o.str("fatal", msg);
    o.build()
}
