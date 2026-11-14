//! SecLang subset parser: SecRule / SecAction / SecRuleEngine /
//! SecDefaultAction / SecMarker, with line continuation and comments.

#[derive(Clone, Debug)]
pub enum Selector {
    Name(String),
    Regex(String),
}

#[derive(Clone, Debug)]
pub struct VarSpec {
    pub excluded: bool, // leading !
    pub count: bool,    // leading &
    pub name: String,   // uppercase
    pub selector: Option<Selector>,
}

#[derive(Clone, Debug)]
pub struct SetVar {
    pub name: String, // e.g. tx.anomaly_score (lowercased)
    pub inc: i8,      // 0 = set, 1 = +=, -1 = -=
    pub value: String,
}

#[derive(Clone, Debug)]
pub enum Ctl {
    RuleRemoveById(i64, i64), // range
    RuleRemoveByTag(String),
    RuleRemoveTargetById(i64, String),
    RuleEngine(String),
}

#[derive(Clone, Debug, Default)]
pub struct Actions {
    pub id: Option<i64>,
    pub phase: Option<u8>,
    pub msg: Option<String>,
    pub logdata: Option<String>,
    pub tags: Vec<String>,
    pub severity: Option<String>,
    pub log: bool,
    pub nolog: bool,
    pub disruptive: Option<String>, // block|deny|pass|drop|allow
    pub status: Option<u16>,
    pub capture: bool,
    pub chain: bool,
    pub transforms: Vec<String>,
    pub setvars: Vec<SetVar>,
    pub ctls: Vec<Ctl>,
    pub skip: Option<usize>,
    pub skip_after: Option<String>,
    pub unknown: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub vars: Vec<VarSpec>, // empty for SecAction
    pub operator: String,   // raw operator string, e.g. "@rx foo" or bare pattern
    pub is_action: bool,    // SecAction
    pub actions: Actions,
    pub chained: Vec<Rule>,
    pub has_chain: bool,
    pub line_no: usize,
    pub raw: String,
}

#[derive(Clone, Debug)]
pub enum Entry {
    Rule(Rule),
    Marker(String),
}

#[derive(Clone, Debug)]
pub struct SecConfig {
    pub rule_engine: String, // On | Off | DetectionOnly
    pub default_phase: Option<u8>,
    pub default_disruptive: Option<String>,
}

impl Default for SecConfig {
    fn default() -> Self {
        SecConfig {
            rule_engine: "On".into(),
            default_phase: None,
            default_disruptive: None,
        }
    }
}

pub struct ParseOutput {
    pub entries: Vec<Entry>,
    pub errors: Vec<String>,
    pub config: SecConfig,
}

/// Join continuation lines (trailing backslash).
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut start_line = 1;
    for (i, line) in text.lines().enumerate() {
        let l = line.trim_end();
        if buf.is_empty() {
            start_line = i + 1;
        }
        if let Some(stripped) = l.strip_suffix('\\') {
            buf.push_str(stripped);
            buf.push(' ');
            continue;
        }
        buf.push_str(l);
        out.push((start_line, std::mem::take(&mut buf)));
    }
    if !buf.is_empty() {
        out.push((start_line, buf));
    }
    out
}

/// Split a line into whitespace-separated tokens, honouring single and
/// double quotes (quotes stripped, backslash escapes the next char).
fn tokenize(line: &str) -> Vec<String> {
    let mut toks = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let mut tok = String::new();
        while i < chars.len() && !chars[i].is_whitespace() {
            let c = chars[i];
            if c == '"' || c == '\'' {
                i += 1;
                while i < chars.len() && chars[i] != c {
                    if chars[i] == '\\' && i + 1 < chars.len() && (chars[i + 1] == c || chars[i + 1] == '\\') {
                        tok.push(chars[i + 1]);
                        i += 2;
                    } else {
                        tok.push(chars[i]);
                        i += 1;
                    }
                }
                i += 1; // closing quote
            } else {
                tok.push(c);
                i += 1;
            }
        }
        toks.push(tok);
    }
    toks
}

/// Split an action string on top-level commas (quotes protect commas).
fn split_actions(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut quote: Option<char> = None;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some(q) => {
                if c == '\\' && i + 1 < chars.len() {
                    cur.push(c);
                    cur.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
                cur.push(c);
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                    cur.push(c);
                } else if c == ',' {
                    out.push(std::mem::take(&mut cur));
                } else {
                    cur.push(c);
                }
            }
        }
        i += 1;
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 {
        let b = s.as_bytes();
        if (b[0] == b'"' && b[s.len() - 1] == b'"') || (b[0] == b'\'' && b[s.len() - 1] == b'\'') {
            return s[1..s.len() - 1].replace("\\\"", "\"").replace("\\'", "'");
        }
    }
    s.to_string()
}

pub fn parse_var_list(s: &str) -> Result<Vec<VarSpec>, String> {
    let mut out = Vec::new();
    for part in s.split('|') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut p = part;
        let mut excluded = false;
        let mut count = false;
        if let Some(rest) = p.strip_prefix('!') {
            excluded = true;
            p = rest;
        }
        if let Some(rest) = p.strip_prefix('&') {
            count = true;
            p = rest;
        }
        let (name, selector) = match p.split_once(':') {
            Some((n, sel)) => {
                let sel = if sel.len() >= 2 && sel.starts_with('/') && sel.ends_with('/') {
                    Some(Selector::Regex(sel[1..sel.len() - 1].to_string()))
                } else {
                    Some(Selector::Name(sel.to_string()))
                };
                (n.to_string(), sel)
            }
            None => (p.to_string(), None),
        };
        if name.is_empty() {
            return Err(format!("empty variable name in {:?}", part));
        }
        out.push(VarSpec {
            excluded,
            count,
            name: name.to_ascii_uppercase(),
            selector,
        });
    }
    if out.is_empty() {
        return Err("empty variable list".into());
    }
    Ok(out)
}

fn parse_setvar(v: &str) -> Result<SetVar, String> {
    let v = unquote(v);
    let (name, expr) = v
        .split_once('=')
        .ok_or_else(|| format!("setvar without '=': {}", v))?;
    let name = name.trim().to_ascii_lowercase();
    let expr = expr.trim();
    let (inc, value) = if let Some(rest) = expr.strip_prefix('+') {
        (1, rest.to_string())
    } else if let Some(rest) = expr.strip_prefix('-') {
        (-1, rest.to_string())
    } else {
        (0, expr.to_string())
    };
    Ok(SetVar { name, inc, value })
}

fn parse_id_range(s: &str) -> (i64, i64) {
    if let Some((a, b)) = s.split_once('-') {
        (
            a.trim().parse().unwrap_or(0),
            b.trim().parse().unwrap_or(i64::MAX),
        )
    } else {
        let n = s.trim().parse().unwrap_or(0);
        (n, n)
    }
}

pub fn parse_actions(s: &str) -> Actions {
    let mut a = Actions::default();
    for piece in split_actions(s) {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let (key, val) = match piece.split_once(':') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim().to_string()),
            None => (piece.to_ascii_lowercase(), String::new()),
        };
        match key.as_str() {
            "id" => a.id = val.trim().parse().ok(),
            "phase" => {
                a.phase = val.trim().trim_matches(|c| c == '"' || c == '\'').parse().ok()
            }
            "msg" => a.msg = Some(unquote(&val)),
            "logdata" => a.logdata = Some(unquote(&val)),
            "tag" => a.tags.push(unquote(&val)),
            "severity" => a.severity = Some(unquote(&val).to_ascii_uppercase()),
            "log" => a.log = true,
            "nolog" => a.nolog = true,
            "auditlog" | "noauditlog" => {}
            "pass" | "block" | "deny" | "drop" | "allow" | "redirect" | "proxy" => {
                a.disruptive = Some(key.clone())
            }
            "status" => a.status = val.trim().parse().ok(),
            "capture" => a.capture = true,
            "chain" => a.chain = true,
            "t" => a.transforms.push(val),
            "setvar" => match parse_setvar(&val) {
                Ok(sv) => a.setvars.push(sv),
                Err(_) => a.unknown.push(format!("setvar:{}", val)),
            },
            "ctl" => {
                let v = unquote(&val);
                if let Some((ck, cv)) = v.split_once('=') {
                    match ck.trim() {
                        "ruleRemoveById" => {
                            let (lo, hi) = parse_id_range(cv);
                            a.ctls.push(Ctl::RuleRemoveById(lo, hi));
                        }
                        "ruleRemoveByTag" => a.ctls.push(Ctl::RuleRemoveByTag(cv.to_string())),
                        "ruleRemoveTargetById" => {
                            if let Some((id, target)) = cv.split_once(';') {
                                a.ctls.push(Ctl::RuleRemoveTargetById(
                                    id.trim().parse().unwrap_or(0),
                                    target.trim().to_string(),
                                ));
                            }
                        }
                        "ruleEngine" => a.ctls.push(Ctl::RuleEngine(cv.to_string())),
                        _ => a.unknown.push(format!("ctl:{}", v)),
                    }
                }
            }
            "skip" => a.skip = val.trim().parse().ok(),
            "skipafter" => a.skip_after = Some(val),
            // accepted but no-ops in the debug console
            "ver" | "rev" | "maturity" | "accuracy" | "sanitisematched"
            | "sanitisematchedbytes" | "multimatch" | "initcol" | "expirevar" | "deprecatevar"
            | "xmlns" | "encode" | "exec" | "prepend" | "append" => {}
            _ => a.unknown.push(piece.to_string()),
        }
    }
    a
}

pub fn parse(text: &str) -> ParseOutput {
    let mut entries: Vec<Entry> = Vec::new();
    let mut errors = Vec::new();
    let mut config = SecConfig::default();

    // flat rules with chain flags, assembled afterwards
    enum Flat {
        R(Rule),
        M(String),
    }
    let mut flat: Vec<Flat> = Vec::new();

    for (line_no, line) in logical_lines(text) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let toks = tokenize(line);
        let directive = toks.first().map(|s| s.as_str()).unwrap_or("");
        match directive.to_ascii_lowercase().as_str() {
            "secrule" => {
                if toks.len() < 4 {
                    errors.push(format!(
                        "line {}: SecRule needs VARIABLES \"OPERATOR\" \"ACTIONS\"",
                        line_no
                    ));
                    continue;
                }
                let vars = match parse_var_list(&toks[1]) {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(format!("line {}: {}", line_no, e));
                        continue;
                    }
                };
                let actions = parse_actions(&toks[3]);
                flat.push(Flat::R(Rule {
                    vars,
                    operator: toks[2].clone(),
                    is_action: false,
                    has_chain: actions.chain,
                    actions,
                    chained: Vec::new(),
                    line_no,
                    raw: line.to_string(),
                }));
            }
            "secaction" => {
                if toks.len() < 2 {
                    errors.push(format!("line {}: SecAction needs \"ACTIONS\"", line_no));
                    continue;
                }
                let actions = parse_actions(&toks[1]);
                flat.push(Flat::R(Rule {
                    vars: Vec::new(),
                    operator: String::new(),
                    is_action: true,
                    has_chain: actions.chain,
                    actions,
                    chained: Vec::new(),
                    line_no,
                    raw: line.to_string(),
                }));
            }
            "secruleengine" => {
                if let Some(v) = toks.get(1) {
                    config.rule_engine = v.clone();
                }
            }
            "secmarker" => {
                let name = toks.get(1).cloned().unwrap_or_default();
                flat.push(Flat::M(name));
            }
            "secdefaultaction" => {
                if let Some(v) = toks.get(1) {
                    let da = parse_actions(v);
                    config.default_phase = da.phase;
                    config.default_disruptive = da.disruptive;
                }
            }
            other => {
                // ignore unknown Sec* directives quietly, flag the rest
                if !other.to_ascii_lowercase().starts_with("sec") {
                    errors.push(format!("line {}: unknown directive {}", line_no, directive));
                }
            }
        }
    }

    // assemble chains: a rule with `chain` pulls the next rule into itself;
    // if that child also has `chain`, the chain continues.
    let mut parent: Option<Rule> = None;
    for item in flat {
        match item {
            Flat::M(name) => {
                if let Some(p) = parent.take() {
                    entries.push(Entry::Rule(p));
                }
                entries.push(Entry::Marker(name));
            }
            Flat::R(rule) => match parent.take() {
                Some(mut p) => {
                    let continues = rule.has_chain;
                    p.chained.push(rule);
                    if continues {
                        parent = Some(p);
                    } else {
                        entries.push(Entry::Rule(p));
                    }
                }
                None => {
                    if rule.has_chain {
                        parent = Some(rule);
                    } else {
                        entries.push(Entry::Rule(rule));
                    }
                }
            },
        }
    }
    if let Some(p) = parent.take() {
        entries.push(Entry::Rule(p));
    }

    ParseOutput {
        entries,
        errors,
        config,
    }
}
