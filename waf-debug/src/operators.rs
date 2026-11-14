//! Rule operators.

use crate::regex;

pub struct OpResult {
    pub matched: bool,
    pub match_value: String,
    pub captures: Vec<Option<String>>, // group 0 = whole match
    pub note: Option<String>,          // e.g. "regex timeout" or "unknown operator"
}

fn no(note: &str) -> OpResult {
    OpResult {
        matched: false,
        match_value: String::new(),
        captures: Vec::new(),
        note: Some(note.to_string()),
    }
}

fn yes(match_value: String, captures: Vec<Option<String>>) -> OpResult {
    OpResult {
        matched: true,
        match_value,
        captures,
        note: None,
    }
}

fn plain(matched: bool, match_value: String) -> OpResult {
    OpResult {
        matched,
        match_value,
        captures: Vec::new(),
        note: None,
    }
}

/// Split a pm pattern string on whitespace, honouring double quotes.
fn pm_terms(param: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = param.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let mut term = String::new();
        if chars[i] == '"' {
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                term.push(chars[i]);
                i += 1;
            }
            i += 1;
        } else {
            while i < chars.len() && !chars[i].is_whitespace() {
                term.push(chars[i]);
                i += 1;
            }
        }
        if !term.is_empty() {
            out.push(term);
        }
    }
    out
}

fn num(s: &str) -> Option<f64> {
    s.trim().parse::<f64>().ok()
}

/// Evaluate an operator string like "@rx foo" (or a bare pattern = @rx)
/// against `value`. `expand` resolves %{...} macros in the parameter.
pub fn eval(op_raw: &str, value: &str, expand: &dyn Fn(&str) -> String) -> OpResult {
    let op_raw = op_raw.trim();
    let (negated, op_raw) = match op_raw.strip_prefix('!') {
        Some(r) => (true, r.trim_start()),
        None => (false, op_raw),
    };
    let (name, param) = if let Some(rest) = op_raw.strip_prefix('@') {
        match rest.split_once(char::is_whitespace) {
            Some((n, p)) => (n.to_ascii_lowercase(), p.trim().to_string()),
            None => (rest.to_ascii_lowercase(), String::new()),
        }
    } else {
        ("rx".to_string(), op_raw.to_string())
    };
    // expand %{...} macros in the parameter
    let param = expand_macros(&param, expand);

    let mut result = match name.as_str() {
        "rx" => match regex::compile(&param) {
            Err(e) => no(&format!("regex compile error: {}", e)),
            Ok(re) => match re.search(value) {
                regex::SearchResult::Timeout => no("regex timeout (step limit exceeded)"),
                regex::SearchResult::NoMatch => plain(false, String::new()),
                regex::SearchResult::Match(caps) => {
                    let chars: Vec<char> = value.chars().collect();
                    let mut out_caps = Vec::new();
                    for c in &caps {
                        out_caps.push(match c {
                            Some((a, b)) if a <= b && *b <= chars.len() => {
                                Some(chars[*a..*b].iter().collect())
                            }
                            _ => None,
                        });
                    }
                    let whole = out_caps.first().cloned().flatten().unwrap_or_default();
                    yes(whole, out_caps)
                }
            },
        },
        "pm" | "pmfromfile" => {
            let terms = pm_terms(&param);
            let mut found: Option<String> = None;
            for t in &terms {
                if value.contains(t.as_str()) {
                    found = Some(t.clone());
                    break;
                }
            }
            match found {
                Some(t) => plain(true, t),
                None => plain(false, String::new()),
            }
        }
        "contains" => plain(value.contains(&param), param.clone()),
        "containsword" => {
            // contains as a word (bounded by non-alnum)
            let pat = format!(r"(?:^|[^A-Za-z0-9_]){}(?:$|[^A-Za-z0-9_])", regex::escape_literal(&param));
            match regex::compile(&pat) {
                Ok(re) => match re.search(value) {
                    regex::SearchResult::Match(_) => plain(true, param.clone()),
                    _ => plain(false, String::new()),
                },
                Err(_) => plain(false, String::new()),
            }
        }
        "streq" => plain(value == param, param.clone()),
        "beginswith" => plain(value.starts_with(&param), param.clone()),
        "endswith" => plain(value.ends_with(&param), param.clone()),
        "within" => plain(param.contains(value), value.to_string()),
        "eq" => match (num(value), num(&param)) {
            (Some(a), Some(b)) => plain((a - b).abs() < f64::EPSILON, String::new()),
            _ => plain(false, String::new()),
        },
        "ne" => match (num(value), num(&param)) {
            (Some(a), Some(b)) => plain((a - b).abs() >= f64::EPSILON, String::new()),
            _ => plain(true, String::new()),
        },
        "gt" => match (num(value), num(&param)) {
            (Some(a), Some(b)) => plain(a > b, String::new()),
            _ => plain(false, String::new()),
        },
        "ge" => match (num(value), num(&param)) {
            (Some(a), Some(b)) => plain(a >= b, String::new()),
            _ => plain(false, String::new()),
        },
        "lt" => match (num(value), num(&param)) {
            (Some(a), Some(b)) => plain(a < b, String::new()),
            _ => plain(false, String::new()),
        },
        "le" => match (num(value), num(&param)) {
            (Some(a), Some(b)) => plain(a <= b, String::new()),
            _ => plain(false, String::new()),
        },
        "unconditionalmatch" => plain(true, String::new()),
        "validatebyterange" => {
            // param like "32-126,10,13"
            let mut allowed = [false; 256];
            for part in param.split(',') {
                let part = part.trim();
                if let Some((a, b)) = part.split_once('-') {
                    if let (Ok(a), Ok(b)) = (a.parse::<usize>(), b.parse::<usize>()) {
                        for i in a..=b.min(255) {
                            allowed[i] = true;
                        }
                    }
                } else if let Ok(n) = part.parse::<usize>() {
                    if n < 256 {
                        allowed[n] = true;
                    }
                }
            }
            let bad = value.bytes().any(|b| !allowed[b as usize]);
            plain(!bad, String::new())
        }
        other => no(&format!("unsupported operator @{}", other)),
    };

    if negated {
        result.matched = !result.matched;
        if result.matched {
            result.match_value = String::new();
            result.captures.clear();
        }
    }
    result
}

/// Expand %{name} macros using the provided resolver.
pub fn expand_macros(s: &str, expand: &dyn Fn(&str) -> String) -> String {
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' && i + 1 < chars.len() && chars[i + 1] == '{' {
            if let Some(end) = chars[i + 2..].iter().position(|&c| c == '}') {
                let name: String = chars[i + 2..i + 2 + end].iter().collect();
                out.push_str(&expand(&name));
                i += 2 + end + 1;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}
