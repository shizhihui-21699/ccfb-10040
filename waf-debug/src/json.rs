//! Minimal JSON output helpers (no dependencies).

/// Escape a string into a JSON string literal (including quotes).
pub fn q(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Object builder. Values are pre-built JSON fragments.
#[derive(Default)]
pub struct Obj {
    fields: Vec<String>,
}

impl Obj {
    pub fn new() -> Self {
        Obj { fields: Vec::new() }
    }
    pub fn set(&mut self, key: &str, val: String) -> &mut Self {
        self.fields.push(format!("{}:{}", q(key), val));
        self
    }
    pub fn str(&mut self, key: &str, val: &str) -> &mut Self {
        self.set(key, q(val))
    }
    pub fn num(&mut self, key: &str, val: i64) -> &mut Self {
        self.set(key, val.to_string())
    }
    pub fn boolean(&mut self, key: &str, val: bool) -> &mut Self {
        self.set(key, if val { "true".into() } else { "false".into() })
    }
    pub fn build(&self) -> String {
        format!("{{{}}}", self.fields.join(","))
    }
}

/// Array builder. Elements are pre-built JSON fragments.
#[derive(Default)]
pub struct Arr {
    items: Vec<String>,
}

impl Arr {
    pub fn new() -> Self {
        Arr { items: Vec::new() }
    }
    pub fn push(&mut self, val: String) -> &mut Self {
        self.items.push(val);
        self
    }
    pub fn push_str(&mut self, val: &str) -> &mut Self {
        self.items.push(q(val));
        self
    }
    pub fn build(&self) -> String {
        format!("[{}]", self.items.join(","))
    }
}
