//! SecLang transformation functions. Every transform is total: malformed
//! input is passed through best-effort, never panics.

#[allow(dead_code)]
pub const KNOWN: &[&str] = &[
    "none",
    "lowercase",
    "uppercase",
    "urldecode",
    "urldecodeuni",
    "htmlentitydecode",
    "removenulls",
    "removewhitespace",
    "compresswhitespace",
    "trim",
    "trimleft",
    "trimright",
    "cmdline",
    "normalisepath",
    "normalisepathwin",
    "length",
    "utf8tounicode",
];

/// Apply a transform by name. Returns Err(()) for unknown names so the
/// caller can log a warning and treat it as identity.
pub fn apply(name: &str, input: &str) -> Result<String, ()> {
    let n = name.to_ascii_lowercase();
    let n = n.strip_prefix("t:").unwrap_or(&n);
    match n {
        "none" => Ok(input.to_string()),
        "lowercase" => Ok(input.to_lowercase()),
        "uppercase" => Ok(input.to_uppercase()),
        "urldecode" => Ok(url_decode(input, false)),
        "urldecodeuni" => Ok(url_decode(input, true)),
        "htmlentitydecode" => Ok(html_entity_decode(input)),
        "removenulls" => Ok(input.chars().filter(|&c| c != '\0').collect()),
        "removewhitespace" => Ok(input.chars().filter(|c| !c.is_whitespace()).collect()),
        "compresswhitespace" => Ok(compress_ws(input)),
        "trim" => Ok(input.trim().to_string()),
        "trimleft" => Ok(input.trim_start().to_string()),
        "trimright" => Ok(input.trim_end().to_string()),
        "cmdline" => Ok(cmdline(input)),
        "normalisepath" | "normalizepath" => Ok(normalise_path(input, false)),
        "normalisepathwin" | "normalizepathwin" => Ok(normalise_path(input, true)),
        "length" => Ok(input.chars().count().to_string()),
        _ => Err(()),
    }
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// URL-decode. If `uni` is true, also handle %uXXXX sequences.
/// Invalid sequences are copied through verbatim (ModSecurity behaviour).
pub fn url_decode(input: &str, uni: bool) -> String {
    let b = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 1 < b.len() {
            if uni && (b[i + 1] == b'u' || b[i + 1] == b'U') && i + 5 < b.len() + 1 {
                // %uXXXX
                let h: Option<u32> = (0..4).try_fold(0u32, |acc, k| {
                    let v = hexval(*b.get(i + 2 + k)?)?;
                    Some(acc * 16 + v as u32)
                });
                if let Some(cp) = h {
                    if let Some(ch) = char::from_u32(cp) {
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        i += 6;
                        continue;
                    }
                }
            }
            if i + 2 < b.len() + 1 {
                match (hexval(*b.get(i + 1).unwrap_or(&0)), b.get(i + 2).and_then(|&c| hexval(c))) {
                    (Some(h), Some(l)) => {
                        out.push(h * 16 + l);
                        i += 3;
                        continue;
                    }
                    _ => {}
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn named_entity(name: &str) -> Option<&'static str> {
    // common HTML4 entities; covers what htmlEntityDecode is used for in practice
    Some(match name {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        "nbsp" => "\u{a0}",
        "sol" => "/",
        "bsol" => "\\",
        "equals" => "=",
        "colon" => ":",
        "semi" => ";",
        "lpar" => "(",
        "rpar" => ")",
        "lcub" => "{",
        "rcub" => "}",
        "lsqb" => "[",
        "rsqb" => "]",
        "num" => "#",
        "percnt" => "%",
        "plus" => "+",
        "minus" => "-",
        "lowbar" => "_",
        "commat" => "@",
        "excl" => "!",
        "quest" => "?",
        "dollar" => "$",
        "hat" => "^",
        "tilde" => "~",
        "grave" => "`",
        "vert" => "|",
        "Tab" => "\t",
        "NewLine" => "\n",
        _ => return None,
    })
}

pub fn html_entity_decode(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '&' {
            // numeric: &#123; or &#x1F;
            if i + 1 < chars.len() && chars[i + 1] == '#' {
                let mut j = i + 2;
                let hex = j < chars.len() && (chars[j] == 'x' || chars[j] == 'X');
                if hex {
                    j += 1;
                }
                let start = j;
                while j < chars.len()
                    && j - start < 10
                    && if hex {
                        chars[j].is_ascii_hexdigit()
                    } else {
                        chars[j].is_ascii_digit()
                    }
                {
                    j += 1;
                }
                if j > start {
                    let s: String = chars[start..j].iter().collect();
                    let cp = u32::from_str_radix(&s, if hex { 16 } else { 10 }).ok();
                    let has_semi = j < chars.len() && chars[j] == ';';
                    if let Some(ch) = cp.and_then(char::from_u32) {
                        out.push(ch);
                        i = if has_semi { j + 1 } else { j };
                        continue;
                    }
                }
            } else {
                // named entity, semicolon optional, max 10 chars
                let mut j = i + 1;
                while j < chars.len() && j - i <= 10 && chars[j].is_ascii_alphanumeric() {
                    j += 1;
                }
                // try longest match down to shortest
                let mut matched = false;
                let mut k = j;
                while k > i + 1 {
                    let name: String = chars[i + 1..k].iter().collect();
                    if let Some(rep) = named_entity(&name) {
                        out.push_str(rep);
                        let mut next = k;
                        if next < chars.len() && chars[next] == ';' {
                            next += 1;
                        }
                        i = next;
                        matched = true;
                        break;
                    }
                    k -= 1;
                }
                if matched {
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn compress_ws(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_ws = false;
    for c in input.chars() {
        if c.is_whitespace() {
            if !in_ws {
                out.push(' ');
            }
            in_ws = true;
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out.trim().to_string()
}

/// t:cmdLine — normalise command-line evasion: lowercase, strip quote-ish
/// chars, turn separators into spaces, collapse whitespace.
fn cmdline(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.to_lowercase().chars() {
        match c {
            '"' | '\'' | '\\' | '^' => {} // deleted
            ',' | ';' => out.push(' '),
            c => out.push(c),
        }
    }
    compress_ws(&out)
}

/// Normalise path: resolve //, /./, /../. If win, also map \ -> /.
fn normalise_path(input: &str, win: bool) -> String {
    let s = if win {
        input.replace('\\', "/")
    } else {
        input.to_string()
    };
    let mut parts: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    if !parts.is_empty() && (s.ends_with('/') ) {
        out.push('/');
    }
    out
}
