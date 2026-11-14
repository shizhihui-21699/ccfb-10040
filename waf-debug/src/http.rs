//! Fault-tolerant HTTP request parsing. Never panics; malformed input sets
//! error flags and yields whatever could be recovered.

use crate::transforms::url_decode;

#[derive(Default, Debug)]
pub struct Request {
    pub method: String,
    pub uri_raw: String,   // as sent on the request line
    pub path: String,
    pub query: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub errors: Vec<String>,
    pub args_get: Vec<(String, String)>,
    pub args_post: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub files: Vec<(String, String)>, // (field name, filename)
    pub content_type: String,
    pub multipart_strict_error: bool,
    pub reqbody_error: bool,
}

impl Request {
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.header_all(name).into_iter().next()
    }
    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

pub fn parse(raw: &str) -> Request {
    let mut req = Request::default();
    let bytes = raw.as_bytes();

    // --- split head / body ---
    let (head, body_start) = match find_subslice(bytes, b"\r\n\r\n") {
        Some(p) => (&raw[..p], p + 4),
        None => match find_subslice(bytes, b"\n\n") {
            Some(p) => (&raw[..p], p + 2),
            None => (raw, raw.len()),
        },
    };

    // --- request line + headers ---
    let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let request_line = lines.next().unwrap_or("").trim();
    parse_request_line(request_line, &mut req);

    let mut current: Option<(String, String)> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // obs-fold continuation
            if let Some((_, v)) = current.as_mut() {
                v.push(' ');
                v.push_str(line.trim());
            } else {
                req.errors.push("header continuation without a header".into());
            }
            continue;
        }
        if let Some(h) = current.take() {
            req.headers.push(h);
        }
        match line.split_once(':') {
            Some((name, value)) => {
                let name = name.trim();
                if name.is_empty() {
                    req.errors.push(format!("malformed header line: {:?}", line));
                    continue;
                }
                current = Some((name.to_string(), value.trim().to_string()));
            }
            None => req.errors.push(format!("malformed header line: {:?}", line)),
        }
    }
    if let Some(h) = current.take() {
        req.headers.push(h);
    }

    // --- body ---
    let raw_body = &bytes[body_start.min(bytes.len())..];
    let te = req
        .header_all("transfer-encoding")
        .join(",")
        .to_ascii_lowercase();
    if te.split(',').any(|t| t.trim() == "chunked") {
        req.body = decode_chunked(raw_body, &mut req);
    } else if let Some(cl) = req.header("content-length") {
        match cl.trim().parse::<usize>() {
            Ok(n) => {
                if raw_body.len() < n {
                    req.errors.push(format!(
                        "Content-Length {} but only {} bytes present",
                        n,
                        raw_body.len()
                    ));
                    req.reqbody_error = true;
                    req.body = raw_body.to_vec();
                } else {
                    if raw_body.len() > n {
                        req.errors.push(format!(
                            "body has {} extra bytes beyond Content-Length {}",
                            raw_body.len() - n,
                            n
                        ));
                    }
                    req.body = raw_body[..n].to_vec();
                }
            }
            Err(_) => {
                req.errors.push(format!("invalid Content-Length: {:?}", cl));
                req.reqbody_error = true;
                req.body = raw_body.to_vec();
            }
        }
    } else {
        req.body = raw_body.to_vec();
    }

    // --- derived collections ---
    req.content_type = req
        .header("content-type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    req.args_get = parse_urlencoded(&req.query);

    if req.method.eq_ignore_ascii_case("post")
        || req.method.eq_ignore_ascii_case("put")
        || req.method.eq_ignore_ascii_case("patch")
    {
        match req.content_type.as_str() {
            "application/x-www-form-urlencoded" => {
                req.args_post = parse_urlencoded(&req.body_string());
            }
            "multipart/form-data" => {
                parse_multipart(&mut req);
            }
            _ => {}
        }
    }

    // cookies
    let cookie_headers: Vec<String> = req
        .header_all("cookie")
        .iter()
        .map(|s| s.to_string())
        .collect();
    for h in &cookie_headers {
        for pair in h.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            match pair.split_once('=') {
                Some((k, v)) => req.cookies.push((k.trim().to_string(), v.trim().to_string())),
                None => req.cookies.push((pair.to_string(), String::new())),
            }
        }
    }

    req
}

fn parse_request_line(line: &str, req: &mut Request) {
    let mut parts = line.split_whitespace();
    req.method = parts.next().unwrap_or("").to_ascii_uppercase();
    req.uri_raw = parts.next().unwrap_or("").to_string();
    req.version = parts.next().unwrap_or("").to_string();
    if req.method.is_empty() && !line.is_empty() {
        req.errors.push(format!("cannot parse request line: {:?}", line));
    }
    if req.version.is_empty() && !req.uri_raw.is_empty() {
        req.errors.push("missing HTTP version on request line".into());
    }
    // strip absolute-form scheme://host
    let uri = req.uri_raw.clone();
    let uri = if let Some(rest) = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))
    {
        match rest.find('/') {
            Some(p) => &rest[p..],
            None => "/",
        }
    } else {
        uri.as_str()
    };
    match uri.split_once('?') {
        Some((p, q)) => {
            req.path = p.to_string();
            req.query = q.to_string();
        }
        None => {
            req.path = uri.to_string();
            req.query = String::new();
        }
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parse k=v&k=v with url-decoding (+ becomes space). Tolerates bare keys,
/// empty segments, and stray '=' in values.
pub fn parse_urlencoded(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let k = url_decode(&k.replace('+', " "), false);
        let v = url_decode(&v.replace('+', " "), false);
        if k.is_empty() {
            continue;
        }
        out.push((k, v));
    }
    out
}

fn decode_chunked(raw: &[u8], req: &mut Request) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let max_chunks = 10_000;
    for _ in 0..max_chunks {
        // read size line
        let line_end = match find_subslice(&raw[pos..], b"\r\n").map(|p| p + pos) {
            Some(p) => (p, 2),
            None => match raw[pos..].iter().position(|&b| b == b'\n').map(|p| p + pos) {
                Some(p) => (p, 1),
                None => {
                    req.errors.push("chunked body: missing chunk size line".into());
                    req.reqbody_error = true;
                    return out;
                }
            },
        };
        let (eol, eol_len) = line_end;
        let size_str = String::from_utf8_lossy(&raw[pos..eol]).into_owned();
        let size_str = size_str.split(';').next().unwrap_or("").trim().to_string();
        let size = match usize::from_str_radix(&size_str, 16) {
            Ok(s) => s,
            Err(_) => {
                req.errors
                    .push(format!("chunked body: bad chunk size {:?}", size_str));
                req.reqbody_error = true;
                return out;
            }
        };
        pos = eol + eol_len;
        if size == 0 {
            // trailers until empty line; ignore content, just stop cleanly
            return out;
        }
        if pos + size > raw.len() {
            req.errors.push(format!(
                "chunked body: chunk of {} bytes truncated ({} available)",
                size,
                raw.len() - pos
            ));
            req.reqbody_error = true;
            out.extend_from_slice(&raw[pos..]);
            return out;
        }
        out.extend_from_slice(&raw[pos..pos + size]);
        pos += size;
        // expect CRLF (tolerate LF or missing)
        if raw[pos..].starts_with(b"\r\n") {
            pos += 2;
        } else if raw[pos..].starts_with(b"\n") {
            pos += 1;
        } else {
            req.errors.push("chunked body: missing CRLF after chunk".into());
            req.reqbody_error = true;
            return out;
        }
    }
    req.errors.push("chunked body: too many chunks".into());
    req.reqbody_error = true;
    out
}

fn parse_multipart(req: &mut Request) {
    let ct = req.header("content-type").unwrap_or("").to_string();
    let boundary = ct
        .split(';')
        .skip(1)
        .find_map(|p| {
            let p = p.trim();
            p.strip_prefix("boundary=").map(|b| b.trim_matches('"').to_string())
        });
    let boundary = match boundary {
        Some(b) if !b.is_empty() => b,
        _ => {
            req.errors.push("multipart: missing boundary".into());
            req.multipart_strict_error = true;
            return;
        }
    };
    let body = req.body.clone();
    let dash = format!("--{}", boundary);
    let dash_b = dash.as_bytes();
    let final_marker = format!("--{}--", boundary);
    if !String::from_utf8_lossy(&body).contains(&final_marker) {
        req.errors.push("multipart: missing final boundary".into());
        req.multipart_strict_error = true;
    }
    // split on --boundary; skip preamble to first boundary
    let mut pos = match find_subslice(&body, dash_b) {
        Some(p) => p + dash_b.len(),
        None => {
            req.errors.push("multipart: no boundary found".into());
            req.multipart_strict_error = true;
            return;
        }
    };
    let mut parts_seen = 0;
    loop {
        parts_seen += 1;
        if parts_seen > 1000 {
            req.errors.push("multipart: too many parts".into());
            req.multipart_strict_error = true;
            break;
        }
        // after boundary: "--" (end), CRLF, or garbage
        if body[pos..].starts_with(b"--") {
            break; // final boundary
        }
        if body[pos..].starts_with(b"\r\n") {
            pos += 2;
        } else if body[pos..].starts_with(b"\n") {
            pos += 1;
        } else {
            req.errors.push("multipart: garbage after boundary".into());
            req.multipart_strict_error = true;
            break;
        }
        // find next boundary
        let next = match find_subslice(&body[pos..], dash_b).map(|p| p + pos) {
            Some(p) => p,
            None => {
                req.errors.push("multipart: unterminated part".into());
                req.multipart_strict_error = true;
                break;
            }
        };
        let part = &body[pos..next];
        pos = next + dash_b.len();
        // strip trailing CRLF of part content
        let mut part = part;
        if part.ends_with(b"\r\n") {
            part = &part[..part.len() - 2];
        } else if part.ends_with(b"\n") {
            part = &part[..part.len() - 1];
        }
        // split part headers / content
        let (phead, pcontent) = match find_subslice(part, b"\r\n\r\n") {
            Some(p) => (&part[..p], &part[p + 4..]),
            None => match find_subslice(part, b"\n\n") {
                Some(p) => (&part[..p], &part[p + 2..]),
                None => {
                    req.errors.push("multipart: part without header/body split".into());
                    req.multipart_strict_error = true;
                    continue;
                }
            },
        };
        let head = String::from_utf8_lossy(phead).into_owned();
        let mut name = String::new();
        let mut filename: Option<String> = None;
        for line in head.split('\n') {
            let line = line.trim_end_matches('\r');
            if let Some((hname, hval)) = line.split_once(':') {
                if hname.trim().eq_ignore_ascii_case("content-disposition") {
                    for param in hval.split(';') {
                        let param = param.trim();
                        if let Some(v) = param.strip_prefix("name=") {
                            name = v.trim_matches('"').to_string();
                        } else if let Some(v) = param.strip_prefix("filename=") {
                            filename = Some(v.trim_matches('"').to_string());
                        }
                    }
                }
            }
        }
        if name.is_empty() {
            req.errors.push("multipart: part without name".into());
            req.multipart_strict_error = true;
            continue;
        }
        match filename {
            Some(f) => req.files.push((name, f)),
            None => req
                .args_post
                .push((name, String::from_utf8_lossy(pcontent).into_owned())),
        }
    }
}
