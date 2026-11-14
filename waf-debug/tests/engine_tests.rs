use waf_debug::engine::{self, EngineConfig};
use waf_debug::{http, regex, seclang, transforms};

// ---- regex ----
#[test]
fn regex_basic() {
    assert!(regex::is_match("(?i)union.*select", "1 UNION SELECT x"));
    assert!(!regex::is_match("^union", "x union"));
    assert!(regex::is_match(r"\d{3}", "abc123"));
    assert!(regex::is_match(r"(?i)union", "UnIoN"));
    assert!(regex::is_match(r"a+?", "aaa"));
    assert!(regex::is_match(r"(foo|bar)baz", "xxbarbaz"));
    assert!(regex::is_match(r"\bselect\b", "a select b"));
    assert!(!regex::is_match(r"\bselect\b", "selected"));
    assert!(regex::is_match(r"(a|b)\1", "aa"));
    assert!(regex::is_match(r"%2e", "%2e"));
    assert!(regex::is_match(r#"[<>'"]"#, "a<b"));
    assert!(regex::is_match(r"x{2,4}", "axxxb"));
    assert!(!regex::is_match(r"x{2,4}", "axb"));
    assert!(regex::is_match(r"colou?r", "color"));
    assert!(regex::is_match(r"\.\./", "../etc"));
    assert!(regex::is_match(r"(?s)a.b", "a\nb"));
    assert!(!regex::is_match(r"a.b", "a\nb"));
}

#[test]
fn regex_no_catastrophic_backtracking() {
    // nested quantifiers on long non-matching input must hit the step budget
    let input = "a".repeat(5000);
    let start = std::time::Instant::now();
    let _ = regex::is_match(r"(a+)+$", &input);
    assert!(start.elapsed().as_secs() < 5);
}

#[test]
fn regex_captures() {
    let caps = regex::captures(r"\bid=(\d+)", "uid=1 id=42 x").unwrap();
    assert_eq!(caps[0].as_deref(), Some("id=42"));
    assert_eq!(caps[1].as_deref(), Some("42"));
}

// ---- transforms ----
#[test]
fn transform_url_decode_uni() {
    assert_eq!(transforms::apply("urlDecodeUni", "%3Cscript%3E").unwrap(), "<script>");
    assert_eq!(transforms::apply("urlDecodeUni", "%u003c%u003e").unwrap(), "<>");
    assert_eq!(transforms::apply("urlDecode", "%41%42").unwrap(), "AB");
    // invalid sequences pass through
    assert_eq!(transforms::apply("urlDecode", "%zz%1").unwrap(), "%zz%1");
}

#[test]
fn transform_html_entity() {
    assert_eq!(transforms::apply("htmlEntityDecode", "&lt;script&gt;").unwrap(), "<script>");
    assert_eq!(transforms::apply("htmlEntityDecode", "&#60;&#x3c;").unwrap(), "<<");
    assert_eq!(transforms::apply("htmlEntityDecode", "&quot;a&apos;").unwrap(), "\"a'");
    assert_eq!(transforms::apply("htmlEntityDecode", "&#49").unwrap(), "1"); // no semicolon
}

#[test]
fn transform_misc() {
    assert_eq!(transforms::apply("lowercase", "AbC").unwrap(), "abc");
    assert_eq!(transforms::apply("removeNulls", "a\0b\0").unwrap(), "ab");
    assert_eq!(transforms::apply("compressWhitespace", "a  \t b").unwrap(), "a b");
    assert_eq!(transforms::apply("cmdLine", "C^M^D /c \"dir\"").unwrap(), "cmd /c dir");
    assert_eq!(transforms::apply("normalisePath", "/a/./b/../c").unwrap(), "/a/c");
    assert!(transforms::apply("noSuchTransform", "x").is_err());
}

// ---- http parsing ----
#[test]
fn http_simple_get() {
    let r = http::parse("GET /a/b?x=1&y=two+words HTTP/1.1\r\nHost: ex.com\r\n\r\n");
    assert_eq!(r.method, "GET");
    assert_eq!(r.path, "/a/b");
    assert_eq!(r.query, "x=1&y=two+words");
    assert_eq!(r.args_get.len(), 2);
    assert_eq!(r.args_get[1], ("y".into(), "two words".into()));
    assert!(r.errors.is_empty());
}

#[test]
fn http_chunked() {
    let raw = "POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n5\r\na=1&b\r\n6\r\n=2&c=3\r\n0\r\n\r\n";
    let r = http::parse(raw);
    assert_eq!(r.body_string(), "a=1&b=2&c=3");
    assert_eq!(r.args_post.len(), 3);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
}

#[test]
fn http_chunked_malformed() {
    let raw = "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc";
    let r = http::parse(raw);
    assert!(r.reqbody_error);
    assert!(!r.errors.is_empty());
}

#[test]
fn http_chunked_truncated() {
    let raw = "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n64\r\nshort";
    let r = http::parse(raw);
    assert!(r.reqbody_error);
    assert_eq!(r.body_string(), "short");
}

#[test]
fn http_multipart() {
    let raw = "POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=----XYZ\r\n\r\n------XYZ\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n------XYZ\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nfilecontent\r\n------XYZ--\r\n";
    let r = http::parse(raw);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(r.args_post, vec![("field1".to_string(), "value1".to_string())]);
    assert_eq!(r.files, vec![("file1".to_string(), "a.txt".to_string())]);
}

#[test]
fn http_multipart_malformed_no_final_boundary() {
    let raw = "POST /u HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=AA\r\n\r\n--AA\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\n1\r\n";
    let r = http::parse(raw);
    assert!(r.multipart_strict_error);
}

#[test]
fn http_garbage_does_not_panic() {
    let inputs: Vec<String> = vec![
        "".into(),
        "\r\n\r\n".into(),
        "GET".into(),
        "GET / HTTP/1.1".into(),
        "NOT HTTP AT ALL \x00\x01\x02".into(),
        "POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\nxyz".into(),
        "POST / HTTP/1.1\r\nContent-Length: 999999\r\n\r\nshort".into(),
        "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".into(),
        format!("GET /?{} HTTP/1.1\r\n\r\n", "a".repeat(10000)),
        "GET / HTTP/1.1\n\n".into(),                       // bare LF
        "GET / HTTP/1.1\r\n folded: x\r\n\tmore\r\n\r\n".into(), // obs-fold
    ];
    for i in &inputs {
        let _ = http::parse(i); // must not panic
    }
}

// ---- seclang parsing ----
#[test]
fn parse_basic_rule() {
    let p = seclang::parse(
        "SecRule ARGS \"@rx attack\" \"id:100,phase:2,deny,msg:'test',t:lowercase,t:urlDecodeUni\"",
    );
    assert!(p.errors.is_empty(), "{:?}", p.errors);
    match &p.entries[0] {
        seclang::Entry::Rule(r) => {
            assert_eq!(r.actions.id, Some(100));
            assert_eq!(r.actions.transforms, vec!["lowercase", "urlDecodeUni"]);
            assert_eq!(r.actions.disruptive.as_deref(), Some("deny"));
        }
        _ => panic!("expected rule"),
    }
}

#[test]
fn parse_chain() {
    let p = seclang::parse(
        "SecRule ARGS:a \"@streq 1\" \"id:1,chain,deny\"\nSecRule ARGS:b \"@streq 2\" \"t:none\"",
    );
    match &p.entries[0] {
        seclang::Entry::Rule(r) => {
            assert_eq!(r.chained.len(), 1);
            assert!(r.has_chain);
        }
        _ => panic!("expected rule"),
    }
    assert_eq!(p.entries.len(), 1);
}

#[test]
fn parse_actions_with_commas_in_msg() {
    let p = seclang::parse("SecRule ARGS \"x\" \"id:5,msg:'a,b,c',pass\"");
    match &p.entries[0] {
        seclang::Entry::Rule(r) => assert_eq!(r.actions.msg.as_deref(), Some("a,b,c")),
        _ => panic!(),
    }
}

#[test]
fn parse_continuation_and_comments() {
    let p = seclang::parse("# comment\nSecRule ARGS \"x\" \\\n  \"id:7,pass\"\n\nSecAction \"id:8,pass\"");
    assert_eq!(p.entries.len(), 2);
    assert!(p.errors.is_empty());
}

// ---- engine end-to-end (assert on JSON output strings) ----
fn cfg() -> EngineConfig {
    EngineConfig::default()
}

fn run(rules: &str, req: &str) -> String {
    engine::run(rules, req, &cfg())
}

#[test]
fn engine_transform_chain_match() {
    let v = run(
        "SecRule ARGS \"@contains <script>\" \"id:1,phase:2,deny,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase\"",
        "GET /?q=%3CSCRIPT%3Ealert(1) HTTP/1.1\r\n\r\n",
    );
    assert!(v.contains("\"verdict\":\"BLOCK\""), "{}", v);
    assert!(v.contains("\"status\":\"matched\""));
    // transform intermediate values recorded
    assert!(v.contains("<SCRIPT>alert(1)"), "{}", v);
}

#[test]
fn engine_anomaly_scoring() {
    let rules = "SecRuleEngine On\n\
        SecRule ARGS \"@rx union\" \"id:1,phase:2,block,severity:CRITICAL,t:lowercase\"\n\
        SecRule ARGS \"@rx select\" \"id:2,phase:2,block,severity:WARNING,t:lowercase\"";
    let v = run(rules, "GET /?q=union+select HTTP/1.1\r\n\r\n");
    // 5 + 3 = 8 >= threshold 5
    assert!(v.contains("\"anomaly_score\":8"), "{}", v);
    assert!(v.contains("\"verdict\":\"BLOCK\""));
}

#[test]
fn engine_anomaly_below_threshold() {
    let rules = "SecRule ARGS \"@rx foo\" \"id:1,phase:2,block,severity:NOTICE\"";
    let v = run(rules, "GET /?q=foo HTTP/1.1\r\n\r\n");
    assert!(v.contains("\"anomaly_score\":2"), "{}", v);
    assert!(v.contains("\"verdict\":\"PASS\""));
}

#[test]
fn engine_chain() {
    let rules = "SecRule ARGS:a \"@streq 1\" \"id:1,phase:2,deny,chain\"\nSecRule ARGS:b \"@streq 2\" \"\"";
    let hit = run(rules, "GET /?a=1&b=2 HTTP/1.1\r\n\r\n");
    assert!(hit.contains("\"verdict\":\"BLOCK\""), "{}", hit);
    let miss = run(rules, "GET /?a=1&b=3 HTTP/1.1\r\n\r\n");
    assert!(miss.contains("\"verdict\":\"PASS\""));
    assert!(hit.contains("\"chain\":[{"), "chain trace present: {}", hit);
}

#[test]
fn engine_capture_and_tx() {
    let rules = "SecRule ARGS \"@rx id=(\\d+)\" \"id:1,phase:2,pass,capture,setvar:tx.user_id=%{tx.1}\"";
    let v = run(rules, "GET /?q=id=42 HTTP/1.1\r\n\r\n");
    assert!(v.contains("\"0\":\"id=42\""), "{}", v);
    assert!(v.contains("\"1\":\"42\""));
    assert!(v.contains("\"user_id\":\"42\""));
}

#[test]
fn engine_setvar_score_and_threshold_rule() {
    // CRS-style: rules add to tx.anomaly_score, final rule checks threshold
    let rules = "SecRule ARGS \"@rx attack\" \"id:1,phase:2,pass,setvar:tx.anomaly_score=+%{tx.critical_anomaly_score}\"\n\
                 SecRule TX:anomaly_score \"@ge %{tx.inbound_anomaly_threshold}\" \"id:2,phase:2,deny\"";
    let v = run(rules, "GET /?q=attack HTTP/1.1\r\n\r\n");
    assert!(v.contains("\"anomaly_score\":\"5\""), "{}", v);
    assert!(v.contains("\"verdict\":\"BLOCK\""));
}

#[test]
fn engine_ctl_remove_by_id() {
    let rules = "SecRule REQUEST_URI \"@contains /health\" \"id:900,phase:1,pass,ctl:ruleRemoveById=100\"\n\
                 SecRule ARGS \"@rx .\" \"id:100,phase:2,deny\"";
    let v = run(rules, "GET /health?x=1 HTTP/1.1\r\n\r\n");
    assert!(v.contains("\"verdict\":\"PASS\""), "{}", v);
    assert!(v.contains("removed by ctl:ruleRemoveById"));
}

#[test]
fn engine_exclusion_and_count() {
    let rules = "SecRule ARGS|!ARGS:safe \"@rx evil\" \"id:1,phase:2,deny\"";
    let v = run(rules, "GET /?safe=evil HTTP/1.1\r\n\r\n");
    assert!(v.contains("\"verdict\":\"PASS\""), "{}", v);

    let rules2 = "SecRule &ARGS \"@gt 2\" \"id:2,phase:2,deny\"";
    let v2 = run(rules2, "GET /?a=1&b=2&c=3 HTTP/1.1\r\n\r\n");
    assert!(v2.contains("\"verdict\":\"BLOCK\""), "{}", v2);
}

#[test]
fn engine_detection_only() {
    let rules = "SecRuleEngine DetectionOnly\nSecRule ARGS \"@rx x\" \"id:1,phase:2,deny\"";
    let v = run(rules, "GET /?q=x HTTP/1.1\r\n\r\n");
    assert!(v.contains("\"verdict\":\"PASS\""), "{}", v);
}

#[test]
fn engine_selfcontained_mode() {
    let mut c = cfg();
    c.mode = "selfcontained".into();
    let rules = "SecRule ARGS \"@rx a\" \"id:1,phase:2,deny\"\nSecRule ARGS \"@rx b\" \"id:2,phase:2,deny\"";
    let out = engine::run(rules, "GET /?q=a+b HTTP/1.1\r\n\r\n", &c);
    assert!(out.contains("\"verdict\":\"BLOCK\""), "{}", out);
    // halted after first deny: rule 2 never evaluated
    assert!(!out.contains("\"id\":2"), "halted: {}", out);
}

#[test]
fn engine_skip_after_marker() {
    // skipAfter is per-phase: rule 2 (same phase) is skipped, rule 3 after
    // the marker still runs
    let rules = "SecRule REQUEST_URI \"@contains /skip\" \"id:1,phase:2,pass,skipAfter:END\"\n\
                 SecRule ARGS \"@rx .\" \"id:2,phase:2,deny\"\n\
                 SecMarker \"END\"\n\
                 SecRule ARGS \"@rx zzz\" \"id:3,phase:2,deny\"";
    let v = run(rules, "GET /skip?x=1 HTTP/1.1\r\n\r\n");
    assert!(v.contains("\"verdict\":\"PASS\""), "{}", v);
    assert!(v.contains("skipAfter:END pending"), "{}", v);
}

#[test]
fn engine_malformed_request_still_works() {
    let rules = "SecRule ARGS \"@rx evil\" \"id:1,phase:2,deny\"";
    let v = run(rules, "GARBAGE \x00\x01 not http");
    assert!(v.contains("\"verdict\":"), "{}", v); // no crash, produces output
    let v2 = run(rules, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nx");
    assert!(v2.contains("bad chunk size"), "{}", v2);
}

#[test]
fn engine_multipart_arg_match() {
    let rules = "SecRule ARGS \"@rx evil\" \"id:1,phase:2,deny\"";
    let req = "POST /u HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=BB\r\n\r\n--BB\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nevil payload\r\n--BB--\r\n";
    let v = run(rules, req);
    assert!(v.contains("\"verdict\":\"BLOCK\""), "{}", v);
}

#[test]
fn engine_chunked_body_arg_match() {
    let rules = "SecRule ARGS:cmd \"@rx /bin/\" \"id:1,phase:2,deny\"";
    let body = "cmd=%2Fbin%2Fsh";
    let req = format!(
        "POST /run HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        body.len(),
        body
    );
    let v = run(&rules, &req);
    assert!(v.contains("\"verdict\":\"BLOCK\""), "{}", v);
}

#[test]
fn engine_operator_macro_expansion() {
    let rules = "SecAction \"id:1,phase:1,pass,setvar:tx.limit=3\"\nSecRule &ARGS \"@gt %{tx.limit}\" \"id:2,phase:2,deny\"";
    let v = run(rules, "GET /?a=1&b=2&c=3&d=4 HTTP/1.1\r\n\r\n");
    assert!(v.contains("\"verdict\":\"BLOCK\""), "{}", v);
}
