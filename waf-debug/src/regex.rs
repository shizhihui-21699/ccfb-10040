//! Small backtracking regex engine (PCRE subset) with a step budget so
//! hostile patterns/inputs cannot hang the engine. Supported: literals, `.`,
//! char classes `[...]` (ranges, negation, escapes), escapes
//! (\d \D \w \W \s \S \n \r \t \f \v \xHH \b \B), anchors ^ $, groups
//! (capturing and (?:...)), alternation, quantifiers * + ? {n} {n,} {n,m}
//! with lazy variants, backreferences \1..\9, leading inline flags (?i) (?s).

const MAX_STEPS: u64 = 2_000_000;
const MAX_REPEAT: u32 = 200;

#[derive(Clone, Debug)]
enum ClassItem {
    Ch(char),
    Range(char, char),
    Digit,
    NotDigit,
    Word,
    NotWord,
    Space,
    NotSpace,
}

#[derive(Clone, Debug)]
enum Inst {
    Char(char),
    Any,
    Class(bool, Vec<ClassItem>), // bool = negated
    Split(usize, usize),
    Jmp(usize),
    Save(usize),
    Match,
    Bol,
    Eol,
    WordB(bool), // true = \b, false = \B
    BackRef(usize),
}

#[derive(Clone, Debug)]
pub struct Regex {
    prog: Vec<Inst>,
    nslots: usize,
    ci: bool,
}

pub enum SearchResult {
    Match(Vec<Option<(usize, usize)>>), // char-index capture spans, slot pairs
    NoMatch,
    Timeout,
}

pub fn compile(pattern: &str) -> Result<Regex, String> {
    let mut p = Parser {
        chars: pattern.chars().collect(),
        pos: 0,
        ci: false,
        dotall: false,
        ngroups: 0,
    };
    // leading inline flags, e.g. (?i) (?s) (?is)
    loop {
        if p.peek() == Some('(') && p.peek_at(1) == Some('?') {
            let mut j = p.pos + 2;
            let mut flags = String::new();
            while j < p.chars.len() && p.chars[j] != ')' && p.chars[j] != ':' {
                flags.push(p.chars[j]);
                j += 1;
            }
            if j < p.chars.len() && p.chars[j] == ')' && !flags.is_empty()
                && flags.chars().all(|c| "imsx".contains(c))
            {
                for f in flags.chars() {
                    match f {
                        'i' => p.ci = true,
                        's' => p.dotall = true,
                        _ => {} // m, x ignored
                    }
                }
                p.pos = j + 1;
                continue;
            }
        }
        break;
    }
    let mut body = p.parse_alt()?;
    if p.pos != p.chars.len() {
        return Err(format!("unexpected '{}' at {}", p.chars[p.pos], p.pos));
    }
    let ngroups = p.ngroups;
    let ci = p.ci;

    // wrap: Save(0) body Save(1) Match
    let mut prog = vec![Inst::Save(0)];
    shift(&mut body, 1);
    prog.append(&mut body);
    prog.push(Inst::Save(1));
    prog.push(Inst::Match);
    Ok(Regex {
        prog,
        nslots: (ngroups + 1) * 2,
        ci,
    })
}

/// Shift jump targets in a fragment by `base`.
fn shift(prog: &mut [Inst], base: usize) {
    for inst in prog.iter_mut() {
        match inst {
            Inst::Split(a, b) => {
                *a += base;
                *b += base;
            }
            Inst::Jmp(t) => *t += base,
            _ => {}
        }
    }
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    ci: bool,
    dotall: bool,
    ngroups: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn peek_at(&self, n: usize) -> Option<char> {
        self.chars.get(self.pos + n).copied()
    }
    fn eat(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }
    fn expect(&mut self, c: char) -> Result<(), String> {
        if self.eat() == Some(c) {
            Ok(())
        } else {
            Err(format!("expected '{}' at {}", c, self.pos))
        }
    }

    fn parse_alt(&mut self) -> Result<Vec<Inst>, String> {
        let mut branches = vec![self.parse_concat()?];
        while self.peek() == Some('|') {
            self.pos += 1;
            branches.push(self.parse_concat()?);
        }
        if branches.len() == 1 {
            return Ok(branches.pop().unwrap_or_default());
        }
        // assemble: chain of splits
        // layout: for branches b1..bn:
        //   split(L1, next) L1: b1 jmp END ... last branch no split
        // compute from the last branch backwards
        let mut suffix = branches.pop().unwrap_or_default();
        while let Some(branch) = branches.pop() {
            // split(1, 1+len(branch)+1) ; branch ; jmp(after) ; suffix
            let blen = branch.len();
            let slen = suffix.len();
            let mut frag = vec![Inst::Split(1, 1 + blen + 1)];
            let mut b = branch;
            shift(&mut b, 1);
            frag.append(&mut b);
            frag.push(Inst::Jmp(1 + blen + 1 + slen));
            shift(&mut suffix, 1 + blen + 1);
            frag.append(&mut suffix);
            suffix = frag;
        }
        Ok(suffix)
    }

    fn parse_concat(&mut self) -> Result<Vec<Inst>, String> {
        let mut out = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let mut frag = self.parse_repeat()?;
            shift(&mut frag, out.len());
            out.append(&mut frag);
        }
        Ok(out)
    }

    fn parse_repeat(&mut self) -> Result<Vec<Inst>, String> {
        let atom = self.parse_atom()?;
        let (min, max) = match self.peek() {
            Some('*') => {
                self.pos += 1;
                (0, None)
            }
            Some('+') => {
                self.pos += 1;
                (1, None)
            }
            Some('?') => {
                self.pos += 1;
                (0, Some(1))
            }
            Some('{') => {
                // try {n} {n,} {n,m}; if malformed treat '{' literally
                let save = self.pos;
                self.pos += 1;
                let mut a = String::new();
                while self.peek().map_or(false, |c| c.is_ascii_digit()) {
                    a.push(self.eat().unwrap_or('0'));
                }
                if a.is_empty() {
                    self.pos = save;
                    return Ok(atom);
                }
                let min: u32 = a.parse().map_err(|_| "bad repeat".to_string())?;
                let max: Option<u32> = if self.peek() == Some(',') {
                    self.pos += 1;
                    let mut b = String::new();
                    while self.peek().map_or(false, |c| c.is_ascii_digit()) {
                        b.push(self.eat().unwrap_or('0'));
                    }
                    if b.is_empty() {
                        None
                    } else {
                        Some(b.parse().map_err(|_| "bad repeat".to_string())?)
                    }
                } else {
                    Some(min)
                };
                if self.peek() != Some('}') {
                    self.pos = save;
                    return Ok(atom);
                }
                self.pos += 1;
                (min, max)
            }
            _ => return Ok(atom),
        };
        let lazy = self.peek() == Some('?');
        if lazy {
            self.pos += 1;
        }
        if min > MAX_REPEAT || max.map_or(false, |m| m > MAX_REPEAT) {
            return Err("repeat count too large".into());
        }
        Ok(build_repeat(&atom, min, max, lazy))
    }

    fn parse_atom(&mut self) -> Result<Vec<Inst>, String> {
        let c = self.eat().ok_or("unexpected end of pattern")?;
        match c {
            '(' => {
                let capturing = if self.peek() == Some('?') && self.peek_at(1) == Some(':') {
                    self.pos += 2;
                    false
                } else if self.peek() == Some('?') {
                    // inline flags mid-pattern: (?i) etc — apply and produce empty frag
                    let mut j = self.pos + 1;
                    let mut flags = String::new();
                    while j < self.chars.len() && self.chars[j] != ')' {
                        flags.push(self.chars[j]);
                        j += 1;
                    }
                    if j < self.chars.len() && flags.chars().all(|c| "imsx".contains(c)) {
                        for f in flags.chars() {
                            match f {
                                'i' => self.ci = true,
                                's' => self.dotall = true,
                                _ => {}
                            }
                        }
                        self.pos = j + 1;
                        return Ok(Vec::new());
                    }
                    return Err("unsupported group syntax".into());
                } else {
                    true
                };
                let group_id = if capturing {
                    self.ngroups += 1;
                    self.ngroups
                } else {
                    0
                };
                let mut inner = self.parse_alt()?;
                self.expect(')')?;
                if capturing {
                    let mut out = vec![Inst::Save(group_id * 2)];
                    shift(&mut inner, 1);
                    out.append(&mut inner);
                    out.push(Inst::Save(group_id * 2 + 1));
                    Ok(out)
                } else {
                    Ok(inner)
                }
            }
            '[' => self.parse_class(),
            '.' => Ok(vec![if self.dotall {
                Inst::Any
            } else {
                // any char except \n
                Inst::Class(true, vec![ClassItem::Ch('\n')])
            }]),
            '^' => Ok(vec![Inst::Bol]),
            '$' => Ok(vec![Inst::Eol]),
            '\\' => self.parse_escape(),
            c => Ok(vec![Inst::Char(c)]),
        }
    }

    fn parse_escape(&mut self) -> Result<Vec<Inst>, String> {
        let c = self.eat().ok_or("trailing backslash")?;
        let inst = match c {
            'd' => Inst::Class(false, vec![ClassItem::Digit]),
            'D' => Inst::Class(false, vec![ClassItem::NotDigit]),
            'w' => Inst::Class(false, vec![ClassItem::Word]),
            'W' => Inst::Class(false, vec![ClassItem::NotWord]),
            's' => Inst::Class(false, vec![ClassItem::Space]),
            'S' => Inst::Class(false, vec![ClassItem::NotSpace]),
            'n' => Inst::Char('\n'),
            'r' => Inst::Char('\r'),
            't' => Inst::Char('\t'),
            'f' => Inst::Char('\u{c}'),
            'v' => Inst::Char('\u{b}'),
            '0' => Inst::Char('\0'),
            'b' => Inst::WordB(true),
            'B' => Inst::WordB(false),
            'A' => Inst::Bol,
            'z' | 'Z' => Inst::Eol,
            'x' => {
                let mut hex = String::new();
                for _ in 0..2 {
                    if let Some(h) = self.peek() {
                        if h.is_ascii_hexdigit() {
                            hex.push(h);
                            self.pos += 1;
                        }
                    }
                }
                if hex.is_empty() {
                    Inst::Char('x')
                } else {
                    let v = u32::from_str_radix(&hex, 16).unwrap_or(0);
                    Inst::Char(char::from_u32(v).unwrap_or('\u{fffd}'))
                }
            }
            '1'..='9' => Inst::BackRef(c.to_digit(10).unwrap_or(0) as usize),
            other => Inst::Char(other),
        };
        Ok(vec![inst])
    }

    fn parse_class(&mut self) -> Result<Vec<Inst>, String> {
        let neg = self.peek() == Some('^');
        if neg {
            self.pos += 1;
        }
        let mut items = Vec::new();
        let mut first = true;
        loop {
            let c = self.eat().ok_or("unterminated character class")?;
            if c == ']' && !first {
                break;
            }
            first = false;
            let lo = if c == '\\' {
                let e = self.eat().ok_or("trailing backslash in class")?;
                match e {
                    'd' => {
                        items.push(ClassItem::Digit);
                        continue;
                    }
                    'D' => {
                        items.push(ClassItem::NotDigit);
                        continue;
                    }
                    'w' => {
                        items.push(ClassItem::Word);
                        continue;
                    }
                    'W' => {
                        items.push(ClassItem::NotWord);
                        continue;
                    }
                    's' => {
                        items.push(ClassItem::Space);
                        continue;
                    }
                    'S' => {
                        items.push(ClassItem::NotSpace);
                        continue;
                    }
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'f' => '\u{c}',
                    'v' => '\u{b}',
                    '0' => '\0',
                    'x' => {
                        let mut hex = String::new();
                        for _ in 0..2 {
                            if let Some(h) = self.peek() {
                                if h.is_ascii_hexdigit() {
                                    hex.push(h);
                                    self.pos += 1;
                                }
                            }
                        }
                        let v = u32::from_str_radix(&hex, 16).unwrap_or(0);
                        char::from_u32(v).unwrap_or('\u{fffd}')
                    }
                    other => other,
                }
            } else {
                c
            };
            // range?
            if self.peek() == Some('-') && self.peek_at(1).map_or(false, |n| n != ']') {
                self.pos += 1;
                let hi = self.eat().ok_or("bad range")?;
                let hi = if hi == '\\' {
                    self.eat().unwrap_or('\\')
                } else {
                    hi
                };
                items.push(ClassItem::Range(lo, hi));
            } else {
                items.push(ClassItem::Ch(lo));
            }
        }
        Ok(vec![Inst::Class(neg, items)])
    }
}

fn build_repeat(atom: &[Inst], min: u32, max: Option<u32>, lazy: bool) -> Vec<Inst> {
    let mut out = Vec::new();
    // required copies
    for _ in 0..min {
        let mut copy = atom.to_vec();
        shift(&mut copy, out.len());
        out.append(&mut copy);
    }
    match max {
        None => {
            // star of the atom at the end
            let base = out.len();
            // split(body, after) body jmp base
            let split_pos = base;
            out.push(Inst::Split(0, 0)); // patched below
            let body_pos = out.len();
            let mut copy = atom.to_vec();
            shift(&mut copy, body_pos);
            out.append(&mut copy);
            out.push(Inst::Jmp(split_pos));
            let after = out.len();
            let (a, b) = if lazy {
                (after, body_pos)
            } else {
                (body_pos, after)
            };
            out[split_pos] = Inst::Split(a, b);
        }
        Some(m) => {
            let opt = m.saturating_sub(min);
            // assemble nested optionals from innermost out: x{0,k} => (x(x)?)?
            let mut suffix: Vec<Inst> = Vec::new();
            for _ in 0..opt {
                // split(1, 1+len(atom)+len(suffix)) atom suffix  -- greedy
                // lazy: split(after, 1)
                let alen = atom.len();
                let slen = suffix.len();
                let after = 1 + alen + slen;
                let (a, b) = if lazy { (after, 1) } else { (1, after) };
                let mut frag = vec![Inst::Split(a, b)];
                let mut copy = atom.to_vec();
                shift(&mut copy, 1);
                frag.append(&mut copy);
                shift(&mut suffix, 1 + alen);
                frag.append(&mut suffix);
                suffix = frag;
            }
            let base = out.len();
            shift(&mut suffix, base);
            out.append(&mut suffix);
        }
    }
    out
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn class_matches(neg: bool, items: &[ClassItem], c: char, ci: bool) -> bool {
    let mut m = false;
    for it in items {
        let hit = match it {
            ClassItem::Ch(x) => ch_eq(*x, c, ci),
            ClassItem::Range(a, b) => {
                (*a <= c && c <= *b)
                    || (ci && {
                        let cl = c.to_ascii_lowercase();
                        let cu = c.to_ascii_uppercase();
                        (*a <= cl && cl <= *b) || (*a <= cu && cu <= *b)
                    })
            }
            ClassItem::Digit => c.is_ascii_digit(),
            ClassItem::NotDigit => !c.is_ascii_digit(),
            ClassItem::Word => is_word(c),
            ClassItem::NotWord => !is_word(c),
            ClassItem::Space => c.is_whitespace(),
            ClassItem::NotSpace => !c.is_whitespace(),
        };
        if hit {
            m = true;
            break;
        }
    }
    m != neg
}

fn ch_eq(a: char, b: char, ci: bool) -> bool {
    if a == b {
        return true;
    }
    if !ci {
        return false;
    }
    a.to_lowercase().eq(b.to_lowercase())
}

impl Regex {
    /// Search anywhere in `text`. Returns captures as char-index spans.
    /// Iterative backtracking with an explicit alternative stack: no
    /// recursion, so deep inputs cannot overflow the (small wasm) stack.
    pub fn search(&self, text: &str) -> SearchResult {
        let chars: Vec<char> = text.chars().collect();
        let mut steps: u64 = MAX_STEPS;
        for start in 0..=chars.len() {
            let slots: Vec<Option<usize>> = vec![None; self.nslots];
            match self.run(&chars, start, slots, &mut steps) {
                Some(slots) => {
                    let mut caps = Vec::with_capacity(self.nslots / 2);
                    for i in 0..self.nslots / 2 {
                        match (slots[i * 2], slots[i * 2 + 1]) {
                            (Some(a), Some(b)) => caps.push(Some((a, b))),
                            _ => caps.push(None),
                        }
                    }
                    return SearchResult::Match(caps);
                }
                None => {
                    if steps == 0 {
                        return SearchResult::Timeout;
                    }
                }
            }
        }
        SearchResult::NoMatch
    }

    /// Run the backtracking VM from `start`. Returns final slots on match.
    fn run(
        &self,
        input: &[char],
        start: usize,
        mut slots: Vec<Option<usize>>,
        steps: &mut u64,
    ) -> Option<Vec<Option<usize>>> {
        // explicit backtrack stack: (pc, sp, slots snapshot)
        let mut stack: Vec<(usize, usize, Vec<Option<usize>>)> = Vec::new();
        let mut pc = 0usize;
        let mut sp = start;
        loop {
            if *steps == 0 {
                return None;
            }
            *steps -= 1;
            let inst = self.prog.get(pc)?;
            match inst {
                Inst::Match => return Some(slots),
                Inst::Char(c) => {
                    let c = *c;
                    if sp < input.len() && ch_eq(input[sp], c, self.ci) {
                        pc += 1;
                        sp += 1;
                    } else if !backtrack(&mut stack, &mut pc, &mut sp, &mut slots) {
                        return None;
                    }
                }
                Inst::Any => {
                    if sp < input.len() {
                        pc += 1;
                        sp += 1;
                    } else if !backtrack(&mut stack, &mut pc, &mut sp, &mut slots) {
                        return None;
                    }
                }
                Inst::Class(neg, items) => {
                    if sp < input.len() && class_matches(*neg, items, input[sp], self.ci) {
                        pc += 1;
                        sp += 1;
                    } else if !backtrack(&mut stack, &mut pc, &mut sp, &mut slots) {
                        return None;
                    }
                }
                Inst::Jmp(t) => pc = *t,
                Inst::Split(a, b) => {
                    stack.push((*b, sp, slots.clone()));
                    pc = *a;
                }
                Inst::Save(slot) => {
                    if *slot < slots.len() {
                        slots[*slot] = Some(sp);
                    }
                    pc += 1;
                }
                Inst::Bol => {
                    if sp == 0 {
                        pc += 1;
                    } else if !backtrack(&mut stack, &mut pc, &mut sp, &mut slots) {
                        return None;
                    }
                }
                Inst::Eol => {
                    if sp == input.len() || (sp + 1 == input.len() && input[sp] == '\n') {
                        pc += 1;
                    } else if !backtrack(&mut stack, &mut pc, &mut sp, &mut slots) {
                        return None;
                    }
                }
                Inst::WordB(want) => {
                    let before = sp > 0 && is_word(input[sp - 1]);
                    let after = sp < input.len() && is_word(input[sp]);
                    if (before != after) == *want {
                        pc += 1;
                    } else if !backtrack(&mut stack, &mut pc, &mut sp, &mut slots) {
                        return None;
                    }
                }
                Inst::BackRef(g) => {
                    let g = *g;
                    let span = match (slots.get(g * 2), slots.get(g * 2 + 1)) {
                        (Some(Some(s)), Some(Some(e))) => (*s, *e),
                        _ => {
                            if !backtrack(&mut stack, &mut pc, &mut sp, &mut slots) {
                                return None;
                            }
                            continue;
                        }
                    };
                    let len = span.1.saturating_sub(span.0);
                    let ok = sp + len <= input.len()
                        && (0..len).all(|i| ch_eq(input[sp + i], input[span.0 + i], self.ci));
                    if ok {
                        pc += 1;
                        sp += len;
                    } else if !backtrack(&mut stack, &mut pc, &mut sp, &mut slots) {
                        return None;
                    }
                }
            }
        }
    }
}

fn backtrack(
    stack: &mut Vec<(usize, usize, Vec<Option<usize>>)>,
    pc: &mut usize,
    sp: &mut usize,
    slots: &mut Vec<Option<usize>>,
) -> bool {
    match stack.pop() {
        Some((p, s, sl)) => {
            *pc = p;
            *sp = s;
            *slots = sl;
            true
        }
        None => false,
    }
}

/// Convenience: is there a match, and what's the matched substring + groups.
#[allow(dead_code)]
pub fn find(pattern: &str, text: &str) -> Result<SearchResult, String> {
    let re = compile(pattern)?;
    Ok(re.search(text))
}

/// True if `pattern` matches anywhere in `text` (false on error/timeout).
pub fn is_match(pattern: &str, text: &str) -> bool {
    match compile(pattern) {
        Ok(re) => matches!(re.search(text), SearchResult::Match(_)),
        Err(_) => false,
    }
}

/// Captured groups (0 = whole match) as strings, if matched.
pub fn captures(pattern: &str, text: &str) -> Option<Vec<Option<String>>> {
    let re = compile(pattern).ok()?;
    match re.search(text) {
        SearchResult::Match(caps) => {
            let chars: Vec<char> = text.chars().collect();
            Some(
                caps.iter()
                    .map(|c| match c {
                        Some((a, b)) if a <= b && *b <= chars.len() => {
                            Some(chars[*a..*b].iter().collect())
                        }
                        _ => None,
                    })
                    .collect(),
            )
        }
        _ => None,
    }
}

/// Escape a string so it matches literally in a pattern.
pub fn escape_literal(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if "\\^$.|?*+()[]{}".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
