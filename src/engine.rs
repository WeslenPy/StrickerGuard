//! Filtering engine: parses ad-block style rules (network rules, hosts lines,
//! DNS rules) and answers whether a URL or host is blocked.
//!
//! The DNS rule rules follow the original's DNS library (AdguardDns.dll), read with
//! Ghidra; addresses are in MECHANICS.md, "DNS rule engine".

use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Ads,
    Trackers,
    Annoyances,
    Security,
    Dns,
    User,
    Parental,
    /// built-in list against ads on streaming platforms (src/streaming.rs)
    Streaming,
    Other,
}

#[derive(Clone, Debug)]
pub struct Origin {
    pub source: Arc<str>,
    pub category: Category,
}

#[derive(Clone, Debug)]
struct RuleRef {
    text: Arc<str>,
    origin: Origin,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Blocked,
    Allowed,
    Allowlisted,
    Rewritten,
    Passed,
}

#[derive(Clone, Debug, Serialize)]
pub struct Verdict {
    pub action: Action,
    pub host: String,
    pub rule: Option<String>,
    pub source: Option<String>,
    pub category: Option<Category>,
    /// Address the host is answered with (0.0.0.0 / :: for blocks, or a $dnsrewrite target).
    pub answer: Option<String>,
}

struct PatternRule {
    pattern: String,
    exception: bool,
    important: bool,
    /// DNS rules are matched against the host name only, network rules against the full address.
    host_only: bool,
    rule: RuleRef,
}

#[derive(Default, Clone, Debug, Serialize)]
pub struct EngineStats {
    pub total_rules: usize,
    pub domain_rules: usize,
    pub pattern_rules: usize,
    pub regex_rules: usize,
    pub cosmetic_rules: usize,
    pub skipped_rules: usize,
    pub badfilter_rules: usize,
    pub rewrite_rules: usize,
}

/// One table of whole-domain rules: `sub` covers the domain and its subdomains, `exact` only the domain.
#[derive(Default)]
struct DomainTable {
    sub: HashMap<String, RuleRef>,
    exact: HashMap<String, RuleRef>,
}

impl DomainTable {
    fn insert(&mut self, host: String, exact: bool, r: RuleRef) {
        let t = if exact { &mut self.exact } else { &mut self.sub };
        t.entry(host).or_insert(r);
    }
    fn lookup(&self, host: &str) -> Option<&RuleRef> {
        self.exact.get(host).or_else(|| suffixes(host).into_iter().find_map(|h| self.sub.get(h)))
    }
    fn retain(&mut self, f: impl Fn(&RuleRef) -> bool) {
        self.sub.retain(|_, r| f(r));
        self.exact.retain(|_, r| f(r));
    }
    fn iter(&self) -> impl Iterator<Item = (&String, &RuleRef)> {
        self.sub.iter().chain(self.exact.iter())
    }
}

#[derive(Default)]
pub struct Engine {
    block: DomainTable,
    important: DomainTable,
    allow: DomainTable,
    rewrites: HashMap<String, (String, RuleRef)>,
    patterns: Vec<PatternRule>,
    regexes: Vec<(Regex, bool, bool, RuleRef)>,
    allowlist: HashSet<String>,
    /// Texts of rules switched off by `$badfilter` rules.
    badfilter: HashSet<String>,
    pub stats: EngineStats,
}

const MAX_REGEX_RULES: usize = 3000;

/// Addresses that turn a hosts line into a block (AdguardDns.dll 0x180060570, table at 0x180330608).
const BLOCKING_IPS: &[&str] = &["0.0.0.0", "127.0.0.1", "::", "::1", "[::]", "[::1]"];

/// The only modifiers the DNS engine accepts (table at 0x180332f60, names at 0x180333168).
/// Any other modifier makes the DNS rule invalid (0x18006fd80 "Unknown modifier").
const DNS_MODIFIERS: &[&str] = &["important", "badfilter", "dnstype", "dnsrewrite", "denyallow"];

/// Scheme prefixes stripped from DNS patterns; they act like `||` (0x180072de0, table at 0x180332ea0).
const SCHEME_PREFIXES: &[&str] = &["https://", "http://", "http*://", "ws://", "wss://", "ws*://", "://", "//"];

/// End markers stripped from DNS patterns (0x18006fb90, table at 0x180332f20 -> "|", "^", "/").
const END_MARKERS: &[char] = &['|', '^', '/'];

/// Longest DNS pattern and label accepted as a domain (0x180070c80).
const MAX_DOMAIN_LEN: usize = 255;
const MAX_LABEL_LEN: usize = 63;
/// Longest pattern accepted as an IP address (0x180070e00).
const MAX_IP_PATTERN_LEN: usize = 45;

/// Characters allowed in a plain host name.
fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'
}

fn looks_like_host(s: &str) -> bool {
    !s.is_empty() && s.contains('.') && s.chars().all(is_host_char) && !s.starts_with('.') && !s.ends_with('.')
}

/// DNS domain pattern check: under 256 chars, letters, digits and `* - . _`, labels up to 63.
fn valid_dns_domain(p: &str) -> bool {
    p.len() <= MAX_DOMAIN_LEN
        && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '*' | '-' | '.' | '_'))
        && p.split('.').all(|l| l.len() <= MAX_LABEL_LEN)
}

/// DNS IP pattern check: 1..=45 chars of hex digits and `* . : [ ]`.
fn ip_like(p: &str) -> bool {
    !p.is_empty() && p.len() <= MAX_IP_PATTERN_LEN && p.chars().all(|c| c.is_ascii_hexdigit() || matches!(c, '*' | '.' | ':' | '[' | ']'))
}

/// "Too wide" (0x180070ba0): two characters or fewer, or only dots and stars,
/// unless the rule carries $dnstype, $dnsrewrite or $denyallow.
fn too_wide(p: &str) -> bool {
    p.len() <= 2 || p.chars().all(|c| c == '.' || c == '*')
}

fn is_cosmetic(line: &str) -> bool {
    ["##", "#@#", "#?#", "#$#", "#%#", "#@$#", "#@%#", "#@?#", "$$", "$@$"]
        .iter()
        .any(|m| line.contains(m))
}

/// Network-rule modifiers that change the request instead of blocking it, or need page context.
/// Rules carrying them are counted but not applied.
const UNSUPPORTED_OPTIONS: &[&str] = &[
    "removeparam", "redirect", "redirect-rule", "csp", "replace", "cookie", "header",
    "removeheader", "stealth", "jsonprune", "xmlprune", "hls", "permissions", "urltransform",
    "referrerpolicy", "network", "app", "denyallow", "domain", "from", "to",
    "method", "elemhide", "generichide", "specifichide", "content", "jsinject", "urlblock",
    "extension", "genericblock", "client", "ctag", "dnstype", "dnsrewrite", "path", "url",
    "popup",
];

/// Lower comes first when the hosts file has to be trimmed.
fn hosts_priority(c: Category) -> u8 {
    match c {
        // small hand-picked lists first, so the hosts limit never cuts them
        Category::User | Category::Parental | Category::Streaming => 0,
        Category::Ads | Category::Trackers | Category::Annoyances | Category::Other => 1,
        Category::Security => 2,
        Category::Dns => 3,
    }
}

pub fn host_of(input: &str) -> String {
    let s = input.trim();
    let with_scheme = if s.contains("://") { s.to_string() } else { format!("http://{s}") };
    match url::Url::parse(&with_scheme) {
        Ok(u) => u.host_str().unwrap_or("").trim_start_matches('[').trim_end_matches(']').to_lowercase(),
        Err(_) => s.split(['/', ':', '?']).next().unwrap_or("").to_lowercase(),
    }
}

fn full_url(input: &str) -> String {
    let s = input.trim();
    if s.contains("://") { s.to_lowercase() } else { format!("http://{}", s.to_lowercase()) }
}

/// Every parent of a host, from the most specific: a.b.c -> [a.b.c, b.c, c].
fn suffixes(host: &str) -> Vec<&str> {
    let mut out = vec![host];
    let mut rest = host;
    while let Some(i) = rest.find('.') {
        rest = &rest[i + 1..];
        if !rest.is_empty() {
            out.push(rest);
        }
    }
    out
}

fn is_separator(c: u8) -> bool {
    !(c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.' || c == b'%')
}

/// Glob match with `*` (any run) and `^` (separator or end); `end_anchor` forces a full match.
fn glob_at(p: &[u8], s: &[u8], end_anchor: bool) -> bool {
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    loop {
        if pi < p.len() {
            match p[pi] {
                b'*' => {
                    star = Some((pi, si));
                    pi += 1;
                    continue;
                }
                b'^' => {
                    if si == s.len() {
                        pi += 1;
                        continue;
                    }
                    if is_separator(s[si]) {
                        pi += 1;
                        si += 1;
                        continue;
                    }
                }
                c => {
                    if si < s.len() && s[si] == c {
                        pi += 1;
                        si += 1;
                        continue;
                    }
                }
            }
        } else if !end_anchor || si == s.len() {
            return true;
        }
        match star {
            Some((sp, ss)) if ss < s.len() => {
                star = Some((sp, ss + 1));
                pi = sp + 1;
                si = ss + 1;
            }
            _ => return false,
        }
    }
}

fn pattern_matches(pattern: &str, url: &str, host: &str) -> bool {
    let (body, end_anchor) = match pattern.strip_suffix('|') {
        Some(b) if !b.ends_with('|') || b.is_empty() => (b, true),
        _ => (pattern, false),
    };
    let u = url.as_bytes();
    if let Some(rest) = body.strip_prefix("||") {
        let Some(host_start) = url.find(host).filter(|_| !host.is_empty()) else { return false };
        let mut offs = vec![host_start];
        for (i, b) in host.bytes().enumerate() {
            if b == b'.' {
                offs.push(host_start + i + 1);
            }
        }
        return offs.into_iter().any(|o| glob_at(rest.as_bytes(), &u[o..], end_anchor));
    }
    if let Some(rest) = body.strip_prefix('|') {
        return glob_at(rest.as_bytes(), u, end_anchor);
    }
    let p = body.as_bytes();
    if p.is_empty() {
        return false;
    }
    (0..u.len()).any(|i| glob_at(p, &u[i..], end_anchor))
}

/// The rule a `$badfilter` rule switches off: the same text without the badfilter modifier.
fn badfilter_target(line: &str) -> Option<String> {
    let i = line.rfind('$')?;
    let opts: Vec<&str> = line[i + 1..].split(',').filter(|o| o.trim() != "badfilter").collect();
    if opts.len() == line[i + 1..].split(',').count() {
        return None;
    }
    Some(if opts.is_empty() { line[..i].to_string() } else { format!("{}${}", &line[..i], opts.join(",")) })
}

impl Engine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_allowlist<I: IntoIterator<Item = String>>(&mut self, hosts: I) {
        self.allowlist = hosts.into_iter().map(|h| host_of(&h)).filter(|h| !h.is_empty()).collect();
    }

    /// Adds one list. `dns_style` parses it with the DNS engine's rules.
    pub fn add_list(&mut self, text: &str, origin: &Origin, dns_style: bool) {
        for line in text.lines() {
            self.add_rule(line, origin, dns_style);
        }
    }

    pub fn add_rule(&mut self, raw: &str, origin: &Origin, dns_style: bool) {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            return;
        }
        if is_cosmetic(line) {
            self.stats.cosmetic_rules += 1;
            self.stats.total_rules += 1;
            return;
        }
        if line.starts_with('#') {
            return; // hosts-style comment
        }
        self.stats.total_rules += 1;
        let rule = RuleRef { text: Arc::from(line), origin: origin.clone() };

        // hosts line: "<ip> host [host…]". Blocking IPs block the exact host; any other IP rewrites it.
        let mut parts = line.split_whitespace();
        if let (Some(first), Some(_)) = (parts.next(), line.split_whitespace().nth(1)) {
            let is_ip = first.trim_matches(|c| c == '[' || c == ']').parse::<std::net::IpAddr>().is_ok();
            if is_ip {
                let blocking = BLOCKING_IPS.contains(&first);
                for h in parts {
                    if h.starts_with('#') {
                        break;
                    }
                    let h = h.to_lowercase();
                    if !looks_like_host(&h) || h == "localhost" {
                        continue;
                    }
                    if blocking {
                        self.block.insert(h, true, rule.clone());
                        self.stats.domain_rules += 1;
                    } else {
                        self.rewrites.entry(h).or_insert((first.to_string(), rule.clone()));
                        self.stats.rewrite_rules += 1;
                    }
                }
                return;
            }
        }
        if dns_style {
            self.add_dns_rule(line, rule);
        } else {
            self.add_network_rule(line, rule);
        }
    }

    /// DNS rule parser modelled on parse_adblock_rule (AdguardDns.dll 0x180071500).
    fn add_dns_rule(&mut self, line: &str, rule: RuleRef) {
        let (exception, body) = match line.strip_prefix("@@") {
            Some(b) => (true, b),
            None => (false, line),
        };
        if body.len() > 2 && body.starts_with('/') && body.ends_with('/') {
            self.push_regex(&body[1..body.len() - 1], exception, true, rule);
            return;
        }
        let (pattern, options) = match body.rfind('$') {
            Some(i) => (&body[..i], Some(&body[i + 1..])),
            None => (body, None),
        };
        let mut seen: Vec<&str> = vec![];
        let mut rewrite: Option<String> = None;
        let mut wide_ok = false;
        for opt in options.map(|o| o.split(',').collect::<Vec<_>>()).unwrap_or_default() {
            let (name, value) = match opt.split_once('=') {
                Some((n, v)) => (n.trim(), Some(v.trim())),
                None => (opt.trim(), None),
            };
            // unknown or repeated modifiers make the whole rule invalid
            if !DNS_MODIFIERS.contains(&name) || seen.contains(&name) {
                self.stats.skipped_rules += 1;
                return;
            }
            seen.push(name);
            match name {
                "badfilter" => {
                    if let Some(t) = badfilter_target(line) {
                        self.badfilter.insert(t);
                        self.stats.badfilter_rules += 1;
                    }
                    return;
                }
                "dnsrewrite" => {
                    wide_ok = true;
                    rewrite = value.map(|v| v.to_string());
                }
                "dnstype" | "denyallow" => {
                    // need the query type or the asking client; not answerable here
                    self.stats.skipped_rules += 1;
                    return;
                }
                _ => {}
            }
        }
        let important = seen.contains(&"important");

        // anchors (0x18006fb90): "||" = domain and subdomains, "|" = exact start
        let mut p = pattern.to_lowercase();
        let mut sub = false;
        let mut exact_start = false;
        if let Some(r) = p.strip_prefix("||") {
            p = r.to_string();
            sub = true;
        } else if let Some(r) = p.strip_prefix('|') {
            p = r.to_string();
            exact_start = true;
        }
        if let Some(pre) = SCHEME_PREFIXES.iter().find(|s| p.starts_with(**s)) {
            p = p[pre.len()..].to_string();
            sub = true;
        }
        if exact_start && sub {
            sub = false;
        }
        let mut end = false;
        while let Some(r) = p.strip_suffix(END_MARKERS) {
            p = r.to_string();
            end = true;
        }
        if !wide_ok && too_wide(&p) {
            self.stats.skipped_rules += 1;
            return;
        }
        if !valid_dns_domain(&p) && !ip_like(&p) {
            self.stats.skipped_rules += 1;
            return;
        }
        let host = p.trim_end_matches('.').to_string();
        let wildcard = p.contains('*');

        if let Some(v) = rewrite {
            let v = v.trim_start_matches("NOERROR;A;").trim_start_matches("NOERROR;AAAA;").to_string();
            if matches!(v.to_uppercase().as_str(), "NXDOMAIN" | "REFUSED" | "SERVFAIL") {
                // answering with an error code is a block
            } else if v.parse::<std::net::IpAddr>().is_ok() && !wildcard {
                self.rewrites.entry(host).or_insert((v, rule));
                self.stats.rewrite_rules += 1;
                return;
            } else {
                self.stats.skipped_rules += 1;
                return;
            }
        }

        // whole-domain rule: "||d^" (domain + subdomains) or "|d^" (exact domain)
        if !wildcard && end && (sub || exact_start) {
            let table = if exception {
                &mut self.allow
            } else if important {
                &mut self.important
            } else {
                &mut self.block
            };
            table.insert(host, exact_start, rule);
            self.stats.domain_rules += 1;
            return;
        }
        // anything else is matched against the host name
        let pat = format!("{}{}{}", if sub { "||" } else if exact_start { "|" } else { "" }, p, if end { "^" } else { "" });
        self.patterns.push(PatternRule { pattern: pat, exception, important, host_only: true, rule });
        self.stats.pattern_rules += 1;
    }

    fn push_regex(&mut self, re: &str, exception: bool, host_only: bool, rule: RuleRef) {
        if self.regexes.len() >= MAX_REGEX_RULES {
            self.stats.skipped_rules += 1;
            return;
        }
        match regex::RegexBuilder::new(re).size_limit(1 << 16).build() {
            Ok(re) => {
                self.regexes.push((re, exception, host_only, rule));
                self.stats.regex_rules += 1;
            }
            Err(_) => self.stats.skipped_rules += 1,
        }
    }

    fn add_network_rule(&mut self, line: &str, rule: RuleRef) {
        let (exception, body) = match line.strip_prefix("@@") {
            Some(b) => (true, b),
            None => (false, line),
        };
        if body.len() > 2 && body.starts_with('/') && body.ends_with('/') {
            self.push_regex(&body[1..body.len() - 1], exception, false, rule);
            return;
        }
        let (pattern, options) = match body.rfind('$') {
            Some(i) if i + 1 < body.len() && !body[i + 1..].contains('/') => (&body[..i], Some(&body[i + 1..])),
            _ => (body, None),
        };
        let mut important = false;
        if let Some(opts) = options {
            for opt in opts.split(',') {
                let name = opt.trim().trim_start_matches('~').split('=').next().unwrap_or("");
                if name == "badfilter" {
                    if let Some(t) = badfilter_target(line) {
                        self.badfilter.insert(t);
                        self.stats.badfilter_rules += 1;
                    }
                    return;
                }
                if name == "important" {
                    important = true;
                } else if UNSUPPORTED_OPTIONS.contains(&name) {
                    self.stats.skipped_rules += 1;
                    return;
                }
            }
        }
        let pattern = pattern.to_lowercase();
        if pattern.is_empty() || pattern == "*" || pattern == "||" {
            self.stats.skipped_rules += 1;
            return;
        }
        if let Some(rest) = pattern.strip_prefix("||") {
            let host = rest.trim_end_matches('|').trim_end_matches('^').trim_end_matches('.');
            if looks_like_host(host) && (rest.ends_with('^') || rest.ends_with("^|") || rest == host) {
                let table = if exception {
                    &mut self.allow
                } else if important {
                    &mut self.important
                } else {
                    &mut self.block
                };
                table.insert(host.to_string(), false, rule);
                self.stats.domain_rules += 1;
                return;
            }
        }
        self.patterns.push(PatternRule { pattern, exception, important, host_only: false, rule });
        self.stats.pattern_rules += 1;
    }

    /// Applies `$badfilter`: drops every rule whose text a badfilter rule names.
    pub fn finish(&mut self) {
        if self.badfilter.is_empty() {
            return;
        }
        let bad = std::mem::take(&mut self.badfilter);
        let keep = |r: &RuleRef| !bad.contains(r.text.as_ref());
        self.block.retain(keep);
        self.important.retain(keep);
        self.allow.retain(keep);
        self.rewrites.retain(|_, (_, r)| keep(r));
        self.patterns.retain(|p| keep(&p.rule));
        self.regexes.retain(|(_, _, _, r)| keep(r));
        self.badfilter = bad;
    }

    fn verdict(action: Action, host: &str, r: Option<&RuleRef>) -> Verdict {
        Verdict {
            action,
            host: host.to_string(),
            rule: r.map(|r| r.text.to_string()),
            source: r.map(|r| r.origin.source.to_string()),
            category: r.map(|r| r.origin.category),
            answer: (action == Action::Blocked).then(|| "0.0.0.0 / ::".to_string()),
        }
    }

    fn pattern_hit(&self, url: &str, host: &str, exception: bool, important: bool) -> Option<&RuleRef> {
        self.patterns
            .iter()
            .find(|p| p.exception == exception && (!important || p.important) && pattern_matches(&p.pattern, if p.host_only { host } else { url }, host))
            .map(|p| &p.rule)
    }

    fn regex_hit(&self, url: &str, host: &str, exception: bool) -> Option<&RuleRef> {
        self.regexes
            .iter()
            .find(|(re, exc, host_only, _)| *exc == exception && re.is_match(if *host_only { host } else { url }))
            .map(|(_, _, _, r)| r)
    }

    /// Decides one address. Order: allowlist, $important blocks, exceptions, rewrites, blocks.
    pub fn check(&self, input: &str) -> Verdict {
        let host = host_of(input);
        let url = full_url(input);
        if host.is_empty() {
            return Self::verdict(Action::Passed, &host, None);
        }
        if suffixes(&host).iter().any(|h| self.allowlist.contains(*h)) {
            return Verdict {
                action: Action::Allowlisted,
                host: host.clone(),
                rule: Some(format!("@@||{host}^$document")),
                source: Some("Lista de permissões".into()),
                category: None,
                answer: None,
            };
        }
        if let Some(r) = self.important.lookup(&host).or_else(|| self.pattern_hit(&url, &host, false, true)) {
            return Self::verdict(Action::Blocked, &host, Some(r));
        }
        if let Some(r) = self
            .allow
            .lookup(&host)
            .or_else(|| self.pattern_hit(&url, &host, true, false))
            .or_else(|| self.regex_hit(&url, &host, true))
        {
            return Self::verdict(Action::Allowed, &host, Some(r));
        }
        if let Some((ip, r)) = self.rewrites.get(&host) {
            let mut v = Self::verdict(Action::Rewritten, &host, Some(r));
            v.answer = Some(ip.clone());
            return v;
        }
        if let Some(r) = self
            .block
            .lookup(&host)
            .or_else(|| self.pattern_hit(&url, &host, false, false))
            .or_else(|| self.regex_hit(&url, &host, false))
        {
            return Self::verdict(Action::Blocked, &host, Some(r));
        }
        Self::verdict(Action::Passed, &host, None)
    }

    /// Lines for the hosts file: whole-domain blocks (minus exceptions and allowlisted sites)
    /// and rewrites, most important lists first. Each item is (host, Some(ip)) for a rewrite.
    pub fn hosts_entries(&self, limit: usize) -> Vec<(String, Option<String>)> {
        let allowed = |h: &str| {
            let sfx = suffixes(h);
            sfx.iter().any(|s| self.allowlist.contains(*s)) || self.allow.lookup(h).is_some()
        };
        let mut out: Vec<(u8, String, Option<String>)> = vec![];
        for (h, r) in self.important.iter() {
            if !suffixes(h).iter().any(|s| self.allowlist.contains(*s)) {
                out.push((hosts_priority(r.origin.category), h.clone(), None));
            }
        }
        for (h, r) in self.block.iter() {
            if !allowed(h) {
                out.push((hosts_priority(r.origin.category), h.clone(), None));
            }
        }
        for (h, (ip, r)) in &self.rewrites {
            if !allowed(h) {
                out.push((hosts_priority(r.origin.category), h.clone(), Some(ip.clone())));
            }
        }
        out.sort();
        let mut seen = HashSet::new();
        out.retain(|(_, h, _)| seen.insert(h.clone()));
        out.truncate(limit);
        let mut entries: Vec<(String, Option<String>)> = out.into_iter().map(|(_, h, ip)| (h, ip)).collect();
        entries.sort();
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Origin {
        Origin { source: Arc::from("teste"), category: Category::Ads }
    }

    #[test]
    fn streaming_list_survives_hosts_limit() {
        let mut e = Engine::new();
        // a big ordinary list whose names sort before the streaming ones
        for i in 0..500 {
            e.add_rule(&format!("||a{i:03}.example^"), &origin(), true);
        }
        let o = Origin { source: Arc::from(crate::streaming::SOURCE), category: Category::Streaming };
        let rules: Vec<String> = crate::streaming::rules().collect();
        for r in &rules {
            e.add_rule(r, &o, true);
        }
        e.finish();
        let hosts: Vec<String> = e.hosts_entries(rules.len()).into_iter().map(|(h, _)| h).collect();
        assert_eq!(hosts.len(), rules.len());
        for r in &rules {
            let h = r.trim_start_matches("||").trim_end_matches('^');
            assert!(hosts.iter().any(|x| x == h), "{h} was cut by the hosts limit");
        }
        assert_eq!(e.check("https://pubads.g.doubleclick.net/gampad/ads?iu=x").action, Action::Blocked);
        assert_ne!(e.check("https://rr1---sn-abc.googlevideo.com/videoplayback").action, Action::Blocked);
    }

    #[test]
    fn domain_rules() {
        let mut e = Engine::new();
        e.add_list("||ads.example.com^\n@@||ok.ads.example.com^\n0.0.0.0 tracker.net\n", &origin(), false);
        assert_eq!(e.check("https://x.ads.example.com/a.js").action, Action::Blocked);
        assert_eq!(e.check("ok.ads.example.com").action, Action::Allowed);
        assert_eq!(e.check("tracker.net").action, Action::Blocked);
        // hosts lines cover only the exact host
        assert_eq!(e.check("cdn.tracker.net").action, Action::Passed);
        assert_eq!(e.check("example.com").action, Action::Passed);
    }

    #[test]
    fn patterns_and_important() {
        let mut e = Engine::new();
        e.add_list("/banner/*/img^\n||cdn.site.org/ads/\n@@||cdn.site.org^\n||cdn.site.org/track$important", &origin(), false);
        assert_eq!(e.check("http://a.com/banner/x/img?x=1").action, Action::Blocked);
        assert_eq!(e.check("http://cdn.site.org/ads/1.png").action, Action::Allowed);
        assert_eq!(e.check("http://cdn.site.org/track.js").action, Action::Blocked);
    }

    #[test]
    fn dns_rules_follow_original_parser() {
        let mut e = Engine::new();
        e.add_list(
            "||ads.net^\n|exact.org^\nab\n*.*\n||x.com^$third-party\n||y.com^$important,important\n\
             ||rw.com^$dnsrewrite=10.0.0.1\n||gone.com^\n||gone.com^$badfilter\nhttps://scheme.io/\n192.168.1.5 local.lan",
            &origin(),
            true,
        );
        e.finish();
        assert_eq!(e.check("a.ads.net").action, Action::Blocked);
        assert_eq!(e.check("exact.org").action, Action::Blocked);
        assert_eq!(e.check("sub.exact.org").action, Action::Passed);
        assert_eq!(e.check("x.com").action, Action::Passed, "unknown modifier makes the rule invalid");
        assert_eq!(e.check("y.com").action, Action::Passed, "duplicated modifier makes the rule invalid");
        assert_eq!(e.check("rw.com").action, Action::Rewritten);
        assert_eq!(e.check("gone.com").action, Action::Passed, "badfilter disables the rule");
        assert_eq!(e.check("www.scheme.io").action, Action::Blocked, "scheme prefix acts like ||");
        assert_eq!(e.check("local.lan").action, Action::Rewritten);
        assert!(e.stats.skipped_rules >= 4, "too wide and invalid rules are skipped");
    }

    #[test]
    fn allowlist_wins() {
        let mut e = Engine::new();
        e.add_list("||news.com^", &origin(), false);
        e.set_allowlist(vec!["news.com".to_string()]);
        assert_eq!(e.check("www.news.com").action, Action::Allowlisted);
        assert!(e.hosts_entries(10).is_empty());
    }

    /// Loads the lists the app downloaded (run with `cargo test -- --ignored`).
    #[test]
    #[ignore]
    fn real_lists() {
        let dir = std::path::PathBuf::from(std::env::var("APPDATA").unwrap()).join("app.escudo.blocker/filters");
        let t = std::time::Instant::now();
        let mut e = Engine::new();
        for (f, dns) in [("s2.txt", false), ("s9.txt", false), ("s208.txt", false), ("s255.txt", false), ("d1.txt", true)] {
            if let Ok(text) = std::fs::read_to_string(dir.join(f)) {
                e.add_list(&text, &origin(), dns);
            }
        }
        e.finish();
        println!("build {:?} {:?}", t.elapsed(), e.stats);
        for u in ["https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js", "doubleclick.net", "https://www.google.com/", "https://github.com"] {
            let v = e.check(u);
            println!("{u} -> {:?} {:?}", v.action, v.rule);
        }
        println!("hosts entries {}", e.hosts_entries(usize::MAX).len());
    }
}
