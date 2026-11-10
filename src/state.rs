//! Settings, filtering log and the set of active filter lists.
//! Defaults follow the original's factory settings (MECHANICS.md).

use crate::catalog::{self, Kind};
use crate::engine::{Action, Category, Engine, Origin, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub protection_enabled: bool,
    // Ad blocking
    pub ad_blocking: bool,
    pub basic_protection: bool,
    pub block_search_ads: bool,
    /// built-in list against ads on streaming platforms (src/streaming.rs)
    pub block_streaming_ads: bool,
    /// AI review of unknown domains (src/ai.rs); off by default: names are sent to Anthropic
    pub ai_enabled: bool,
    /// block strong AI verdicts without asking
    pub ai_auto_block: bool,
    /// "anthropic" or "openai_compat" (OpenAI, OpenRouter, LM Studio, Ollama…)
    pub ai_provider: String,
    /// model id, chosen by the user
    pub ai_model: String,
    /// base address of an OpenAI-compatible server (…/v1)
    pub ai_endpoint: String,
    pub language_specific: bool,
    pub language_auto: bool,
    pub user_rules_enabled: bool,
    // Tracking protection
    pub tracking_protection: bool,
    pub block_trackers: bool,
    pub strip_url: bool,
    pub hide_search_queries: bool,
    pub do_not_track: bool,
    pub block_webrtc: bool,
    pub block_push_api: bool,
    pub block_location_api: bool,
    // Annoyances
    pub annoyance_blocking: bool,
    pub block_cookie_notices: bool,
    pub block_popups: bool,
    pub block_mobile_app_banners: bool,
    pub block_widgets: bool,
    pub block_other_annoyances: bool,
    // Browsing security
    pub browsing_security: bool,
    pub security_notifications: bool,
    pub security_sound: bool,
    // DNS
    pub dns_protection: bool,
    pub dns_filters: bool,
    pub dns_server: String,
    /// Address answered for blocked names; empty = 0.0.0.0 (WindowsAdvancedSettings.DnsCustomIpv4Address).
    pub custom_block_ipv4: String,
    /// Same for IPv6; empty = :: (DnsCustomIpv6Address).
    pub custom_block_ipv6: String,
    // Parental control
    pub parental_control: bool,
    pub safe_search: bool,
    pub block_adult: bool,
    // App
    pub theme: String,
    pub statistics_enabled: bool,
    pub auto_update: bool,
    pub filters_update_hours: u32,
    pub apply_to_system: bool,
    pub sidebar_expanded: bool,
    pub banner_dismissed: bool,
    /// Extra lists switched on in the Filters screen (catalog keys such as "s101").
    pub extra_filters: Vec<String>,
    pub user_rules: Vec<String>,
    pub dns_user_rules: Vec<String>,
    pub allowlist: Vec<String>,
    pub parental_blocklist: Vec<String>,
    pub apps: Vec<AppEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppEntry {
    pub name: String,
    pub exe: String,
    pub filtered: bool,
}

impl Default for Settings {
    fn default() -> Self {
        let app = |n: &str, e: &str| AppEntry { name: n.into(), exe: e.into(), filtered: true };
        Settings {
            protection_enabled: true,
            ad_blocking: true,
            basic_protection: true,
            block_search_ads: true,
            block_streaming_ads: true,
            ai_enabled: false,
            ai_auto_block: true,
            ai_provider: "anthropic".into(),
            ai_model: crate::ai::DEFAULT_ANTHROPIC_MODEL.into(),
            ai_endpoint: crate::ai::DEFAULT_COMPAT_ENDPOINT.into(),
            language_specific: true,
            language_auto: true,
            user_rules_enabled: true,
            tracking_protection: false,
            block_trackers: true,
            strip_url: false,
            hide_search_queries: false,
            do_not_track: true,
            block_webrtc: false,
            block_push_api: false,
            block_location_api: false,
            annoyance_blocking: false,
            block_cookie_notices: true,
            block_popups: true,
            block_mobile_app_banners: true,
            block_widgets: true,
            block_other_annoyances: true,
            browsing_security: true,
            security_notifications: true,
            security_sound: true,
            dns_protection: true,
            dns_filters: true,
            dns_server: "system".into(),
            custom_block_ipv4: String::new(),
            custom_block_ipv6: String::new(),
            parental_control: false,
            safe_search: true,
            block_adult: true,
            theme: "dark".into(),
            statistics_enabled: true,
            auto_update: true,
            filters_update_hours: 0,
            apply_to_system: false,
            sidebar_expanded: false,
            banner_dismissed: false,
            extra_filters: vec![],
            user_rules: vec![],
            dns_user_rules: vec![],
            allowlist: vec![],
            parental_blocklist: vec![],
            apps: vec![
                app("Google Chrome", "chrome.exe"),
                app("Microsoft Edge", "msedge.exe"),
                app("Mozilla Firefox", "firefox.exe"),
                app("Opera", "opera.exe"),
                app("Brave", "brave.exe"),
                app("Discord", "Discord.exe"),
                app("Spotify", "Spotify.exe"),
            ],
        }
    }
}

impl Settings {
    /// Catalog keys of every list that is active with the current switches.
    pub fn active_filters(&self) -> Vec<&'static str> {
        let mut keys: Vec<&'static str> = vec![];
        if !self.protection_enabled {
            return keys;
        }
        let mut add = |k: &'static str, on: bool| {
            if on && !keys.contains(&k) {
                keys.push(k);
            }
        };
        if self.ad_blocking {
            add("s2", self.basic_protection);
            // filter 10 *unblocks* search ads, so it is on when blocking them is off
            add("s10", !self.block_search_ads);
            add("s9", self.language_specific);
        }
        if self.tracking_protection {
            add("s3", self.block_trackers);
            add("s17", self.strip_url);
        }
        if self.annoyance_blocking {
            add("s18", self.block_cookie_notices);
            add("s19", self.block_popups);
            add("s20", self.block_mobile_app_banners);
            add("s21", self.block_other_annoyances);
            add("s22", self.block_widgets);
        }
        if self.browsing_security {
            add("s208", true);
            add("s255", true);
        }
        if self.dns_protection && self.dns_filters {
            add("d1", true);
        }
        for k in &self.extra_filters {
            if let Some(f) = catalog::find(k) {
                let section_on = match f.category {
                    Category::Ads | Category::Streaming | Category::Other => self.ad_blocking,
                    Category::Ai => self.ai_enabled,
                    Category::Trackers => self.tracking_protection,
                    Category::Annoyances => self.annoyance_blocking,
                    Category::Security => self.browsing_security || (f.kind == Kind::Dns && self.dns_protection),
                    Category::Dns => self.dns_protection && self.dns_filters,
                    _ => true,
                };
                add(f.key, section_on);
            }
        }
        keys
    }

    /// Turns a list on or off from the Filters screen; core lists flip their switch.
    pub fn set_filter(&mut self, key: &str, on: bool) {
        match key {
            "s2" => self.basic_protection = on,
            "s10" => self.block_search_ads = !on,
            "s9" => self.language_specific = on,
            "s3" => self.block_trackers = on,
            "s17" => self.strip_url = on,
            "s18" => self.block_cookie_notices = on,
            "s19" => self.block_popups = on,
            "s20" => self.block_mobile_app_banners = on,
            "s21" => self.block_other_annoyances = on,
            "s22" => self.block_widgets = on,
            "d1" => self.dns_filters = on,
            _ => {
                self.extra_filters.retain(|k| k != key);
                if on {
                    self.extra_filters.push(key.to_string());
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub ts: i64,
    pub url: String,
    pub host: String,
    pub action: String,
    pub rule: Option<String>,
    pub source: Option<String>,
    pub category: Option<String>,
    pub app: String,
}

impl LogEntry {
    pub fn from_verdict(url: &str, v: &Verdict, app: &str) -> Self {
        let action = match v.action {
            Action::Blocked => "blocked",
            Action::Allowed => "allowed",
            Action::Allowlisted => "allowlisted",
            Action::Rewritten => "rewritten",
            Action::Passed => "passed",
        };
        LogEntry {
            ts: chrono::Utc::now().timestamp(),
            url: url.to_string(),
            host: v.host.clone(),
            action: action.into(),
            rule: v.rule.clone(),
            source: v.source.clone(),
            category: v.category.map(|c| serde_json::to_value(c).ok().and_then(|x| x.as_str().map(String::from)).unwrap_or_default()),
            app: app.to_string(),
        }
    }
}

pub const LOG_LIMIT: usize = 20_000;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FilterMeta {
    pub updated: Option<i64>,
    pub rules: usize,
    pub error: Option<String>,
}

pub struct Store {
    pub dir: PathBuf,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(dir.join("filters"));
        Store { dir }
    }
    fn read_json<T: for<'de> Deserialize<'de> + Default>(&self, name: &str) -> T {
        std::fs::read_to_string(self.dir.join(name))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    fn write_json<T: Serialize>(&self, name: &str, v: &T) {
        if let Ok(s) = serde_json::to_string_pretty(v) {
            let _ = std::fs::write(self.dir.join(name), s);
        }
    }
    pub fn load_settings(&self) -> Settings {
        self.read_json("settings.json")
    }
    pub fn save_settings(&self, s: &Settings) {
        self.write_json("settings.json", s)
    }
    pub fn load_log(&self) -> Vec<LogEntry> {
        self.read_json("log.json")
    }
    pub fn save_log(&self, l: &[LogEntry]) {
        self.write_json("log.json", &l)
    }
    pub fn load_meta(&self) -> BTreeMap<String, FilterMeta> {
        self.read_json("filters.json")
    }
    pub fn save_meta(&self, m: &BTreeMap<String, FilterMeta>) {
        self.write_json("filters.json", m)
    }
    pub fn load_ai(&self) -> crate::ai::AiStore {
        self.read_json("ai.json")
    }
    pub fn save_ai(&self, a: &crate::ai::AiStore) {
        self.write_json("ai.json", a)
    }
    pub fn filter_path(&self, key: &str) -> PathBuf {
        self.dir.join("filters").join(format!("{key}.txt"))
    }
}

/// Downloads one list and stores it next to the settings.
pub fn download_filter(store: &Store, key: &str) -> Result<usize, String> {
    let f = catalog::find(key).ok_or("lista desconhecida")?;
    let body = ureq::get(&f.url())
        .timeout(std::time::Duration::from_secs(60))
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    std::fs::write(store.filter_path(key), &body).map_err(|e| e.to_string())?;
    Ok(body.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('!') && !l.starts_with('#')).count())
}

/// Builds the engine from the active lists that are on disk plus the user's own rules.
pub fn build_engine(store: &Store, s: &Settings) -> Engine {
    let mut e = Engine::new();
    for key in s.active_filters() {
        let Some(f) = catalog::find(key) else { continue };
        if let Ok(text) = std::fs::read_to_string(store.filter_path(key)) {
            let origin = Origin { source: Arc::from(f.name), category: f.category };
            e.add_list(&text, &origin, f.kind == Kind::Dns);
        }
    }
    if s.protection_enabled {
        if s.ad_blocking && s.block_streaming_ads {
            let o = Origin { source: Arc::from(crate::streaming::SOURCE), category: Category::Streaming };
            for r in crate::streaming::rules() {
                e.add_rule(&r, &o, true);
            }
        }
        if s.ai_enabled {
            let o = Origin { source: Arc::from(crate::ai::SOURCE), category: Category::Ai };
            for h in store.load_ai().blocked() {
                e.add_rule(&format!("||{h}^"), &o, true);
            }
        }
        if s.ad_blocking && s.user_rules_enabled {
            let o = Origin { source: Arc::from("Regras de usuário"), category: Category::User };
            for r in &s.user_rules {
                e.add_rule(r, &o, false);
            }
        }
        if s.dns_protection {
            let o = Origin { source: Arc::from("Regras de usuário DNS"), category: Category::Dns };
            for r in &s.dns_user_rules {
                e.add_rule(r, &o, true);
            }
        }
        if s.parental_control {
            let o = Origin { source: Arc::from("Controle parental"), category: Category::Parental };
            for d in &s.parental_blocklist {
                e.add_rule(&format!("||{}^", crate::engine::host_of(d)), &o, true);
            }
        }
    }
    e.set_allowlist(s.allowlist.clone());
    e.finish();
    e
}

pub fn data_dir_fallback() -> PathBuf {
    let base = std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| Path::new(".").to_path_buf());
    base.join("Escudo")
}
