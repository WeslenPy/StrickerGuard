#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ai;
mod catalog;
mod engine;
mod state;
mod streaming;
mod system;
mod tray;

use engine::{Engine, EngineStats};
use serde::Serialize;
use serde_json::Value;
use state::{FilterMeta, LogEntry, Settings, Store};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tauri::{AppHandle, Emitter, Manager, State};

struct Core {
    store: Store,
    settings: Mutex<Settings>,
    engine: RwLock<Engine>,
    log: Mutex<Vec<LogEntry>>,
    meta: Mutex<BTreeMap<String, FilterMeta>>,
    rebuild_gen: AtomicU64,
    busy: AtomicBool,
    updating: AtomicBool,
    system_msg: Mutex<Option<String>>,
    applied_dns: Mutex<Option<String>>,
    seen_dns: Mutex<HashMap<String, i64>>,
    pause_gen: AtomicU64,
    /// AI review: verdicts, queue, last run (ai.json)
    ai: Mutex<ai::AiStore>,
    /// a batch is being analysed right now
    ai_running: AtomicBool,
}

type Shared = Arc<Core>;

#[derive(Serialize)]
struct FilterView {
    key: &'static str,
    id: u32,
    kind: catalog::Kind,
    group: &'static str,
    name: &'static str,
    desc: &'static str,
    url: String,
    active: bool,
    downloaded: bool,
    updated: Option<i64>,
    rules: usize,
    error: Option<String>,
}

#[derive(Serialize)]
struct View {
    settings: Settings,
    filters: Vec<FilterView>,
    dns_servers: &'static [catalog::DnsServer],
    engine: EngineStats,
    admin: bool,
    hosts_count: usize,
    run_on_startup: bool,
    busy: bool,
    updating: bool,
    system_msg: Option<String>,
    version: &'static str,
    data_dir: String,
}

fn view(core: &Core) -> View {
    let settings = core.settings.lock().unwrap().clone();
    let active = settings.active_filters();
    let meta = core.meta.lock().unwrap().clone();
    let filters = catalog::CATALOG
        .iter()
        .map(|f| {
            let m = meta.get(f.key).cloned().unwrap_or_default();
            FilterView {
                key: f.key,
                id: f.id,
                kind: f.kind,
                group: f.group,
                name: f.name,
                desc: f.desc,
                url: f.url(),
                active: active.contains(&f.key),
                downloaded: core.store.filter_path(f.key).exists(),
                updated: m.updated,
                rules: m.rules,
                error: m.error,
            }
        })
        .collect();
    View {
        settings,
        filters,
        dns_servers: catalog::DNS_SERVERS,
        engine: core.engine.read().unwrap().stats.clone(),
        admin: system::is_admin(),
        hosts_count: system::hosts_count(),
        run_on_startup: system::run_on_startup(),
        busy: core.busy.load(Ordering::SeqCst),
        updating: core.updating.load(Ordering::SeqCst),
        system_msg: core.system_msg.lock().unwrap().clone(),
        version: env!("CARGO_PKG_VERSION"),
        data_dir: core.store.dir.display().to_string(),
    }
}

/// Rebuilds the rule engine in the background, then applies it to Windows if asked.
fn rebuild(app: &AppHandle, core: &Shared) {
    let gen = core.rebuild_gen.fetch_add(1, Ordering::SeqCst) + 1;
    core.busy.store(true, Ordering::SeqCst);
    let core = core.clone();
    let app = app.clone();
    std::thread::spawn(move || {
        let settings = core.settings.lock().unwrap().clone();
        let eng = state::build_engine(&core.store, &settings);
        if core.rebuild_gen.load(Ordering::SeqCst) != gen {
            return; // a newer rebuild is running
        }
        *core.engine.write().unwrap() = eng;
        apply_system(&core, &settings);
        core.busy.store(false, Ordering::SeqCst);
        let _ = app.emit("state-changed", ());
    });
}

fn apply_system(core: &Core, s: &Settings) {
    let admin = system::is_admin();
    let mut msg = None;
    if s.apply_to_system {
        if !admin {
            msg = Some("Para aplicar o bloqueio no Windows, abra o app como administrador.".to_string());
        } else {
            let entries = if s.protection_enabled { core.engine.read().unwrap().hosts_entries(system::HOSTS_LIMIT) } else { vec![] };
            match system::write_hosts(&entries, &s.custom_block_ipv4, &s.custom_block_ipv6) {
                Ok(n) if n > 0 => msg = Some(format!("{n} domínios bloqueados no Windows.")),
                Ok(_) => {}
                Err(e) => msg = Some(e),
            }
            let want = if s.protection_enabled && s.dns_protection { s.dns_server.clone() } else { "system".into() };
            let mut applied = core.applied_dns.lock().unwrap();
            if applied.as_deref() != Some(want.as_str()) {
                match system::set_dns(catalog::dns_server(&want).addresses) {
                    Ok(()) => *applied = Some(want),
                    Err(e) => msg = Some(format!("DNS: {e}")),
                }
            }
        }
    } else if admin && system::hosts_count() > 0 {
        // switched off: take the app's lines back out of the hosts file
        if let Err(e) = system::write_hosts(&[], "", "") {
            msg = Some(e);
        }
        let mut applied = core.applied_dns.lock().unwrap();
        if applied.as_deref().is_some_and(|d| d != "system") && system::set_dns(&[]).is_ok() {
            *applied = Some("system".into());
        }
    }
    *core.system_msg.lock().unwrap() = msg;
}

fn merge(dst: &mut Value, patch: &Value) {
    if let (Some(d), Some(p)) = (dst.as_object_mut(), patch.as_object()) {
        for (k, v) in p {
            d.insert(k.clone(), v.clone());
        }
    }
}

#[tauri::command]
fn get_state(core: State<Shared>) -> View {
    view(&core)
}

#[tauri::command]
fn update_settings(app: AppHandle, core: State<Shared>, patch: Value) -> Result<View, String> {
    let needs_download;
    if patch.get("protection_enabled").is_some() {
        core.pause_gen.fetch_add(1, Ordering::SeqCst); // a manual switch cancels a running pause
    }
    {
        let mut s = core.settings.lock().unwrap();
        let mut v = serde_json::to_value(&*s).map_err(|e| e.to_string())?;
        merge(&mut v, &patch);
        *s = serde_json::from_value(v).map_err(|e| e.to_string())?;
        core.store.save_settings(&s);
        tray::sync(&app, s.protection_enabled);
        needs_download = s.active_filters().into_iter().any(|k| !core.store.filter_path(k).exists());
    }
    rebuild(&app, &core);
    if needs_download {
        start_update(&app, &core, false);
    }
    Ok(view(&core))
}

#[tauri::command]
fn set_filter(app: AppHandle, core: State<Shared>, key: String, on: bool) -> View {
    {
        let mut s = core.settings.lock().unwrap();
        s.set_filter(&key, on);
        core.store.save_settings(&s);
    }
    rebuild(&app, &core);
    if on && !core.store.filter_path(&key).exists() {
        start_update(&app, &core, false);
    }
    view(&core)
}

/// Downloads the active lists (all of them, or only the missing ones).
fn start_update(app: &AppHandle, core: &Shared, all: bool) {
    if core.updating.swap(true, Ordering::SeqCst) {
        return;
    }
    let core = core.clone();
    let app = app.clone();
    std::thread::spawn(move || {
        let keys: Vec<&str> = core.settings.lock().unwrap().active_filters();
        for key in keys {
            if !all && core.store.filter_path(key).exists() {
                continue;
            }
            let _ = app.emit("state-changed", ());
            let res = state::download_filter(&core.store, key);
            let mut meta = core.meta.lock().unwrap();
            let m = meta.entry(key.to_string()).or_default();
            match res {
                Ok(n) => {
                    m.updated = Some(chrono::Utc::now().timestamp());
                    m.rules = n;
                    m.error = None;
                }
                Err(e) => m.error = Some(e),
            }
            core.store.save_meta(&meta);
        }
        core.updating.store(false, Ordering::SeqCst);
        rebuild(&app, &core);
    });
}

#[tauri::command]
fn update_filters(app: AppHandle, core: State<Shared>) -> View {
    start_update(&app, &core, true);
    view(&core)
}

fn record(core: &Core, entry: LogEntry) {
    if !core.settings.lock().unwrap().statistics_enabled {
        return;
    }
    let mut log = core.log.lock().unwrap();
    log.push(entry);
    if log.len() > state::LOG_LIMIT {
        let cut = log.len() - state::LOG_LIMIT;
        log.drain(..cut);
    }
}

#[tauri::command]
fn check_url(core: State<Shared>, url: String) -> engine::Verdict {
    let v = core.engine.read().unwrap().check(&url);
    record(&core, LogEntry::from_verdict(&url, &v, "Verificação manual"));
    core.store.save_log(&core.log.lock().unwrap());
    v
}

#[tauri::command]
fn get_log(core: State<Shared>, limit: usize, query: String, only: String) -> Vec<LogEntry> {
    let q = query.to_lowercase();
    core.log
        .lock()
        .unwrap()
        .iter()
        .rev()
        .filter(|e| q.is_empty() || e.url.to_lowercase().contains(&q) || e.host.contains(&q))
        .filter(|e| only.is_empty() || e.action == only)
        .take(limit)
        .cloned()
        .collect()
}

#[derive(Serialize)]
struct Stats {
    total: usize,
    ads: usize,
    trackers: usize,
    blocked: usize,
    buckets: Vec<(i64, usize, usize)>,
    top_blocked: Vec<(String, usize)>,
    top_domains: Vec<(String, usize)>,
    apps: Vec<(String, usize, usize)>,
}

#[tauri::command]
fn get_stats(core: State<Shared>, period: String) -> Stats {
    let now = chrono::Utc::now().timestamp();
    let (span, bucket) = match period.as_str() {
        "24h" => (86_400, 3_600),
        "7d" => (7 * 86_400, 86_400),
        "14d" => (14 * 86_400, 86_400),
        _ => (i64::MAX / 4, 86_400),
    };
    let log = core.log.lock().unwrap();
    let items: Vec<&LogEntry> = log.iter().filter(|e| now - e.ts <= span).collect();
    let is_tracker = |e: &&LogEntry| e.category.as_deref() == Some("trackers");
    let blocked: Vec<&&LogEntry> = items.iter().filter(|e| e.action == "blocked").collect();
    let trackers = blocked.iter().filter(|e| is_tracker(e)).count();
    let n_buckets = if span > 30 * 86_400 { 30 } else { (span / bucket) as usize };
    let start = now - (n_buckets as i64) * bucket;
    let mut buckets: Vec<(i64, usize, usize)> = (0..n_buckets).map(|i| (start + i as i64 * bucket, 0, 0)).collect();
    for e in &items {
        if e.ts >= start {
            let i = (((e.ts - start) / bucket) as usize).min(n_buckets.saturating_sub(1));
            if let Some(b) = buckets.get_mut(i) {
                b.1 += 1;
                if e.action == "blocked" {
                    b.2 += 1;
                }
            }
        }
    }
    let top = |it: &mut dyn Iterator<Item = &String>| {
        let mut m: HashMap<String, usize> = HashMap::new();
        for h in it {
            *m.entry(h.clone()).or_default() += 1;
        }
        let mut v: Vec<(String, usize)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(8);
        v
    };
    let mut apps: HashMap<String, (usize, usize)> = HashMap::new();
    for e in &items {
        let a = apps.entry(e.app.clone()).or_default();
        a.0 += 1;
        if e.action == "blocked" {
            a.1 += 1;
        }
    }
    let mut apps: Vec<(String, usize, usize)> = apps.into_iter().map(|(k, (t, b))| (k, t, b)).collect();
    apps.sort_by(|a, b| b.1.cmp(&a.1));
    Stats {
        total: items.len(),
        ads: blocked.len() - trackers,
        trackers,
        blocked: blocked.len(),
        buckets,
        top_blocked: top(&mut blocked.iter().map(|e| &e.host)),
        top_domains: top(&mut items.iter().map(|e| &e.host)),
        apps,
    }
}

#[tauri::command]
fn clear_stats(core: State<Shared>) {
    core.log.lock().unwrap().clear();
    core.seen_dns.lock().unwrap().clear();
    core.store.save_log(&[]);
}

// The commands below run Windows tools (reg, PowerShell); they are async and do the work
// on a worker thread so the window keeps drawing (and its loading spinners keep turning).

#[tauri::command]
async fn set_startup(core: State<'_, Shared>, on: bool) -> Result<View, String> {
    tauri::async_runtime::spawn_blocking(move || system::set_run_on_startup(on)).await.map_err(|e| e.to_string())??;
    Ok(view(&core))
}

#[tauri::command]
async fn relaunch_admin(app: AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(system::relaunch_as_admin).await.map_err(|e| e.to_string())??;
    app.exit(0);
    Ok(())
}

/// Measures each address of a DNS server; None means no answer within the timeout.
#[tauri::command]
async fn test_dns(id: String) -> Vec<(String, Option<u64>)> {
    let addrs = catalog::dns_server(&id).addresses;
    tauri::async_runtime::spawn_blocking(move || addrs.iter().map(|a| (a.to_string(), system::probe_dns(a))).collect())
        .await
        .unwrap_or_default()
}

#[tauri::command]
fn open_link(url: String) {
    if url.starts_with("https://") || url.starts_with("http://") {
        system::open_url(&url);
    }
}

/// Every 30 s, reads the names Windows has just resolved and runs them through the rules,
/// so the statistics show real traffic from this computer.
fn dns_monitor(app: AppHandle, core: Shared) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
        let (on, stats, ai_on) = {
            let s = core.settings.lock().unwrap();
            (s.protection_enabled, s.statistics_enabled, s.ai_enabled)
        };
        // wait while lists are downloading or the rules are being rebuilt
        let ready = !core.busy.load(Ordering::SeqCst) && !core.updating.load(Ordering::SeqCst);
        if on && (stats || ai_on) && ready {
            let mut cmd = std::process::Command::new("powershell");
            // entries answered with 0.0.0.0 come from the hosts file, not from real lookups
            cmd.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-DnsClientCache | Where-Object { $_.Data -ne '0.0.0.0' -and $_.Data -ne '::' } | ForEach-Object { $_.Entry }",
            ]);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(0x0800_0000);
            }
            if let Ok(out) = cmd.output() {
                let now = chrono::Utc::now().timestamp();
                let text = String::from_utf8_lossy(&out.stdout).to_string();
                let mut fresh = vec![];
                {
                    let mut seen = core.seen_dns.lock().unwrap();
                    for h in text.lines().map(|l| l.trim().to_lowercase()) {
                        if h.is_empty() || !h.contains('.') || h.ends_with(".arpa") {
                            continue;
                        }
                        let last = seen.get(&h).copied().unwrap_or(0);
                        if now - last > 600 {
                            seen.insert(h.clone(), now);
                            fresh.push(h);
                        }
                    }
                }
                if ai_on && !fresh.is_empty() {
                    // names no list has an opinion on go to the AI queue
                    let eng = core.engine.read().unwrap();
                    let unknown: Vec<&String> =
                        fresh.iter().filter(|h| ai::candidate(h) && eng.check(h).action == engine::Action::Passed).collect();
                    drop(eng);
                    if !unknown.is_empty() {
                        let mut a = core.ai.lock().unwrap();
                        let added = unknown.into_iter().filter(|h| a.enqueue(h)).count();
                        if added > 0 {
                            core.store.save_ai(&a);
                            let _ = app.emit("ai-changed", ());
                        }
                    }
                }
                if stats && !fresh.is_empty() {
                    let eng = core.engine.read().unwrap();
                    let entries: Vec<LogEntry> = fresh
                        .iter()
                        .map(|h| LogEntry::from_verdict(h, &eng.check(h), "Windows (DNS)"))
                        .collect();
                    drop(eng);
                    let any_blocked = entries.iter().any(|e| e.action == "blocked");
                    for e in entries {
                        record(&core, e);
                    }
                    core.store.save_log(&core.log.lock().unwrap());
                    let _ = app.emit("log-changed", any_blocked);
                }
            }
        }
    });
}

fn set_protection(app: &AppHandle, core: &Shared, on: bool) {
    {
        let mut s = core.settings.lock().unwrap();
        s.protection_enabled = on;
        core.store.save_settings(&s);
    }
    tray::sync(app, on);
    rebuild(app, core);
    let _ = app.emit("state-changed", ());
}

/// Menu actions from the tray icon.
fn on_tray(app: &AppHandle, action: tray::TrayAction) {
    let core = app.state::<Shared>().inner().clone();
    match action {
        tray::TrayAction::Toggle => {
            core.pause_gen.fetch_add(1, Ordering::SeqCst); // a manual switch cancels a running pause
            let on = !core.settings.lock().unwrap().protection_enabled;
            set_protection(app, &core, on);
        }
        tray::TrayAction::Pause => {
            if !core.settings.lock().unwrap().protection_enabled {
                return;
            }
            let gen = core.pause_gen.fetch_add(1, Ordering::SeqCst) + 1;
            set_protection(app, &core, false);
            let (app, core) = (app.clone(), core.clone());
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(tray::PAUSE_SECONDS));
                if core.pause_gen.load(Ordering::SeqCst) == gen {
                    set_protection(&app, &core, true);
                }
            });
        }
        tray::TrayAction::UpdateFilters => start_update(app, &core, true),
        tray::TrayAction::ResetStats => {
            core.log.lock().unwrap().clear();
            core.seen_dns.lock().unwrap().clear();
            core.store.save_log(&[]);
            let _ = app.emit("log-changed", false);
            let _ = app.emit("toast", "As estatísticas foram redefinidas");
        }
        tray::TrayAction::ResetSettings => {
            let defaults = Settings::default();
            let on = defaults.protection_enabled;
            {
                let mut s = core.settings.lock().unwrap();
                *s = defaults;
                core.store.save_settings(&s);
            }
            tray::sync(app, on);
            rebuild(app, &core);
            let _ = app.emit("state-changed", ());
            let _ = app.emit("toast", "Configurações redefinidas para o padrão");
        }
        tray::TrayAction::Exit => {
            // like the original, ask whether filtering should go on after closing
            if system::hosts_count() > 0 {
                tray::show_main(app);
                let _ = app.emit("confirm-exit", ());
            } else {
                app.exit(0);
            }
        }
    }
}

/// Leaves the app; `keep_filtering` leaves the Windows hosts entries in place.
#[tauri::command]
async fn quit_app(app: AppHandle, keep_filtering: bool) {
    if !keep_filtering && system::is_admin() {
        let _ = tauri::async_runtime::spawn_blocking(|| {
            let _ = system::write_hosts(&[], "", "");
            let _ = system::set_dns(&[]);
        })
        .await;
    }
    app.exit(0);
}

// ---------- AI review of unknown domains (src/ai.rs) ----------

fn ai_provider(s: &Settings) -> ai::Provider {
    ai::Provider {
        kind: s.ai_provider.clone(),
        model: s.ai_model.clone(),
        endpoint: s.ai_endpoint.clone(),
        key: system::api_key_load(&s.ai_provider),
    }
}

#[derive(Serialize)]
struct AiItem {
    domain: String,
    verdict: String,
    confidence: f64,
    reason: String,
    at: i64,
    status: ai::Status,
    by_user: bool,
}

#[derive(Serialize)]
struct AiView {
    has_key: bool,
    /// what stops the analysis from running, if anything
    problem: Option<String>,
    /// false for a server on this PC (nothing leaves the computer)
    remote: bool,
    running: bool,
    queue: usize,
    analyzed: u64,
    last_run: Option<i64>,
    last_error: Option<String>,
    blocked: usize,
    review: usize,
    /// blocked / review / allowed names, newest first (benign ones are only counted)
    items: Vec<AiItem>,
}

fn ai_view(core: &Core) -> AiView {
    let settings = core.settings.lock().unwrap().clone();
    let p = ai_provider(&settings);
    let a = core.ai.lock().unwrap();
    let mut items: Vec<AiItem> = a
        .entries
        .iter()
        .filter(|(_, e)| e.status != ai::Status::Benign)
        .map(|(d, e)| AiItem {
            domain: d.clone(),
            verdict: e.verdict.clone(),
            confidence: e.confidence,
            reason: e.reason.clone(),
            at: e.at,
            status: e.status,
            by_user: e.by_user,
        })
        .collect();
    items.sort_by(|x, y| y.at.cmp(&x.at));
    items.truncate(500);
    AiView {
        has_key: p.key.is_some(),
        problem: p.problem().map(String::from),
        remote: p.is_remote(),
        running: core.ai_running.load(Ordering::SeqCst),
        queue: a.queue.len(),
        analyzed: a.analyzed,
        last_run: a.last_run,
        last_error: a.last_error.clone(),
        blocked: a.entries.values().filter(|e| e.status == ai::Status::Blocked).count(),
        review: a.entries.values().filter(|e| e.status == ai::Status::Review).count(),
        items,
    }
}

/// Sends one batch from the queue. Returns an error message when it could not.
fn ai_run_batch(app: &AppHandle, core: &Shared) -> Result<(), String> {
    if core.ai_running.swap(true, Ordering::SeqCst) {
        return Ok(()); // one at a time
    }
    let _ = app.emit("ai-changed", ());
    let settings = core.settings.lock().unwrap().clone();
    let provider = ai_provider(&settings);
    let batch: Vec<String> = {
        let mut a = core.ai.lock().unwrap();
        let n = a.queue.len().min(ai::BATCH);
        a.queue.drain(..n).collect()
    };
    let result = if batch.is_empty() { Ok(vec![]) } else { ai::classify(&provider, &batch) };
    let now = chrono::Utc::now().timestamp();
    let newly_blocked = {
        let mut a = core.ai.lock().unwrap();
        a.last_run = Some(now);
        let out = match result {
            Ok(results) => {
                a.analyzed += results.len() as u64;
                a.last_error = None;
                // names the model skipped go back to the end of the queue once
                let answered: std::collections::HashSet<String> = results.iter().map(|v| v.domain.clone()).collect();
                let blocked = a.apply(results, settings.ai_auto_block, now);
                for d in batch.iter().filter(|d| !answered.contains(*d)) {
                    a.entries.insert(
                        d.clone(),
                        ai::Entry { verdict: "benign".into(), confidence: 0.0, reason: "Sem resposta da IA".into(), at: now, status: ai::Status::Benign, by_user: false },
                    );
                }
                Ok(blocked)
            }
            Err(e) => {
                // put the batch back in front, try again on the next round
                let rest = std::mem::take(&mut a.queue);
                a.queue = batch.into_iter().chain(rest).collect();
                a.last_error = Some(e.clone());
                Err(e)
            }
        };
        core.store.save_ai(&a);
        out
    };
    core.ai_running.store(false, Ordering::SeqCst);
    if let Ok(n) = newly_blocked {
        if n > 0 {
            rebuild(app, core);
            let _ = app.emit("toast", format!("Análise por IA: {n} domínio(s) bloqueado(s)"));
        }
    }
    let _ = app.emit("ai-changed", ());
    newly_blocked.map(|_| ())
}

/// Checks the queue every 20 s and sends a batch when it is full or has waited long enough.
fn ai_worker(app: AppHandle, core: Shared) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(20));
        let (on, ready) = {
            let s = core.settings.lock().unwrap();
            (s.ai_enabled && s.protection_enabled, ai_provider(&s).problem().is_none())
        };
        let due = core.ai.lock().unwrap().due(chrono::Utc::now().timestamp());
        if on && ready && due {
            let _ = ai_run_batch(&app, &core);
        }
    });
}

#[tauri::command]
fn ai_state(core: State<Shared>) -> AiView {
    ai_view(&core)
}

#[tauri::command]
async fn ai_set_key(core: State<'_, Shared>, key: String) -> Result<AiView, String> {
    let key = key.trim().to_string();
    if key.is_empty() || key.len() > 512 || key.chars().any(char::is_whitespace) {
        return Err("Chave inválida.".into());
    }
    let provider = core.settings.lock().unwrap().ai_provider.clone();
    tauri::async_runtime::spawn_blocking(move || system::api_key_save(&provider, &key)).await.map_err(|e| e.to_string())??;
    Ok(ai_view(&core))
}

#[tauri::command]
fn ai_clear_key(core: State<Shared>) -> AiView {
    let provider = core.settings.lock().unwrap().ai_provider.clone();
    system::api_key_delete(&provider);
    ai_view(&core)
}

/// The user's call on one name: "block", "allow" (never block) or "undo" (back to review).
#[tauri::command]
fn ai_decide(app: AppHandle, core: State<Shared>, domain: String, action: String) -> Result<AiView, String> {
    let changed_block = {
        let mut a = core.ai.lock().unwrap();
        let e = a.entries.get_mut(&domain).ok_or("Domínio não encontrado.")?;
        let before = e.status;
        e.status = match action.as_str() {
            "block" => ai::Status::Blocked,
            "allow" => ai::Status::Allowed,
            "undo" => ai::Status::Review,
            _ => return Err("Ação desconhecida.".into()),
        };
        e.by_user = action != "undo";
        let changed = (before == ai::Status::Blocked) != (e.status == ai::Status::Blocked);
        core.store.save_ai(&a);
        changed
    };
    if changed_block {
        rebuild(&app, &core);
    }
    Ok(ai_view(&core))
}

#[tauri::command]
async fn ai_run_now(app: AppHandle, core: State<'_, Shared>) -> Result<AiView, String> {
    let c: Shared = core.inner().clone();
    let a2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || ai_run_batch(&a2, &c)).await.map_err(|e| e.to_string())??;
    Ok(ai_view(&core))
}

/// Forgets every verdict and the queue (blocked names are released).
#[tauri::command]
fn ai_forget(app: AppHandle, core: State<Shared>) -> AiView {
    {
        let mut a = core.ai.lock().unwrap();
        *a = ai::AiStore::default();
        core.store.save_ai(&a);
    }
    rebuild(&app, &core);
    ai_view(&core)
}

fn main() {
    // started with Windows: stay in the tray
    let minimized = std::env::args().any(|a| a == "--minimized");

    // keep the Windows startup entry pointing at this exe (its path changes when the
    // installer renames the program folder, e.g. Escudo -> StrickerGuard)
    if system::run_on_startup() {
        let _ = system::set_run_on_startup(true);
    }

    // Started as administrator (by "Abrir como admin" or by the user) while a copy
    // without those rights is still running: replace it. Otherwise the single-instance
    // check below would just bring the old, non-admin window forward and quit.
    if system::is_admin() {
        system::close_other_instances();
    }

    tauri::Builder::default()
        // a second launch just brings the running window forward
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| tray::show_main(app)))
        .on_window_event(move |window, event| {
            // closing the window keeps protection running in the tray, like the original
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(move |app| {
            let dir = app.path().app_data_dir().unwrap_or_else(|_| state::data_dir_fallback());
            let store = Store::new(dir);
            let settings = store.load_settings();
            let log = store.load_log();
            let meta = store.load_meta();
            let ai_store = store.load_ai();
            let core: Shared = Arc::new(Core {
                store,
                settings: Mutex::new(settings.clone()),
                engine: RwLock::new(Engine::new()),
                log: Mutex::new(log),
                meta: Mutex::new(meta),
                rebuild_gen: AtomicU64::new(0),
                busy: AtomicBool::new(false),
                updating: AtomicBool::new(false),
                system_msg: Mutex::new(None),
                applied_dns: Mutex::new(None),
                seen_dns: Mutex::new(HashMap::new()),
                ai: Mutex::new(ai_store),
                ai_running: AtomicBool::new(false),
                pause_gen: AtomicU64::new(0),
            });
            app.manage(core.clone());
            let handle = app.handle().clone();
            rebuild(&handle, &core);
            tray::create(&handle, settings.protection_enabled, on_tray)?;
            if minimized {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }
            let missing = settings.active_filters().into_iter().any(|k| !core.store.filter_path(k).exists());
            let stale = core.meta.lock().unwrap().values().filter_map(|m| m.updated).min().is_some_and(|t| chrono::Utc::now().timestamp() - t > 86_400);
            if missing || (settings.auto_update && stale) {
                start_update(&handle, &core, stale);
            }
            dns_monitor(handle.clone(), core.clone());
            ai_worker(handle.clone(), core.clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            update_settings,
            set_filter,
            update_filters,
            check_url,
            get_log,
            get_stats,
            clear_stats,
            set_startup,
            relaunch_admin,
            test_dns,
            open_link,
            quit_app,
            ai_state,
            ai_set_key,
            ai_clear_key,
            ai_decide,
            ai_run_now,
            ai_forget
        ])
        .run(tauri::generate_context!())
        .expect("erro ao iniciar o app");
}
