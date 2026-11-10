//! Changes made to Windows itself: hosts file, DNS servers, start with Windows.
//! Everything here is opt-in from the app's settings.

use std::path::PathBuf;
use std::process::Command;

const BEGIN: &str = "# >>> Escudo";
const END: &str = "# <<< Escudo";
/// Most names written to the hosts file (two lines each: IPv4 and IPv6).
pub const HOSTS_LIMIT: usize = 50000;

fn hosts_path() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    PathBuf::from(root).join("System32").join("drivers").join("etc").join("hosts")
}

fn hidden(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    cmd
}

/// True when this process runs elevated (as administrator).
/// Checks the process token, not the hosts file: the hosts file can be locked by
/// Defender or another program even for an administrator.
pub fn is_admin() -> bool {
    #[cfg(windows)]
    {
        unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Ends other running copies of this program (same .exe name), then waits for them
/// to go. Used by an elevated start so it replaces a copy that runs without
/// administrator rights instead of handing over to it.
pub fn close_other_instances() {
    let Some(name) = std::env::current_exe().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())) else {
        return;
    };
    let me = std::process::id();
    let others = || -> Vec<u32> {
        let out = hidden(Command::new("tasklist").args(["/FI", &format!("IMAGENAME eq {name}"), "/FO", "CSV", "/NH"])).output();
        let Ok(out) = out else { return vec![] };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split("\",\"").nth(1).and_then(|pid| pid.trim_matches('"').parse::<u32>().ok()))
            .filter(|&pid| pid != me)
            .collect()
    };
    let pids = others();
    if pids.is_empty() {
        return;
    }
    for pid in &pids {
        let _ = hidden(Command::new("taskkill").args(["/F", "/PID", &pid.to_string()])).output();
    }
    for _ in 0..20 {
        if others().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn strip_block(text: &str) -> String {
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if line.trim() == BEGIN {
            inside = true;
            continue;
        }
        if line.trim() == END {
            inside = false;
            continue;
        }
        if !inside {
            out.push(line);
        }
    }
    let mut s = out.join("\r\n");
    while s.ends_with("\r\n\r\n") {
        s.truncate(s.len() - 2);
    }
    s
}

/// Blocked names are answered like the original's DNS blocking response
/// (AdguardDns.dll 0x18004d670): A -> 0.0.0.0, AAAA -> ::, unless custom addresses are set.
pub const BLOCK_ANSWER_V4: &str = "0.0.0.0";
pub const BLOCK_ANSWER_V6: &str = "::";

/// Writes (or with an empty list removes) the app's section of the hosts file.
/// Each entry is a host and, for a $dnsrewrite / hosts rewrite, the address to answer.
pub fn write_hosts(entries: &[(String, Option<String>)], v4: &str, v6: &str) -> Result<usize, String> {
    let ok = |a: &str, want_v4: bool| a.parse::<std::net::IpAddr>().map(|ip| ip.is_ipv4() == want_v4).unwrap_or(false);
    let v4 = if ok(v4, true) { v4 } else { BLOCK_ANSWER_V4 };
    let v6 = if ok(v6, false) { v6 } else { BLOCK_ANSWER_V6 };
    let path = hosts_path();
    let current = std::fs::read_to_string(&path).unwrap_or_default();
    let mut text = strip_block(&current);
    if !entries.is_empty() {
        if !text.is_empty() && !text.ends_with("\r\n") {
            text.push_str("\r\n");
        }
        text.push_str("\r\n");
        text.push_str(BEGIN);
        text.push_str("\r\n");
        for (host, rewrite) in entries {
            match rewrite {
                Some(ip) => text.push_str(&format!("{ip} {host}\r\n")),
                None => text.push_str(&format!("{v4} {host}\r\n{v6} {host}\r\n")),
            }
        }
        text.push_str(END);
    }
    text.push_str("\r\n");
    if text == current {
        return Ok(entries.len());
    }
    std::fs::write(&path, text).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            if is_admin() {
                "O arquivo hosts está bloqueado (somente leitura, Windows Defender ou antivírus). Libere a alteração do hosts e tente de novo.".to_string()
            } else {
                "É preciso abrir o app como administrador para aplicar no sistema.".to_string()
            }
        } else {
            e.to_string()
        }
    })?;
    let _ = hidden(Command::new("ipconfig").arg("/flushdns")).output();
    Ok(entries.len())
}

/// How many distinct names the app's section of the hosts file covers.
pub fn hosts_count() -> usize {
    let text = std::fs::read_to_string(hosts_path()).unwrap_or_default();
    let mut inside = false;
    let mut names = std::collections::HashSet::new();
    for line in text.lines() {
        match line.trim() {
            BEGIN => inside = true,
            END => inside = false,
            l if inside => {
                if let Some(h) = l.split_whitespace().nth(1) {
                    names.insert(h.to_string());
                }
            }
            _ => {}
        }
    }
    names.len()
}

/// Points every connected adapter at the given DNS servers (empty = back to automatic).
pub fn set_dns(addresses: &[&str]) -> Result<(), String> {
    let script = if addresses.is_empty() {
        "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }".to_string()
    } else {
        let list = addresses.iter().map(|a| format!("'{a}'")).collect::<Vec<_>>().join(",");
        format!("Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {{ Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses @({list}) }}")
    };
    let out = hidden(Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]))
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("falha ao mudar o DNS").to_string())
    }
}

/// WindowsAdvancedSettings.DnsCustomTimeout in the original's factory settings.
pub const DNS_TIMEOUT_MS: u64 = 5000;

/// Sends one DNS question (A record of example.com) and returns the reply time in ms.
pub fn probe_dns(server: &str) -> Option<u64> {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(DNS_TIMEOUT_MS))).ok()?;
    let mut q: Vec<u8> = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in "example.com".split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let start = Instant::now();
    sock.send_to(&q, (server, 53)).ok()?;
    let mut buf = [0u8; 512];
    let (n, _) = sock.recv_from(&mut buf).ok()?;
    (n >= 12 && buf[0] == 0x12 && buf[1] == 0x34).then(|| start.elapsed().as_millis() as u64)
}

const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

pub fn run_on_startup() -> bool {
    hidden(Command::new("reg").args(["query", RUN_KEY, "/v", "Escudo"]))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn set_run_on_startup(on: bool) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = Command::new("reg");
    if on {
        cmd.args(["add", RUN_KEY, "/v", "Escudo", "/t", "REG_SZ", "/d", &format!("\"{}\" --minimized", exe.display()), "/f"]);
    } else {
        cmd.args(["delete", RUN_KEY, "/v", "Escudo", "/f"]);
    }
    let out = hidden(&mut cmd).output().map_err(|e| e.to_string())?;
    if out.status.success() { Ok(()) } else { Err("não foi possível mudar a inicialização".into()) }
}

/// Starts a new copy of the app with administrator rights (Windows asks first).
pub fn relaunch_as_admin() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let script = format!("Start-Process -FilePath '{}' -Verb RunAs", exe.display());
    let status = hidden(Command::new("powershell").args(["-NoProfile", "-Command", &script]))
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() { Ok(()) } else { Err("o Windows não deu permissão de administrador".into()) }
}

pub fn open_url(url: &str) {
    let _ = hidden(Command::new("cmd").args(["/C", "start", "", url])).spawn();
}

// ---------- API key for the AI review (Windows Credential Manager) ----------

/// Where a provider's key lives in Credential Manager ("Credenciais do Windows").
fn key_target(provider: &str) -> String {
    format!("StrickerGuard/ai-key/{provider}")
}

/// Saves the key encrypted by Windows for this user (never in settings.json).
#[cfg(windows)]
pub fn api_key_save(provider: &str, key: &str) -> Result<(), String> {
    use windows::core::PWSTR;
    use windows::Win32::Security::Credentials::{CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC};
    let mut target: Vec<u16> = key_target(provider).encode_utf16().chain(std::iter::once(0)).collect();
    let mut blob = key.as_bytes().to_vec();
    let cred = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target.as_mut_ptr()),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        ..Default::default()
    };
    unsafe { CredWriteW(&cred, 0) }.map_err(|e| format!("não foi possível guardar a chave: {e}"))
}

#[cfg(windows)]
pub fn api_key_load(provider: &str) -> Option<String> {
    use windows::core::HSTRING;
    use windows::Win32::Security::Credentials::{CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC};
    let mut ptr: *mut CREDENTIALW = std::ptr::null_mut();
    unsafe {
        CredReadW(&HSTRING::from(key_target(provider)), CRED_TYPE_GENERIC, None, &mut ptr).ok()?;
        let c = &*ptr;
        let bytes = std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize).to_vec();
        CredFree(ptr as *const _);
        String::from_utf8(bytes).ok().filter(|k| !k.is_empty())
    }
}

#[cfg(windows)]
pub fn api_key_delete(provider: &str) {
    use windows::core::HSTRING;
    use windows::Win32::Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC};
    let _ = unsafe { CredDeleteW(&HSTRING::from(key_target(provider)), CRED_TYPE_GENERIC, None) };
}

#[cfg(not(windows))]
pub fn api_key_save(_provider: &str, _key: &str) -> Result<(), String> {
    Err("disponível só no Windows".into())
}
#[cfg(not(windows))]
pub fn api_key_load(_provider: &str) -> Option<String> {
    None
}
#[cfg(not(windows))]
pub fn api_key_delete(_provider: &str) {}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn api_key_round_trip() {
        let p = "selftest";
        super::api_key_delete(p);
        assert_eq!(super::api_key_load(p), None);
        super::api_key_save(p, "sk-test-123").unwrap();
        assert_eq!(super::api_key_load(p).as_deref(), Some("sk-test-123"));
        super::api_key_delete(p);
        assert_eq!(super::api_key_load(p), None);
    }
}
