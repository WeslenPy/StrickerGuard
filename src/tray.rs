//! Icon in the Windows notification area. The menu follows the original's
//! taskbar menu (Adguard.UI.dll resources "TaskbarMenu*", see MECHANICS.md):
//! open, enable/disable protection, disable for 30 seconds, tools, filter updates,
//! settings, advanced resets, about, exit. Left click opens the window; the icon
//! turns grey when protection is off.

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};

const TRAY_ID: &str = "main";
const ICON_ON: &[u8] = include_bytes!("../icons/icon.png");
const ICON_OFF: &[u8] = include_bytes!("../icons/tray-off.png");

/// "Desativar proteção por 30 segundos" (TaskbarMenuTemporarilyDisableProtection).
pub const PAUSE_SECONDS: u64 = 30;

struct TrayState {
    toggle: MenuItem<Wry>,
}

/// What the menu asks the app to do; handled in main.rs.
pub enum TrayAction {
    Toggle,
    Pause,
    UpdateFilters,
    ResetStats,
    ResetSettings,
    Exit,
}

fn toggle_text(on: bool) -> &'static str {
    if on { "Desativar proteção" } else { "Ativar proteção" }
}

pub fn create(app: &AppHandle, protection_on: bool, on_action: impl Fn(&AppHandle, TrayAction) + Send + Sync + 'static) -> tauri::Result<()> {
    let item = |id: &str, text: &str| MenuItem::with_id(app, id, text, true, None::<&str>);
    let toggle = item("toggle", toggle_text(protection_on))?;
    let tools = Submenu::with_items(
        app,
        "Ferramentas",
        true,
        &[
            &item("go:settings/filters", "Editor de filtros")?,
            &item("go:settings/log", "Registro de filtragem")?,
            &item("go:protection/dns-rules", "Editor de filtros DNS")?,
        ],
    )?;
    let advanced = Submenu::with_items(
        app,
        "Avançado",
        true,
        &[&item("reset-stats", "Redefinir estatísticas")?, &item("reset-settings", "Redefinir configurações para o padrão")?],
    )?;
    let menu = Menu::with_items(
        app,
        &[
            &item("open", "Abrir Escudo")?,
            &PredefinedMenuItem::separator(app)?,
            &toggle,
            &item("pause", "Desativar proteção por 30 segundos")?,
            &PredefinedMenuItem::separator(app)?,
            &tools,
            &item("update", "Verificar atualizações de filtros...")?,
            &item("go:settings", "Configurações...")?,
            &advanced,
            &item("go:settings/about", "Sobre...")?,
            &PredefinedMenuItem::separator(app)?,
            &item("exit", "Sair do Escudo")?,
        ],
    )?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon(protection_on)?)
        .tooltip(tooltip(protection_on))
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(move |app, event| {
            let id = event.id().as_ref();
            if let Some(route) = id.strip_prefix("go:") {
                navigate(app, route);
                return;
            }
            match id {
                "open" => show_main(app),
                "toggle" => on_action(app, TrayAction::Toggle),
                "pause" => on_action(app, TrayAction::Pause),
                "update" => on_action(app, TrayAction::UpdateFilters),
                "reset-stats" => on_action(app, TrayAction::ResetStats),
                "reset-settings" => on_action(app, TrayAction::ResetSettings),
                "exit" => on_action(app, TrayAction::Exit),
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    app.manage(TrayState { toggle });
    Ok(())
}

fn icon(on: bool) -> tauri::Result<Image<'static>> {
    Image::from_bytes(if on { ICON_ON } else { ICON_OFF })
}

fn tooltip(on: bool) -> &'static str {
    if on { "Escudo — proteção ativada" } else { "Escudo — proteção desativada" }
}

/// Keeps the tray icon, tooltip and menu text in step with the protection switch.
pub fn sync(app: &AppHandle, on: bool) {
    if let Some(state) = app.try_state::<TrayState>() {
        let _ = state.toggle.set_text(toggle_text(on));
    }
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        if let Ok(img) = icon(on) {
            let _ = tray.set_icon(Some(img));
        }
        let _ = tray.set_tooltip(Some(tooltip(on)));
    }
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Opens the window on a given screen.
pub fn navigate(app: &AppHandle, route: &str) {
    show_main(app);
    let _ = app.emit("navigate", route.to_string());
}
