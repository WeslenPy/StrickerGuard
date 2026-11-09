import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { api, type BoolKey, type Settings, type View } from "./api";
import { icon } from "./icons";
import * as P from "./pages";
import type { Ui } from "./pages";
import { esc } from "./ui";

const appEl = document.getElementById("app")!;
const win = getCurrentWindow();

const ui: Ui = {
  view: undefined as unknown as View,
  route: "home",
  stats: null,
  period: "24h",
  log: [],
  logQuery: "",
  logOnly: "",
  verdict: null,
  transition: "",
  dnsTest: {},
};
let toastText = "";
let toastTimer = 0;
// tray "Sair" while the hosts file still blocks: ask like the original's exit warning
let askExit = false;

function exitDialog() {
  if (!askExit) return "";
  return `<div class="absolute inset-0 z-40 bg-black/60 flex items-center justify-center">
    <div class="bg-page border border-line rounded-full w-[460px] p-6 shadow-xl">
      <div class="text-[18px] font-semibold mb-2">Atenção!</div>
      <p class="text-[14px] text-muted mb-5">Você vai fechar o Escudo. O bloqueio aplicado no Windows pode continuar funcionando depois de fechar.</p>
      <div class="flex flex-col gap-2">
        <button class="bg-accent hover:bg-accent-hover active:bg-accent-pressed text-on-accent rounded-[10px] h-10 text-[14px] font-semibold" data-act="exit-keep">Fechar, mas continuar filtrando</button>
        <button class="border border-line hover:bg-card rounded-[10px] h-10 text-[14px]" data-act="exit-stop">Sair e parar a proteção</button>
        <button class="hover:bg-card rounded-[10px] h-10 text-[14px] text-muted" data-act="exit-cancel">Cancelar</button>
      </div>
    </div>
  </div>`;
}

// ---------- shell ----------

const nav: [string, string, (s?: number) => string][] = [
  ["home", "Início", icon.home],
  ["protection", "Proteção", icon.shield],
  ["stats", "Estatísticas", icon.pie],
  ["apps", "Gerenciamento de aplicativo", icon.apps],
  ["settings", "Configurações", icon.gear],
];

function sidebar() {
  const st = ui.view.settings;
  const wide = st.sidebar_expanded;
  const top = ui.route.split("/")[0];
  const item = (route: string, label: string, ic: string, act = "go") => {
    const active = top === route;
    return `<button class="nav flex items-center gap-3 h-14 w-full ${wide ? "px-4" : "justify-center"} ${active ? "bg-card" : "hover:bg-card/60"} text-brand" data-act="${act}" data-arg="${route}" title="${label}" aria-current="${active}">
      ${ic}${wide ? `<span class="text-ink text-[14px] truncate">${label}</span>` : ""}
    </button>`;
  };
  return `<nav class="h-full ${wide ? "w-[220px]" : "w-[56px]"} shrink-0 border-r border-sideline flex flex-col bg-page" data-tauri-drag-region>
    <div class="h-[72px] flex items-center ${wide ? "px-4 gap-3" : "justify-center"}" data-tauri-drag-region>${icon.logo(24)}${wide ? `<span class="font-semibold text-[16px]">Escudo</span>` : ""}</div>
    ${nav.map(([r, l, ic]) => item(r, l, ic())).join("")}
    ${item("updates", ui.view.updating ? "Atualizando filtros…" : "Verificar atualizações", `<span class="${ui.view.updating ? "spin inline-block" : ""}">${icon.refresh()}</span>`, "update-filters")}
    <div class="flex-1" data-tauri-drag-region></div>
    <button class="h-14 flex items-center ${wide ? "px-4 gap-3" : "justify-center"} text-ink hover:text-brand" data-act="flip" data-arg="sidebar_expanded" title="${wide ? "Ocultar" : "Expandir"}">
      ${wide ? icon.chevronLeft() : icon.chevronRight()}${wide ? `<span class="text-[14px]">Ocultar</span>` : ""}
    </button>
  </nav>`;
}

function caption() {
  const b = (act: string, ic: string, hover: string, label: string) =>
    `<button class="w-[46px] h-8 flex items-center justify-center text-ink ${hover}" data-act="${act}" aria-label="${label}">${ic}</button>`;
  return `<div class="absolute top-0 right-0 left-0 h-8 flex justify-end z-20" data-tauri-drag-region>
    ${b("win-min", icon.winMin, "hover:bg-card", "Minimizar")}${b("win-max", icon.winMax, "hover:bg-card", "Maximizar")}${b("win-close", icon.winClose, "hover:bg-[#c42b1c] hover:text-white", "Fechar")}
  </div>`;
}

function page() {
  switch (ui.route) {
    case "home": return P.home(ui);
    case "protection": return P.protection(ui);
    case "protection/ads": return P.adBlocking(ui);
    case "protection/tracking": return P.tracking(ui);
    case "protection/annoyances": return P.annoyances(ui);
    case "protection/security": return P.security(ui);
    case "protection/dns": return P.dns(ui);
    case "protection/dns-servers": return P.dnsServers(ui);
    case "protection/dns-rules": return P.rulesEditor(ui, "dns_user_rules");
    case "protection/user-rules": return P.rulesEditor(ui, "user_rules");
    case "protection/allowlist": return P.rulesEditor(ui, "allowlist");
    case "protection/parental": return P.parental(ui);
    case "protection/parental-list": return P.rulesEditor(ui, "parental_blocklist");
    case "stats": return P.statistics(ui);
    case "apps": return P.apps(ui);
    case "settings": return P.settings(ui);
    case "settings/app": return P.appSettings(ui);
    case "settings/filters": return P.filters(ui);
    case "settings/log": return P.filteringLog(ui);
    case "settings/about": return P.about(ui);
    default: return P.home(ui);
  }
}

function applyTheme() {
  let t = ui.view.settings.theme;
  if (t === "system") t = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  document.documentElement.dataset.theme = t;
}

function render() {
  applyTheme();
  const scroller = document.getElementById("content");
  const keep = scroller?.scrollTop ?? 0;
  const sameRoute = appEl.dataset.route === ui.route;
  appEl.dataset.route = ui.route;
  appEl.innerHTML = `<div class="relative h-full flex">
    ${caption()}
    ${sidebar()}
    <main id="content" class="relative flex-1 h-full overflow-y-auto">${page()}</main>
    ${exitDialog()}
    ${toastText ? `<div class="absolute bottom-5 left-1/2 -translate-x-1/2 bg-card text-ink text-[14px] px-4 py-2.5 rounded-[10px] shadow-lg z-30">${esc(toastText)}</div>` : ""}
  </div>`;
  if (sameRoute) document.getElementById("content")!.scrollTop = keep;
}

function toast(text: string) {
  toastText = text;
  clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    toastText = "";
    render();
  }, 3200);
  render();
}

// ---------- data ----------

async function refresh() {
  ui.view = await api.state();
  render();
}

async function patch(p: Partial<Settings>) {
  ui.view = await api.update(p);
  render();
}

async function loadStats() {
  ui.stats = await api.stats(ui.period);
  if (ui.route === "stats") render();
}

async function loadLog() {
  ui.log = await api.log(300, ui.logQuery, ui.logOnly);
  if (ui.route === "settings/log") render();
}

async function go(route: string) {
  ui.route = route;
  if (route === "settings/log") ui.verdict = null;
  render();
  document.getElementById("content")?.scrollTo(0, 0);
  if (route === "stats") await loadStats();
  if (route === "settings/log") await loadLog();
}

// ---------- actions ----------

const actions: Record<string, (arg: string, el: HTMLElement) => unknown> = {
  go: (a) => go(a),
  flip: (a) => patch({ [a]: !ui.view.settings[a as BoolKey] } as Partial<Settings>),
  "toggle-protection": async () => {
    const on = !ui.view.settings.protection_enabled;
    ui.transition = on ? "enabling" : "disabling";
    render();
    const started = performance.now();
    ui.view = await api.update({ protection_enabled: on });
    // keep the "enabling" state on screen briefly, like the original's transition
    await new Promise((r) => setTimeout(r, Math.max(0, 600 - (performance.now() - started))));
    ui.transition = "";
    render();
  },
  "enable-system": () => patch({ apply_to_system: true }),
  "relaunch-admin": async () => {
    try {
      await api.relaunchAdmin();
    } catch (e) {
      toast(String(e));
    }
  },
  "dismiss-banner": () => patch({ banner_dismissed: true }),
  "set-dns": (a) => patch({ dns_server: a }),
  "test-dns": async (a) => {
    ui.dnsTest[a] = "Testando…";
    render();
    const res = await api.testDns(a);
    ui.dnsTest[a] = res.map(([ip, ms]) => `${ip}: ${ms === null ? "sem resposta" : `${ms} ms`}`).join(" · ");
    render();
  },
  filter: async (a, el) => {
    ui.view = await api.setFilter(a, el.dataset.on !== "true");
    render();
  },
  "update-filters": async () => {
    ui.view = await api.updateFilters();
    toast("Verificando atualizações dos filtros…");
  },
  startup: async (_a, el) => {
    try {
      ui.view = await api.setStartup(el.dataset.on !== "true");
      render();
    } catch (e) {
      toast(String(e));
    }
  },
  "save-list": async (a) => {
    const text = (document.getElementById("editor") as HTMLTextAreaElement).value;
    const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    await patch({ [a]: lines } as Partial<Settings>);
    toast("Salvo");
  },
  period: async (a) => {
    ui.period = a;
    await loadStats();
  },
  "clear-stats": async () => {
    if (!confirm("Limpar estatísticas? Todo o registro de filtragem será apagado.")) return;
    await api.clearStats();
    await loadStats();
    toast("Estatísticas limpas");
  },
  "toggle-app": async (a) => {
    const apps = ui.view.settings.apps.map((x, i) => (i === Number(a) ? { ...x, filtered: !x.filtered } : x));
    await patch({ apps });
  },
  "add-app": async () => {
    const name = (document.getElementById("app-name") as HTMLInputElement).value.trim();
    const exe = (document.getElementById("app-exe") as HTMLInputElement).value.trim();
    if (!name || !exe) return toast("Preencha o nome e o arquivo .exe");
    await patch({ apps: [...ui.view.settings.apps, { name, exe, filtered: true }] });
  },
  check: async () => {
    const input = document.getElementById("check-url") as HTMLInputElement;
    const url = input.value.trim();
    if (!url) return;
    ui.verdict = await api.check(url);
    await loadLog();
    render();
    (document.getElementById("check-url") as HTMLInputElement).value = url;
  },
  block: async (host) => {
    const rules = ui.view.settings.user_rules.filter((r) => r !== `@@||${host}^`);
    await patch({ user_rules: [...rules, `||${host}^`] });
    toast(`Regra criada: ||${host}^`);
  },
  unblock: async (host) => {
    const rules = ui.view.settings.user_rules.filter((r) => r !== `||${host}^`);
    await patch({ user_rules: [...rules, `@@||${host}^`] });
    toast(`Regra criada: @@||${host}^`);
  },
  "refresh-log": () => loadLog(),
  "exit-keep": () => api.quit(true),
  "exit-stop": () => api.quit(false),
  "exit-cancel": () => {
    askExit = false;
    render();
  },
  "win-min": () => win.minimize(),
  "win-max": () => win.toggleMaximize(),
  "win-close": () => win.close(),
};

document.addEventListener("click", (ev) => {
  const el = (ev.target as HTMLElement).closest<HTMLElement>("[data-act]");
  if (!el) return;
  ev.preventDefault();
  ev.stopPropagation();
  actions[el.dataset.act!]?.(el.dataset.arg ?? "", el);
});

document.addEventListener("submit", (ev) => {
  ev.preventDefault();
  const act = (ev.target as HTMLElement).dataset.submit;
  if (act) actions[act]?.("", ev.target as HTMLElement);
});

document.addEventListener("change", (ev) => {
  const el = ev.target as HTMLSelectElement;
  switch (el.dataset.change) {
    case "theme": patch({ theme: el.value }); break;
    case "update-period": patch({ filters_update_hours: Number(el.value) }); break;
    case "log-only": ui.logOnly = el.value; loadLog(); break;
    case "custom-v4": patch({ custom_block_ipv4: el.value.trim() }); break;
    case "custom-v6": patch({ custom_block_ipv6: el.value.trim() }); break;
  }
});

let searchTimer = 0;
document.addEventListener("input", (ev) => {
  const el = ev.target as HTMLInputElement;
  if (el.dataset.input === "log-q") {
    ui.logQuery = el.value;
    clearTimeout(searchTimer);
    searchTimer = window.setTimeout(async () => {
      ui.log = await api.log(300, ui.logQuery, ui.logOnly);
      render();
      const box = document.getElementById("log-q") as HTMLInputElement;
      box.focus();
      box.setSelectionRange(box.value.length, box.value.length);
    }, 250);
  }
});

// ---------- start ----------

async function start() {
  await refresh();
  if (ui.view.start_route) await go(ui.view.start_route);
  listen("state-changed", async () => {
    const editing = document.activeElement?.tagName === "TEXTAREA" || document.activeElement?.tagName === "INPUT";
    ui.view = await api.state();
    if (!editing) render();
  });
  listen("log-changed", () => {
    if (ui.route === "stats") loadStats();
    if (ui.route === "settings/log") loadLog();
  });
  listen<string>("navigate", (e) => go(e.payload));
  listen<string>("toast", (e) => toast(e.payload));
  listen("confirm-exit", () => {
    askExit = true;
    render();
  });
  matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => applyTheme());

  if (ui.view.screenshot) {
    // draw about 120 frames, then let the app save its picture
    let frames = 0;
    const tick = () => (++frames >= 120 ? api.screenshotReady() : requestAnimationFrame(tick));
    requestAnimationFrame(tick);
  }
}

start();
