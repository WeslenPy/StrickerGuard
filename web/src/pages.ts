// Every screen of the app, rendered as HTML strings from the current state.
import type { FilterView, LogEntry, Stats, Verdict, View } from "./api";
import { icon } from "./icons";
import { btn, esc, fmtDate, fmtNum, pageHead, row, sw } from "./ui";

export interface Ui {
  view: View;
  route: string;
  stats: Stats | null;
  period: string;
  log: LogEntry[];
  logQuery: string;
  logOnly: string;
  verdict: Verdict | null;
  transition: "" | "enabling" | "disabling";
  dnsTest: Record<string, string>;
}

const s = (u: Ui) => u.view.settings;

// ---------- Home ----------

export function home(u: Ui) {
  const st = s(u);
  const on = st.protection_enabled;
  const busy = u.transition !== "";
  const features: [string, boolean, string, string, string][] = [
    [icon.noAds(18), st.ad_blocking, "Bloqueio de anúncios", "Anúncios", "protection/ads"],
    [icon.noTrack(18), st.tracking_protection, "Proteção contra rastreamento", "Rastreadores", "protection/tracking"],
    [icon.annoy(18), st.annoyance_blocking, "Bloqueio de aborrecimentos", "Aborrecimentos", "protection/annoyances"],
    [icon.dns(18), st.dns_protection, "Proteção de DNS", "DNS", "protection/dns"],
  ];
  const title = busy
    ? u.transition === "enabling" ? "Ativando a proteção" : "Desativando a proteção"
    : on ? "A proteção está ativada" : "A proteção está desativada";
  const sub = busy ? "Um momento" : on ? "Navegue com segurança, estamos te protegendo" : "Anúncios e rastreadores não estão sendo bloqueados";
  const chips = features
    .map(([ic, f, label, short, route]) => {
      const active = f && on;
      return `<button data-act="go" data-arg="${route}" title="${label}: ${active ? "ativado" : "desativado"}" class="flex items-center gap-2 h-9 pl-3 pr-3.5 rounded-full border transition-colors ${
        active ? "border-line bg-card text-ink hover:border-brand" : "border-dashed border-line text-faint hover:text-ink"
      }"><span class="${active ? "text-brand" : ""}">${ic}</span><span class="text-[13px]">${short}</span></button>`;
    })
    .join("");
  const spinner = (c: string) => `<span class="w-4 h-4 border-2 ${c} border-t-transparent rounded-full spin"></span>`;
  const knob = on
    ? `<span class="absolute right-1 top-1 w-9 h-9 rounded-full bg-on-accent text-accent flex items-center justify-center transition-all">${busy ? spinner("border-accent") : icon.check(20)}</span>`
    : `<span class="absolute left-1 top-1 w-9 h-9 rounded-full bg-white text-[#3a404a] shadow-[0_2px_6px_rgba(0,0,0,.25)] flex items-center justify-center transition-all">${busy ? spinner("border-[#3a404a]") : icon.close(18)}</span>`;
  const status = busy ? "· · ·" : on ? "● Protegido" : "○ Desprotegido";
  return `
  <div class="relative h-full flex flex-col items-center">
    <div class="scan-grid absolute inset-0 pointer-events-none"></div>
    <div class="relative flex-1 flex flex-col items-center justify-center pb-[96px] pt-[40px]">
      <div class="emblem mb-5" data-on="${on && !busy}">${icon.logo(64)}</div>
      <div class="label mb-2 ${on && !busy ? "!text-brand" : ""}">${status}</div>
      <h1 class="text-[30px] font-semibold leading-9">${title}</h1>
      <p class="text-[14px] text-muted mt-2">${sub}</p>
      <button class="relative mt-7 w-[92px] h-11 rounded-full ${on ? "bg-accent" : "bg-switch-off"} transition-colors" data-act="toggle-protection" aria-label="${on ? "Desativar" : "Ativar"} proteção" ${busy ? "disabled" : ""}>
        ${knob}
      </button>
      <div class="flex gap-2 mt-8">${chips}</div>
    </div>
    ${banner(u)}
  </div>`;
}

function banner(u: Ui) {
  const st = s(u);
  const v = u.view;
  if (st.banner_dismissed && !v.system_msg) return "";
  let title = "";
  let desc = "";
  let action = "";
  let label = "Ativar";
  if (!st.apply_to_system) {
    title = "Aplicar o bloqueio em todo o Windows?";
    desc = "Sem isso, os bloqueios valem só para as verificações feitas no app.";
    action = "enable-system";
  } else if (!v.admin) {
    title = "Precisa de permissão de administrador";
    desc = "Abra o app como administrador para escrever as regras no Windows.";
    action = "relaunch-admin";
    label = "Abrir como admin";
  } else if (v.system_msg) {
    title = "Bloqueio aplicado no Windows";
    desc = esc(v.system_msg);
    action = "";
  } else return "";
  return `
    <div class="absolute left-6 right-6 bottom-4 bg-card rounded-[10px] flex items-center gap-4 pl-4 pr-3 h-[72px]">
      <div class="text-danger">${icon.alert(22)}</div>
      <div class="flex-1 min-w-0">
        <div class="text-[15px] leading-5">${title}</div>
        <div class="text-[13px] text-ink mt-1">${desc} <a class="text-brand underline cursor-pointer" data-act="go" data-arg="settings/app">Saiba mais</a></div>
      </div>
      ${action ? `<button class="bg-accent hover:bg-accent-hover active:bg-accent-pressed text-on-accent rounded-full w-[200px] h-12 text-[15px] font-semibold" data-act="${action}">${label}</button>` : ""}
      <button class="w-10 h-10 flex items-center justify-center text-ink hover:text-brand" data-act="dismiss-banner" aria-label="Fechar">${icon.close(22)}</button>
    </div>`;
}

// ---------- Protection ----------

export function protection(u: Ui) {
  const st = s(u);
  const disabled = !st.protection_enabled;
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Proteção", disabled ? "A proteção geral está desativada. Ative-a na tela inicial para que estes recursos funcionem." : "")}
    <div class="rounded-[10px] border border-line overflow-hidden">
      ${row({ ico: icon.noAds(24), title: "Bloqueio de anúncios", desc: "Bloqueia anúncios indesejados, como pop-ups, banners e anúncios em vídeo", toggle: "flip", arg: "ad_blocking", on: st.ad_blocking, open: "protection/ads" })}
      ${row({ ico: icon.noTrack(24), title: "Proteção contra rastreamento", desc: "Protege sua atividade online e dados pessoais de rastreadores da web", toggle: "flip", arg: "tracking_protection", on: st.tracking_protection, open: "protection/tracking" })}
      ${row({ ico: icon.annoy(24), title: "Bloqueio de aborrecimentos", desc: "Bloqueia avisos de cookies, widgets e pop-ups nas páginas", toggle: "flip", arg: "annoyance_blocking", on: st.annoyance_blocking, open: "protection/annoyances" })}
      ${row({ ico: icon.security(), title: "Segurança da navegação", desc: "Bloqueia solicitações a sites maliciosos e de phishing", toggle: "flip", arg: "browsing_security", on: st.browsing_security, open: "protection/security" })}
      ${row({ ico: icon.dns(24), title: "Proteção de DNS", desc: "Protege contra anúncios, rastreadores e ameaças no nível do DNS", toggle: "flip", arg: "dns_protection", on: st.dns_protection, open: "protection/dns" })}
      ${row({ ico: icon.parental(), title: "Controle parental", desc: "Bloqueia o acesso a conteúdo indesejável", toggle: "flip", arg: "parental_control", on: st.parental_control, open: "protection/parental" })}
      ${row({ ico: icon.globe(), title: "Lista de permissões de sites", desc: "Sites que nunca são bloqueados", open: "protection/allowlist" })}
    </div>
  </div>`;
}

const master = (title: string, key: string, on: boolean) => `
  <div class="bg-card rounded-[10px] flex items-center px-4 h-14 mb-5">
    <div class="flex-1 text-[15px] font-semibold">${title}</div>${sw(on, "flip", key)}
  </div>`;

const section = (title: string, rows: string) =>
  `<h2 class="label mt-7 mb-2.5">${title}</h2><div class="rounded-[10px] border border-line overflow-hidden">${rows}</div>`;

const countActive = (u: Ui, groups: string[], core: string[]) =>
  u.view.filters.filter((f) => groups.includes(f.group) && f.active && !core.includes(f.key)).length;

export function adBlocking(u: Ui) {
  const st = s(u);
  const off = !st.ad_blocking;
  const warn = st.ad_blocking && !st.basic_protection && !st.block_search_ads && !st.language_specific && !st.user_rules_enabled;
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Bloqueio de anúncios", "Bloqueia anúncios indesejados, como pop-ups, banners, anúncios em vídeo e anúncios do Windows", "protection")}
    ${master("Bloqueio de anúncios", "ad_blocking", st.ad_blocking)}
    ${warn ? `<p class="text-attention text-[13px] -mt-2 mb-3">Este recurso não é aplicado porque todas as suas subconfigurações estão desativadas</p>` : ""}
    <div class="rounded-[10px] border border-line overflow-hidden">
      ${row({ title: "Proteção básica", desc: st.basic_protection ? "Remove a maioria dos anúncios de sites" : `<span class="text-danger">Sem a proteção básica, a maioria dos anúncios não será bloqueada</span>`, toggle: "flip", arg: "basic_protection", on: st.basic_protection, disabled: off })}
      ${row({ title: "Bloquear anúncios de pesquisa e autopromoção", desc: "Bloqueia anúncios nos resultados de pesquisa e autopromoção de sites", toggle: "flip", arg: "block_search_ads", on: st.block_search_ads, disabled: off })}
      ${row({ title: "Bloqueio de anúncios específicos do idioma", desc: "Bloqueia anúncios em sites em português e espanhol", toggle: "flip", arg: "language_specific", on: st.language_specific, disabled: off })}
      ${row({ title: "Regras de usuário", desc: `Regras adicionadas manualmente e pelo registro de filtragem · ${st.user_rules.filter((r) => r.trim() && !r.startsWith("!")).length} regras`, toggle: "flip", arg: "user_rules_enabled", on: st.user_rules_enabled, open: "protection/user-rules", disabled: off })}
      ${row({ title: "Outros filtros de bloqueio de anúncios", desc: `Ativados em Filtros: ${countActive(u, ["Bloqueio de anúncios", "Idiomas", "Outros"], ["s2", "s9", "s10"])}`, open: "settings/filters" })}
    </div>
  </div>`;
}

export function tracking(u: Ui) {
  const st = s(u);
  const off = !st.tracking_protection;
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Proteção contra rastreamento", "Protege sua atividade online e dados pessoais de rastreadores da web", "protection")}
    ${master("Proteção contra rastreamento", "tracking_protection", st.tracking_protection)}
    ${section("Geral", `
      ${row({ title: "Bloquear rastreadores", desc: "Bloqueia rastreadores e análises da web com o filtro de proteção contra rastreamento", toggle: "flip", arg: "block_trackers", on: st.block_trackers, disabled: off })}
      ${row({ title: "Remover parâmetros de rastreamento de URLs", desc: "Usa o filtro de rastreamento de URL", toggle: "flip", arg: "strip_url", on: st.strip_url, disabled: off })}
      ${row({ title: "Ocultar consultas de pesquisa", desc: "Esconde suas buscas dos sites visitados a partir de resultados de pesquisa", toggle: "flip", arg: "hide_search_queries", on: st.hide_search_queries, disabled: off })}
      ${row({ title: "Pedir aos sites que não me rastreiem", desc: "Envia os sinais Global Privacy Control e Do Not Track", toggle: "flip", arg: "do_not_track", on: st.do_not_track, disabled: off })}
      ${row({ title: "Outros filtros de privacidade", desc: `Ativados em Filtros: ${countActive(u, ["Privacidade", "Widgets sociais"], ["s3", "s17"])}`, open: "settings/filters" })}`)}
    ${section("API do navegador", `
      ${row({ title: "Evitar vazamento de IP pelo WebRTC", desc: "Política de IP mais rígida para manter seu endereço real oculto", toggle: "flip", arg: "block_webrtc", on: st.block_webrtc, disabled: off })}
      ${row({ title: "Bloquear API Push", desc: "Bloqueia notificações push de sites", toggle: "flip", arg: "block_push_api", on: st.block_push_api, disabled: off })}
      ${row({ title: "Bloquear API de localização", desc: "Impede que sites detectem sua localização", toggle: "flip", arg: "block_location_api", on: st.block_location_api, disabled: off })}`)}
    <p class="text-[12px] text-faint mt-4">Nesta versão, os itens de “API do navegador”, consultas de pesquisa e Do Not Track ficam salvos, mas só têm efeito com um módulo de navegador (ainda não incluído).</p>
  </div>`;
}

export function annoyances(u: Ui) {
  const st = s(u);
  const off = !st.annoyance_blocking;
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Bloqueio de aborrecimentos", "Bloqueia elementos irritantes da web, como avisos de cookies, widgets de redes sociais ou pop-ups", "protection")}
    ${master("Bloqueio de aborrecimentos", "annoyance_blocking", st.annoyance_blocking)}
    <div class="rounded-[10px] border border-line overflow-hidden">
      ${row({ title: "Bloquear avisos de cookies", desc: "Bloqueia formulários de consentimento de cookies em sites", toggle: "flip", arg: "block_cookie_notices", on: st.block_cookie_notices, disabled: off })}
      ${row({ title: "Bloquear pop-ups", desc: "Bloqueia pop-ups desnecessários para o funcionamento do site", toggle: "flip", arg: "block_popups", on: st.block_popups, disabled: off })}
      ${row({ title: "Bloquear banners de aplicativos móveis", desc: "Bloqueia banners que promovem o app do site", toggle: "flip", arg: "block_mobile_app_banners", on: st.block_mobile_app_banners, disabled: off })}
      ${row({ title: "Bloquear widgets", desc: "Bloqueia widgets de terceiros, como assistentes online e chats de suporte", toggle: "flip", arg: "block_widgets", on: st.block_widgets, disabled: off })}
      ${row({ title: "Bloquear outros aborrecimentos", desc: "Bloqueia elementos incomuns e irritantes da web", toggle: "flip", arg: "block_other_annoyances", on: st.block_other_annoyances, disabled: off })}
      ${row({ title: "Outros filtros de aborrecimentos", desc: `Ativados em Filtros: ${countActive(u, ["Aborrecimentos"], ["s18", "s19", "s20", "s21", "s22"])}`, open: "settings/filters" })}
    </div>
  </div>`;
}

export function security(u: Ui) {
  const st = s(u);
  const off = !st.browsing_security;
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Segurança da navegação", "Bloqueia solicitações a sites maliciosos e de phishing", "protection")}
    ${master("Segurança da navegação", "browsing_security", st.browsing_security)}
    <div class="rounded-[10px] border border-line overflow-hidden">
      ${row({ title: "Ser notificado sobre solicitações bloqueadas", desc: "Mostra um aviso quando um site perigoso for bloqueado", toggle: "flip", arg: "security_notifications", on: st.security_notifications, disabled: off })}
      ${row({ title: "Ativar sons de notificações", toggle: "flip", arg: "security_sound", on: st.security_sound, disabled: off || !st.security_notifications })}
    </div>
  </div>`;
}

export function dns(u: Ui) {
  const st = s(u);
  const off = !st.dns_protection;
  const server = u.view.dns_servers.find((d) => d.id === st.dns_server) ?? u.view.dns_servers[0];
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Proteção de DNS", "Protege você contra anúncios, rastreadores e ameaças no nível do DNS", "protection")}
    ${master("Proteção de DNS", "dns_protection", st.dns_protection)}
    <div class="rounded-[10px] border border-line overflow-hidden">
      ${row({ title: "Servidor DNS", desc: `Escolha o servidor que resolve os endereços.<br><b>Atual: ${esc(server.name)}</b>`, open: "protection/dns-servers" })}
      ${row({ title: "Filtros DNS", desc: "Bloqueia anúncios e rastreadores no nível do domínio", toggle: "flip", arg: "dns_filters", on: st.dns_filters, disabled: off })}
      ${row({ title: "Regras de usuário DNS", desc: `Bloqueie, desbloqueie ou redirecione domínios · ${st.dns_user_rules.filter((r) => r.trim()).length} regras`, open: "protection/dns-rules" })}
    </div>
  </div>`;
}

export function dnsServers(u: Ui) {
  const st = s(u);
  const items = u.view.dns_servers
    .map(
      (d) => `<label class="flex items-center gap-4 px-4 py-3 border-b border-line last:border-b-0 cursor-pointer hover:bg-card" data-act="set-dns" data-arg="${d.id}">
        <span class="w-[18px] h-[18px] rounded-full border-2 ${d.id === st.dns_server ? "border-brand" : "border-faint"} flex items-center justify-center">${d.id === st.dns_server ? `<span class="w-2 h-2 rounded-full bg-accent"></span>` : ""}</span>
        <span class="flex-1"><span class="block text-[15px]">${esc(d.name)}</span><span class="block text-[13px] text-muted">${esc(d.desc)}${d.addresses.length ? ` · ${d.addresses.join(", ")}` : ""}</span>${u.dnsTest[d.id] ? `<span class="block text-[12px] text-brand mt-0.5">${esc(u.dnsTest[d.id])}</span>` : ""}</span>
        ${d.addresses.length ? `<button class="text-[13px] text-brand hover:underline px-2" data-act="test-dns" data-arg="${d.id}">Testar</button>` : ""}
      </label>`,
    )
    .join("");
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Servidor DNS", "O servidor escolhido passa a valer no Windows quando “Aplicar bloqueio no Windows” estiver ligado e o app rodar como administrador.", "protection/dns")}
    <div class="rounded-[10px] border border-line overflow-hidden">${items}</div>
  </div>`;
}

export function rulesEditor(u: Ui, which: "user_rules" | "dns_user_rules" | "allowlist" | "parental_blocklist") {
  const st = s(u);
  const meta = {
    user_rules: ["Regras de usuário", "Uma regra por linha. Ex.: ||anuncios.exemplo.com^ bloqueia o domínio; @@||exemplo.com^ libera; linhas com ! são comentários.", "protection/ads"],
    dns_user_rules: ["Regras de usuário DNS", "Uma regra por linha. Ex.: ||rastreador.com^, 0.0.0.0 anuncio.net ou só o domínio. @@ libera.", "protection/dns"],
    allowlist: ["Lista de permissões de sites", "Um site por linha. Nada é bloqueado nesses sites nem nos seus subdomínios.", "protection"],
    parental_blocklist: ["Sites bloqueados", "Um site por linha. Bloqueados enquanto o controle parental estiver ligado.", "protection/parental"],
  }[which];
  return `<div class="px-8 pt-10 pb-8 h-full flex flex-col">
    ${pageHead(meta[0], meta[1], meta[2])}
    <textarea id="editor" spellcheck="false" class="flex-1 min-h-[300px] w-full bg-field rounded-[10px] p-3 font-mono text-[13px] leading-5 outline-none focus:ring-1 focus:ring-brand resize-none">${esc(st[which].join("\n"))}</textarea>
    <div class="flex gap-3 mt-4">${btn("Salvar", "save-list", which)}${btn("Cancelar", "go", meta[2], "ghost")}</div>
  </div>`;
}

export function parental(u: Ui) {
  const st = s(u);
  const off = !st.parental_control;
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Controle parental", "Bloqueia o acesso a conteúdo indesejável", "protection")}
    ${master("Controle parental", "parental_control", st.parental_control)}
    <div class="rounded-[10px] border border-line overflow-hidden">
      ${row({ title: "Bloquear sites adultos", desc: "Usa um servidor DNS família quando aplicado no Windows", toggle: "flip", arg: "block_adult", on: st.block_adult, disabled: off })}
      ${row({ title: "Pesquisa segura", desc: "Pede aos buscadores para esconder resultados adultos", toggle: "flip", arg: "safe_search", on: st.safe_search, disabled: off })}
      ${row({ title: "Sites bloqueados", desc: `${st.parental_blocklist.length} sites na lista`, open: "protection/parental-list" })}
    </div>
  </div>`;
}

// ---------- Statistics ----------

export function statistics(u: Ui) {
  const st = u.stats;
  const periods: [string, string][] = [["24h", "24 horas"], ["7d", "7 dias"], ["14d", "14 dias"], ["all", "Todo tempo"]];
  const tabs = periods
    .map(([k, l]) => `<button class="px-3.5 h-8 rounded-full text-[13px] ${u.period === k ? "bg-accent text-on-accent font-semibold" : "text-muted hover:text-ink"}" data-act="period" data-arg="${k}">${l}</button>`)
    .join("");
  const paused = !s(u).statistics_enabled;
  let body = "";
  if (!st || st.total === 0) {
    body = `<div class="flex flex-col items-center justify-center py-20 text-center">
      <div class="text-faint mb-4">${icon.pie(56)}</div>
      <p class="text-[15px]">Sem estatísticas ainda — continue usando o app para vê-las</p>
      <p class="text-[13px] text-muted mt-2 max-w-[460px]">Os números vêm dos endereços que o Windows consulta (lidos a cada 30 s) e das verificações feitas no Registro de filtragem.</p>
    </div>`;
  } else {
    const max = Math.max(1, ...st.buckets.map((b) => b[1]));
    const bars = st.buckets
      .map((b) => `<div class="flex-1 flex flex-col justify-end h-full" title="${b[1]} solicitações, ${b[2]} bloqueadas"><div class="bg-card-pressed rounded-t-[3px]" style="height:${((b[1] - b[2]) / max) * 100}%"></div><div class="bg-accent" style="height:${(b[2] / max) * 100}%"></div></div>`)
      .join("");
    const list = (title: string, items: [string, number][]) => `
      <div class="bg-card rounded-[10px] p-4">
        <div class="text-[15px] font-semibold mb-3">${title}</div>
        ${items.length ? items.map(([h, n]) => `<div class="flex justify-between text-[13px] py-1"><span class="truncate mr-3">${esc(h)}</span><span class="num text-muted">${fmtNum(n)}</span></div>`).join("") : `<div class="text-[13px] text-muted">Nada por enquanto</div>`}
      </div>`;
    body = `
      <div class="bg-card rounded-[10px] p-5 mb-4">
        <div class="text-[15px] font-semibold mb-4">Solicitações</div>
        <div class="flex gap-10 mb-5">
          <div><div class="num text-[30px] font-semibold">${fmtNum(st.total)}</div><div class="label mt-1">Total</div></div>
          <div><div class="num text-[30px] font-semibold text-brand">${fmtNum(st.ads)}</div><div class="label mt-1">Anúncios</div></div>
          <div><div class="num text-[30px] font-semibold text-attention">${fmtNum(st.trackers)}</div><div class="label mt-1">Rastreadores</div></div>
        </div>
        <div class="flex items-end gap-[3px] h-[90px]">${bars}</div>
      </div>
      <div class="grid grid-cols-3 gap-4">
        ${list("Domínios bloqueados", st.top_blocked)}
        ${list("Domínios", st.top_domains)}
        ${list("Aplicativos", st.apps.map(([a, t]) => [a, t] as [string, number]))}
      </div>`;
  }
  return `<div class="px-8 pt-10 pb-8">
    <div class="flex items-center mb-6">
      <h1 class="text-[26px] font-semibold flex-1">Estatísticas</h1>
      <div class="flex gap-1 p-1 rounded-full bg-card border border-line">${tabs}</div>
    </div>
    ${paused ? `<div class="bg-row-changed rounded-[10px] px-4 py-3 mb-4 flex items-center justify-between text-[14px]"><span>As estatísticas estão pausadas</span>${btn("Ativar", "flip", "statistics_enabled")}</div>` : ""}
    ${body}
    <div class="flex gap-3 mt-5">
      ${btn("Abrir registro de filtragem", "go", "settings/log", "ghost")}
      ${btn(paused ? "Ativar estatísticas" : "Desativar estatísticas", "flip", "statistics_enabled", "ghost")}
      ${btn("Limpar estatísticas", "clear-stats", "", "ghost")}
    </div>
  </div>`;
}

// ---------- App management ----------

export function apps(u: Ui) {
  const st = s(u);
  const list = st.apps
    .map((a, i) =>
      row({
        ico: icon.window(),
        title: esc(a.name),
        desc: esc(a.exe),
        toggle: "toggle-app",
        arg: String(i),
        on: a.filtered,
        extra: "",
      }),
    )
    .join("");
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Gerenciamento de aplicativos", "Escolha quais aplicativos devem ter o tráfego filtrado. Com o bloqueio aplicado no Windows, os bloqueios por domínio valem para todo o sistema.")}
    <div class="rounded-[10px] border border-line overflow-hidden">${list}</div>
    <div class="flex gap-3 mt-4">
      <input id="app-name" placeholder="Nome do aplicativo" class="flex-1 bg-field rounded-[10px] px-3 h-10 text-[14px] outline-none focus:ring-1 focus:ring-brand" />
      <input id="app-exe" placeholder="arquivo.exe" class="w-[200px] bg-field rounded-[10px] px-3 h-10 text-[14px] outline-none focus:ring-1 focus:ring-brand" />
      ${btn("Adicionar", "add-app")}
    </div>
  </div>`;
}

// ---------- Settings ----------

export function settings(_u: Ui) {
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Configurações")}
    <div class="rounded-[10px] border border-line overflow-hidden">
      ${row({ ico: icon.gear(), title: "Configurações de aplicativo", desc: "Tema, inicialização, atualizações e bloqueio no Windows", open: "settings/app" })}
      ${row({ ico: icon.filter(), title: "Filtros", desc: "Listas de bloqueio ativas e atualização", open: "settings/filters" })}
      ${row({ ico: icon.log(), title: "Registro de filtragem", desc: "Veja o que foi bloqueado e teste um endereço", open: "settings/log" })}
      ${row({ ico: icon.edit(), title: "Regras de usuário", desc: "Suas próprias regras de bloqueio", open: "protection/user-rules" })}
      ${row({ ico: icon.globe(), title: "Lista de permissões de sites", desc: "Sites que nunca são bloqueados", open: "protection/allowlist" })}
      ${row({ ico: icon.info(), title: "Sobre", desc: "Informações do aplicativo", open: "settings/about" })}
    </div>
  </div>`;
}

export function appSettings(u: Ui) {
  const st = s(u);
  const v = u.view;
  const themes: [string, string][] = [["dark", "Escuro"], ["light", "Claro"], ["system", "Sistema"]];
  const periods: [number, string][] = [[0, "Automático"], [1, "A cada hora"], [6, "A cada 6 horas"], [24, "Diariamente"], [168, "Semanalmente"]];
  const sel = (act: string, cur: string | number, opts: [string | number, string][]) =>
    `<select data-change="${act}" class="bg-field rounded-[10px] h-9 px-2 text-[14px] outline-none">${opts.map(([k, l]) => `<option value="${k}" ${String(k) === String(cur) ? "selected" : ""}>${l}</option>`).join("")}</select>`;
  const sysDesc = st.apply_to_system
    ? v.admin
      ? `Ativo: ${fmtNum(v.hosts_count)} domínios no arquivo hosts do Windows.`
      : `<span class="text-attention">Ligado, mas o app não está como administrador — nada foi aplicado.</span>`
    : "Escreve os domínios bloqueados no arquivo hosts do Windows e aplica o servidor DNS escolhido. Precisa de administrador.";
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Configurações de aplicativo", "", "settings")}
    <div class="rounded-[10px] border border-line overflow-hidden">
      <div class="flex items-center gap-4 px-4 min-h-[64px] border-b border-line"><div class="flex-1 text-[15px]">Tema</div>${sel("theme", st.theme, themes)}</div>
      ${row({ title: "Iniciar com o Windows", desc: "Abre o app quando você entra no Windows", toggle: "startup", on: v.run_on_startup })}
      ${row({ title: "Aplicar bloqueio no Windows", desc: sysDesc, toggle: "flip", arg: "apply_to_system", on: st.apply_to_system, extra: st.apply_to_system && !v.admin ? `<button class="mt-2 text-brand text-[13px] underline" data-act="relaunch-admin">Abrir como administrador</button>` : "" })}
      ${row({ title: "Atualizar filtros automaticamente", desc: "Baixa as versões novas das listas de bloqueio", toggle: "flip", arg: "auto_update", on: st.auto_update })}
      <div class="flex items-center gap-4 px-4 min-h-[64px] border-b border-line"><div class="flex-1 text-[15px]">Período de atualização dos filtros</div>${sel("update-period", st.filters_update_hours, periods)}</div>
      ${row({ title: "Estatísticas", desc: "Guarda o histórico de solicitações no seu computador", toggle: "flip", arg: "statistics_enabled", on: st.statistics_enabled })}
      <div class="flex items-center gap-4 px-4 min-h-[64px]">
        <div class="flex-1"><div class="text-[15px]">Resposta para endereços bloqueados</div><div class="text-[13px] text-muted">Vazio = 0.0.0.0 (IPv4) e :: (IPv6)</div></div>
        <input data-change="custom-v4" value="${esc(st.custom_block_ipv4)}" placeholder="0.0.0.0" class="w-[130px] bg-field rounded-[10px] px-2 h-9 text-[14px] outline-none focus:ring-1 focus:ring-brand" />
        <input data-change="custom-v6" value="${esc(st.custom_block_ipv6)}" placeholder="::" class="w-[130px] bg-field rounded-[10px] px-2 h-9 text-[14px] outline-none focus:ring-1 focus:ring-brand" />
      </div>
    </div>
    ${v.system_msg ? `<p class="text-[13px] text-muted mt-3">${esc(v.system_msg)}</p>` : ""}
  </div>`;
}

export function filters(u: Ui) {
  const v = u.view;
  const groups = [...new Set(v.filters.map((f) => f.group))];
  const status = (f: FilterView) => {
    if (f.error) return `<span class="text-danger">Erro: ${esc(f.error)}</span>`;
    if (!f.downloaded) return f.active ? (v.updating ? "Baixando…" : "Ainda não baixado") : "Não baixado";
    return `${fmtNum(f.rules)} regras · atualizado ${fmtDate(f.updated)}`;
  };
  const blocks = groups
    .map((g) =>
      section(
        g,
        v.filters
          .filter((f) => f.group === g)
          .map((f) => row({ title: esc(f.name), desc: `${esc(f.desc)}<br><span class="text-faint">${status(f)}</span>`, toggle: "filter", arg: f.key, on: f.active }))
          .join(""),
      ),
    )
    .join("");
  const e = v.engine;
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Filtros", `${fmtNum(e.total_rules)} regras carregadas: ${fmtNum(e.domain_rules)} de domínio, ${fmtNum(e.pattern_rules + e.regex_rules)} de endereço, ${fmtNum(e.rewrite_rules)} redirecionamentos, ${fmtNum(e.cosmetic_rules)} cosméticas (contadas, não aplicadas), ${fmtNum(e.skipped_rules + e.badfilter_rules)} recusadas ou desativadas.`, "settings")}
    <div class="flex gap-3 items-center">${btn(v.updating ? "Atualizando…" : "Verificar atualizações", "update-filters")}${v.busy ? `<span class="text-[13px] text-muted">Recarregando regras…</span>` : ""}</div>
    ${blocks}
  </div>`;
}

export function filteringLog(u: Ui) {
  const vd = u.verdict;
  const verdictBox = vd
    ? `<div class="mt-3 rounded-[10px] px-4 py-3 text-[14px] ${vd.action === "blocked" ? "bg-row-blocked" : vd.action === "passed" ? "bg-card" : "bg-row-allowed"}">
        <b>${{ blocked: "Bloqueado", allowed: "Liberado por exceção", allowlisted: "Liberado (lista de permissões)", rewritten: "Redirecionado", passed: "Não bloqueado" }[vd.action]}</b> · ${esc(vd.host)}${vd.answer ? ` · resposta: <span class="font-mono">${esc(vd.answer)}</span>` : ""}
        ${vd.rule ? `<div class="font-mono text-[12px] mt-1 break-all">${esc(vd.rule)}</div><div class="text-[12px] text-muted">${esc(vd.source)}</div>` : ""}
      </div>`
    : "";
  const label: Record<string, string> = { blocked: "Bloqueado", allowed: "Exceção", allowlisted: "Permitido", rewritten: "Redirecionado", passed: "Processado" };
  const rows = u.log
    .map(
      (e) => `<div class="grid grid-cols-[70px_1fr_110px_120px] gap-3 items-center px-3 py-2 text-[13px] border-b border-line ${e.action === "blocked" ? "bg-row-blocked" : e.action === "allowed" || e.action === "allowlisted" ? "bg-row-allowed" : ""}">
        <span class="text-muted leading-4">${new Date(e.ts * 1000).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" })}<span class="block text-[11px]">${label[e.action] ?? ""}</span></span>
        <span class="min-w-0"><span class="block truncate">${esc(e.url)}</span>${e.rule ? `<span class="block truncate font-mono text-[11px] text-muted">${esc(e.rule)}</span>` : ""}</span>
        <span class="truncate text-muted">${esc(e.app)}</span>
        <span class="text-right">${
          e.action === "blocked"
            ? `<button class="text-brand underline" data-act="unblock" data-arg="${esc(e.host)}">Desbloquear</button>`
            : `<button class="text-danger underline" data-act="block" data-arg="${esc(e.host)}">Bloquear</button>`
        }</span>
      </div>`,
    )
    .join("");
  const opts: [string, string][] = [["", "Todos"], ["blocked", "Bloqueados"], ["passed", "Processados"], ["allowed", "Exceções"], ["allowlisted", "Permitidos"], ["rewritten", "Redirecionados"]];
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Registro de filtragem", "Teste um endereço ou veja os mais recentes. Bloquear ou desbloquear cria uma regra de usuário.", "settings")}
    <form class="flex gap-3" data-submit="check">
      <input id="check-url" value="" placeholder="https://exemplo.com/anuncio.js ou só o domínio" class="flex-1 bg-field rounded-[10px] px-3 h-10 text-[14px] outline-none focus:ring-1 focus:ring-brand" />
      ${btn("Verificar", "check")}
    </form>
    ${verdictBox}
    <div class="flex gap-3 mt-6 mb-2 items-center">
      <input id="log-q" value="${esc(u.logQuery)}" placeholder="Pesquisar" data-input="log-q" class="flex-1 bg-field rounded-[10px] px-3 h-9 text-[14px] outline-none" />
      <select data-change="log-only" class="bg-field rounded-[10px] h-9 px-2 text-[14px]">${opts.map(([k, l]) => `<option value="${k}" ${u.logOnly === k ? "selected" : ""}>${l}</option>`).join("")}</select>
      ${btn("Atualizar", "refresh-log", "", "ghost", "h-9")}
    </div>
    <div class="rounded-[10px] border border-line overflow-hidden">${rows || `<div class="px-4 py-6 text-[14px] text-muted">Nenhuma solicitação registrada ainda.</div>`}</div>
  </div>`;
}

export function about(u: Ui) {
  const v = u.view;
  return `<div class="px-8 pt-10 pb-8">
    ${pageHead("Sobre", "", "settings")}
    <div class="flex items-center gap-4 mb-6">${icon.logo(56)}<div><div class="text-[22px] font-semibold">Escudo</div><div class="text-muted text-[14px]">Versão ${esc(v.version)}</div></div></div>
    <p class="text-[14px] text-muted max-w-[600px]">Bloqueador de anúncios, rastreadores e sites perigosos. As listas de bloqueio são baixadas de filters.adtidy.org; as regras são verificadas no seu computador e nada é enviado para fora.</p>
    <div class="mt-6 text-[13px] text-muted">Pasta de dados: <span class="font-mono">${esc(v.data_dir)}</span></div>
  </div>`;
}
