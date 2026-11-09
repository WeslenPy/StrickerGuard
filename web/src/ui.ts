// Small HTML helpers shared by every screen.
import { icon } from "./icons";

export const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export const sw = (on: boolean, act: string, arg = "", disabled = false) =>
  `<button class="switch" role="switch" aria-checked="${on}" data-on="${on}" data-disabled="${disabled}" data-act="${act}" data-arg="${esc(arg)}"></button>`;

/** A settings row: title, description and a switch (or a chevron when it opens a sub-screen). */
export function row(opts: {
  title: string;
  desc?: string;
  ico?: string;
  on?: boolean;
  toggle?: string;
  arg?: string;
  open?: string;
  disabled?: boolean;
  extra?: string;
}) {
  const clickable = opts.open ? `data-act="go" data-arg="${esc(opts.open)}" role="button"` : "";
  return `<div class="flex items-center gap-4 px-4 py-3.5 min-h-[64px] border-b border-line last:border-b-0 ${
    opts.open ? "cursor-pointer hover:bg-card" : ""
  }" ${clickable}>
    ${opts.ico ? `<div class="text-brand shrink-0 w-10 h-10 rounded-[10px] bg-card-hover/60 flex items-center justify-center">${opts.ico}</div>` : ""}
    <div class="flex-1 min-w-0">
      <div class="text-[15px] leading-5">${opts.title}</div>
      ${opts.desc ? `<div class="text-[13px] leading-[18px] text-muted mt-0.5">${opts.desc}</div>` : ""}
      ${opts.extra ?? ""}
    </div>
    ${opts.toggle ? `<div data-stop>${sw(!!opts.on, opts.toggle, opts.arg ?? "", opts.disabled)}</div>` : ""}
    ${opts.open && !opts.toggle ? `<div class="text-faint shrink-0">${icon.chevronRight()}</div>` : ""}
  </div>`;
}

export const pageHead = (title: string, desc = "", back = "") => `
  <div class="flex items-start gap-3 mb-6">
    ${back ? `<button class="mt-1 text-ink hover:text-brand" data-act="go" data-arg="${back}" aria-label="Voltar">${icon.back()}</button>` : ""}
    <div class="flex-1">
      <h1 class="text-[26px] font-semibold leading-8">${title}</h1>
      ${desc ? `<p class="text-[14px] text-muted mt-1.5 max-w-[620px]">${desc}</p>` : ""}
    </div>
  </div>`;

export const btn = (label: string, act: string, arg = "", kind: "main" | "ghost" | "danger" = "main", extra = "") => {
  const cls =
    kind === "main"
      ? "bg-accent hover:bg-accent-hover active:bg-accent-pressed text-on-accent"
      : kind === "danger"
        ? "bg-danger hover:opacity-90 text-white"
        : "border border-line hover:bg-card text-ink";
  return `<button class="${cls} rounded-full px-5 h-10 text-[14px] font-semibold transition-colors ${extra}" data-act="${act}" data-arg="${esc(arg)}">${label}</button>`;
};

export const fmtDate = (ts: number | null) => {
  if (!ts) return "nunca";
  return new Date(ts * 1000).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
};

export const fmtNum = (n: number) => n.toLocaleString("pt-BR");
