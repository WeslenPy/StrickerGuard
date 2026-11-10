import { invoke } from "@tauri-apps/api/core";

export interface AppEntry {
  name: string;
  exe: string;
  filtered: boolean;
}

export interface Settings {
  protection_enabled: boolean;
  ad_blocking: boolean;
  basic_protection: boolean;
  block_search_ads: boolean;
  language_specific: boolean;
  language_auto: boolean;
  user_rules_enabled: boolean;
  tracking_protection: boolean;
  block_trackers: boolean;
  strip_url: boolean;
  hide_search_queries: boolean;
  do_not_track: boolean;
  block_webrtc: boolean;
  block_push_api: boolean;
  block_location_api: boolean;
  annoyance_blocking: boolean;
  block_cookie_notices: boolean;
  block_popups: boolean;
  block_mobile_app_banners: boolean;
  block_widgets: boolean;
  block_other_annoyances: boolean;
  browsing_security: boolean;
  security_notifications: boolean;
  security_sound: boolean;
  dns_protection: boolean;
  dns_filters: boolean;
  dns_server: string;
  custom_block_ipv4: string;
  custom_block_ipv6: string;
  parental_control: boolean;
  safe_search: boolean;
  block_adult: boolean;
  theme: string;
  statistics_enabled: boolean;
  auto_update: boolean;
  filters_update_hours: number;
  apply_to_system: boolean;
  sidebar_expanded: boolean;
  banner_dismissed: boolean;
  extra_filters: string[];
  user_rules: string[];
  dns_user_rules: string[];
  allowlist: string[];
  parental_blocklist: string[];
  apps: AppEntry[];
}

export type BoolKey = { [K in keyof Settings]: Settings[K] extends boolean ? K : never }[keyof Settings];

export interface FilterView {
  key: string;
  id: number;
  kind: "standard" | "dns";
  group: string;
  name: string;
  desc: string;
  url: string;
  active: boolean;
  downloaded: boolean;
  updated: number | null;
  rules: number;
  error: string | null;
}

export interface DnsServer {
  id: string;
  name: string;
  desc: string;
  addresses: string[];
}

export interface View {
  settings: Settings;
  filters: FilterView[];
  dns_servers: DnsServer[];
  engine: {
    total_rules: number;
    domain_rules: number;
    pattern_rules: number;
    regex_rules: number;
    cosmetic_rules: number;
    skipped_rules: number;
    badfilter_rules: number;
    rewrite_rules: number;
  };
  admin: boolean;
  hosts_count: number;
  run_on_startup: boolean;
  busy: boolean;
  updating: boolean;
  system_msg: string | null;
  version: string;
  data_dir: string;
}

export interface Verdict {
  action: "blocked" | "allowed" | "allowlisted" | "rewritten" | "passed";
  host: string;
  rule: string | null;
  source: string | null;
  category: string | null;
  answer: string | null;
}

export interface LogEntry {
  ts: number;
  url: string;
  host: string;
  action: string;
  rule: string | null;
  source: string | null;
  category: string | null;
  app: string;
}

export interface Stats {
  total: number;
  ads: number;
  trackers: number;
  blocked: number;
  buckets: [number, number, number][];
  top_blocked: [string, number][];
  top_domains: [string, number][];
  apps: [string, number, number][];
}

export const api = {
  state: () => invoke<View>("get_state"),
  update: (patch: Partial<Settings>) => invoke<View>("update_settings", { patch }),
  setFilter: (key: string, on: boolean) => invoke<View>("set_filter", { key, on }),
  updateFilters: () => invoke<View>("update_filters"),
  check: (url: string) => invoke<Verdict>("check_url", { url }),
  log: (limit: number, query: string, only: string) => invoke<LogEntry[]>("get_log", { limit, query, only }),
  stats: (period: string) => invoke<Stats>("get_stats", { period }),
  clearStats: () => invoke<void>("clear_stats"),
  setStartup: (on: boolean) => invoke<View>("set_startup", { on }),
  relaunchAdmin: () => invoke<void>("relaunch_admin"),
  testDns: (id: string) => invoke<[string, number | null][]>("test_dns", { id }),
  open: (url: string) => invoke<void>("open_link", { url }),
  quit: (keepFiltering: boolean) => invoke<void>("quit_app", { keepFiltering }),
};
