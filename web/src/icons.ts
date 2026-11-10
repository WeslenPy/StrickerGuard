// Simple line icons drawn for this app (24×24, stroke = currentColor).
const svg = (body: string, size = 24) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`;

export const icon = {
  // StrickerGuard mark: shield in "Sinal" lime with an S monogram.
  logo: (s = 24) =>
    `<svg width="${s}" height="${s}" viewBox="0 0 24 24"><path d="M12 1.8 3.6 4.9v6.6c0 5 3.4 9 8.4 10.9 5-1.9 8.4-5.9 8.4-10.9V4.9z" fill="#C5F04A"/><path d="M15.4 8.6c-.6-.8-1.8-1.3-3.3-1.3-2 0-3.4 1-3.4 2.4 0 3.3 7 1.8 7 5 0 1.5-1.5 2.6-3.6 2.6-1.6 0-2.9-.6-3.6-1.6" fill="none" stroke="#12160A" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  home: (s = 24) => svg(`<path d="M4 10.5 12 4l8 6.5V20h-5v-6h-6v6H4z"/>`, s),
  shield: (s = 24) => svg(`<path d="M12 3 5 5.8v5.7c0 4.2 2.9 7.6 7 9 4.1-1.4 7-4.8 7-9V5.8z"/><path d="m9 12 2.2 2.2L15.5 10"/>`, s),
  pie: (s = 24) => svg(`<path d="M11 4.1A8 8 0 1 0 19.9 13H11z"/><path d="M14 3.2V10h6.8A7.5 7.5 0 0 0 14 3.2z"/>`, s),
  apps: (s = 24) => svg(`<rect x="4" y="13.5" width="6.5" height="6.5" rx="1"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1"/><path d="M7.25 4 11 10.5H3.5z"/><circle cx="16.75" cy="7.25" r="3.25"/>`, s),
  gear: (s = 24) =>
    svg(`<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>`, s),
  refresh: (s = 24) => svg(`<path d="M19.5 9.5A8 8 0 0 0 5 7.5M4.5 14.5A8 8 0 0 0 19 16.5"/><path d="M5 3.5v4h4M19 20.5v-4h-4"/>`, s),
  chevronRight: (s = 20) => svg(`<path d="m9 6 6 6-6 6"/>`, s),
  chevronLeft: (s = 20) => svg(`<path d="m15 6-6 6 6 6"/>`, s),
  back: (s = 24) => svg(`<path d="M19 12H5M11 6l-6 6 6 6"/>`, s),
  check: (s = 24) => svg(`<path d="m5 12.5 4.5 4.5L19 7.5"/>`, s),
  close: (s = 20) => svg(`<path d="M6 6l12 12M18 6 6 18"/>`, s),
  alert: (s = 20) => svg(`<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.2v.1"/>`, s),
  // feature icons for the home screen
  noAds: (s = 26) => svg(`<rect x="3.5" y="6" width="17" height="12" rx="1.5"/><path d="M4 20 20 4"/>`, s),
  noTrack: (s = 26) => svg(`<path d="M2.5 12S6 6 12 6s9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6z"/><circle cx="12" cy="12" r="2.6"/><path d="M4 20 20 4"/>`, s),
  annoy: (s = 26) => svg(`<path d="M4 5h16v11H9l-5 4z"/><path d="M12 8v4M12 14.2v.1"/>`, s),
  dns: (s = 26) => svg(`<rect x="4" y="4.5" width="16" height="6" rx="1.5"/><rect x="4" y="13.5" width="16" height="6" rx="1.5"/><path d="M7.5 7.5h.1M7.5 16.5h3"/>`, s),
  security: (s = 24) => svg(`<path d="M12 3 5 5.8v5.7c0 4.2 2.9 7.6 7 9 4.1-1.4 7-4.8 7-9V5.8z"/><path d="M12 8v4.5M12 15.3v.1"/>`, s),
  parental: (s = 24) => svg(`<circle cx="8.5" cy="7" r="2.5"/><circle cx="16.5" cy="9" r="2"/><path d="M4 19v-2.5A3.5 3.5 0 0 1 7.5 13h2a3.5 3.5 0 0 1 3.5 3.5V19M14 19v-2a3 3 0 0 1 3-3h0a3 3 0 0 1 3 3v2"/>`, s),
  globe: (s = 24) => svg(`<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>`, s),
  list: (s = 24) => svg(`<path d="M9 6h11M9 12h11M9 18h11M4.5 6h.1M4.5 12h.1M4.5 18h.1"/>`, s),
  edit: (s = 24) => svg(`<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/>`, s),
  info: (s = 24) => svg(`<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.8v.1"/>`, s),
  filter: (s = 24) => svg(`<path d="M4 5h16l-6 7.5V19l-4 1.5v-8z"/>`, s),
  log: (s = 24) => svg(`<rect x="5" y="3.5" width="14" height="17" rx="1.5"/><path d="M8.5 8h7M8.5 12h7M8.5 16h4"/>`, s),
  window: (s = 24) => svg(`<rect x="3.5" y="4.5" width="17" height="15" rx="1.5"/><path d="M3.5 8.5h17"/>`, s),
  ai: (s = 24) => svg(`<path d="M12 3.5 13.9 9 19.5 10.9 13.9 12.8 12 18.5 10.1 12.8 4.5 10.9 10.1 9z"/><path d="M18.5 3.5v3M17 5h3M5.5 16.5v3M4 18h3"/>`, s),
  plus: (s = 20) => svg(`<path d="M12 5v14M5 12h14"/>`, s),
  trash: (s = 20) => svg(`<path d="M4.5 7h15M9.5 7V4.5h5V7M6.5 7l1 13h9l1-13"/>`, s),
  // window caption
  winMin: `<svg width="10" height="10" viewBox="0 0 10 10"><path d="M0 5h10" stroke="currentColor"/></svg>`,
  winMax: `<svg width="10" height="10" viewBox="0 0 10 10"><rect x=".5" y=".5" width="9" height="9" fill="none" stroke="currentColor"/></svg>`,
  winClose: `<svg width="10" height="10" viewBox="0 0 10 10"><path d="M0 0l10 10M10 0 0 10" stroke="currentColor" stroke-width="1.1"/></svg>`,
};
