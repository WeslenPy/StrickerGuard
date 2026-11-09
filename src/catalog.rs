//! Filter lists the app can subscribe to. Ids and download addresses come
//! from the original's catalog (MECHANICS.md, "Filter catalog").

use crate::engine::Category;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Standard,
    Dns,
}

#[derive(Clone, Debug, Serialize)]
pub struct FilterInfo {
    pub key: &'static str,
    pub id: u32,
    pub kind: Kind,
    pub group: &'static str,
    pub name: &'static str,
    pub desc: &'static str,
    pub category: Category,
}

impl FilterInfo {
    pub fn url(&self) -> String {
        match self.kind {
            Kind::Standard => format!("https://filters.adtidy.org/windows/filters/{}.txt", self.id),
            Kind::Dns => format!("https://filters.adtidy.org/dns/filter_{}.txt", self.id),
        }
    }
}

macro_rules! f {
    ($key:literal, $id:literal, $kind:ident, $group:literal, $cat:ident, $name:literal, $desc:literal) => {
        FilterInfo { key: $key, id: $id, kind: Kind::$kind, group: $group, name: $name, desc: $desc, category: Category::$cat }
    };
}

pub const CATALOG: &[FilterInfo] = &[
    f!("s2", 2, Standard, "Bloqueio de anúncios", Ads, "Filtro base", "Remove a maioria dos anúncios de sites em inglês e internacionais"),
    f!("s11", 11, Standard, "Bloqueio de anúncios", Ads, "Anúncios móveis", "Redes de anúncios usadas em sites e apps móveis"),
    f!("s101", 101, Standard, "Bloqueio de anúncios", Ads, "EasyList", "Lista comunitária principal contra anúncios"),
    f!("s3", 3, Standard, "Privacidade", Trackers, "Proteção contra rastreamento", "Contadores e ferramentas de análise da web"),
    f!("s17", 17, Standard, "Privacidade", Trackers, "Rastreamento de URL", "Remove parâmetros de rastreamento dos endereços"),
    f!("s118", 118, Standard, "Privacidade", Trackers, "EasyPrivacy", "Complemento de privacidade da EasyList"),
    f!("s204", 204, Standard, "Privacidade", Trackers, "Peter Lowe's Blocklist", "Servidores de anúncios e rastreamento"),
    f!("s4", 4, Standard, "Widgets sociais", Annoyances, "Redes sociais", "Botões de curtir e compartilhar"),
    f!("s18", 18, Standard, "Aborrecimentos", Annoyances, "Avisos de cookies", "Formulários de consentimento de cookies"),
    f!("s19", 19, Standard, "Aborrecimentos", Annoyances, "Pop-ups", "Pop-ups desnecessários para o site funcionar"),
    f!("s20", 20, Standard, "Aborrecimentos", Annoyances, "Banners de apps móveis", "Banners que promovem o app do site"),
    f!("s21", 21, Standard, "Aborrecimentos", Annoyances, "Outros aborrecimentos", "Elementos irritantes que não entram nas outras categorias"),
    f!("s22", 22, Standard, "Aborrecimentos", Annoyances, "Widgets", "Assistentes online e chats de suporte"),
    f!("s208", 208, Standard, "Segurança", Security, "URLs maliciosas", "Domínios usados para espalhar malware"),
    f!("s255", 255, Standard, "Segurança", Security, "Phishing", "Sites de phishing conhecidos"),
    f!("s10", 10, Standard, "Outros", Other, "Liberar anúncios de pesquisa", "Desbloqueia anúncios de buscadores e autopromoção de sites"),
    f!("s9", 9, Standard, "Idiomas", Ads, "Espanhol / Português", "Anúncios em sites em espanhol e português"),
    f!("s124", 124, Standard, "Idiomas", Ads, "EasyList Portuguese", "Complemento para sites em português"),
    f!("s6", 6, Standard, "Idiomas", Ads, "Alemão", "Anúncios em sites em alemão"),
    f!("s16", 16, Standard, "Idiomas", Ads, "Francês", "Anúncios em sites em francês"),
    f!("d1", 1, Dns, "DNS", Dns, "Filtro DNS", "Lista combinada de anúncios, rastreadores e redes sociais para DNS"),
    f!("d3", 3, Dns, "DNS", Dns, "Peter Lowe's Blocklist (DNS)", "Servidores de anúncios e rastreamento"),
    f!("d33", 33, Dns, "DNS", Dns, "Steven Black's List", "Arquivo hosts unificado (adware + malware)"),
    f!("d11", 11, Dns, "DNS", Security, "URLHaus", "Sites maliciosos da base URLhaus"),
    f!("d30", 30, Dns, "DNS", Security, "Phishing (PhishTank e OpenPhish)", "Sites de phishing"),
];

pub fn find(key: &str) -> Option<&'static FilterInfo> {
    CATALOG.iter().find(|f| f.key == key)
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsServer {
    pub id: &'static str,
    pub name: &'static str,
    pub desc: &'static str,
    pub addresses: &'static [&'static str],
}

/// Plain-DNS servers offered by the original (settings.json DnsProviders).
pub const DNS_SERVERS: &[DnsServer] = &[
    DnsServer { id: "system", name: "Padrão do sistema", desc: "Usa os servidores DNS do seu provedor de internet", addresses: &[] },
    DnsServer { id: "block", name: "DNS com bloqueio de anúncios", desc: "Bloqueia anúncios e rastreadores", addresses: &["94.140.14.14", "94.140.15.15"] },
    DnsServer { id: "family", name: "DNS família", desc: "Bloqueia também conteúdo adulto e ativa a pesquisa segura", addresses: &["94.140.14.15", "94.140.15.16"] },
    DnsServer { id: "nofilter", name: "DNS sem filtragem", desc: "Conexão segura e confiável, sem bloqueios", addresses: &["94.140.14.140", "94.140.14.141"] },
    DnsServer { id: "google", name: "Google DNS", desc: "Serviço DNS público do Google", addresses: &["8.8.8.8", "8.8.4.4"] },
    DnsServer { id: "cloudflare", name: "Cloudflare DNS", desc: "Serviço DNS público da Cloudflare", addresses: &["1.1.1.1", "1.0.0.1"] },
    DnsServer { id: "cf-malware", name: "Cloudflare – bloqueio de malware", desc: "Bloqueia malware", addresses: &["1.1.1.2", "1.0.0.2"] },
    DnsServer { id: "cf-family", name: "Cloudflare – malware e adulto", desc: "Bloqueia malware e conteúdo adulto", addresses: &["1.1.1.3", "1.0.0.3"] },
    DnsServer { id: "opendns", name: "OpenDNS", desc: "Bloqueia malware e phishing", addresses: &["208.67.222.222", "208.67.220.220"] },
    DnsServer { id: "opendns-family", name: "OpenDNS FamilyShield", desc: "Bloqueia conteúdo adulto", addresses: &["208.67.222.123", "208.67.220.123"] },
    DnsServer { id: "quad9", name: "Quad9", desc: "Bloqueia domínios maliciosos", addresses: &["9.9.9.9", "149.112.112.112"] },
];

pub fn dns_server(id: &str) -> &'static DnsServer {
    DNS_SERVERS.iter().find(|s| s.id == id).unwrap_or(&DNS_SERVERS[0])
}
