//! Built-in list against ads on streaming platforms (video and music).
//!
//! The Windows hosts file has no wildcards: `||doubleclick.net^` written there only covers
//! `doubleclick.net` itself, not `pubads.g.doubleclick.net`. So every ad host is listed by
//! its full name. Only hosts that serve ads (or ad decisions) go here, never the servers
//! that carry the video or audio itself; blocking those would stop playback. The test at
//! the bottom keeps it that way.
//!
//! Limit: YouTube, Twitch, Prime Video, Disney+ and others often stitch ads into the same
//! stream as the show ("server-side ad insertion"). Those come from the content servers
//! and cannot be told apart by name, so no hosts/DNS blocker can remove them.

pub const SOURCE: &str = "Anúncios de streaming";

/// (platforms, hosts)
pub const HOSTS: &[(&str, &[&str])] = &[
    (
        // Google Ad Manager / IMA SDK: YouTube, Globoplay, Crunchyroll and most web players
        "Google (YouTube, Globoplay, Crunchyroll, players com IMA)",
        &[
            "imasdk.googleapis.com",
            "doubleclick.net",
            "ad.doubleclick.net",
            "pubads.g.doubleclick.net",
            "securepubads.g.doubleclick.net",
            "googleads.g.doubleclick.net",
            "static.doubleclick.net",
            "cm.g.doubleclick.net",
            "2mdn.net",
            "s0.2mdn.net",
            "pagead2.googlesyndication.com",
            "tpc.googlesyndication.com",
            "googleadservices.com",
            "www.googleadservices.com",
            "www.googletagservices.com",
            "ads.youtube.com",
        ],
    ),
    (
        "Amazon (Twitch, Prime Video)",
        &[
            "amazon-adsystem.com",
            "aax.amazon-adsystem.com",
            "c.amazon-adsystem.com",
            "s.amazon-adsystem.com",
        ],
    ),
    ("Spotify", &["adeventtracker.spotify.com", "ads-fa.spotify.com"]),
    (
        "Hulu",
        &["ads.hulu.com", "ads-a-darwin.hulustream.com", "ads-e-darwin.hulustream.com", "ads-v-darwin.hulustream.com"],
    ),
    (
        // video ad servers used by Paramount+, Pluto TV, Peacock, sports and news players
        "Servidores de anúncios em vídeo",
        &[
            "fwmrm.net",
            "mssl.fwmrm.net",
            "spotxchange.com",
            "search.spotxchange.com",
            "spotx.tv",
            "spotxcdn.com",
            "springserve.com",
            "vid.springserve.com",
            "innovid.com",
            "tremorhub.com",
            "ads.tremorhub.com",
            "teads.tv",
            "a.teads.tv",
            "serving-sys.com",
            "bs.serving-sys.com",
            "adsrvr.org",
            "match.adsrvr.org",
            "insight.adsrvr.org",
            "adnxs.com",
            "ib.adnxs.com",
        ],
    ),
];

/// Every host as a `||host^` rule.
pub fn rules() -> impl Iterator<Item = String> {
    HOSTS.iter().flat_map(|(_, hosts)| hosts.iter().map(|h| format!("||{h}^")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Servers that carry the shows and songs themselves: never block these.
    const CONTENT: &[&str] = &[
        "youtube.com", "googlevideo.com", "ytimg.com", "youtubei.googleapis.com", "ggpht.com",
        "twitch.tv", "ttvnw.net", "jtvnw.net", "spotify.com", "scdn.co", "spotifycdn.com",
        "spclient.wg.spotify.com", "apresolve.spotify.com", "netflix.com", "nflxvideo.net",
        "globo.com", "globoplay.globo.com", "crunchyroll.com", "hulu.com", "hulustream.com",
        "primevideo.com", "aiv-cdn.net", "disneyplus.com", "dssott.com", "pluto.tv",
        "googleapis.com", "gstatic.com", "akamaized.net", "cloudfront.net",
    ];

    #[test]
    fn no_content_servers() {
        for (_, hosts) in HOSTS {
            for h in *hosts {
                assert!(!CONTENT.contains(h), "{h} carries content and must not be blocked");
                assert_eq!(*h, h.trim().to_lowercase(), "{h} must be a plain lowercase name");
                assert!(!h.contains('*') && !h.contains('/'), "{h}: hosts file takes plain names only");
            }
        }
    }

    #[test]
    fn no_duplicates() {
        let mut all: Vec<&str> = HOSTS.iter().flat_map(|(_, h)| h.iter().copied()).collect();
        let n = all.len();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), n);
    }
}
