//! The console's typefaces, in one place.
//!
//! The console sets words in EB Garamond (roman and italic) and data in
//! IBM Plex Mono. Pages carry a policy that loads nothing from anywhere
//! else, so the fonts the crate bundles travel with the page: inlined as
//! `data:` URIs in a single-file page (an exported run, an evidence
//! report), or served from the console's own origin with a year-long
//! immutable cache (Pragmatic Server and `pragmatic serve`, whose policy
//! then allows `font-src 'self'`).
//!
//! The crate bundles all four faces the design uses, as the Latin subsets
//! Google Fonts serves, unmodified: EB Garamond roman and italic, and IBM
//! Plex Mono regular and medium. Every face loads from its bundled file
//! only, never from a copy installed on the reader's machine (which may be
//! another version with other metrics), so a page looks the same
//! everywhere, as the website does. While a file loads, Georgia (scaled to
//! Garamond's metrics) or Menlo (scaled to Plex Mono's x-height) stands
//! in, so text barely moves.
//!
//! Both families are under the SIL Open Font License 1.1, whose text is in
//! `assets/fonts/` (`OFL-EBGaramond.txt`, `OFL-IBMPlexMono.txt`), and the
//! stylesheet repeats each font's copyright line in a comment. IBM Plex
//! has the Reserved Font Name "Plex": its files are shipped exactly as
//! distributed and keep their family name. Adding a font is one line in
//! [`BUNDLED`]: the file in `assets/fonts/`, its family, style, weight and
//! copyright line.

use std::sync::OnceLock;

use pragmatic::encoding::{base64_encode, hex_encode};
use pragmatic::sha256::sha256;

/// A font file the crate ships.
#[derive(Debug)]
pub struct BundledFont {
    /// The CSS family it provides (one of the faces in [`FACES`]).
    pub family: &'static str,
    /// `normal` or `italic`.
    pub style: &'static str,
    /// The CSS weight, `400` or `500`.
    pub weight: u16,
    /// The file's name in `assets/fonts/`.
    pub file: &'static str,
    /// Its copyright line, repeated in the stylesheet.
    pub copyright: &'static str,
    pub bytes: &'static [u8],
}

/// One bundled font: `font!(family, style, weight, file, copyright)`.
macro_rules! font {
    ($family:literal, $style:literal, $weight:literal, $file:literal, $copyright:expr) => {
        BundledFont {
            family: $family,
            style: $style,
            weight: $weight,
            file: $file,
            copyright: $copyright,
            bytes: include_bytes!(concat!("../assets/fonts/", $file)),
        }
    };
}

const GARAMOND: &str =
    "Copyright 2017 The EB Garamond Project Authors (https://github.com/octaviopardo/EBGaramond12)";
const PLEX: &str = "Copyright \u{a9} 2017 IBM Corp. with Reserved Font Name \"Plex\"";

/// The fonts the crate ships. A `static`, so each font has one address
/// (its served name and data URI are looked up by it).
pub static BUNDLED: &[BundledFont] = &[
    font!(
        "EB Garamond",
        "normal",
        400,
        "eb-garamond-latin.woff2",
        GARAMOND
    ),
    font!(
        "EB Garamond",
        "italic",
        400,
        "eb-garamond-italic-latin.woff2",
        GARAMOND
    ),
    font!(
        "IBM Plex Mono",
        "normal",
        400,
        "ibm-plex-mono-400-latin.woff2",
        PLEX
    ),
    font!(
        "IBM Plex Mono",
        "normal",
        500,
        "ibm-plex-mono-500-latin.woff2",
        PLEX
    ),
];

/// Where a page finds the bundled fonts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fonts<'a> {
    /// Inlined in the page as `data:` URIs (a single-file page; its policy
    /// allows `font-src data:`).
    Inline,
    /// Served by the console itself under this path prefix, such as
    /// `/console/assets/` (its policy allows `font-src 'self'`).
    Served(&'a str),
}

impl BundledFont {
    /// The name the font is served under: its file name with the first 12
    /// hex digits of its SHA-256, so a changed font gets a new URL and the
    /// old one can be cached for good.
    pub fn served_name(&self) -> &'static str {
        static NAMES: OnceLock<Vec<String>> = OnceLock::new();
        let names = NAMES.get_or_init(|| {
            BUNDLED
                .iter()
                .map(|f| {
                    let hash = hex_encode(&sha256(f.bytes));
                    match f.file.rsplit_once('.') {
                        Some((stem, ext)) => format!("{stem}.{}.{ext}", &hash[..12]),
                        None => format!("{}.{}", f.file, &hash[..12]),
                    }
                })
                .collect()
        });
        let i = BUNDLED
            .iter()
            .position(|f| std::ptr::eq(f, self))
            .unwrap_or(0);
        names[i].as_str()
    }
}

/// The bundled font served under `name` ([`BundledFont::served_name`]).
pub fn served(name: &str) -> Option<&'static BundledFont> {
    BUNDLED.iter().find(|f| f.served_name() == name)
}

/// The `Content-Type` of a served font.
pub const FONT_TYPE: &str = "font/woff2";

/// The `Cache-Control` of a served font: its URL changes with its bytes.
pub const FONT_CACHE: &str = "public, max-age=31536000, immutable";

fn data_uri(f: &BundledFont) -> &'static str {
    static URIS: OnceLock<Vec<String>> = OnceLock::new();
    let uris = URIS.get_or_init(|| {
        BUNDLED
            .iter()
            .map(|f| format!("data:font/woff2;base64,{}", base64_encode(f.bytes)))
            .collect()
    });
    let i = BUNDLED.iter().position(|b| std::ptr::eq(b, f)).unwrap_or(0);
    uris[i].as_str()
}

/// The `@font-face` rules of a page: one per bundled file.
pub fn font_faces(fonts: Fonts<'_>) -> String {
    let mut out =
        String::from("/* Fonts: SIL Open Font License 1.1 (https://openfontlicense.org).\n");
    for f in BUNDLED {
        out.push_str(&format!(
            "   {} {} {}: {}\n",
            f.family, f.style, f.weight, f.copyright
        ));
    }
    out.push_str("*/\n");
    for f in BUNDLED {
        let url = match fonts {
            Fonts::Inline => data_uri(f).to_string(),
            // The prefix is the console's own literal path; the name is a
            // fixed file name and hex.
            Fonts::Served(prefix) => format!("{prefix}{}", f.served_name()),
        };
        out.push_str(&format!(
            "@font-face {{ font-family: '{}'; font-style: {}; font-weight: {}; \
             font-display: swap; src: url({url}) format('woff2'); }}\n",
            f.family, f.style, f.weight
        ));
    }
    // While EB Garamond loads (or where it is missing), Georgia stands in,
    // scaled to Garamond's width and line metrics, as on the website.
    out.push_str(
        "@font-face { font-family: 'Garamond Fallback'; src: local('Georgia'); \
         font-style: normal; font-weight: 400; size-adjust: 86%; ascent-override: 117%; \
         descent-override: 35%; line-gap-override: 0%; }\n\
         @font-face { font-family: 'Garamond Fallback'; src: local('Georgia Italic'), \
         local('Georgia-Italic'); font-style: italic; font-weight: 400; size-adjust: 81.3%; \
         ascent-override: 124%; descent-override: 37%; line-gap-override: 0%; }\n",
    );
    // While IBM Plex Mono loads, Menlo (macOS) or DejaVu Sans Mono (Linux)
    // stands in, scaled to Plex Mono's x-height (0.516 against their
    // 0.547), so data in a line of Garamond is not set larger than the
    // design draws it.
    out.push_str(
        "@font-face { font-family: 'Mono Fallback'; src: local('Menlo-Regular'), \
         local('Menlo Regular'), local('Menlo'), local('DejaVuSansMono'), \
         local('DejaVu Sans Mono'); font-style: normal; font-weight: 400; \
         size-adjust: 94.3%; }\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundled_font_is_an_unmodified_woff2() {
        for f in BUNDLED {
            assert_eq!(&f.bytes[..4], b"wOF2", "{}", f.file);
            assert!(served(f.served_name()).is_some());
            assert!(f.served_name().ends_with(".woff2"));
        }
        assert!(
            served("eb-garamond-latin.woff2").is_none(),
            "names carry a hash"
        );
        let faces: Vec<(&str, &str, u16)> = BUNDLED
            .iter()
            .map(|f| (f.family, f.style, f.weight))
            .collect();
        assert_eq!(
            faces,
            [
                ("EB Garamond", "normal", 400),
                ("EB Garamond", "italic", 400),
                ("IBM Plex Mono", "normal", 400),
                ("IBM Plex Mono", "normal", 500),
            ]
        );
    }

    #[test]
    fn faces_load_from_the_bundled_files_only() {
        let css = font_faces(Fonts::Served("/console/assets/"));
        for f in BUNDLED {
            let face = css
                .lines()
                .find(|l| {
                    l.contains(&format!("'{}'", f.family))
                        && l.contains(&format!("font-style: {};", f.style))
                        && l.contains(&format!("font-weight: {};", f.weight))
                })
                .unwrap_or_else(|| panic!("no face for {}", f.file));
            assert!(face.contains(&format!("url(/console/assets/{})", f.served_name())));
            assert!(!face.contains("local("), "{face}");
            assert!(css.contains(f.copyright));
        }
        let inline = font_faces(Fonts::Inline);
        assert_eq!(
            inline.matches("url(data:font/woff2;base64,d09GMg").count(),
            4
        );
        assert!(css.contains("SIL Open Font License"));
        assert!(css.contains("Reserved Font Name \"Plex\""));
    }
}
