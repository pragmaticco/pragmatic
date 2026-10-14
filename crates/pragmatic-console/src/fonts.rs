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
//! Every face first tries the fonts installed on the reader's machine
//! (`local()`), then the bundled file if there is one. A face with no
//! bundled file and no installed font falls through the family stack to
//! Georgia (scaled to Garamond's metrics) or the system monospace.
//!
//! Adding a font is one line in [`BUNDLED`]: the file in
//! `assets/fonts/`, its family and its style. Every bundled font is under
//! the SIL Open Font License 1.1 (`assets/fonts/OFL.txt`), which the
//! stylesheet repeats in a comment with each font's copyright line.

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
    /// The file's name in `assets/fonts/`.
    pub file: &'static str,
    /// Its copyright line, repeated in the stylesheet.
    pub copyright: &'static str,
    pub bytes: &'static [u8],
}

/// One bundled font: `font!(family, style, file, copyright)`.
macro_rules! font {
    ($family:literal, $style:literal, $file:literal, $copyright:literal) => {
        BundledFont {
            family: $family,
            style: $style,
            file: $file,
            copyright: $copyright,
            bytes: include_bytes!(concat!("../assets/fonts/", $file)),
        }
    };
}

/// The fonts the crate ships. EB Garamond Italic and IBM Plex Mono are
/// added here, one line each, once their files are in `assets/fonts/`.
pub const BUNDLED: &[BundledFont] = &[font!(
    "EB Garamond",
    "normal",
    "eb-garamond-latin.woff2",
    "Copyright 2017 The EB Garamond Project Authors (https://github.com/octaviopardo/EBGaramond12)"
)];

/// The faces the stylesheet declares, and the names an installed copy of
/// each goes by (full name and PostScript name).
struct Face {
    family: &'static str,
    style: &'static str,
    local: &'static [&'static str],
}

const FACES: &[Face] = &[
    Face {
        family: "EB Garamond",
        style: "normal",
        local: &["EB Garamond Regular", "EBGaramond-Regular", "EB Garamond"],
    },
    Face {
        family: "EB Garamond",
        style: "italic",
        local: &["EB Garamond Italic", "EBGaramond-Italic"],
    },
    Face {
        family: "IBM Plex Mono",
        style: "normal",
        local: &[
            "IBM Plex Mono",
            "IBMPlexMono",
            "IBM Plex Mono Regular",
            "IBMPlexMono-Regular",
        ],
    },
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

/// The `@font-face` rules of a page.
pub fn font_faces(fonts: Fonts<'_>) -> String {
    let mut out =
        String::from("/* Fonts: SIL Open Font License 1.1 (https://openfontlicense.org).\n");
    for f in BUNDLED {
        out.push_str(&format!("   {} {}: {}\n", f.family, f.style, f.copyright));
    }
    out.push_str("*/\n");
    for face in FACES {
        let mut src: Vec<String> = face.local.iter().map(|n| format!("local('{n}')")).collect();
        for f in BUNDLED
            .iter()
            .filter(|f| f.family == face.family && f.style == face.style)
        {
            let url = match fonts {
                Fonts::Inline => data_uri(f).to_string(),
                // The prefix is the console's own literal path; the name is
                // hex and a fixed file name.
                Fonts::Served(prefix) => format!("{prefix}{}", f.served_name()),
            };
            src.push(format!("url({url}) format('woff2')"));
        }
        out.push_str(&format!(
            "@font-face {{ font-family: '{}'; font-style: {}; font-weight: 400; \
             font-display: swap; src: {}; }}\n",
            face.family,
            face.style,
            src.join(", ")
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundled_font_is_a_woff2_with_a_face() {
        for f in BUNDLED {
            assert_eq!(&f.bytes[..4], b"wOF2", "{}", f.file);
            assert!(FACES
                .iter()
                .any(|face| face.family == f.family && face.style == f.style));
            assert!(served(f.served_name()).is_some());
            assert!(f.served_name().ends_with(".woff2"));
        }
        assert!(
            served("eb-garamond-latin.woff2").is_none(),
            "names carry a hash"
        );
    }

    #[test]
    fn faces_try_installed_fonts_first() {
        let css = font_faces(Fonts::Served("/console/assets/"));
        let italic = css
            .lines()
            .find(|l| l.contains("font-style: italic") && l.contains("EB Garamond'"))
            .unwrap();
        assert!(italic.contains("local('EB Garamond Italic'), local('EBGaramond-Italic')"));
        let mono = css.lines().find(|l| l.contains("IBM Plex Mono'")).unwrap();
        assert!(mono.contains("local('IBM Plex Mono'), local('IBMPlexMono')"));
        let roman = css
            .lines()
            .find(|l| l.contains("EB Garamond'") && l.contains("font-style: normal"))
            .unwrap();
        let local = roman.find("local(").unwrap();
        let url = roman
            .find("url(/console/assets/eb-garamond-latin.")
            .unwrap();
        assert!(local < url);
        assert!(font_faces(Fonts::Inline).contains("url(data:font/woff2;base64,d09GMg"));
        assert!(css.contains("SIL Open Font License"));
    }
}
