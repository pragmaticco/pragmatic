//! `#[pragmatic::durable]` - mark an agent function as a durable program.
//!
//! The macro does one thing, and it matters: it injects a `program_marker`
//! call at the top of the body, naming the function and its version. The
//! marker is journaled on the branch that calls the function and *checked*
//! on replay, so a run recorded under one version of your agent refuses to
//! replay under another (unless the run's code-change policy accepts it):
//! assumption A2 ("the same term is replayed") becomes an enforced property
//! instead of a footgun.
//!
//! The version is a stable hash of the function's source tokens, or the
//! explicit `version` you give, which lets you change the source (a comment,
//! a refactor) without changing the recorded identity:
//!
//! ```ignore
//! #[pragmatic::durable]
//! fn research(ctx: &mut Ctx) -> Result<Value, Fault> {
//!     let plan = ctx.oracle("plan the task")?;   // journaled
//!     // ...
//! }
//!
//! #[pragmatic::durable(version = "2")]
//! fn summarize(ctx: &mut Ctx) -> Result<Value, Fault> { /* ... */ }
//! ```
//!
//! Requirements: the function's **first parameter** must be the `&mut Ctx`
//! (any binding name), and it must return `Result<_, Fault>` (the marker uses
//! `?`). The macro is a token-level transform with zero dependencies - no
//! syn, no quote.

use proc_macro::{Delimiter, Group, TokenStream, TokenTree};

/// FNV-1a over the function's token text: cheap, stable across compilations
/// of identical source, and any edit to the body or signature changes it.
fn fnv1a(text: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in text.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Extract the binding name of the first parameter from the signature's
/// parenthesized argument list (e.g. `ctx` from `(ctx: &mut Ctx, depth: u32)`,
/// handling an optional leading `mut`).
fn first_param_name(args: &Group) -> Option<String> {
    let mut last_ident: Option<String> = None;
    for tt in args.stream() {
        match tt {
            TokenTree::Ident(i) => {
                let s = i.to_string();
                if s != "mut" {
                    last_ident = Some(s);
                }
            }
            TokenTree::Punct(p) if p.as_char() == ':' => return last_ident,
            _ => {}
        }
    }
    None
}

/// The explicit version in `version = "..."`, `None` for an empty
/// attribute, or an error message for anything else.
fn explicit_version(attr: TokenStream) -> Result<Option<String>, &'static str> {
    const USAGE: &str = "#[pragmatic::durable] takes no arguments or `version = \"...\"`";
    let tokens: Vec<TokenTree> = attr.into_iter().collect();
    match tokens.as_slice() {
        [] => Ok(None),
        [TokenTree::Ident(key), TokenTree::Punct(eq), TokenTree::Literal(lit)]
            if key.to_string() == "version" && eq.as_char() == '=' =>
        {
            let text = lit.to_string();
            match text
                .strip_prefix('"')
                .and_then(|t| t.strip_suffix('"'))
                .filter(|t| !t.is_empty() && !t.contains('\\'))
            {
                Some(v) => Ok(Some(v.to_string())),
                None => Err("the durable version must be a non-empty plain string literal"),
            }
        }
        _ => Err(USAGE),
    }
}

/// See the crate docs. Applied to a `fn` whose first parameter is
/// `&mut pragmatic::Ctx` (or `&mut pragmatic::AsyncCtx`).
#[proc_macro_attribute]
pub fn durable(attr: TokenStream, item: TokenStream) -> TokenStream {
    let version = match explicit_version(attr) {
        Ok(v) => v,
        Err(msg) => return err(&item, msg),
    };

    let tokens: Vec<TokenTree> = item.clone().into_iter().collect();

    // The program hash covers the entire item, signature and body, unless
    // an explicit version names the program instead.
    let hash = version.unwrap_or_else(|| format!("{:016x}", fnv1a(&item.to_string())));

    // Find the function name: the ident right after the `fn` keyword.
    let mut fn_name: Option<String> = None;
    for pair in tokens.windows(2) {
        if let (TokenTree::Ident(kw), TokenTree::Ident(name)) = (&pair[0], &pair[1]) {
            if kw.to_string() == "fn" {
                fn_name = Some(name.to_string());
                break;
            }
        }
    }
    let Some(fn_name) = fn_name else {
        return err(&item, "#[pragmatic::durable] must be applied to a function");
    };

    // The argument list: the first parenthesized group after the fn name.
    let ctx_name = tokens
        .iter()
        .find_map(|tt| match tt {
            TokenTree::Group(g) if g.delimiter() == Delimiter::Parenthesis => Some(g),
            _ => None,
        })
        .and_then(first_param_name);
    let Some(ctx_name) = ctx_name else {
        return err(
            &item,
            "#[pragmatic::durable] requires the first parameter to be the `&mut Ctx`",
        );
    };

    // The body: the final brace-delimited group of the item.
    let body_index = tokens
        .iter()
        .rposition(|tt| matches!(tt, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace));
    let Some(body_index) = body_index else {
        return err(
            &item,
            "#[pragmatic::durable] requires a function with a body",
        );
    };
    let body = match &tokens[body_index] {
        TokenTree::Group(g) => g.stream(),
        _ => unreachable!("checked by rposition"),
    };

    // New body: `{ ctx.program_marker("name", "hash")?; <original body> }`.
    // The marker journals the program identity on the calling context's
    // branch on record and checks it on replay; `?` surfaces a refused
    // change as a JournalDesync fault.
    let marker: TokenStream = format!("{ctx_name}.program_marker({fn_name:?}, {hash:?})?;")
        .parse()
        .expect("marker statement parses");
    let mut new_body = TokenStream::new();
    new_body.extend(marker);
    new_body.extend(body);

    let mut out = TokenStream::new();
    for (i, tt) in tokens.into_iter().enumerate() {
        if i == body_index {
            out.extend([TokenTree::Group(Group::new(
                Delimiter::Brace,
                new_body.clone(),
            ))]);
        } else {
            out.extend([tt]);
        }
    }
    out
}

/// Emit the original item plus a compile error, so the user sees one clear
/// message rather than a cascade of missing-fn errors.
fn err(item: &TokenStream, msg: &str) -> TokenStream {
    let mut out: TokenStream = format!("compile_error!({msg:?});").parse().unwrap();
    out.extend(item.clone());
    out
}
