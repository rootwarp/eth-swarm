//! Rule 9 of the module docs of `locked`: a cargo config file of the repository must not alias
//! a subcommand that the check reads, and must not include another file.

use super::{NEEDS_LOCK, NO_LOCK};
use toml::{Table, Value};

/// One message for each problem of `text` (a `.cargo/config` or `.cargo/config.toml`), read
/// as TOML:
/// - the file does not parse, so its aliases are unknown;
/// - an `include` key, which can bring in any alias;
/// - an `alias` that is not a table;
/// - an alias of a name in [`NO_LOCK`] or [`NEEDS_LOCK`]. Cargo ignores an alias of a built-in
///   subcommand, but not of an external one such as `fmt` or `clippy`.
pub(super) fn aliases(text: &str) -> Vec<String> {
    let table: Table = match toml::from_str(text) {
        Ok(table) => table,
        Err(e) => return vec![format!("not valid TOML, so its aliases are unknown: {e}")],
    };
    let mut out = Vec::new();
    if table.contains_key("include") {
        out.push("include can bring in an alias from another file: remove it".into());
    }
    match table.get("alias") {
        None => {}
        Some(Value::Table(aliases)) => {
            for name in aliases.keys() {
                if NO_LOCK.contains(&name.as_str()) || NEEDS_LOCK.contains(&name.as_str()) {
                    out.push(format!(
                        "alias {name:?} changes a cargo subcommand that the check reads: \
                         remove it"
                    ));
                }
            }
        }
        Some(_) => out.push("alias is not a table, so its aliases are unknown".into()),
    }
    out
}
