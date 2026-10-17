//! A strict reader for the flat YAML subset that eth-clients `config.yaml` files use.
//!
//! Accepted shapes, one per top-level key:
//! - `KEY: value` with an optional `'single'` or `"double"` quoted value;
//! - `KEY: []`, an empty list of records;
//! - `KEY:` followed by indented records, each `- FIELD: value` plus further `FIELD: value` lines.
//!
//! `#` starts a comment at the start of a line or after whitespace. Anything else, including a
//! duplicate key, is an error that names its 1-based line. Nothing is coerced; typed readers in
//! [`crate::chain_config`] interpret the strings.

use crate::ConfigError;
use std::collections::{BTreeMap, BTreeSet};

/// One record of a list value, in file order.
pub(crate) type Record = Vec<(String, String)>;

/// A top-level value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Scalar(String),
    Records(Vec<Record>),
}

/// The list whose records the indented lines that follow belong to.
struct OpenList {
    key: String,
    /// Column of the `-` of every record, fixed by the first record.
    item_indent: Option<usize>,
    /// Column of the first field of the current record; continuation lines must match it.
    field_indent: usize,
    /// Fields of the current record, for duplicate detection.
    seen_fields: BTreeSet<String>,
}

/// Parses `text` into its top-level keys.
pub(crate) fn parse(text: &str) -> Result<BTreeMap<String, Value>, ConfigError> {
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    let mut open_list: Option<OpenList> = None;

    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let err = |reason: String| ConfigError::Parse { line, reason };
        let content = strip_comment(raw).trim_end();
        if content.trim().is_empty() {
            continue;
        }

        if content.starts_with([' ', '\t']) {
            let list = open_list
                .as_mut()
                .ok_or_else(|| err("indented line outside a list".into()))?;
            let Some(Value::Records(records)) = out.get_mut(&list.key) else {
                unreachable!("an open list always names a Records value");
            };
            let (field, value) = record_line(content, list, records).map_err(err)?;
            if !list.seen_fields.insert(field.clone()) {
                return Err(err(format!("duplicate field {field}")));
            }
            records
                .last_mut()
                .expect("record_line opened a record")
                .push((field, value));
            continue;
        }

        let (key, value) = split_key(content).map_err(err)?;
        if out.contains_key(&key) {
            return Err(err(format!("duplicate key {key}")));
        }
        let value = match value.as_str() {
            "" => {
                open_list = Some(OpenList {
                    key: key.clone(),
                    item_indent: None,
                    field_indent: 0,
                    seen_fields: BTreeSet::new(),
                });
                Value::Records(Vec::new())
            }
            "[]" => {
                open_list = None;
                Value::Records(Vec::new())
            }
            _ => {
                open_list = None;
                Value::Scalar(unquote(&value).map_err(err)?)
            }
        };
        out.insert(key, value);
    }
    Ok(out)
}

/// Reads one indented line of `list`: either `- FIELD: value`, which opens a record, or a
/// `FIELD: value` continuation aligned under the record's first field.
fn record_line(
    content: &str,
    list: &mut OpenList,
    records: &mut Vec<Record>,
) -> Result<(String, String), String> {
    let item = content.trim_start_matches(' ');
    if item.starts_with('\t') {
        return Err("indentation must use spaces".into());
    }
    let indent = content.len() - item.len();
    if let Some(rest) = item.strip_prefix('-') {
        let field_text = rest.trim_start_matches(' ');
        if field_text.len() == rest.len() || field_text.is_empty() {
            return Err("a record must start with `- FIELD: value`".into());
        }
        if let Some(expected) = list.item_indent.filter(|&e| e != indent) {
            return Err(format!(
                "record indented {indent} spaces, expected {expected}"
            ));
        }
        list.item_indent = Some(indent);
        list.field_indent = indent + 1 + (rest.len() - field_text.len());
        list.seen_fields.clear();
        records.push(Record::new());
        return split_pair(field_text);
    }
    if records.is_empty() {
        return Err("list field before the first `- ` item".into());
    }
    if indent != list.field_indent {
        return Err(format!(
            "record field indented {indent} spaces, expected {}",
            list.field_indent
        ));
    }
    split_pair(item)
}

/// Removes a `#` comment that is not inside quotes.
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut prev_is_space = true;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (Some(q), _) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '#') if prev_is_space => return &line[..i],
            (None, _) => {}
        }
        prev_is_space = c.is_whitespace();
    }
    line
}

/// Splits `KEY: rest` at the top level; `rest` may be empty.
fn split_key(content: &str) -> Result<(String, String), String> {
    let (key, rest) = content
        .split_once(':')
        .ok_or_else(|| format!("expected `KEY: value`, got {content:?}"))?;
    check_name(key)?;
    Ok((key.to_owned(), rest.trim().to_owned()))
}

/// Splits `FIELD: value` inside a record; the value must be present.
fn split_pair(text: &str) -> Result<(String, String), String> {
    let (field, value) = split_key(text)?;
    if value.is_empty() {
        return Err(format!("record field {field} has no value"));
    }
    Ok((field, unquote(&value)?))
}

fn check_name(name: &str) -> Result<(), String> {
    if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Ok(())
    } else {
        Err(format!("invalid key {name:?}"))
    }
}

fn unquote(value: &str) -> Result<String, String> {
    let Some(q) = value.chars().next().filter(|c| matches!(c, '\'' | '"')) else {
        return Ok(value.to_owned());
    };
    value
        .strip_prefix(q)
        .and_then(|v| v.strip_suffix(q))
        .filter(|inner| !inner.contains(q))
        .map(str::to_owned)
        .ok_or_else(|| format!("unterminated quoted value {value}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(s: &str) -> Value {
        Value::Scalar(s.into())
    }

    #[test]
    fn scalars_lists_and_comments() {
        let text = "\
# header
A: 1  # trailing
B: 'quoted # not a comment'
C: \"dq\"
D: []
E:
  - X: 1
    Y: 2
  - X: 3
F: 0xab#c
";
        let doc = parse(text).unwrap();
        assert_eq!(doc["A"], scalar("1"));
        assert_eq!(doc["B"], scalar("quoted # not a comment"));
        assert_eq!(doc["C"], scalar("dq"));
        assert_eq!(doc["D"], Value::Records(vec![]));
        assert_eq!(
            doc["E"],
            Value::Records(vec![
                vec![("X".into(), "1".into()), ("Y".into(), "2".into())],
                vec![("X".into(), "3".into())],
            ])
        );
        assert_eq!(doc["F"], scalar("0xab#c"));
    }

    #[test]
    fn errors_name_the_line() {
        let err = |t: &str| match parse(t).unwrap_err() {
            ConfigError::Parse { line, reason } => (line, reason),
            other => panic!("{other:?}"),
        };
        assert_eq!(err("A: 1\nA: 2\n").0, 2);
        assert!(err("L:\n  - X: 1\n    X: 2\n")
            .1
            .contains("duplicate field"));
        assert_eq!(err("A: 1\n  - X: 1\n").0, 2);
        assert_eq!(err("A: 'x\"\n").0, 1);
        assert_eq!(err("A B: 1\n").0, 1);
    }
}
