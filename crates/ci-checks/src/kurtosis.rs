//! Image pin lint for the ethereum-package args files of the Kurtosis devnet
//! (`testing/kurtosis/*.yaml`).
//!
//! Each file is parsed as YAML (so quoting, flow mappings, escapes and aliases cannot hide an
//! image; a duplicated key is a parse error), and must be a single mapping without merge keys
//! (`<<`), which this parser would not apply. Rules:
//!
//! 1. Every value of a mapping key named `image` or ending in `_image` (any letter case, at any
//!    depth) is a string `repo:tag@sha256:<64 lower-case hex>`: a tag, so the reader sees which
//!    release the digest is, and the digest, so the tag cannot move. A registry port
//!    (`host:5000/repo`) is not a tag. An empty value is not a pin either: ethereum-package
//!    reads `""` as "use the default image", which is a floating tag.
//! 2. Every `participants[]` entry sets `cl_image`, `el_image` (unless `el_type: None`) and
//!    `vc_image` (unless `use_separate_vc: false`), and every `participants_matrix` `el[]`,
//!    `cl[]` and `vc[]` entry sets its own image: an omitted image is the package default, a
//!    floating tag.
//! 3. Every `additional_services` entry `<svc>` sets `<svc>_params.image`. This is the
//!    package's naming for the services this devnet uses (spamoor, dora, buildoor, assertoor,
//!    ...); a service whose images live under other keys fails closed until the rule learns them.
//! 4. `ethereum_genesis_generator_params.image` is set: it builds the genesis state, so a
//!    floating generator could change the genesis root between two runs.
//!
//! Images the package starts from its own constants (helpers such as yq or eth2-val-tools)
//! are not in the args file; they are fixed only by the pinned package commit.

use crate::{check_yaml_dir, Report, Violation};
use std::path::Path;
use yaml_rust2::{Yaml, YamlLoader};

/// Checks every `*.yml` / `*.yaml` file directly in `dir`. An unreadable directory or one
/// without args files is an error, never a pass.
pub fn check_dir(dir: &Path) -> Result<Report, String> {
    check_yaml_dir(dir, "args files", check_args_file)
}

/// Checks one args file's text. `name` is only used to label violations.
pub fn check_args_file(name: &str, text: &str) -> Vec<Violation> {
    let mut c = Lint {
        name,
        out: Vec::new(),
    };
    let docs = match YamlLoader::load_from_str(text) {
        Ok(docs) => docs,
        Err(e) => {
            c.error(format!("not valid YAML: {e}"));
            return c.out;
        }
    };
    let [doc] = docs.as_slice() else {
        c.error("expected exactly one YAML document".into());
        return c.out;
    };
    if !matches!(doc, Yaml::Hash(_)) {
        c.error("args file is not a mapping".into());
        return c.out;
    }
    if has_merge_key(doc) {
        c.error("YAML merge keys (<<) are not allowed: the rules read keys literally".into());
        return c.out;
    }
    c.image_values(doc, "");
    c.participants(doc);
    c.participants_matrix(doc);
    c.additional_services(doc);
    if get(doc, "ethereum_genesis_generator_params")
        .and_then(|p| get(p, "image"))
        .is_none()
    {
        c.error(
            "ethereum_genesis_generator_params.image is not set: the package default is a \
             floating tag, and the generator builds the genesis state"
                .into(),
        );
    }
    c.out
}

/// `repo:tag@sha256:<64 lower-case hex>`. `repo` is lower-case `[a-z0-9._-]` components
/// joined by `/`, each starting and ending with a letter or digit; the first may carry a
/// registry port (`host:5000`) when more components follow. `tag` is
/// `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
pub fn is_image_pinned(r: &str) -> bool {
    let Some((named, digest)) = r.split_once("@sha256:") else {
        return false;
    };
    let Some((repo, tag)) = named.rsplit_once(':') else {
        return false;
    };
    is_digest(digest) && is_tag(tag) && is_repo(repo)
}

fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_tag(s: &str) -> bool {
    let mut bytes = s.bytes();
    let first_ok = bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');
    first_ok
        && s.len() <= 128
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn is_repo(s: &str) -> bool {
    let components: Vec<&str> = s.split('/').collect();
    components.iter().enumerate().all(|(i, c)| {
        let (name, port) = match c.split_once(':') {
            // A port only on a registry host that more components follow.
            Some((host, port)) if i == 0 && components.len() > 1 => (host, Some(port)),
            Some(_) => return false,
            None => (*c, None),
        };
        let port_ok = port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        port_ok && is_component(name)
    })
}

fn is_component(s: &str) -> bool {
    let edge = |b: Option<u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    edge(s.bytes().next())
        && edge(s.bytes().last())
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

fn is_image_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    k == "image" || k.ends_with("_image")
}

fn get<'y>(map: &'y Yaml, k: &str) -> Option<&'y Yaml> {
    match map {
        Yaml::Hash(h) => h.get(&Yaml::String(k.to_owned())),
        _ => None,
    }
}

fn has_merge_key(node: &Yaml) -> bool {
    match node {
        Yaml::Hash(h) => h
            .iter()
            .any(|(k, v)| k.as_str() == Some("<<") || has_merge_key(k) || has_merge_key(v)),
        Yaml::Array(items) => items.iter().any(has_merge_key),
        _ => false,
    }
}

fn describe(node: &Yaml) -> String {
    match node {
        Yaml::String(s) => format!("{s:?}"),
        Yaml::Null => "null".into(),
        Yaml::Integer(i) => i.to_string(),
        Yaml::Boolean(b) => b.to_string(),
        Yaml::Array(_) => "a list".into(),
        Yaml::Hash(_) => "a mapping".into(),
        other => format!("{other:?}"),
    }
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

struct Lint<'a> {
    name: &'a str,
    out: Vec<Violation>,
}

impl Lint<'_> {
    fn error(&mut self, message: String) {
        self.out.push(Violation {
            file: self.name.to_owned(),
            line: None,
            message,
        });
    }

    /// Rule 1, over the whole tree. `path` names `node` (`a.b[0].c`).
    fn image_values(&mut self, node: &Yaml, path: &str) {
        match node {
            Yaml::Hash(h) => {
                for (k, v) in h {
                    let key = match k {
                        Yaml::String(s) => s.clone(),
                        other => describe(other),
                    };
                    let here = join(path, &key);
                    if is_image_key(&key) && !matches!(v, Yaml::String(s) if is_image_pinned(s)) {
                        self.error(format!(
                            "{here}: image {} is not pinned as repo:tag@sha256:<64 hex>",
                            describe(v)
                        ));
                    }
                    self.image_values(v, &here);
                }
            }
            Yaml::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    self.image_values(item, &format!("{path}[{i}]"));
                }
            }
            _ => {}
        }
    }

    /// The entries of the list at `doc.<key>`, or a violation if it is not a list.
    fn entries<'y>(&mut self, doc: &'y Yaml, path: &str) -> &'y [Yaml] {
        let mut node = Some(doc);
        for k in path.split('.') {
            node = node.and_then(|n| get(n, k));
        }
        match node {
            None => &[],
            Some(Yaml::Array(items)) => items,
            Some(_) => {
                self.error(format!("{path} is not a list"));
                &[]
            }
        }
    }

    /// `path[i]` must set `key`.
    fn requires(&mut self, entry: &Yaml, path: &str, i: usize, key: &str) {
        if get(entry, key).is_none() {
            self.error(format!(
                "{path}[{i}] does not set {key}: the package default is a floating tag"
            ));
        }
    }

    /// Rule 2 for `participants`.
    fn participants(&mut self, doc: &Yaml) {
        for (i, p) in self.entries(doc, "participants").iter().enumerate() {
            if !matches!(p, Yaml::Hash(_)) {
                self.error(format!("participants[{i}] is not a mapping"));
                continue;
            }
            self.requires(p, "participants", i, "cl_image");
            if get(p, "el_type").and_then(Yaml::as_str) != Some("None") {
                self.requires(p, "participants", i, "el_image");
            }
            if get(p, "use_separate_vc").and_then(Yaml::as_bool) != Some(false) {
                self.requires(p, "participants", i, "vc_image");
            }
        }
    }

    /// Rule 2 for `participants_matrix`.
    fn participants_matrix(&mut self, doc: &Yaml) {
        for layer in ["el", "cl", "vc"] {
            let path = format!("participants_matrix.{layer}");
            let key = format!("{layer}_image");
            for (i, p) in self.entries(doc, &path).iter().enumerate() {
                if !matches!(p, Yaml::Hash(_)) {
                    self.error(format!("{path}[{i}] is not a mapping"));
                    continue;
                }
                self.requires(p, &path, i, &key);
            }
        }
    }

    /// Rule 3.
    fn additional_services(&mut self, doc: &Yaml) {
        let services = match get(doc, "additional_services") {
            None => return,
            Some(Yaml::Array(items)) => items,
            Some(_) => {
                self.error("additional_services is not a list of service names".into());
                return;
            }
        };
        for (i, s) in services.iter().enumerate() {
            let Some(svc) = s.as_str() else {
                self.error(format!("additional_services[{i}] is not a service name"));
                continue;
            };
            let params = format!("{svc}_params");
            if get(doc, &params).and_then(|p| get(p, "image")).is_none() {
                self.error(format!(
                    "additional service {svc}: {params}.image is not set: the package default \
                     is a floating tag"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests;
