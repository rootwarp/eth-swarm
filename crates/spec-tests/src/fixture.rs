//! Reading the YAML fixtures of the `bls` and `kzg` runners, and the `manifest.yaml` that
//! consensus-spec-tests puts next to every case.

use crate::coverage::Reads;
use crate::plan::CaseKey;
use std::path::Path;
use yaml_rust2::{Yaml, YamlLoader};

/// Reads (recording the path) and parses a single-document YAML file.
pub fn load(reads: &Reads, path: &Path) -> Result<Yaml, String> {
    let text = reads
        .read_to_string(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Parses a single-document YAML text.
pub fn parse(text: &str) -> Result<Yaml, String> {
    let mut docs = YamlLoader::load_from_str(text).map_err(|e| e.to_string())?;
    match (docs.pop(), docs.is_empty()) {
        (Some(doc), true) => Ok(doc),
        _ => Err("expected exactly one YAML document".into()),
    }
}

/// `map[key]`, or an error naming the missing key.
pub fn field<'y>(map: &'y Yaml, key: &str) -> Result<&'y Yaml, String> {
    match &map[key] {
        Yaml::BadValue => Err(format!("missing `{key}`")),
        v => Ok(v),
    }
}

/// A scalar as text. Fixtures write hex unquoted when it happens to look like a plain word, so
/// numbers keep their source text where the parser kept it (`Real`) and integers are refused
/// (leading zeros would be lost).
fn text(y: &Yaml) -> Result<&str, String> {
    match y {
        Yaml::String(s) | Yaml::Real(s) => Ok(s),
        other => Err(format!("expected a hex string, got {other:?}")),
    }
}

/// A hex scalar (with or without `0x`) as bytes. `Ok(None)` when the text is not valid hex:
/// to the function under test that is an undecodable input, like a wrong length.
pub fn hex(y: &Yaml) -> Result<Option<Vec<u8>>, String> {
    let s = text(y)?;
    Ok(hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok())
}

/// A hex scalar decoded to exactly `N` bytes; `Ok(None)` for bad hex or another length.
pub fn hex_array<const N: usize>(y: &Yaml) -> Result<Option<[u8; N]>, String> {
    Ok(hex(y)?.and_then(|b| b.try_into().ok()))
}

/// A sequence of `N`-byte hex scalars; `Ok(None)` if any element is undecodable.
pub fn hex_arrays<const N: usize>(y: &Yaml) -> Result<Option<Vec<[u8; N]>>, String> {
    let mut out = Vec::new();
    for item in list(y)? {
        match hex_array::<N>(item)? {
            Some(a) => out.push(a),
            None => return Ok(None),
        }
    }
    Ok(Some(out))
}

/// A sequence of hex scalars of any length; `Ok(None)` if any element is not hex.
pub fn hex_list(y: &Yaml) -> Result<Option<Vec<Vec<u8>>>, String> {
    let mut out = Vec::new();
    for item in list(y)? {
        match hex(item)? {
            Some(b) => out.push(b),
            None => return Ok(None),
        }
    }
    Ok(Some(out))
}

/// A YAML sequence.
pub fn list(y: &Yaml) -> Result<&[Yaml], String> {
    y.as_vec()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("expected a list, got {y:?}"))
}

/// A boolean.
pub fn boolean(y: &Yaml) -> Result<bool, String> {
    y.as_bool()
        .ok_or_else(|| format!("expected true or false, got {y:?}"))
}

/// Unsigned integers, e.g. `cell_indices`.
pub fn u64_list(y: &Yaml) -> Result<Vec<u64>, String> {
    list(y)?
        .iter()
        .map(|v| {
            v.as_i64()
                .and_then(|i| u64::try_from(i).ok())
                .ok_or_else(|| format!("expected an unsigned integer, got {v:?}"))
        })
        .collect()
}

/// `None` for `output: null` (the spec function raises), else `parse(output)`. An output that
/// does not parse is a malformed fixture, not an expectation.
pub fn nullable<T>(
    output: &Yaml,
    parse: impl Fn(&Yaml) -> Result<Option<T>, String>,
) -> Result<Option<T>, String> {
    if output.is_null() {
        return Ok(None);
    }
    parse(output)?
        .map(Some)
        .ok_or_else(|| "undecodable expected output".to_string())
}

/// Compares a result (`None` = the function raised) with the vector's expectation.
pub fn compare<T: PartialEq>(got: Option<T>, want: Option<T>) -> Result<(), String> {
    match (got, want) {
        (None, None) => Ok(()),
        (Some(g), Some(w)) if g == w => Ok(()),
        (Some(_), Some(_)) => Err("output differs from the expected value".into()),
        (None, Some(_)) => Err("rejected an input the vector expects to succeed".into()),
        (Some(_), None) => Err("accepted an input the vector expects to raise".into()),
    }
}

/// Checks that a case's `manifest.yaml` (`preset`, `fork`, `runner`, `handler`, `suite`, `case`)
/// names the directory it sits in, so a misplaced or mislabelled case cannot pass as another.
pub fn check_manifest(reads: &Reads, path: &Path, key: &CaseKey) -> Result<(), String> {
    let doc = load(reads, path)?;
    let (suite, case) = key.case.split_once('/').unwrap_or(("", &key.case));
    for (name, want) in [
        ("preset", key.preset.as_str()),
        ("fork", &key.fork),
        ("runner", &key.runner),
        ("handler", &key.handler),
        ("suite", suite),
        ("case", case),
    ] {
        let got = field(&doc, name).and_then(|v| {
            v.as_str()
                .ok_or_else(|| format!("`{name}` is not a string"))
        });
        match got {
            Ok(got) if got == want => {}
            Ok(got) => {
                return Err(format!(
                    "{}: `{name}` is {got:?}, the directory says {want:?}",
                    path.display()
                ))
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_scalars_with_and_without_prefix() {
        let doc = parse("a: '0x0aff'\nb: c0ff\nc: 'zz'\nd: 7\n").unwrap();
        assert_eq!(hex(&doc["a"]), Ok(Some(vec![0x0a, 0xff])));
        assert_eq!(hex(&doc["b"]), Ok(Some(vec![0xc0, 0xff])));
        assert_eq!(hex(&doc["c"]), Ok(None));
        assert!(hex(&doc["d"]).is_err());
        assert_eq!(hex_array::<2>(&doc["a"]), Ok(Some([0x0a, 0xff])));
        assert_eq!(hex_array::<3>(&doc["a"]), Ok(None));
    }

    #[test]
    fn lists_and_scalars() {
        let doc = parse("l: ['0x01', '0x02']\nbad: ['0x01', 'zz']\ni: [0, 3]\nn: [-1]\nt: true\n")
            .unwrap();
        assert_eq!(hex_arrays::<1>(&doc["l"]), Ok(Some(vec![[1], [2]])));
        assert_eq!(hex_arrays::<1>(&doc["bad"]), Ok(None));
        assert_eq!(hex_list(&doc["l"]), Ok(Some(vec![vec![1], vec![2]])));
        assert_eq!(hex_list(&doc["bad"]), Ok(None));
        assert_eq!(u64_list(&doc["i"]), Ok(vec![0, 3]));
        assert!(u64_list(&doc["n"]).is_err());
        assert_eq!(boolean(&doc["t"]), Ok(true));
        assert!(boolean(&doc["l"]).is_err());
        assert!(list(&doc["t"]).is_err());
        assert!(field(&doc, "missing").is_err());
    }

    #[test]
    fn rejects_multi_document_and_invalid_yaml() {
        assert!(parse("a: 1\n---\nb: 2\n").is_err());
        assert!(parse("a: [\n").is_err());
    }

    fn key() -> CaseKey {
        CaseKey {
            source: "consensus-specs".into(),
            fork: "gloas".into(),
            preset: "minimal".into(),
            runner: "ssz_static".into(),
            handler: "Checkpoint".into(),
            case: "ssz_one/case_0".into(),
        }
    }

    #[test]
    fn manifest_must_name_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.yaml");
        let good = "preset: minimal\nfork: gloas\nrunner: ssz_static\nhandler: Checkpoint\n\
                    suite: ssz_one\ncase: case_0\n";
        std::fs::write(&path, good).unwrap();
        let reads = Reads::default();
        assert_eq!(check_manifest(&reads, &path, &key()), Ok(()));
        assert!(reads.contains(&path));

        std::fs::write(&path, good.replace("case_0", "case_1")).unwrap();
        let err = check_manifest(&reads, &path, &key()).unwrap_err();
        assert!(err.contains("`case` is \"case_1\""), "{err}");

        std::fs::write(&path, good.replace("suite: ssz_one\n", "")).unwrap();
        assert!(check_manifest(&reads, &path, &key())
            .unwrap_err()
            .contains("missing `suite`"));
        assert!(check_manifest(&reads, &dir.path().join("nope.yaml"), &key()).is_err());
    }
}
