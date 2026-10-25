//! [`open_verified`]: the only way replay opens an archive.

use super::error::ArchiveError;
use super::manifest::{
    ArchiveFile, Manifest, ManifestError, Sha256Digest, MANIFEST_FILE, MAX_MANIFEST_LEN,
};
use super::names::segment_name;
use super::payload::decompress;
use super::writer::OPEN_PREFIX;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// A segment whose manifest and every file were verified when it was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive {
    dir: PathBuf,
    manifest: Manifest,
    archive_sha256: Sha256Digest,
}

impl Archive {
    /// The segment directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The verified manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The archive digest: the sha256 of the manifest body, which holds every file's sha256.
    /// Pin this to pin the archive.
    pub fn archive_sha256(&self) -> Sha256Digest {
        self.archive_sha256
    }

    /// The files, sorted by path.
    pub fn files(&self) -> &[ArchiveFile] {
        &self.manifest.files
    }

    /// The file's bytes as received (snappy-compressed), re-checked against the verified
    /// manifest's length and sha256: the file may have changed since the archive was opened.
    /// `file` must be one of [`Archive::files`] exactly; any other entry is
    /// [`ArchiveError::NotListed`], so a caller's forged entry never reads a file.
    pub fn read(&self, file: &ArchiveFile) -> Result<Vec<u8>, ArchiveError> {
        let files = &self.manifest.files;
        let listed = files
            .binary_search_by(|f| f.path.cmp(&file.path))
            .ok()
            .map(|at| &files[at])
            .filter(|listed| *listed == file)
            .ok_or_else(|| ArchiveError::NotListed(file.path.clone()))?;
        read_listed(&self.dir, listed)
    }

    /// The file's SSZ bytes: [`Archive::read`], then decompressed within the gossip bounds.
    pub fn read_ssz(&self, file: &ArchiveFile) -> Result<Vec<u8>, ArchiveError> {
        Ok(decompress(&self.read(file)?)?)
    }
}

/// Opens the segment at `dir` after verifying all of it: the manifest's header digest and
/// fields, the segment's place (`<network>/<slot_start>-<slot_end>` of its manifest, by the
/// names `dir` resolves to), and every file's presence, length and sha256. It also refuses an
/// unsealed `.open-*` directory, any file or directory the manifest does not list, and any
/// symlink or other non-regular entry, anywhere in `dir`.
///
/// The fork digests are checked with the manifest's own digest schedule, with no outside
/// config ([`Manifest::validate`]): a file whose fork digest is not the schedule's for its
/// slot ([`ManifestError::ForkDigest`]), a schedule that is empty, not ascending or does not
/// cover the slot range, and `fork_digests` that are not the schedule's are refused. A
/// manifest of an older format is refused ([`ManifestError::Version`]).
pub fn open_verified(dir: &Path) -> Result<Archive, ArchiveError> {
    let meta = fs::symlink_metadata(dir).map_err(ArchiveError::io(dir))?;
    if !meta.is_dir() {
        return Err(ArchiveError::NotRegular(dir.display().to_string()));
    }
    let real = fs::canonicalize(dir).map_err(ArchiveError::io(dir))?;
    let segment = name_of(Some(&real)).unwrap_or_default();
    if segment.starts_with(OPEN_PREFIX) {
        return Err(ArchiveError::Unsealed(dir.display().to_string()));
    }
    let manifest_path = dir.join(MANIFEST_FILE);
    let bytes = read_regular(&manifest_path, MANIFEST_FILE, MAX_MANIFEST_LEN)?;
    if bytes.len() as u64 > MAX_MANIFEST_LEN {
        return Err(ArchiveError::Manifest {
            path: manifest_path,
            source: ManifestError::Invalid(format!("over {MAX_MANIFEST_LEN} bytes")),
        });
    }
    let (manifest, archive_sha256) =
        Manifest::parse(&bytes).map_err(|source| ArchiveError::Manifest {
            path: manifest_path,
            source,
        })?;
    let expected = segment_name(manifest.slot_start, manifest.slot_end);
    if segment != expected || name_of(real.parent()) != Some(manifest.network.as_str()) {
        return Err(ArchiveError::Misplaced {
            dir: dir.display().to_string(),
            expected: format!("{}/{expected}", manifest.network),
        });
    }
    refuse_unlisted(dir, &manifest)?;
    for file in &manifest.files {
        read_listed(dir, file)?;
    }
    Ok(Archive {
        dir: dir.to_owned(),
        manifest,
        archive_sha256,
    })
}

/// The last component of `path`, if it is UTF-8.
fn name_of(path: Option<&Path>) -> Option<&str> {
    path.and_then(Path::file_name).and_then(|n| n.to_str())
}

/// Fails on the first entry of `dir` the manifest does not account for: anything but
/// `manifest.toml` and the topic directories of listed files at the top, and anything but
/// listed files inside those.
fn refuse_unlisted(dir: &Path, manifest: &Manifest) -> Result<(), ArchiveError> {
    let topics: BTreeSet<&str> = manifest.files.iter().map(|f| f.topic.as_str()).collect();
    let paths: BTreeSet<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
    for (name, kind) in entries(dir)? {
        if name == MANIFEST_FILE {
            continue;
        }
        match kind {
            Kind::Dir if topics.contains(name.as_str()) => {}
            Kind::Dir | Kind::File => return Err(ArchiveError::ExtraFile(name)),
            Kind::Other => return Err(ArchiveError::NotRegular(name)),
        }
        for (inner, kind) in entries(&dir.join(&name))? {
            let rel = format!("{name}/{inner}");
            match kind {
                Kind::File if paths.contains(rel.as_str()) => {}
                Kind::File | Kind::Dir => return Err(ArchiveError::ExtraFile(rel)),
                Kind::Other => return Err(ArchiveError::NotRegular(rel)),
            }
        }
    }
    Ok(())
}

/// A directory entry's type, never following a symlink.
enum Kind {
    File,
    Dir,
    Other,
}

/// The entries of `dir`, sorted by name. A name that is not UTF-8 is listed lossily: it is
/// never in a manifest.
fn entries(dir: &Path) -> Result<Vec<(String, Kind)>, ArchiveError> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).map_err(ArchiveError::io(dir))? {
        let entry = entry.map_err(ArchiveError::io(dir))?;
        let file_type = entry.file_type().map_err(ArchiveError::io(entry.path()))?;
        let kind = if file_type.is_file() {
            Kind::File
        } else if file_type.is_dir() {
            Kind::Dir
        } else {
            Kind::Other
        };
        out.push((entry.file_name().to_string_lossy().into_owned(), kind));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Reads at most `limit + 1` bytes of the regular file at `path` (`name` in errors): a missing
/// file is [`ArchiveError::MissingFile`], a symlink or other non-regular entry
/// [`ArchiveError::NotRegular`].
pub(crate) fn read_regular(path: &Path, name: &str, limit: u64) -> Result<Vec<u8>, ArchiveError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(ArchiveError::MissingFile(name.to_owned()))
        }
        Err(e) => return Err(ArchiveError::io(path)(e)),
    };
    if !meta.is_file() {
        return Err(ArchiveError::NotRegular(name.to_owned()));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take(limit.saturating_add(1)).read_to_end(&mut bytes))
        .map_err(ArchiveError::io(path))?;
    Ok(bytes)
}

/// Reads a listed file and checks its length and sha256 against the manifest.
fn read_listed(dir: &Path, file: &ArchiveFile) -> Result<Vec<u8>, ArchiveError> {
    let bytes = read_regular(&dir.join(&file.path), &file.path, file.len)?;
    if bytes.len() as u64 != file.len {
        return Err(ArchiveError::LengthMismatch {
            path: file.path.clone(),
            expected: file.len,
            actual: bytes.len() as u64,
        });
    }
    let actual: Sha256Digest = Sha256::digest(&bytes).into();
    if actual != file.sha256 {
        return Err(ArchiveError::Sha256Mismatch {
            path: file.path.clone(),
            expected: hex::encode(file.sha256),
            actual: hex::encode(actual),
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::fixtures::{self, Spec};
    use crate::archive::writer::{Capture, CaptureConfig, Writer, OPEN_PREFIX};
    use crate::archive::ManifestError;
    use std::fs;

    const COLUMN: &str = "data_column_sidecar_3";

    /// A sealed segment with two blocks and a column; and the payloads by path.
    fn segment(out: &Path) -> (PathBuf, Vec<(String, Vec<u8>)>) {
        let mut w = Writer::<Spec>::create(
            out,
            CaptureConfig {
                network: "devnet".into(),
                topics: vec!["beacon_block".into(), COLUMN.into()],
                capture_host: "probe-1".into(),
                clock_source: "chrony".into(),
                slots_per_segment: 32,
                max_bytes: 1 << 30,
                fork_digests: fixtures::fork_digests(),
            },
            fixtures::chain(),
        )
        .unwrap();
        let mut stored = Vec::new();
        let (b1, _) = fixtures::block(3, 0);
        let (b2, _) = fixtures::block(4, 0);
        let (c1, _) = fixtures::column(3, 0, 3);
        for (topic, payload) in [("beacon_block", b1), ("beacon_block", b2), (COLUMN, c1)] {
            let s = w
                .put(Capture {
                    topic,
                    fork_digest: fixtures::FULU_DIGEST,
                    payload: &payload,
                })
                .unwrap();
            stored.push((s.path, payload));
        }
        (w.close().unwrap().remove(0), stored)
    }

    #[test]
    fn opens_a_sealed_segment() {
        let out = tempfile::tempdir().unwrap();
        let (dir, stored) = segment(out.path());
        let archive = open_verified(&dir).unwrap();
        assert_eq!(archive.dir(), dir);
        assert_eq!(archive.files().len(), 3);
        let manifest_bytes = fs::read(dir.join(MANIFEST_FILE)).unwrap();
        assert_eq!(
            Manifest::parse(&manifest_bytes).unwrap(),
            (archive.manifest().clone(), archive.archive_sha256())
        );
        for (path, payload) in &stored {
            let file = archive.files().iter().find(|f| &f.path == path).unwrap();
            assert_eq!(&archive.read(file).unwrap(), payload);
            assert_eq!(
                archive.read_ssz(file).unwrap(),
                fixtures::decompressed(payload)
            );
        }
    }

    #[test]
    fn read_trusts_only_the_verified_manifest() {
        let out = tempfile::tempdir().unwrap();
        let (dir, _) = segment(out.path());
        let archive = open_verified(&dir).unwrap();
        // An entry naming a file the manifest does not list, with that file's true length and
        // sha256, is refused all the same.
        let bytes = fs::read(dir.join(MANIFEST_FILE)).unwrap();
        let forged = ArchiveFile {
            path: MANIFEST_FILE.into(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(&bytes).into(),
            ..archive.files()[0].clone()
        };
        let e = archive.read(&forged).unwrap_err();
        assert!(
            matches!(&e, ArchiveError::NotListed(p) if p == MANIFEST_FILE),
            "{e}"
        );
        // A listed path with any other field changed is not the listed entry.
        let mut changed = archive.files()[0].clone();
        changed.slot += 1;
        assert!(matches!(
            archive.read(&changed),
            Err(ArchiveError::NotListed(_))
        ));
        assert!(matches!(
            archive.read_ssz(&changed),
            Err(ArchiveError::NotListed(_))
        ));
        archive.read(&archive.files()[0]).unwrap();
    }

    #[test]
    fn a_segment_out_of_its_place_is_refused() {
        let out = tempfile::tempdir().unwrap();
        let (dir, _) = segment(out.path());
        let net = out.path().join("devnet");
        assert_eq!(dir, net.join("3-4"));
        let place = |to: &Path| {
            fs::create_dir_all(to.parent().unwrap()).unwrap();
            fs::rename(&dir, to).unwrap();
            let got = open_verified(to);
            fs::rename(to, &dir).unwrap();
            got
        };
        for to in [net.join("3-5"), net.join("x"), out.path().join("hoodi/3-4")] {
            let e = place(&to).unwrap_err();
            assert!(
                matches!(&e, ArchiveError::Misplaced { .. }),
                "{}: {e}",
                to.display()
            );
        }
        let e = place(&net.join(format!("{OPEN_PREFIX}0-0"))).unwrap_err();
        assert!(matches!(&e, ArchiveError::Unsealed(_)), "{e}");
        // A relative path is checked by the names it resolves to.
        let e = open_verified(&dir.join(".")).map(|_| ()).err();
        assert!(e.is_none(), "{e:?}");
        let e = open_verified(&net.join("3-4/beacon_block/.."))
            .map(|_| ())
            .err();
        assert!(e.is_none(), "{e:?}");
        open_verified(&dir).unwrap();
    }

    #[test]
    fn a_changed_file_after_opening_is_refused_on_read() {
        let out = tempfile::tempdir().unwrap();
        let (dir, stored) = segment(out.path());
        let archive = open_verified(&dir).unwrap();
        let file = archive.files()[0].clone();
        let mut bytes = stored
            .iter()
            .find(|(p, _)| p == &file.path)
            .unwrap()
            .1
            .clone();
        bytes[0] ^= 1;
        fs::write(dir.join(&file.path), &bytes).unwrap();
        assert!(matches!(
            archive.read(&file),
            Err(ArchiveError::Sha256Mismatch { .. })
        ));
        assert!(matches!(
            archive.read_ssz(&file),
            Err(ArchiveError::Sha256Mismatch { .. })
        ));
        bytes.push(0);
        fs::write(dir.join(&file.path), &bytes).unwrap();
        assert!(matches!(
            archive.read(&file),
            Err(ArchiveError::LengthMismatch { .. })
        ));
        fs::remove_file(dir.join(&file.path)).unwrap();
        assert!(matches!(
            archive.read(&file),
            Err(ArchiveError::MissingFile(_))
        ));
    }

    #[test]
    fn manifest_problems_are_refused() {
        let out = tempfile::tempdir().unwrap();
        let (dir, _) = segment(out.path());
        let manifest = dir.join(MANIFEST_FILE);
        let good = fs::read(&manifest).unwrap();

        let mut flipped = good.clone();
        flipped[good.len() / 2] ^= 1;
        fs::write(&manifest, &flipped).unwrap();
        let e = open_verified(&dir).unwrap_err();
        assert!(
            matches!(
                &e,
                ArchiveError::Manifest {
                    source: ManifestError::DigestMismatch { .. },
                    ..
                }
            ),
            "{e}"
        );

        fs::remove_file(&manifest).unwrap();
        assert!(
            matches!(open_verified(&dir), Err(ArchiveError::MissingFile(f)) if f == MANIFEST_FILE)
        );

        std::os::unix::fs::symlink(out.path().join("elsewhere"), &manifest).unwrap();
        fs::write(out.path().join("elsewhere"), &good).unwrap();
        assert!(matches!(
            open_verified(&dir),
            Err(ArchiveError::NotRegular(_))
        ));
        fs::remove_file(&manifest).unwrap();

        let file = fs::File::create(&manifest).unwrap();
        file.set_len(MAX_MANIFEST_LEN + 1).unwrap();
        assert!(matches!(
            open_verified(&dir),
            Err(ArchiveError::Manifest { .. })
        ));

        fs::write(&manifest, &good).unwrap();
        open_verified(&dir).unwrap();
    }

    /// The manifest text with `edit` applied to its body, rehashed: a forged manifest whose
    /// archive digest still holds.
    fn rehashed(manifest: &[u8], edit: impl Fn(&str) -> String) -> Vec<u8> {
        let text = std::str::from_utf8(manifest).unwrap();
        let (_, body) = text.split_once('\n').unwrap();
        let body = edit(body);
        assert_ne!(
            body,
            text.split_once('\n').unwrap().1,
            "the edit changes the body"
        );
        let digest = hex::encode(Sha256::digest(body.as_bytes()));
        format!("archive_sha256 = \"{digest}\"\n{body}").into_bytes()
    }

    #[test]
    fn a_digest_schedule_that_does_not_hold_or_an_old_format_is_refused() {
        let out = tempfile::tempdir().unwrap();
        let (dir, _) = segment(out.path());
        let manifest = dir.join(MANIFEST_FILE);
        let good = fs::read(&manifest).unwrap();
        let archive = open_verified(&dir).unwrap();
        assert_eq!(
            archive.manifest().digest_schedule,
            [crate::archive::DigestEntry {
                epoch: 0,
                digest: fixtures::FULU_DIGEST
            }]
        );
        let fulu = format!("\"0x{}\"", hex::encode(fixtures::FULU_DIGEST));
        let bpo = format!("\"0x{}\"", hex::encode(fixtures::BPO_DIGEST));
        let schedule = format!("[[digest_schedule]]\nepoch = 0\ndigest = {fulu}\n");
        let refusals = [
            // Starts after the segment's first slot.
            (
                rehashed(&good, |b| b.replace("epoch = 0", "epoch = 1")),
                "after slot_start's epoch",
            ),
            // Empty: no table, and an empty array before the first table.
            (
                rehashed(&good, |b| b.replace(&schedule, "")),
                "missing field",
            ),
            (
                rehashed(&good, |b| {
                    b.replace(&schedule, "").replacen(
                        "format_version = 2\n",
                        "format_version = 2\ndigest_schedule = []\n",
                        1,
                    )
                }),
                "digest_schedule is empty",
            ),
            // fork_digests that are not the schedule's.
            (
                rehashed(&good, |b| {
                    b.replace(
                        &format!("fork_digests = [{fulu}]"),
                        &format!("fork_digests = [{bpo}]"),
                    )
                }),
                "sorted digests of digest_schedule",
            ),
            // A version 1 manifest.
            (
                rehashed(&good, |b| {
                    b.replace("format_version = 2", "format_version = 1")
                }),
                "format_version 1",
            ),
        ];
        for (forged, says) in refusals {
            fs::write(&manifest, forged).unwrap();
            let e = open_verified(&dir).unwrap_err();
            assert!(
                matches!(&e, ArchiveError::Manifest { .. }) && e.to_string().contains(says),
                "{says}: {e}"
            );
        }
        // The file digests alone changed: each file is on another digest than its slot's.
        fs::write(
            &manifest,
            rehashed(&good, |b| {
                b.replace(
                    &format!("fork_digest = {fulu}"),
                    &format!("fork_digest = {bpo}"),
                )
            }),
        )
        .unwrap();
        assert!(matches!(
            open_verified(&dir),
            Err(ArchiveError::Manifest {
                source: ManifestError::ForkDigest { got, expected: Some(want), .. },
                ..
            }) if got == fixtures::BPO_DIGEST && want == fixtures::FULU_DIGEST
        ));

        // Every digest replaced by another one holds together: the values are not recomputed
        // from the network's config. Only the pinned archive digest tells it apart.
        fs::write(&manifest, rehashed(&good, |b| b.replace(&fulu, &bpo))).unwrap();
        let forged = open_verified(&dir).unwrap();
        assert_eq!(forged.manifest().fork_digests, [fixtures::BPO_DIGEST]);
        assert_ne!(forged.archive_sha256(), archive.archive_sha256());

        fs::write(&manifest, &good).unwrap();
        open_verified(&dir).unwrap();
    }

    #[test]
    fn non_regular_entries_are_refused() {
        let out = tempfile::tempdir().unwrap();
        let (dir, stored) = segment(out.path());
        let path = dir.join(&stored[0].0);
        let moved = out.path().join("moved");
        fs::rename(&path, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &path).unwrap();
        assert!(matches!(
            open_verified(&dir),
            Err(ArchiveError::NotRegular(_))
        ));
        fs::remove_file(&path).unwrap();
        fs::rename(&moved, &path).unwrap();
        open_verified(&dir).unwrap();

        // A topic directory replaced by a symlink to a copy of itself.
        let topic = dir.join(COLUMN);
        let copy = out.path().join("copy");
        fs::rename(&topic, &copy).unwrap();
        std::os::unix::fs::symlink(&copy, &topic).unwrap();
        assert!(matches!(
            open_verified(&dir),
            Err(ArchiveError::NotRegular(_))
        ));

        // The segment itself.
        fs::remove_file(&topic).unwrap();
        fs::rename(&copy, &topic).unwrap();
        let link = out.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(matches!(
            open_verified(&link),
            Err(ArchiveError::NotRegular(_))
        ));
        assert!(matches!(
            open_verified(&out.path().join("absent")),
            Err(ArchiveError::Io { .. })
        ));
    }

    #[test]
    fn extra_entries_are_refused() {
        let out = tempfile::tempdir().unwrap();
        let (dir, _) = segment(out.path());
        for (extra, reported) in [
            ("notes.txt", "notes.txt"),
            (
                "beacon_block/.9_0x00.ssz_snappy.tmp",
                "beacon_block/.9_0x00.ssz_snappy.tmp",
            ),
            ("voluntary_exit/1.ssz_snappy", "voluntary_exit"),
        ] {
            let path = dir.join(extra);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"x").unwrap();
            let e = open_verified(&dir).unwrap_err();
            assert!(
                matches!(&e, ArchiveError::ExtraFile(f) if f == reported),
                "{extra}: {e}"
            );
            fs::remove_file(&path).unwrap();
        }
        fs::remove_dir(dir.join("voluntary_exit")).unwrap();
        fs::create_dir(dir.join("empty")).unwrap();
        assert!(matches!(open_verified(&dir), Err(ArchiveError::ExtraFile(f)) if f == "empty"));
        fs::remove_dir(dir.join("empty")).unwrap();
        fs::create_dir(dir.join("beacon_block/nested")).unwrap();
        assert!(matches!(
            open_verified(&dir),
            Err(ArchiveError::ExtraFile(f)) if f == "beacon_block/nested"
        ));
    }
}
