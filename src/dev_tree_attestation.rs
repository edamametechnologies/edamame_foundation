//! Structural facts about developer toolchain trees, measured on disk.
//!
//! The attack pattern detector grades a temp-resident writer as "bare
//! lineage" unless something corroborates it. Developer toolchains and
//! coding agents put whole work trees under the OS temp roots (a cargo
//! `CARGO_TARGET_DIR` in a Claude Code scratchpad, `git worktree add
//! /tmp/...`, a `python -m venv` in `$TMPDIR`), and their ordinary output
//! then looks like staging. This module answers, for a path, three
//! questions the detector cannot answer itself because it performs no I/O:
//!
//! 1. Is the path inside a toolchain BUILD tree, recognised by what the
//!    toolchain itself writes at the tree root:
//!    - `CACHEDIR.TAG` beginning with the Cache Directory Tagging signature
//!      (cargo writes one at every target directory root; pytest's
//!      `.pytest_cache`, mypy, ruff, uv, Gradle 8.x `caches/`, ccache and
//!      others follow the same spec),
//!    - `CMakeCache.txt` (a CMake build directory),
//!    - a Go build work directory (`go-build<digits>/b<NNN>/` holding the
//!      `importcfg` / `importcfg.link` the go command writes; `go test` and
//!      `go run` execute their binaries from there),
//!    - a JavaScript project root: `package.json` next to a `node_modules`
//!      holding a package manager's install state (`.package-lock.json`
//!      from npm, `.modules.yaml` from pnpm, `.yarn-state.yml` /
//!      `.yarn-integrity` from yarn) -- the tree an `esbuild` / `swc` /
//!      `node_modules/.bin` binary writes its output into.
//! 2. Is the path inside a PEP 405 virtual environment (`pyvenv.cfg` at the
//!    venv root)?
//! 3. Is the path inside a git work tree, is it an entry of that work tree's
//!    index, and is the file unmodified relative to the index by git's own
//!    stat check (same size and mtime, plus ctime on Unix)?
//!
//! None of these facts is proof of benignity -- an attacker can plant any
//! marker, `git init` a directory, or `git add` a payload. The detector uses
//! them only to replace missing parent attribution in the bare-lineage LOW
//! grade, never to override corroboration (content, sensitive material,
//! egress, anomaly, blacklist), so a planted marker at worst yields the LOW
//! the severity invariant already assigns to uncorroborated temp lineage.
//!
//! Called on both sides of the sandbox boundary: in-process by the
//! standalone core and by the helper's `attest_dev_trees` utility order.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Cache Directory Tagging Specification signature
/// (<https://bford.info/cachedir/>). The file must BEGIN with these bytes.
pub const CACHEDIR_TAG_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";

/// Ancestor directories inspected above a path. Deeper trees exist, but a
/// toolchain root farther than this from the file it produced is not the
/// shape we attest.
const MAX_ANCESTOR_DEPTH: usize = 24;
/// Index files larger than this are not parsed (a monorepo index is tens of
/// MB; we do not want a detector tick to read it).
const MAX_GIT_INDEX_BYTES: u64 = 32 * 1024 * 1024;
/// Paths attested per call. The detector sends at most one entry per FIM
/// event / session process; the cap bounds a hostile burst.
pub const MAX_ATTESTED_PATHS: usize = 512;

/// Filesystem facts about one path. Every field is measured; `None` / `false`
/// means "not observed", never "observed benign".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevTreeAttestation {
    /// The path as the caller supplied it (the join key).
    pub path: String,
    /// Innermost ancestor directory that is a toolchain build tree root
    /// (see the module docs for the recognised markers).
    pub build_tree_root: Option<String>,
    /// Which marker attested `build_tree_root`: `cachedir_tag`,
    /// `cmake_build`, `go_build_work`, `node_project`.
    pub build_tree_kind: Option<String>,
    /// Innermost ancestor directory holding `pyvenv.cfg`.
    pub venv_root: Option<String>,
    /// Innermost ancestor directory that is a git work tree (`.git`
    /// directory with a `HEAD`, or a `.git` file naming a `gitdir:`).
    pub git_worktree_root: Option<String>,
    /// `path` is an entry of that work tree's index.
    pub git_tracked: bool,
    /// The file is unmodified relative to its index entry by git's own stat
    /// check (size + mtime, and ctime on Unix): the bytes on disk are what
    /// the last checkout / `git add` put there.
    pub git_index_stat_clean: bool,
    /// For a tracked, stat-clean file only: secret-signature hits of its
    /// content (`secret_content_scan::inspect_secret_like_file`). `None` when
    /// not measured (untracked, modified, unreadable, excluded by the scan's
    /// own gates).
    pub tracked_content_secret_hits: Option<usize>,
}

impl DevTreeAttestation {
    pub fn is_empty(&self) -> bool {
        self.build_tree_root.is_none()
            && self.venv_root.is_none()
            && self.git_worktree_root.is_none()
    }
}

/// Attest every path (deduplicated, capped at [`MAX_ATTESTED_PATHS`]).
/// Returns one entry per path that sits inside at least one recognised tree;
/// paths inside none are omitted.
pub fn attest_dev_trees(paths: &[String]) -> Vec<DevTreeAttestation> {
    let mut walker = TreeWalker::default();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for raw in paths {
        let trimmed = raw.trim();
        if trimmed.is_empty() || !seen.insert(trimmed.to_string()) {
            continue;
        }
        if seen.len() > MAX_ATTESTED_PATHS {
            break;
        }
        let attestation = walker.attest(trimmed);
        if !attestation.is_empty() {
            out.push(attestation);
        }
    }
    out
}

#[derive(Default, Clone)]
struct DirMarkers {
    build_tree: Option<&'static str>,
    venv: bool,
    git_dir: Option<PathBuf>,
}

/// Per-call caches: many FIM events share ancestors and one index.
#[derive(Default)]
struct TreeWalker {
    dirs: HashMap<PathBuf, DirMarkers>,
    indexes: HashMap<PathBuf, Option<GitIndex>>,
}

impl TreeWalker {
    fn markers(&mut self, dir: &Path) -> DirMarkers {
        if let Some(found) = self.dirs.get(dir) {
            return found.clone();
        }
        let markers = DirMarkers {
            build_tree: build_tree_marker(dir),
            venv: dir.join("pyvenv.cfg").is_file(),
            git_dir: resolve_git_dir(dir),
        };
        self.dirs.insert(dir.to_path_buf(), markers.clone());
        markers
    }

    fn attest(&mut self, raw: &str) -> DevTreeAttestation {
        let mut result = DevTreeAttestation {
            path: raw.to_string(),
            ..Default::default()
        };
        let path = Path::new(raw);
        let mut git: Option<(PathBuf, PathBuf)> = None;
        for dir in path.ancestors().skip(1).take(MAX_ANCESTOR_DEPTH) {
            if dir.as_os_str().is_empty() {
                break;
            }
            let markers = self.markers(dir);
            if result.build_tree_root.is_none() {
                let kind = markers
                    .build_tree
                    .or_else(|| go_build_work_marker(dir, path));
                if let Some(kind) = kind {
                    result.build_tree_root = Some(dir.to_string_lossy().to_string());
                    result.build_tree_kind = Some(kind.to_string());
                }
            }
            if markers.venv && result.venv_root.is_none() {
                result.venv_root = Some(dir.to_string_lossy().to_string());
            }
            if git.is_none() {
                if let Some(git_dir) = markers.git_dir {
                    result.git_worktree_root = Some(dir.to_string_lossy().to_string());
                    git = Some((dir.to_path_buf(), git_dir));
                }
            }
            if result.build_tree_root.is_some() && result.venv_root.is_some() && git.is_some() {
                break;
            }
        }
        if let Some((root, git_dir)) = git {
            self.attest_git(&mut result, path, &root, &git_dir);
        }
        result
    }

    fn attest_git(
        &mut self,
        result: &mut DevTreeAttestation,
        path: &Path,
        root: &Path,
        git_dir: &Path,
    ) {
        let Ok(relative) = path.strip_prefix(root) else {
            return;
        };
        let relative = relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join("/");
        if relative.is_empty() {
            return;
        }
        let index_path = git_dir.join("index");
        let index = self
            .indexes
            .entry(index_path.clone())
            .or_insert_with(|| GitIndex::load(&index_path));
        let Some(index) = index.as_ref() else {
            return;
        };
        let Some(entry) = index.entries.get(relative.as_bytes()) else {
            return;
        };
        result.git_tracked = true;
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return;
        };
        result.git_index_stat_clean = entry.stat_matches(&metadata);
        if result.git_index_stat_clean {
            result.tracked_content_secret_hits =
                crate::secret_content_scan::inspect_secret_like_file(&path.to_string_lossy())
                    .map(|m| m.secret_hits)
                    .or_else(|| {
                        // `inspect_secret_like_file` returns `None` both for
                        // "unreadable / gated" and for a readable file with
                        // nothing to report. Only the second is a measurement.
                        scan_measured_clean(path).then_some(0)
                    });
        }
    }
}

/// True when the secret scan would have read `path` (regular file within the
/// scan's size cap, not excluded by extension or location) -- so a `None`
/// from `inspect_secret_like_file` means "no signature matched".
fn scan_measured_clean(path: &Path) -> bool {
    let text = path.to_string_lossy();
    if crate::vuln_detector_params::is_secret_content_scan_skipped_extension(&text)
        || crate::vuln_detector_params::is_secret_content_scan_excluded_path(&text)
    {
        return false;
    }
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    metadata.is_file()
        && metadata.len() <= crate::vuln_detector_params::secret_content_scan_max_bytes()
        && std::fs::File::open(path).is_ok()
}

/// Build-tree root markers a directory carries by itself (Go work dirs are
/// recognised per path, see [`go_build_work_marker`]).
fn build_tree_marker(dir: &Path) -> Option<&'static str> {
    if has_cachedir_tag(dir) {
        return Some("cachedir_tag");
    }
    if dir.join("CMakeCache.txt").is_file() {
        return Some("cmake_build");
    }
    if dir.join("package.json").is_file()
        && [
            ".package-lock.json",
            ".modules.yaml",
            ".yarn-state.yml",
            ".yarn-integrity",
        ]
        .iter()
        .any(|state| dir.join("node_modules").join(state).is_file())
    {
        return Some("node_project");
    }
    None
}

/// `dir` is a Go build work directory (`$WORK`, `go-build<digits>`) and
/// `path` lies in one of its action directories (`b<NNN>/`) that holds the
/// import configuration the go command writes before compiling or linking.
fn go_build_work_marker(dir: &Path, path: &Path) -> Option<&'static str> {
    let name = dir.file_name()?.to_str()?;
    let digits = name.strip_prefix("go-build")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let action = path.strip_prefix(dir).ok()?.components().next()?;
    let action = action.as_os_str().to_str()?;
    let number = action.strip_prefix('b')?;
    if number.len() < 3 || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let action_dir = dir.join(action);
    (action_dir.join("importcfg").is_file() || action_dir.join("importcfg.link").is_file())
        .then_some("go_build_work")
}

fn has_cachedir_tag(dir: &Path) -> bool {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(dir.join("CACHEDIR.TAG")) else {
        return false;
    };
    let mut head = [0u8; 43];
    file.read_exact(&mut head).is_ok() && head == CACHEDIR_TAG_SIGNATURE
}

/// The git directory of the work tree rooted at `dir`, if `dir` is one:
/// `dir/.git/` holding `HEAD`, or a `dir/.git` file `gitdir: <path>`
/// (linked worktrees and submodules; relative paths resolve against `dir`).
fn resolve_git_dir(dir: &Path) -> Option<PathBuf> {
    let dot_git = dir.join(".git");
    let metadata = std::fs::symlink_metadata(&dot_git).ok()?;
    if metadata.is_dir() {
        return dot_git.join("HEAD").is_file().then_some(dot_git);
    }
    if !metadata.is_file() || metadata.len() > 4096 {
        return None;
    }
    let text = std::fs::read_to_string(&dot_git).ok()?;
    let target = text.lines().next()?.strip_prefix("gitdir:")?.trim();
    if target.is_empty() {
        return None;
    }
    let target = Path::new(target);
    let resolved = if target.is_absolute() {
        target.to_path_buf()
    } else {
        dir.join(target)
    };
    resolved.join("HEAD").is_file().then_some(resolved)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexStat {
    ctime_sec: u32,
    ctime_nsec: u32,
    mtime_sec: u32,
    mtime_nsec: u32,
    size: u32,
}

impl IndexStat {
    /// git's own "is this entry clean" stat comparison (`ie_match_stat`):
    /// size and mtime always; ctime where the platform has one git records
    /// (Unix). Nanoseconds only when the index recorded them.
    fn stat_matches(&self, metadata: &std::fs::Metadata) -> bool {
        if !metadata.is_file() {
            return false;
        }
        // The index stores the low 32 bits of the size.
        if (metadata.len() & 0xffff_ffff) as u32 != self.size {
            return false;
        }
        let Some((mtime_sec, mtime_nsec)) = file_mtime(metadata) else {
            return false;
        };
        if mtime_sec as u32 != self.mtime_sec {
            return false;
        }
        if self.mtime_nsec != 0 && mtime_nsec != self.mtime_nsec {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.ctime() as u32 != self.ctime_sec {
                return false;
            }
            if self.ctime_nsec != 0 && metadata.ctime_nsec() as u32 != self.ctime_nsec {
                return false;
            }
        }
        true
    }
}

fn file_mtime(metadata: &std::fs::Metadata) -> Option<(u64, u32)> {
    let modified = metadata.modified().ok()?;
    let since = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some((since.as_secs(), since.subsec_nanos()))
}

/// Minimal reader for the git index (versions 2, 3 and 4): entry names and
/// the stat fields git compares. SHA-256 repositories and split indexes are
/// not parsed (the loader returns `None`, which the caller treats as "not
/// tracked" -- fail closed).
struct GitIndex {
    entries: HashMap<Vec<u8>, IndexStat>,
}

impl GitIndex {
    fn load(index_path: &Path) -> Option<Self> {
        let metadata = std::fs::metadata(index_path).ok()?;
        if metadata.len() > MAX_GIT_INDEX_BYTES {
            return None;
        }
        let bytes = std::fs::read(index_path).ok()?;
        Self::parse(&bytes)
    }

    fn parse(bytes: &[u8]) -> Option<Self> {
        const HASH_LEN: usize = 20;
        if bytes.len() < 12 || &bytes[0..4] != b"DIRC" {
            return None;
        }
        let be32 = |at: usize| -> Option<u32> {
            bytes
                .get(at..at + 4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        };
        let version = be32(4)?;
        if !(2..=4).contains(&version) {
            return None;
        }
        let count = be32(8)? as usize;
        let mut entries = HashMap::with_capacity(count.min(1 << 20));
        let mut offset = 12usize;
        let mut previous_name: Vec<u8> = Vec::new();
        for _ in 0..count {
            let start = offset;
            let stat = IndexStat {
                ctime_sec: be32(offset)?,
                ctime_nsec: be32(offset + 4)?,
                mtime_sec: be32(offset + 8)?,
                mtime_nsec: be32(offset + 12)?,
                size: be32(offset + 36)?,
            };
            let mode = be32(offset + 24)?;
            offset += 40 + HASH_LEN;
            let flags = bytes.get(offset..offset + 2)?;
            let flags = u16::from_be_bytes([flags[0], flags[1]]);
            offset += 2;
            if version >= 3 && flags & 0x4000 != 0 {
                offset += 2;
            }
            let name = if version == 4 {
                // Prefix-compressed: varint N (bytes to drop from the
                // previous name), then the NUL-terminated suffix.
                let (strip, used) = read_offset_varint(bytes.get(offset..)?)?;
                offset += used;
                let keep = previous_name.len().checked_sub(strip)?;
                let rest = bytes.get(offset..)?;
                let nul = rest.iter().position(|b| *b == 0)?;
                let mut name = previous_name[..keep].to_vec();
                name.extend_from_slice(&rest[..nul]);
                offset += nul + 1;
                name
            } else {
                let rest = bytes.get(offset..)?;
                let nul = rest.iter().position(|b| *b == 0)?;
                let name = rest[..nul].to_vec();
                // Entries are padded with 1..8 NULs to a multiple of 8.
                let entry_len = offset - start + nul;
                let padded = (entry_len + 8) & !7;
                offset = start + padded;
                name
            };
            previous_name = name.clone();
            // Sparse-index directory entries (mode 040000) are not files.
            if mode & 0o170000 == 0o040000 {
                continue;
            }
            entries.insert(name, stat);
        }
        Some(Self { entries })
    }
}

/// git's `decode_varint` ("offset" encoding used by index v4).
fn read_offset_varint(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut iter = bytes.iter().enumerate();
    let (_, first) = iter.next()?;
    let mut value = (*first & 0x7f) as usize;
    let mut byte = *first;
    let mut used = 1;
    while byte & 0x80 != 0 {
        let (_, next) = iter.next()?;
        byte = *next;
        value = value.checked_add(1)?.checked_shl(7)? | (byte & 0x7f) as usize;
        used += 1;
        if used > 9 {
            return None;
        }
    }
    Some((value, used))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "edamame_dev_tree_{}_{}_{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(dir)
            .output()
            .expect("git runs");
        assert!(
            status.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&status.stderr)
        );
    }

    #[test]
    fn cachedir_tag_requires_the_signature() {
        let root = scratch("cachedir");
        let target = root.join("target-x");
        std::fs::create_dir_all(target.join("debug/build/serde-1/out")).unwrap();
        let file = target.join("debug/build/serde-1/out/private.rs");
        std::fs::write(&file, "// generated").unwrap();

        // A CACHEDIR.TAG without the signature is not the marker.
        std::fs::write(target.join("CACHEDIR.TAG"), "hello").unwrap();
        let got = attest_dev_trees(&[file.to_string_lossy().to_string()]);
        assert!(got.is_empty(), "{got:?}");

        std::fs::write(
            target.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n# cargo\n",
        )
        .unwrap();
        let got = attest_dev_trees(&[file.to_string_lossy().to_string()]);
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].build_tree_root.as_deref(),
            Some(target.to_string_lossy().as_ref())
        );
        assert_eq!(got[0].build_tree_kind.as_deref(), Some("cachedir_tag"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cmake_go_and_node_trees_are_found() {
        let root = scratch("trees");
        // CMake build dir.
        let cmake = root.join("proj/build");
        std::fs::create_dir_all(cmake.join("CMakeFiles")).unwrap();
        std::fs::write(cmake.join("CMakeCache.txt"), "# cache").unwrap();
        let hello = cmake.join("hello");
        std::fs::write(&hello, "").unwrap();
        // Go work dir: only the action dir holding importcfg counts.
        let work = root.join("go-build123456");
        std::fs::create_dir_all(work.join("b001/exe")).unwrap();
        std::fs::create_dir_all(work.join("b002")).unwrap();
        std::fs::write(work.join("b001/importcfg.link"), "packagefile x=y").unwrap();
        let test_bin = work.join("b001/pkg.test");
        std::fs::write(&test_bin, "").unwrap();
        let unconfigured = work.join("b002/evil");
        std::fs::write(&unconfigured, "").unwrap();
        let not_work = root.join("go-buildx/b001");
        std::fs::create_dir_all(&not_work).unwrap();
        std::fs::write(not_work.join("importcfg"), "").unwrap();
        std::fs::write(not_work.join("evil"), "").unwrap();
        // Node project with npm's hidden lockfile.
        let node = root.join("app");
        std::fs::create_dir_all(node.join("node_modules/.bin")).unwrap();
        std::fs::create_dir_all(node.join("dist")).unwrap();
        std::fs::write(node.join("package.json"), "{}").unwrap();
        std::fs::write(node.join("node_modules/.package-lock.json"), "{}").unwrap();
        let bundle = node.join("dist/sum.js");
        std::fs::write(&bundle, "").unwrap();
        // A package.json without install state is not a project root.
        let bare = root.join("bare");
        std::fs::create_dir_all(bare.join("node_modules")).unwrap();
        std::fs::write(bare.join("package.json"), "{}").unwrap();
        std::fs::write(bare.join("x.js"), "").unwrap();

        let paths: Vec<String> = [
            &hello,
            &test_bin,
            &unconfigured,
            &not_work.join("evil"),
            &bundle,
            &bare.join("x.js"),
        ]
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
        let got = attest_dev_trees(&paths);
        let kind = |p: &Path| {
            got.iter()
                .find(|a| a.path == p.to_string_lossy())
                .and_then(|a| a.build_tree_kind.clone())
        };
        assert_eq!(kind(&hello).as_deref(), Some("cmake_build"));
        assert_eq!(kind(&test_bin).as_deref(), Some("go_build_work"));
        assert_eq!(kind(&unconfigured), None);
        assert_eq!(kind(&not_work.join("evil")), None);
        assert_eq!(kind(&bundle).as_deref(), Some("node_project"));
        assert_eq!(kind(&bare.join("x.js")), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn venv_root_is_found() {
        let root = scratch("venv");
        let venv = root.join("venv");
        let pkg = venv.join("lib/python3.14/site-packages/pkg");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(venv.join("pyvenv.cfg"), "home = /usr/bin\n").unwrap();
        let file = pkg.join("__init__.py");
        std::fs::write(&file, "").unwrap();
        let got = attest_dev_trees(&[file.to_string_lossy().to_string()]);
        assert_eq!(
            got[0].venv_root.as_deref(),
            Some(venv.to_string_lossy().as_ref())
        );
        assert!(got[0].build_tree_root.is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn git_tracked_clean_modified_and_untracked() {
        if !git_available() {
            eprintln!("git not available; skipping");
            return;
        }
        for version in ["2", "3", "4"] {
            let root = scratch(&format!("git_v{version}"));
            git(&root, &["init", "-q"]);
            git(&root, &["config", "index.version", version]);
            std::fs::create_dir_all(root.join("sub/dir")).unwrap();
            std::fs::write(root.join(".env"), "EDAMAME_VERSION=1.0\n").unwrap();
            std::fs::write(root.join("sub/dir/a.rs"), "fn a() {}\n").unwrap();
            std::fs::write(root.join("sub/dir/b.rs"), "fn b() {}\n").unwrap();
            git(&root, &["add", "."]);
            git(&root, &["commit", "-q", "-m", "init"]);
            // Force index v`version` to be written.
            git(&root, &["update-index", "--index-version", version]);
            std::fs::write(root.join("untracked.txt"), "x").unwrap();
            // Modify b.rs with a different size.
            std::fs::write(root.join("sub/dir/b.rs"), "fn b() { let _ = 1; }\n").unwrap();

            let paths: Vec<String> = [".env", "sub/dir/a.rs", "sub/dir/b.rs", "untracked.txt"]
                .iter()
                .map(|p| root.join(p).to_string_lossy().to_string())
                .collect();
            let got = attest_dev_trees(&paths);
            let by_path = |suffix: &str| {
                got.iter()
                    .find(|a| a.path.ends_with(suffix))
                    .cloned()
                    .unwrap_or_else(|| panic!("{suffix} attested: {got:?}"))
            };
            let env = by_path("/.env");
            assert!(
                env.git_tracked && env.git_index_stat_clean,
                "v{version} {env:?}"
            );
            assert_eq!(env.tracked_content_secret_hits, Some(0), "v{version}");
            let a = by_path("a.rs");
            assert!(a.git_tracked && a.git_index_stat_clean, "v{version} {a:?}");
            let b = by_path("b.rs");
            assert!(b.git_tracked && !b.git_index_stat_clean, "v{version} {b:?}");
            assert_eq!(b.tracked_content_secret_hits, None);
            let u = by_path("untracked.txt");
            assert!(
                !u.git_tracked && u.git_worktree_root.is_some(),
                "v{version} {u:?}"
            );
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn linked_worktree_resolves_through_gitdir_file() {
        if !git_available() {
            return;
        }
        let root = scratch("worktree");
        let main = root.join("main");
        std::fs::create_dir_all(&main).unwrap();
        git(&main, &["init", "-q"]);
        std::fs::write(main.join(".env"), "A=1\n").unwrap();
        git(&main, &["add", "."]);
        git(&main, &["commit", "-q", "-m", "init"]);
        git(&main, &["worktree", "add", "-q", "../wt", "-b", "wt"]);
        let file = root.join("wt/.env");
        let got = attest_dev_trees(&[file.to_string_lossy().to_string()]);
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].git_tracked && got[0].git_index_stat_clean, "{got:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tracked_secret_content_is_measured() {
        if !git_available() {
            return;
        }
        let root = scratch("git_secret");
        git(&root, &["init", "-q"]);
        std::fs::write(
            root.join(".env"),
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=x\n",
        )
        .unwrap();
        git(&root, &["add", "."]);
        let got = attest_dev_trees(&[root.join(".env").to_string_lossy().to_string()]);
        assert!(got[0].git_tracked && got[0].git_index_stat_clean);
        assert!(
            got[0].tracked_content_secret_hits.unwrap_or(0) > 0,
            "{got:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_dot_git_directory_without_head_is_not_a_work_tree() {
        let root = scratch("fake_git");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join("x.rs"), "").unwrap();
        let got = attest_dev_trees(&[root.join("x.rs").to_string_lossy().to_string()]);
        assert!(got.is_empty(), "{got:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn garbage_index_is_rejected() {
        assert!(GitIndex::parse(b"").is_none());
        assert!(GitIndex::parse(b"DIRC\0\0\0\x09\0\0\0\x01").is_none());
        let mut truncated = b"DIRC\0\0\0\x02\0\0\0\x05".to_vec();
        truncated.extend_from_slice(&[0u8; 30]);
        assert!(GitIndex::parse(&truncated).is_none());
    }
}
