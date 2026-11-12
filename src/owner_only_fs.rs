//! Directories and files a process keeps for its own account, opened without
//! following a link, and the free space of the volume they are on.
//!
//! For data that must not be redirected by a link planted where the
//! directory, or a file in it, belongs: the directory is checked to be a real
//! directory of this account before anything is written into it, and a file
//! is opened as itself, never as the target of a link. An open never waits:
//! a named pipe planted where a file belongs is refused at once, not read
//! until something writes to it. This does not keep another process of the
//! same account out: such a process can read, change or delete what is here.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

fn refused(what: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, what)
}

/// Create the folders above `dir` when they are missing. They are the
/// caller's ordinary storage folders and keep the mode they get.
fn create_parents(dir: &Path) -> io::Result<()> {
    match dir.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => std::fs::create_dir_all(parent),
        _ => Ok(()),
    }
}

/// Make `dir` a directory of this account alone: created with mode 0700 when
/// missing (its parents with their default mode), refused when it is a link,
/// anything but a directory, or another account's, and set back to 0700 when
/// it was there with another mode. The directory is opened without following
/// a link, and its owner and mode are read and set on that open directory.
#[cfg(unix)]
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    if let Err(e) = std::fs::symlink_metadata(dir) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e);
        }
        create_parents(dir)?;
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("{} is not a directory of its own: {e}", dir.display()),
            )
        })?;
    let meta = handle.metadata()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() } as u32;
    if meta.uid() != me {
        return Err(refused(format!(
            "{} belongs to another account (uid {})",
            dir.display(),
            meta.uid()
        )));
    }
    if meta.permissions().mode() & 0o777 != 0o700 {
        handle.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Win32 open flags and file attributes, under their own names.
#[cfg(windows)]
mod win32 {
    pub const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    pub const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
}

/// Make `dir` a directory of its own: created when missing, refused when it
/// is a reparse point (a link, a junction) or anything but a directory. The
/// directory is opened as itself, without following a reparse point, and its
/// attributes are read on that handle, not on the path. No owner is checked
/// and no access control is set here: the directory inherits its parent's.
#[cfg(windows)]
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    if let Err(e) = std::fs::symlink_metadata(dir) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e);
        }
        create_parents(dir)?;
        match std::fs::create_dir(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(win32::FILE_FLAG_BACKUP_SEMANTICS | win32::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(dir)?;
    let attributes = handle.metadata()?.file_attributes();
    if attributes & win32::FILE_ATTRIBUTE_REPARSE_POINT != 0
        || attributes & win32::FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(refused(format!(
            "{} is not a directory of its own",
            dir.display()
        )));
    }
    Ok(())
}

/// Make `dir` a directory of its own: created when missing, refused when it
/// is a link or anything but a directory.
#[cfg(not(any(unix, windows)))]
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    if let Err(e) = std::fs::symlink_metadata(dir) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e);
        }
        create_parents(dir)?;
        match std::fs::create_dir(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    if !std::fs::symlink_metadata(dir)?.file_type().is_dir() {
        return Err(refused(format!(
            "{} is not a directory of its own",
            dir.display()
        )));
    }
    Ok(())
}

/// Open `path` for writing as a file of this account alone (mode 0600 when
/// created), never through a link: `create_new` refuses a path that exists,
/// otherwise the file is created when missing and kept as it is when there.
/// A link at `path`, or anything but a regular file, is refused. The open
/// does not wait: a named pipe at `path` that nothing reads is refused at
/// once (a blocking open of it would wait for a reader for ever).
#[cfg(unix)]
pub fn open_private_file(path: &Path, create_new: bool) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(false);
    }
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(refused(format!("{} is not a regular file", path.display())));
    }
    Ok(file)
}

/// Open `path` for writing, never through a reparse point: `create_new`
/// refuses a path that exists, otherwise the file is created when missing and
/// kept as it is when there. The file is opened as itself and its attributes
/// are read on that handle: a reparse point (a link) or a directory is
/// refused.
#[cfg(windows)]
pub fn open_private_file(path: &Path, create_new: bool) -> io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let mut options = OpenOptions::new();
    options
        .write(true)
        .custom_flags(win32::FILE_FLAG_OPEN_REPARSE_POINT);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(false);
    }
    let file = options.open(path)?;
    let attributes = file.metadata()?.file_attributes();
    if attributes & (win32::FILE_ATTRIBUTE_REPARSE_POINT | win32::FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(refused(format!("{} is not a regular file", path.display())));
    }
    Ok(file)
}

/// Open `path` for writing: `create_new` refuses a path that exists,
/// otherwise the file is created when missing and kept as it is when there.
/// A link at `path`, or anything but a regular file, is refused.
#[cfg(not(any(unix, windows)))]
pub fn open_private_file(path: &Path, create_new: bool) -> io::Result<File> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_file() {
            return Err(refused(format!("{} is not a regular file", path.display())));
        }
    }
    let mut options = OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(false);
    }
    options.open(path)
}

/// `path` is a regular file itself, not a link to one.
pub fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
}

/// The nearest folder at or above `path` that exists.
#[cfg(any(unix, windows))]
fn nearest_existing(path: &Path) -> Option<&Path> {
    path.ancestors().find(|ancestor| ancestor.exists())
}

/// Bytes an unprivileged process can still write on the volume that holds
/// `path` (the nearest existing folder when `path` is not there yet). `None`
/// when it cannot be measured: unknown, not zero.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
pub fn available_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let existing = nearest_existing(path)?;
    let c_path = std::ffi::CString::new(existing.as_os_str().as_bytes()).ok()?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c_path` is a valid C string and `stats` is writable storage
    // for one `statvfs`, which the call fills when it returns 0.
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: the call returned 0, so `stats` is initialized.
    let stats = unsafe { stats.assume_init() };
    Some((stats.f_bavail as u64).saturating_mul(stats.f_frsize as u64))
}

/// Bytes the calling account can still write on the volume that holds `path`
/// (the nearest existing folder when `path` is not there yet). `None` when
/// it cannot be measured: unknown, not zero.
#[cfg(windows)]
pub fn available_bytes(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let existing = nearest_existing(path)?;
    let wide: Vec<u16> = existing
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut free: u64 = 0;
    // SAFETY: `wide` is NUL-terminated and outlives the call; `free` is
    // writable storage for the one value asked for.
    unsafe {
        GetDiskFreeSpaceExW(
            PCWSTR(wide.as_ptr()),
            Some(&mut free as *mut u64),
            None,
            None,
        )
    }
    .ok()?;
    Some(free)
}

/// Not measured on this platform: unknown, not zero.
#[cfg(not(any(unix, windows)))]
pub fn available_bytes(_path: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_private_dir_is_created_owner_only_with_its_parents() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("storage").join("recording");
        ensure_private_dir(&dir).unwrap();
        assert!(dir.is_dir());
        // Again: a directory that is there and its own is taken as it is.
        ensure_private_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            // A directory left with another mode is set back.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            ensure_private_dir(&dir).unwrap();
            assert_eq!(mode(&dir), 0o700);
        }
    }

    #[test]
    fn a_file_where_the_directory_belongs_is_refused() {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("recording");
        std::fs::write(&path, "not a directory").unwrap();
        assert!(ensure_private_dir(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not a directory");
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_never_followed() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = tempfile::tempdir().unwrap();
        let elsewhere = scratch.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
        // A link where the directory belongs: refused, its target untouched.
        let dir = scratch.path().join("recording");
        std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
        assert!(ensure_private_dir(&dir).is_err());
        let mode = std::fs::metadata(&elsewhere).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "the link's target keeps its mode");
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());

        // A link where a file belongs: refused, its target untouched.
        let real = scratch.path().join("real");
        ensure_private_dir(&real).unwrap();
        let target = elsewhere.join("target");
        std::fs::write(&target, "kept").unwrap();
        let link = real.join("writer.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_private_file(&link, false).is_err());
        assert!(open_private_file(&link, true).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "kept");
        assert!(!is_regular_file(&link));
        assert!(is_regular_file(&target));
    }

    /// A named pipe where a file belongs is refused at once: a blocking open
    /// of it would wait for a reader for ever. A directory there is refused
    /// too, and so is a pipe where the directory belongs.
    #[cfg(unix)]
    #[test]
    fn a_named_pipe_or_a_directory_where_a_file_belongs_is_refused_without_waiting() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("recording");
        ensure_private_dir(&dir).unwrap();
        let mkfifo = |path: &Path| {
            let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: `c_path` is a valid C string.
            assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        };
        // An open that waits for the pipe's other end fails this test within
        // a bound instead of holding it: the open runs on its own thread, and
        // when it has not returned in time the pipe is opened at both ends
        // (and kept open) so that it returns, and the test fails with the
        // reason.
        let within_bound = |what: &str, path: &Path, open: fn(&Path) -> bool| {
            let (done, returned) = std::sync::mpsc::channel();
            let target = path.to_path_buf();
            std::thread::spawn(move || {
                let _ = done.send(open(&target));
            });
            match returned.recv_timeout(std::time::Duration::from_secs(5)) {
                Ok(refused) => assert!(refused, "{what}: refused"),
                Err(_) => {
                    let both_ends = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .custom_flags(libc::O_NONBLOCK)
                        .open(path);
                    std::mem::forget(both_ends);
                    panic!("{what}: the open waited for the pipe's other end");
                }
            }
        };
        let pipe = dir.join("writer.lock");
        mkfifo(&pipe);
        within_bound("an existing file's open", &pipe, |path| {
            open_private_file(path, false).is_err()
        });
        within_bound("a new file's open", &pipe, |path| {
            open_private_file(path, true).is_err()
        });
        assert!(!is_regular_file(&pipe));

        let folder = dir.join("a-folder");
        std::fs::create_dir(&folder).unwrap();
        assert!(open_private_file(&folder, false).is_err());
        assert!(open_private_file(&folder, true).is_err());

        let pipe_dir = scratch.path().join("pipe-where-the-directory-belongs");
        mkfifo(&pipe_dir);
        within_bound("a directory's open", &pipe_dir, |path| {
            ensure_private_dir(path).is_err()
        });
    }

    #[test]
    fn a_private_file_is_created_once_and_kept() {
        use std::io::Write;
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("segment");
        let mut file = open_private_file(&path, true).unwrap();
        file.write_all(b"one").unwrap();
        drop(file);
        assert!(open_private_file(&path, true).is_err(), "it exists");
        // Opened again without `create_new`, it keeps what it holds.
        drop(open_private_file(&path, false).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        assert!(is_regular_file(&path));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn free_space_is_measured_for_a_path_that_is_not_there_yet() {
        let scratch = tempfile::tempdir().unwrap();
        let there = available_bytes(scratch.path());
        let not_yet = available_bytes(&scratch.path().join("a").join("b"));
        #[cfg(any(unix, windows))]
        {
            assert!(there.is_some_and(|bytes| bytes > 0));
            assert!(not_yet.is_some());
        }
        #[cfg(not(any(unix, windows)))]
        assert!(there.is_none() && not_yet.is_none());
    }
}
