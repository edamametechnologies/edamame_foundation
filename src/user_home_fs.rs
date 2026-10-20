//! What a privileged process creates in a user's home, on that user's behalf.
//!
//! The EDAMAME Helper (root on macOS) and posture running as root write a few
//! files into the operator's home: the prompt and the launcher script of an
//! agent fix run, under `~/.edamame/agent-fix-runs/`. What they create there
//! belongs to the home's owner, so the user's own EDAMAME (the app, the CLI)
//! keeps writing to `~/.edamame`: its file secret store lives there, and on
//! Linux its settings too.
//!
//! These functions create each missing folder and the file inside the home
//! only, as real folders and a new file (an existing file is refused), and give
//! what they create to the home's owner. Not running as root, they do the same
//! without the ownership change. They only touch EDAMAME's own folder
//! ([`EDAMAME_HOME_DIR`]).

use std::io;
use std::path::{Component, Path, PathBuf};

/// EDAMAME's folder in a home.
pub const EDAMAME_HOME_DIR: &str = ".edamame";

/// `relative` must be a plain relative path inside EDAMAME's folder.
fn check_relative(relative: &Path) -> io::Result<()> {
    let mut components = relative.components();
    let inside =
        matches!(components.next(), Some(Component::Normal(first)) if first == EDAMAME_HOME_DIR);
    if !inside || !components.all(|c| matches!(c, Component::Normal(_))) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a plain path inside {EDAMAME_HOME_DIR}",
                relative.display()
            ),
        ));
    }
    Ok(())
}

fn check_file_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name:?} is not a file name"),
        ));
    }
    Ok(())
}

/// Create `home/relative` (each missing folder `0700`) and return its path.
/// Running as root, every folder it creates belongs to the home's owner, and so
/// does a folder of that tree a root process created before. A symlink or a
/// file where a folder belongs is refused.
pub fn create_user_dir(home: &Path, relative: &Path) -> io::Result<PathBuf> {
    check_relative(relative)?;
    imp::open_user_dir(home, relative)?;
    Ok(home.join(relative))
}

/// Create the new file `home/relative_dir/name` with `contents` and `mode`,
/// its folders as [`create_user_dir`] does. An existing file or symlink of that
/// name is refused, never written through. Running as root, the file belongs to
/// the home's owner.
pub fn create_user_file(
    home: &Path,
    relative_dir: &Path,
    name: &str,
    contents: &[u8],
    mode: u32,
) -> io::Result<PathBuf> {
    check_relative(relative_dir)?;
    check_file_name(name)?;
    imp::create_user_file(home, relative_dir, name, contents, mode)
}

/// Give a root-owned `home/.edamame` back to the home's owner. Only running as
/// root, only a real folder (never a symlink), only in a home that belongs to
/// someone else. Returns whether it changed the owner. A root process that
/// created the folder with the user's `HOME` (a `sudo` run that kept `HOME`)
/// leaves it unwritable for the user's own EDAMAME.
pub fn restore_edamame_dir_owner(home: &Path) -> io::Result<bool> {
    imp::restore_edamame_dir_owner(home)
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::ffi::{CString, OsStr};
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn c_name(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a path holds a NUL byte"))
    }

    fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }

    /// The home's owner, when this process is root and the home belongs to
    /// someone else: what root creates there goes to that account.
    fn new_owner(home: &Path) -> io::Result<Option<(u32, u32)>> {
        if unsafe { libc::geteuid() } != 0 {
            return Ok(None);
        }
        let meta = std::fs::metadata(home)?;
        if !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a directory", home.display()),
            ));
        }
        Ok((meta.uid() != 0).then_some((meta.uid(), meta.gid())))
    }

    fn open_home(home: &Path) -> io::Result<OwnedFd> {
        let path = c_name(home.as_os_str())?;
        let fd = check(unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        })?;
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// `O_NOFOLLOW`: a symlink where a folder belongs is ELOOP, a file ENOTDIR.
    fn open_child_dir(parent: &OwnedFd, name: &CString) -> io::Result<OwnedFd> {
        let fd = check(unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn uid_of(fd: &OwnedFd) -> io::Result<u32> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        check(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) })?;
        Ok(st.st_uid)
    }

    fn give(fd: &OwnedFd, (uid, gid): (u32, u32)) -> io::Result<()> {
        check(unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) })?;
        Ok(())
    }

    pub(super) fn open_user_dir(home: &Path, relative: &Path) -> io::Result<OwnedFd> {
        let owner = new_owner(home)?;
        let mut dir = open_home(home)?;
        for component in relative.components() {
            let name = c_name(component.as_os_str())?;
            let created = match check(unsafe {
                libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700 as libc::mode_t)
            }) {
                Ok(_) => true,
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => false,
                Err(e) => return Err(e),
            };
            let child = open_child_dir(&dir, &name)?;
            if let Some(owner) = owner {
                if created || uid_of(&child)? == 0 {
                    give(&child, owner)?;
                }
            }
            dir = child;
        }
        Ok(dir)
    }

    pub(super) fn create_user_file(
        home: &Path,
        relative_dir: &Path,
        name: &str,
        contents: &[u8],
        mode: u32,
    ) -> io::Result<PathBuf> {
        let owner = new_owner(home)?;
        let dir = open_user_dir(home, relative_dir)?;
        let c = c_name(OsStr::new(name))?;
        let fd = check(unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        })?;
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        if let Some(owner) = owner {
            give(&fd, owner)?;
        }
        let mut file = std::fs::File::from(fd);
        file.write_all(contents)?;
        // The umask may have trimmed `mode` at creation.
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        Ok(home.join(relative_dir).join(name))
    }

    pub(super) fn restore_edamame_dir_owner(home: &Path) -> io::Result<bool> {
        let Some(owner) = new_owner(home)? else {
            return Ok(false);
        };
        let home_fd = open_home(home)?;
        let name = c_name(OsStr::new(EDAMAME_HOME_DIR))?;
        let dir = match open_child_dir(&home_fd, &name) {
            Ok(dir) => dir,
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOENT) | Some(libc::ELOOP) | Some(libc::ENOTDIR)
                ) =>
            {
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        if uid_of(&dir)? != 0 {
            return Ok(false);
        }
        give(&dir, owner)?;
        Ok(true)
    }
}

/// Windows: the helper (SYSTEM) creates folders in a profile that inherit the
/// profile's ACL, so the user keeps access; only the no-overwrite rule applies.
#[cfg(not(unix))]
mod imp {
    use super::*;
    use std::io::Write;

    pub(super) fn open_user_dir(home: &Path, relative: &Path) -> io::Result<()> {
        std::fs::create_dir_all(home.join(relative))
    }

    pub(super) fn create_user_file(
        home: &Path,
        relative_dir: &Path,
        name: &str,
        contents: &[u8],
        _mode: u32,
    ) -> io::Result<PathBuf> {
        open_user_dir(home, relative_dir)?;
        let path = home.join(relative_dir).join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(contents)?;
        Ok(path)
    }

    pub(super) fn restore_edamame_dir_owner(_home: &Path) -> io::Result<bool> {
        Ok(false)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "edamame-user-home-fs-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn folders_and_a_file_are_created_inside_edamames_folder_only() {
        let home = temp_home("create");
        let runs = Path::new(EDAMAME_HOME_DIR).join("agent-fix-runs");
        let dir = create_user_dir(&home, &runs).unwrap();
        assert!(dir.is_dir());
        let mode = std::fs::metadata(home.join(EDAMAME_HOME_DIR))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);

        let path = create_user_file(&home, &runs, "a.prompt.txt", b"hello", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // A second write of the same name is refused, never overwritten.
        assert!(create_user_file(&home, &runs, "a.prompt.txt", b"again", 0o600).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");

        // Outside EDAMAME's folder, or a name that walks out of it: refused.
        assert!(create_user_dir(&home, Path::new("Library/x")).is_err());
        assert!(create_user_dir(&home, Path::new(".edamame/../x")).is_err());
        assert!(create_user_file(&home, &runs, "../x", b"", 0o600).is_err());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_planted_symlink_is_refused_not_followed() {
        let home = temp_home("symlink");
        let elsewhere = temp_home("elsewhere");
        // The folder itself is a symlink to a tree outside the home.
        std::os::unix::fs::symlink(&elsewhere, home.join(EDAMAME_HOME_DIR)).unwrap();
        let runs = Path::new(EDAMAME_HOME_DIR).join("agent-fix-runs");
        assert!(create_user_dir(&home, &runs).is_err());
        assert!(!elsewhere.join("agent-fix-runs").exists());
        std::fs::remove_file(home.join(EDAMAME_HOME_DIR)).unwrap();

        // The file name is a symlink to a file outside the home.
        let target = elsewhere.join("victim");
        std::fs::write(&target, b"untouched").unwrap();
        create_user_dir(&home, &runs).unwrap();
        std::os::unix::fs::symlink(&target, home.join(&runs).join("b.command")).unwrap();
        assert!(create_user_file(&home, &runs, "b.command", b"#!/bin/bash\n", 0o755).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        std::fs::remove_dir_all(&home).ok();
        std::fs::remove_dir_all(&elsewhere).ok();
    }

    #[test]
    fn restoring_the_owner_is_for_root_only() {
        // Tests do not run as root: nothing to give back, nothing changed.
        let home = temp_home("restore");
        std::fs::create_dir_all(home.join(EDAMAME_HOME_DIR)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(!restore_edamame_dir_owner(&home).unwrap());
        }
        std::fs::remove_dir_all(&home).ok();
    }
}
