//! Inode kind derived from a Unix mode.

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFREG: u32 = 0o100000;
const S_IFIFO: u32 = 0o010000;
const S_IFLNK: u32 = 0o120000;
const S_IFSOCK: u32 = 0o140000;

/// Kind of an inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeKind {
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Regular file.
    Regular,
    /// Character device.
    CharDevice,
    /// Block device.
    BlockDevice,
    /// FIFO / named pipe.
    Fifo,
    /// Unix-domain socket.
    Socket,
    /// Unrecognized file-type bits.
    Unknown,
}

/// Map a Unix mode bitfield (`st_mode`) to an [`InodeKind`].
pub fn mode_kind(mode: u32) -> InodeKind {
    match mode & S_IFMT {
        S_IFDIR => InodeKind::Directory,
        S_IFLNK => InodeKind::Symlink,
        S_IFREG => InodeKind::Regular,
        S_IFCHR => InodeKind::CharDevice,
        S_IFBLK => InodeKind::BlockDevice,
        S_IFIFO => InodeKind::Fifo,
        S_IFSOCK => InodeKind::Socket,
        _ => InodeKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_modes() {
        assert_eq!(mode_kind(0o040755), InodeKind::Directory);
        assert_eq!(mode_kind(0o100644), InodeKind::Regular);
        assert_eq!(mode_kind(0o120777), InodeKind::Symlink);
        assert_eq!(mode_kind(0o020000), InodeKind::CharDevice);
        assert_eq!(mode_kind(0o060000), InodeKind::BlockDevice);
        assert_eq!(mode_kind(0o010000), InodeKind::Fifo);
        assert_eq!(mode_kind(0o140000), InodeKind::Socket);
        assert_eq!(mode_kind(0), InodeKind::Unknown);
    }
}
