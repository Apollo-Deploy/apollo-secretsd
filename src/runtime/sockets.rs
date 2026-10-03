//! A pinned runtime directory and exclusive lock protect socket creation/removal.
use crate::{Error, Result, filesystem::SecureDir};
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, Mode},
    net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType},
};

pub(super) struct Sockets {
    pub admin: OwnedFd,
    pub deliver: OwnedFd,
    _lock: OwnedFd,
    _directory: SecureDir,
}

impl Sockets {
    pub(super) fn bind(directory: SecureDir) -> Result<Self> {
        let lock = directory.lock("runtime.lock")?;

        let admin = bind_one(&directory, "admin.sock", 0o600)?;

        let deliver = bind_one(&directory, "deliver.sock", 0o666)?;

        Ok(Self {
            admin,
            deliver,
            _lock: lock,
            _directory: directory,
        })
    }
}

fn bind_one(directory: &SecureDir, name: &str, mode: u32) -> Result<OwnedFd> {
    match fs::statat(directory.fd(), name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::Socket
                || stat.st_uid != rustix::process::geteuid().as_raw()
            {
                return Err(Error::Protection);
            }

            fs::unlinkat(directory.fd(), name, AtFlags::empty())?;
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(e) => return Err(e.into()),
    }

    let fd = net::socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;

    net::sockopt::set_socket_passcred(&fd, true)?;

    net::bind(&fd, &SocketAddrUnix::new(directory.proc_path(name)?)?)?;

    fs::chmodat(
        directory.fd(),
        name,
        Mode::from_bits_truncate(mode),
        AtFlags::empty(),
    )?;

    net::listen(&fd, 128)?;

    Ok(fd)
}
