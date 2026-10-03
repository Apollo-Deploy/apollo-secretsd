//! Kernel credentials plus a live pidfd and procfs incarnation, never caller PID trust.
use crate::{Error, Result, capability::Peer};
use rustix::{
    event::{PollFd, PollFlags, Timespec},
    fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    fs::{self, Mode, OFlags, ResolveFlags},
    net::{self, UCred},
    process::{Pid, PidfdFlags},
};
use std::{io::Read, sync::Arc};

pub struct Process {
    pub peer: Peer,
    pidfd: OwnedFd,
    pub cgroup: String,
}

impl Process {
    pub fn capture(pid: u32) -> Result<Arc<Self>> {
        let pid_t =
            Pid::from_raw(i32::try_from(pid).map_err(|_| Error::Denied)?).ok_or(Error::Denied)?;

        let pidfd = rustix::process::pidfd_open(pid_t, PidfdFlags::empty())?;

        Self::capture_with_pidfd(pid, pidfd)
    }

    fn capture_with_pidfd(pid: u32, pidfd: OwnedFd) -> Result<Arc<Self>> {
        let start_time = starttime(pid)?;

        let status = read_proc(pid, "status")?;

        let uid = effective(&status, "Uid:")?;

        let gid = effective(&status, "Gid:")?;

        let cgroup = cgroup(pid)?;

        let process = Arc::new(Self {
            peer: Peer {
                uid,
                gid,
                pid,
                start_time,
            },
            pidfd,
            cgroup,
        });

        if starttime(pid)? != start_time || !process.alive()? {
            return Err(Error::Denied);
        }

        Ok(process)
    }

    pub fn alive(&self) -> Result<bool> {
        let mut fds = [PollFd::new(&self.pidfd, PollFlags::IN)];

        let ready = rustix::event::poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )?;

        Ok(ready == 0)
    }
}

pub fn authenticate(socket: impl AsFd, message: &UCred) -> Result<Arc<Process>> {
    let socket = socket.as_fd();

    let connection = net::sockopt::socket_peercred(socket)?;

    if connection.uid != message.uid
        || connection.gid != message.gid
        || connection.pid != message.pid
    {
        return Err(Error::Denied);
    }

    // SO_PEERPIDFD refers to the socket's original peer PID object. Reopening
    // a numeric PID here could instead capture an incarnation created later.
    let pidfd = peer_pidfd(socket)?;

    let process = Process::capture_with_pidfd(message.pid.as_raw_nonzero().get() as u32, pidfd)?;

    if process.peer.uid != message.uid.as_raw() || process.peer.gid != message.gid.as_raw() {
        return Err(Error::Denied);
    }

    Ok(process)
}

/// Linux 6.5+ peer-incarnation primitive. Unsupported kernels fail closed.
pub fn peer_pidfd(socket: impl AsFd) -> Result<OwnedFd> {
    let mut raw = -1;

    let mut length = std::mem::size_of_val(&raw) as libc::socklen_t;

    // SAFETY: Both output pointers describe live, correctly sized scalar storage;
    // the borrowed socket remains live. The kernel returns one new owned pidfd.
    let result = unsafe {
        libc::getsockopt(
            socket.as_fd().as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut raw as *mut libc::c_int).cast(),
            &mut length,
        )
    };

    if result != 0 {
        return Err(
            rustix::io::Errno::from_io_error(&std::io::Error::last_os_error())
                .map(Error::Sys)
                .unwrap_or(Error::Protection),
        );
    }

    if raw < 0 {
        return Err(Error::Protection);
    }

    // SAFETY: Successful SO_PEERPIDFD transfers this fresh descriptor exactly once.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    if length as usize != std::mem::size_of_val(&raw) {
        return Err(Error::Protection);
    }

    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;

    Ok(fd)
}

fn read_proc(pid: u32, file: &str) -> Result<String> {
    let path = format!("/proc/{pid}/{file}");

    let fd = fs::openat2(
        fs::CWD,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;

    let mut input = std::fs::File::from(fd).take(16385);

    let mut bytes = Vec::new();

    input.read_to_end(&mut bytes)?;

    if bytes.len() > 16384 {
        return Err(Error::Denied);
    }

    String::from_utf8(bytes).map_err(|_| Error::Denied)
}

fn starttime(pid: u32) -> Result<u64> {
    let stat = read_proc(pid, "stat")?;

    let (_, fields) = stat.rsplit_once(')').ok_or(Error::Denied)?;

    fields
        .split_ascii_whitespace()
        .nth(19)
        .ok_or(Error::Denied)?
        .parse()
        .map_err(|_| Error::Denied)
}

fn effective(status: &str, label: &str) -> Result<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(label))
        .ok_or(Error::Denied)?
        .split_ascii_whitespace()
        .nth(1)
        .ok_or(Error::Denied)?
        .parse()
        .map_err(|_| Error::Denied)
}

pub fn cgroup(pid: u32) -> Result<String> {
    let group = read_proc(pid, "cgroup")?;

    let path = group
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or(Error::Denied)?;

    if !path.starts_with('/') || path.len() > 1024 || path.contains("..") {
        return Err(Error::Denied);
    }

    Ok(path.into())
}
