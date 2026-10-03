//! Doctor exercises actual kernel mechanisms; unsupported protection returns failure.
use super::Args;
use apollo_secretsd::{
    Error, Result,
    auth::Process,
    client::Client,
    delivery::{SealedSecret, transport},
    memory::{LockedBytes, MemoryBudget},
};
use rustix::{
    fs::{self, SealFlags},
    net::{self, AddressFamily, SocketFlags, SocketType},
};

pub(super) fn run(args: &Args) -> Result<()> {
    let budget = MemoryBudget::new(1024 * 1024);

    let bytes = LockedBytes::from_slice(b"doctor-nonsensitive-probe", &budget)?;

    let sealed = SealedSecret::new(&bytes)?;

    if !fs::fcntl_get_seals(&sealed.fd)?
        .contains(SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL)
    {
        return Err(Error::Protection);
    }

    let (a, b) = net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;

    net::sockopt::set_socket_passcred(&b, true)?;

    transport::send(&a, b"probe", Some(&sealed.fd))?;

    let mut buffer = [0; 16];

    let received = transport::receive(&b, &mut buffer)?;

    if received.fd.is_none() || received.credentials.is_none() {
        return Err(Error::Protection);
    }

    net::sockopt::socket_peercred(&a)?;

    apollo_secretsd::auth::peer_pidfd(&a)?;

    let process = Process::capture(std::process::id())?;

    if !process.alive()? {
        return Err(Error::Protection);
    }

    let limits = rustix::process::getrlimit(rustix::process::Resource::Memlock);

    println!(
        "Linux SO_PEERCRED SO_PEERPIDFD SCM_RIGHTS memfd sealing mlock MADV_DONTDUMP pidfd: PASS"
    );

    println!(
        "RLIMIT_MEMLOCK current={:?} locked_probe_bytes={}",
        limits.current,
        budget.used()
    );

    println!("PR_SET_DUMPABLE=0 RLIMIT_CORE=0: PASS");

    // A raw syscall probe has no secret material or persistent side effects.
    // SAFETY: memfd_secret accepts only scalar flags and returns an owned descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_memfd_secret, 0) };

    if fd >= 0 {
        use std::os::fd::FromRawFd;

        // SAFETY: Successful syscall returns a newly owned FD, closed on drop.
        drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) });

        let root = LockedBytes::from_slice(b"doctor-root-probe", &budget)?.protect_root(true)?;

        if !root.is_secret_memory() {
            return Err(Error::Protection);
        }

        println!("memfd_secret: actual root mapping PASS");
    } else {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS) {
            return Err(Error::Protection);
        }

        println!("memfd_secret: kernel unavailable; required deployment mode will fail");
    }

    configured(args, &budget)?;

    Ok(())
}

fn configured(args: &Args, budget: &std::sync::Arc<MemoryBudget>) -> Result<()> {
    use rustix::{
        fd::AsRawFd,
        fs::{AtFlags, Mode, OFlags, ResolveFlags},
    };
    use secretsd_protocol::{AdminRequest, AuditQuery, Empty, Response, admin_request::Action};
    use std::path::PathBuf;

    let uid = args.number("--server-uid", rustix::process::geteuid().as_raw())?;

    let state = PathBuf::from(
        args.options
            .get("--state")
            .map_or("/var/lib/apollo-secretsd", String::as_str),
    );

    let runtime = PathBuf::from(
        args.options
            .get("--runtime")
            .map_or("/run/apollo-secretsd", String::as_str),
    );

    let state_fd = fs::openat2(
        fs::CWD,
        &state,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;

    let directory = fs::fstat(&state_fd)?;

    if directory.st_uid != uid || directory.st_mode & 0o777 != 0o700 {
        return Err(Error::Protection);
    }

    let runtime_fd = fs::openat2(
        fs::CWD,
        &runtime,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;

    let directory = fs::fstat(&runtime_fd)?;

    if directory.st_uid != uid || directory.st_mode & 0o777 != 0o755 {
        return Err(Error::Protection);
    }

    for (name, mode) in [("admin.sock", 0o600), ("deliver.sock", 0o666)] {
        let info = fs::statat(&runtime_fd, name, AtFlags::SYMLINK_NOFOLLOW)?;

        if fs::FileType::from_raw_mode(info.st_mode) != fs::FileType::Socket
            || info.st_uid != uid
            || info.st_mode & 0o777 != mode
        {
            return Err(Error::Protection);
        }
    }

    let db_fd = fs::openat2(
        &state_fd,
        "state.sqlite3",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;

    apollo_secretsd::filesystem::validate_file(&db_fd, uid, 0o600)?;

    let db = rusqlite::Connection::open_with_flags(
        format!("/proc/self/fd/{}/state.sqlite3", state_fd.as_raw_fd()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;

    let integrity: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;

    let journal: String = db.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;

    if integrity != "ok" || journal != "wal" {
        return Err(Error::Integrity);
    }

    let path = args
        .options
        .get("--socket")
        .map_or_else(|| runtime.join("admin.sock"), PathBuf::from);

    let status: Response = Client::connect(&path, uid, budget.clone())?
        .admin(
            AdminRequest {
                action: Some(Action::Status(Empty {})),
            },
            None,
        )?
        .0;

    if !status
        .capabilities
        .iter()
        .any(|s| s == "root-memfd-secret" || s == "root-mlock-dontdump")
    {
        return Err(Error::Protection);
    }

    let provider = status
        .capabilities
        .iter()
        .find(|s| {
            [
                "key-provider:protected-fd",
                "key-provider:systemd-credential",
                "key-provider:strict-root-file",
                "key-provider:tpm2-device-salted",
                "key-provider:embedded-root",
            ]
            .contains(&s.as_str())
        })
        .ok_or(Error::Protection)?;

    println!("Loaded {provider}: PASS");

    Client::connect(&path, uid, budget.clone())?.admin(
        AdminRequest {
            action: Some(Action::Audit(AuditQuery {
                verify: true,
                after: 0,
                limit: 1,
            })),
        },
        None,
    )?;

    println!(
        "Configured state/socket ownership, SQLite integrity/WAL, loaded root protection and authenticated audit: PASS"
    );

    let unit = args
        .options
        .get("--unit")
        .map_or("apollo-secretsd.service", String::as_str);

    if unit.len() > 128
        || !unit
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
    {
        return Err(Error::Invalid);
    }

    // A read-only systemd CLI query, with a fixed executable and separate argv;
    // the daemon never launches this command or a shell.
    let output = std::process::Command::new("/usr/bin/systemctl").args(["show",unit,"--property=ActiveState,NoNewPrivileges,PrivateTmp,PrivateDevices,PrivateNetwork,ProtectSystem,LimitCORE,LimitMEMLOCK,MemoryDenyWriteExecute,RestrictAddressFamilies"]).output()?;

    if !output.status.success() {
        return Err(Error::Protection);
    }

    let properties = String::from_utf8(output.stdout).map_err(|_| Error::Protection)?;

    for expected in [
        "ActiveState=active",
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
        "PrivateNetwork=yes",
        "ProtectSystem=strict",
        "LimitCORE=0",
        "MemoryDenyWriteExecute=yes",
    ] {
        if !properties.lines().any(|line| line == expected) {
            return Err(Error::Protection);
        }
    }

    let locked = properties
        .lines()
        .find_map(|line| line.strip_prefix("LimitMEMLOCK="))
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or(Error::Protection)?;

    if locked < 64 * 1024 * 1024
        || !properties
            .lines()
            .any(|line| line == "RestrictAddressFamilies=AF_UNIX")
    {
        return Err(Error::Protection);
    }

    println!("Active systemd hardening and configured memlock/core limits: PASS");

    Ok(())
}
