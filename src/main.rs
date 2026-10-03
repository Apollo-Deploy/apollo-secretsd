//! Fail closed before loading keys; only explicitly configured local sockets.
#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = run() {
        eprintln!("apollo-secretsd: {}", error);

        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("apollo-secretsd requires Linux");

    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn run() -> apollo_secretsd::Result<()> {
    use apollo_secretsd::{
        Error,
        config::{Config, Limits},
        crypto::Keys,
        filesystem::SecureDir,
        key_provider::{KeyProvider, ProtectedFd, RootFile},
        memory::{self, MemoryBudget, ProtectedThread},
        runtime::Runtime,
        service::Service,
        storage::Store,
    };
    use rustix::fd::{BorrowedFd, OwnedFd};
    use std::{
        path::PathBuf,
        sync::{Arc, atomic::AtomicBool},
    };

    memory::harden_process()?;

    // SAFETY: Startup is single-threaded; prevent environment-enabled native TPM
    // tracing from writing sensitive intermediate buffers to stderr or a file.
    unsafe {
        std::env::set_var("TSS2_LOG", "all+NONE");
    }

    let mut state = PathBuf::from("/var/lib/apollo-secretsd");

    let mut runtime = PathBuf::from("/run/apollo-secretsd");

    let mut admin_uids = vec![0];

    let mut limits = Limits::default();

    let mut configured_limits = std::collections::HashSet::new();

    let mut provider: Option<Box<dyn KeyProvider>> = None;

    let mut require_secret_memory = false;

    #[cfg(feature = "tpm2")]
    type TpmConfiguration = (u32, u32, String, [u8; 34], [u8; 34]);

    #[cfg(feature = "tpm2")]
    let mut tpm: Option<TpmConfiguration> = None;

    let mut args = std::env::args().skip(1);

    while let Some(flag) = args.next() {
        if flag == "--require-secret-memory" {
            require_secret_memory = true;

            continue;
        }

        if flag == "--help" {
            println!(
                "apollo-secretsd [--state DIR] [--runtime DIR] [--admin-uids UID,...] [--limit NAME=U64] [--require-secret-memory] (--key-fd N | --key-file PATH | --credential NAME | --tpm2 SEALED:SALT:AUTH_SOURCE:SEALED_NAME:SALT_NAME [feature=tpm2])"
            );

            return Ok(());
        }

        let value = args.next().ok_or(Error::Invalid)?;

        match flag.as_str() {
            "--limit" => {
                let (name, value) = value.split_once('=').ok_or(Error::Invalid)?;

                if !configured_limits.insert(name.to_owned()) {
                    return Err(Error::Invalid);
                }

                limits.set(name, value.parse().map_err(|_| Error::Invalid)?)?;
            }
            #[cfg(feature = "tpm2")]
            "--tpm2" => {
                let parts: Vec<_> = value.split(':').collect();

                if parts.len() != 5 || tpm.is_some() {
                    return Err(Error::Invalid);
                }

                tpm = Some((
                    u32::from_str_radix(parts[0].trim_start_matches("0x"), 16)
                        .map_err(|_| Error::Invalid)?,
                    u32::from_str_radix(parts[1].trim_start_matches("0x"), 16)
                        .map_err(|_| Error::Invalid)?,
                    parts[2].to_owned(),
                    tpm_name(parts[3])?,
                    tpm_name(parts[4])?,
                ));
            }
            "--state" => state = value.into(),
            "--runtime" => runtime = value.into(),
            "--admin-uids" => {
                admin_uids = value
                    .split(',')
                    .map(|s| s.parse::<u32>().map_err(|_| Error::Invalid))
                    .collect::<Result<_, _>>()?;
            }
            "--key-file" => {
                if provider.is_some() {
                    return Err(Error::Invalid);
                }

                provider = Some(Box::new(RootFile { path: value.into() }));
            }
            "--key-fd" => {
                if provider.is_some() {
                    return Err(Error::Invalid);
                }

                let fd = value.parse::<i32>().map_err(|_| Error::Invalid)?;

                if fd < 3 {
                    return Err(Error::Invalid);
                }

                // SAFETY: The controller explicitly designates an inherited live FD;
                // borrow it only for dup, which validates it without taking ownership.
                let owned: OwnedFd = rustix::io::dup(unsafe { BorrowedFd::borrow_raw(fd) })?;

                // SAFETY: --key-fd transfers ownership of this inherited FD. A
                // checked duplicate is already owned; retire the original now.
                unsafe {
                    libc::close(fd);
                }

                provider = Some(Box::new(ProtectedFd::new(owned)));
            }
            "--credential" => {
                if provider.is_some() {
                    return Err(Error::Invalid);
                }

                provider = Some(Box::new(startup_phase(
                    "credential-open",
                    credential_provider(&value),
                )?));
            }
            _ => return Err(Error::Invalid),
        }
    }

    let config = Config {
        state,
        runtime,
        admin_uids,
        limits,
    };

    #[cfg(feature = "tpm2")]
    if let Some((sealed_handle, salt_handle, source, sealed_name, salt_name)) = tpm {
        if provider.is_some() {
            return Err(Error::Invalid);
        }

        let auth: Box<dyn KeyProvider> = if let Some(name) = source.strip_prefix("credential=") {
            Box::new(credential_provider(name)?)
        } else {
            let raw: i32 = source.parse().map_err(|_| Error::Invalid)?;

            if raw < 3 {
                return Err(Error::Invalid);
            }

            // SAFETY: The controller transfers the inherited authentication FD;
            // dup validates it before taking ownership of the original descriptor.
            let fd = rustix::io::dup(unsafe { BorrowedFd::borrow_raw(raw) })?;

            // SAFETY: The validated duplicate owns the key source; the controller
            // transferred the original inherited descriptor, which is now retired.
            unsafe {
                libc::close(raw);
            }

            Box::new(ProtectedFd::new(fd))
        };

        provider = Some(Box::new(apollo_secretsd::key_provider::Tpm2 {
            sealed_handle,
            salt_handle,
            sealed_name,
            salt_name,
            auth,
        }));
    }

    config.validate()?;

    startup_phase("address-space-lock", memory::lock_address_space())?;

    let budget = MemoryBudget::new(config.limits.locked_bytes);

    let boot_budget = Arc::clone(&budget);

    let boot_config = config.clone();

    let mut provider = provider.ok_or(Error::Invalid)?;

    let service = ProtectedThread::spawn(&budget, move || {
        let root = startup_phase("provider-load", provider.load(&boot_budget))?;

        let root = startup_phase(
            "root-secret-memory",
            root.protect_root(require_secret_memory),
        )?;

        let keys = startup_phase("key-derivation", Keys::new(root, boot_budget))?;

        let directory = startup_phase(
            "state-directory",
            SecureDir::open(&boot_config.state, 0o700),
        )?;

        let store = startup_phase(
            "database",
            Store::open(directory, keys, boot_config.limits.audit_records),
        )?;

        Service::with_provider(store, boot_config.limits, &*provider)
    })?
    .join()??;

    let stop = Arc::new(AtomicBool::new(false));

    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(signal, Arc::clone(&stop))?;
    }

    let daemon = startup_phase("socket-runtime", Runtime::bind(config, service, stop))?;

    daemon.run_with_ready(|| startup_phase("systemd-notify", notify_ready()))
}

#[cfg(target_os = "linux")]
fn startup_phase<T>(
    phase: &'static str,
    result: apollo_secretsd::Result<T>,
) -> apollo_secretsd::Result<T> {
    result.inspect_err(|_| eprintln!("apollo-secretsd startup phase: {phase}"))
}

#[cfg(target_os = "linux")]
fn notify_ready() -> apollo_secretsd::Result<()> {
    // systemd notification is local AF_UNIX and contains no security material.
    if let Some(path) = std::env::var_os("NOTIFY_SOCKET") {
        use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
        use std::os::unix::ffi::OsStrExt;

        let bytes = path.as_os_str().as_bytes();

        let address = if bytes.first() == Some(&b'@') {
            SocketAddrUnix::new_abstract_name(&bytes[1..])?
        } else {
            SocketAddrUnix::new(std::path::Path::new(&path))?
        };

        let fd = net::socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )?;

        net::sendto(&fd, b"READY=1", net::SendFlags::NOSIGNAL, &address)?;
    }

    Ok(())
}

#[cfg(all(target_os = "linux", feature = "tpm2"))]
fn tpm_name(value: &str) -> apollo_secretsd::Result<[u8; 34]> {
    use apollo_secretsd::Error;

    if value.len() != 68 || !value.is_ascii() {
        return Err(Error::Invalid);
    }

    let mut name = [0; 34];

    for (i, byte) in name.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| Error::Invalid)?;
    }

    if name[..2] != [0, 0x0b] {
        return Err(Error::Invalid);
    }

    Ok(name)
}

#[cfg(target_os = "linux")]
fn credential_provider(
    name: &str,
) -> apollo_secretsd::Result<apollo_secretsd::key_provider::SystemdCredential> {
    use apollo_secretsd::Error;

    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::Invalid);
    }

    let directory = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(Error::Invalid)?;

    apollo_secretsd::key_provider::SystemdCredential::open(std::path::Path::new(&directory), name)
}
