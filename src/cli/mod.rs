//! Explicit FD input/output. There is no plaintext retrieval or argv value option.
mod commands;
mod doctor;

use apollo_secretsd::{
    Error, Result,
    client::Client,
    delivery::SealedSecret,
    memory::{self, LockedBytes, MemoryBudget},
};
use secretsd_protocol::*;
use std::{collections::HashMap, io::Read, path::PathBuf};

pub(super) struct Args {
    pub positional: Vec<String>,
    pub options: HashMap<String, String>,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut positional = Vec::new();

        let mut options = HashMap::new();

        let mut raw = std::env::args().skip(1);

        while let Some(arg) = raw.next() {
            if arg.starts_with("--") {
                if ![
                    "--socket",
                    "--server-uid",
                    "--namespace",
                    "--secret",
                    "--capability",
                    "--version",
                    "--name",
                    "--recipient",
                    "--generation",
                    "--uid",
                    "--gid",
                    "--pid",
                    "--ttl-ms",
                    "--max-uses",
                    "--cgroup",
                    "--stdin",
                    "--file",
                    "--fd",
                    "--out-fd",
                    "--after",
                    "--limit",
                    "--kind",
                    "--next-generation",
                    "--state",
                    "--runtime",
                    "--unit",
                ]
                .contains(&arg.as_str())
                {
                    return Err(Error::Invalid);
                }

                let value = if arg == "--stdin" {
                    String::new()
                } else {
                    raw.next().ok_or(Error::Invalid)?
                };

                if options.insert(arg, value).is_some() {
                    return Err(Error::Invalid);
                }
            } else {
                positional.push(arg);
            }
        }

        Ok(Self {
            positional,
            options,
        })
    }

    pub(crate) fn get(&self, key: &str) -> Result<&str> {
        self.options
            .get(key)
            .map(String::as_str)
            .ok_or(Error::Invalid)
    }

    pub(crate) fn number<T: std::str::FromStr>(&self, key: &str, default: T) -> Result<T> {
        self.options
            .get(key)
            .map_or(Ok(default), |v| v.parse().map_err(|_| Error::Invalid))
    }

    pub(crate) fn id(&self, key: &str) -> Result<Vec<u8>> {
        parse_id(self.get(key)?)
    }
}

pub(crate) fn run() -> Result<()> {
    memory::harden_process()?;

    if std::env::args().skip(1).eq(["--help"]) {
        println!(
            "apollo-secretsctl doctor|status|namespace create/inspect/delete|secret create/put/metadata/list/activate/disable/delete|grant issue/revoke|key status/rotate|audit verify/tail\nValues enter through --stdin, --file or --fd. Grant tokens leave through --out-fd (Unix socket). Use --socket and --server-uid for a configured daemon."
        );

        return Ok(());
    }

    let args = Args::parse()?;

    if args.positional.first().is_some_and(|s| s == "doctor") {
        return doctor::run(&args);
    }

    let action = commands::action(&args)?;

    let budget = MemoryBudget::new(16 * 1024 * 1024);

    let input = if matches!(
        action,
        admin_request::Action::SecretCreate(_) | admin_request::Action::SecretPut(_)
    ) {
        Some(read_input(&args, &budget)?)
    } else {
        None
    };

    let sealed = input.as_ref().map(SealedSecret::new).transpose()?;

    let mut action = action;

    if let admin_request::Action::SecretCreate(ref mut input)
    | admin_request::Action::SecretPut(ref mut input) = action
    {
        input.length = sealed.as_ref().ok_or(Error::Invalid)?.length as u64;
    }

    if matches!(action, admin_request::Action::GrantIssue(_))
        && !args.options.contains_key("--out-fd")
    {
        return Err(Error::Invalid);
    }

    let path = PathBuf::from(
        args.options
            .get("--socket")
            .map_or("/run/apollo-secretsd/admin.sock", String::as_str),
    );

    let uid = args.number("--server-uid", rustix::process::geteuid().as_raw())?;

    let client = Client::connect(&path, uid, budget)?;

    let (response, fd) = client.admin(
        AdminRequest {
            action: Some(action),
        },
        sealed.as_ref().map(|s| &s.fd),
    )?;

    if let Some(fd) = fd {
        let raw = args.number::<i32>("--out-fd", -1)?;

        if raw < 3 {
            return Err(Error::Invalid);
        }

        // Transfer the capability FD itself over a controller-designated Unix socket;
        // never write token bytes to a caller-selected file or terminal.
        use rustix::fd::BorrowedFd;

        // SAFETY: Only borrow for sendmsg. The user owns the inherited descriptor;
        // sendmsg validates whether it is a socket and does not close it.
        let channel = unsafe { BorrowedFd::borrow_raw(raw) };

        apollo_secretsd::delivery::transport::send(channel, b"grant", Some(&fd))?;
    }

    if !response.id.is_empty() {
        println!(
            "id={} version={} generation={}",
            hex(&response.id),
            response.version,
            response.generation
        );
    }

    if !response.daemon_version.is_empty() {
        println!(
            "daemon={} protocol={}-{}",
            response.daemon_version, response.minimum_protocol, response.maximum_protocol
        );
    }

    for capability in response.capabilities {
        println!("{capability}");
    }

    for entry in response.entries {
        println!(
            "{} {} {} enabled={}",
            hex(&entry.id),
            entry.version,
            entry.name,
            entry.enabled
        );
    }

    Ok(())
}

fn read_input(args: &Args, budget: &std::sync::Arc<MemoryBudget>) -> Result<LockedBytes> {
    let count = ["--stdin", "--file", "--fd"]
        .iter()
        .filter(|k| args.options.contains_key(**k))
        .count();

    if count != 1 {
        return Err(Error::Invalid);
    }

    let mut input: Box<dyn Read> = if args.options.contains_key("--stdin") {
        Box::new(std::io::stdin())
    } else if let Some(path) = args.options.get("--file") {
        Box::new(std::fs::File::open(path)?)
    } else {
        use rustix::fd::BorrowedFd;

        let raw = args.number::<i32>("--fd", -1)?;

        if raw < 3 {
            return Err(Error::Invalid);
        }

        // SAFETY: Borrow a controller-designated FD only for a checked dup.
        let fd = rustix::io::dup(unsafe { BorrowedFd::borrow_raw(raw) })?;

        Box::new(std::fs::File::from(fd))
    };

    let mut bytes = LockedBytes::new(1024 * 1024 + 1, budget)?;

    let mut length = 0;

    while length < bytes.len() {
        let n = input.read(&mut bytes.as_mut_slice()[length..])?;

        if n == 0 {
            break;
        }

        length += n;
    }

    if length == 0 || length > 1024 * 1024 {
        return Err(Error::Limit);
    }

    bytes.truncate(length)?;

    Ok(bytes)
}

pub(super) fn parse_id(value: &str) -> Result<Vec<u8>> {
    if value.len() != 32 || !value.is_ascii() {
        return Err(Error::Invalid);
    }

    let mut id = Vec::with_capacity(16);

    for pair in value.as_bytes().chunks_exact(2) {
        let part = std::str::from_utf8(pair).map_err(|_| Error::Invalid)?;

        id.push(u8::from_str_radix(part, 16).map_err(|_| Error::Invalid)?);
    }

    if id == [0; 16] {
        return Err(Error::Invalid);
    }

    Ok(id)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut out = String::new();

    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }

    out
}
