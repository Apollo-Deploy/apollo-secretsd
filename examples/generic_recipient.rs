//! A generic caller exchanges one opaque capability for an immutable secret FD.
//! Its controller issues the grant for this process after spawning it.
#[cfg(target_os = "linux")]
fn main() -> apollo_secretsd::Result<()> {
    use apollo_secretsd::{
        Error,
        client::Client,
        delivery::{self, transport},
        memory::{self, LockedBytes, MemoryBudget},
    };
    use rustix::{
        event::{PollFd, PollFlags, Timespec},
        fd::BorrowedFd,
    };

    memory::harden_process()?;

    let mut args = std::env::args().skip(1);

    let channel: i32 = args
        .next()
        .ok_or(Error::Invalid)?
        .parse()
        .map_err(|_| Error::Invalid)?;

    let socket = std::path::PathBuf::from(args.next().ok_or(Error::Invalid)?);

    let server_uid: u32 = args
        .next()
        .ok_or(Error::Invalid)?
        .parse()
        .map_err(|_| Error::Invalid)?;

    if channel < 3 || args.next().is_some() {
        return Err(Error::Invalid);
    }

    // SAFETY: The controller transfers a live inherited socket; dup validates it.
    let channel = rustix::io::dup(unsafe { BorrowedFd::borrow_raw(channel) })?;

    rustix::net::sockopt::set_socket_passcred(&channel, true)?;

    let budget = MemoryBudget::new(1024 * 1024);

    let mut packet = LockedBytes::new(64, &budget)?;

    // The controller needs time to capture this live process and issue its grant.
    // The shared transport stays nonblocking; wait here with a finite deadline.
    let mut ready = [PollFd::new(&channel, PollFlags::IN)];

    if rustix::event::poll(
        &mut ready,
        Some(&Timespec {
            tv_sec: 5,
            tv_nsec: 0,
        }),
    )? != 1
        || !ready[0].revents().contains(PollFlags::IN)
    {
        return Err(Error::Limit);
    }

    let received = transport::receive(&channel, packet.as_mut_slice())?;

    if &packet.as_slice()[..received.bytes] != b"grant" {
        return Err(Error::Invalid);
    }

    let capability = delivery::import(received.fd.ok_or(Error::Invalid)?, 32, 32, &budget)?;

    let secret = Client::connect(&socket, server_uid, budget)?.redeem(capability.key()?)?;

    // The authorized recipient can now pass this exact sealed FD to its consumer.
    transport::send(&channel, b"secret", Some(&secret))?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux required");

    std::process::exit(1);
}
