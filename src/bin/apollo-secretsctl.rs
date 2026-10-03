#[cfg(target_os = "linux")]
#[path = "../cli/mod.rs"]
mod cli;

fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = cli::run() {
        eprintln!("apollo-secretsctl: {error}");

        std::process::exit(1);
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("apollo-secretsctl requires Linux");

        std::process::exit(1);
    }
}
