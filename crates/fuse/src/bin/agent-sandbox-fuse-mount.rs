//! Root helper policyd runs to mount or unmount a FUSE filesystem in a
//! sandbox's mount namespace.
//!
//! The requester's pidfd arrives on stdin and the reply socket on stdout:
//! policyd verifies the requester before it starts the helper and the helper
//! never learns a pid it could be fooled about.

use std::{os::fd::AsFd, path::PathBuf, process::ExitCode};

use agent_sandbox_fuse::{
    helper::{Action, HelperRequest, run},
    mountpoint::RefusedPaths,
    protocol::{HelperReply, send_reply},
};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "agent-sandbox-fuse-mount", version, about)]
struct Cli {
    #[command(subcommand)]
    action: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Mount a FUSE filesystem; prints nothing, returns the `/dev/fuse` fd.
    Mount {
        #[command(flatten)]
        target: Target,

        /// The fusermount `-o` option string.
        #[arg(long, default_value = "")]
        options: String,
    },

    /// Unmount the requester's FUSE mount.
    Unmount {
        #[command(flatten)]
        target: Target,

        /// Detach lazily.
        #[arg(long)]
        lazy: bool,
    },
}

#[derive(clap::Args, Debug)]
struct Target {
    /// The requester's uid.
    #[arg(long)]
    uid: u32,

    /// The requester's gid.
    #[arg(long)]
    gid: u32,

    /// The mountpoint as the requester sees it.
    #[arg(long)]
    mountpoint: PathBuf,

    /// A path a mount may not touch, besides the built-in set.
    #[arg(long = "refuse")]
    refused: Vec<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let (action, target) = match cli.action {
        Command::Mount { target, options } => (Action::Mount { options }, target),
        Command::Unmount { target, lazy } => (Action::Unmount { lazy }, target),
    };

    let request = HelperRequest {
        action,
        uid: target.uid,
        gid: target.gid,
        mountpoint: target.mountpoint,
        refused: RefusedPaths::new(target.refused),
    };

    let reply = run(&request, std::io::stdin().as_fd())
        .unwrap_or_else(|err| HelperReply::Refused(err.to_string()));

    match send_reply(std::io::stdout(), &reply) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("agent-sandbox-fuse-mount: cannot send reply: {err}");

            ExitCode::FAILURE
        }
    }
}
