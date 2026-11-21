//! The sandbox-exec-shaped CLI: build a policy from flags, launch a
//! command confined from its first instruction.
//!
//! ```sh
//! seatlock --root /tmp/build --network deny -- sh -c './fetch.sh'
//! seatlock --policy sandbox.json -- drop-caches
//! ```
//!
//! NOT sandbox-exec parity: the flag set is seatlock's minimal policy —
//! grants, network ports, capability drops — not SBPL's profile language.
//! The whole module is gated behind the `cli` feature: a library consumer
//! builds with `default-features = false` and clap never enters the build
//! (the binary compiles to a stub naming the feature).

#[cfg(feature = "cli")]
mod cli {
    use clap::{Parser, ValueEnum};
    use seatlock::Policy;
    use std::path::PathBuf;
    use std::process::ExitCode;

    #[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
    enum NetMode {
        /// Open networking (the default).
        Allow,
        /// Deny all network — tcp and udp, bind and connect.
        Deny,
    }

    #[allow(clippy::struct_excessive_bools)] // the flags ARE a bag of toggles
    #[derive(Debug, Parser)]
    #[command(
        name = "seatlock",
        about = "Run a command under a seatlock policy — deny by default: \
                 what is not granted does not exist.",
        after_help = "The command is confined from its first instruction; \
                      every child it spawns inherits the confinement.",
        after_long_help = "EXAMPLES:\n\
          \x20 seatlock --root /tmp/build --network deny -- sh -c './fetch.sh'\n\
          \x20 seatlock --drop-caps all --no-new-privs -- nc -l 8080\n\
          \x20 seatlock --policy sandbox.json -- ./agent\n\
          \x20 seatlock --self-restrict --root /tmp/w -- ./agent\n\
          \x20(everything after the flags is the command; the leading `--` is\n\
          \x20 conventional, not required — use it when the command's own\n\
          \x20 flags could collide with seatlock's)"
    )]
    struct Args {
        /// Write-confined root — the only writable tree (created if
        /// missing), plus temp and /dev unless switched off. Repeatable:
        /// each adds a write grant. Default: the current directory.
        #[arg(short, long = "root")]
        roots: Vec<PathBuf>,

        /// A policy file (JSON — the crate's serde shape) instead of the
        /// flag-built policy; the flags are ignored.
        #[arg(short, long)]
        policy: Option<PathBuf>,

        /// Narrow reads to the root(s) instead of world-read. CAVEAT: on
        /// darwin >= 27 a denied boot-path read aborts dyld — this flag is
        /// reliable on Linux, profile-shaped on macOS.
        #[arg(long = "narrow-reads")]
        narrow_reads: bool,

        /// Deny writes under the system temp dir (granted by default).
        #[arg(long = "no-temp")]
        no_temp: bool,

        /// Deny writes under /dev (granted by default).
        #[arg(long = "no-dev")]
        no_dev: bool,

        /// Network posture (default: allow).
        #[arg(long, value_enum, default_value_t = NetMode::Allow)]
        network: NetMode,

        /// TCP ports the command may BIND (server); comma-separated.
        /// Setting any port list deny-lists the rest of that protocol.
        #[arg(long = "tcp-bind", value_delimiter = ',')]
        tcp_bind: Option<Vec<u16>>,

        /// TCP ports the command may CONNECT to (client); comma-separated.
        #[arg(long = "tcp-connect", value_delimiter = ',')]
        tcp_connect: Option<Vec<u16>>,

        /// UDP ports the command may bind; comma-separated.
        #[arg(long = "udp-bind", value_delimiter = ',')]
        udp_bind: Option<Vec<u16>>,

        /// UDP ports the command may send to; comma-separated.
        #[arg(long = "udp-connect", value_delimiter = ',')]
        udp_connect: Option<Vec<u16>>,

        /// Capabilities to drop from the bounding set (`all` or kernel
        /// names without `cap_`); comma-separated. Linux only.
        #[arg(long = "drop-caps", value_delimiter = ',')]
        drop_caps: Option<Vec<String>>,

        /// Capabilities spared from a broad drop; comma-separated.
        #[arg(long = "keep-caps", value_delimiter = ',')]
        keep_caps: Option<Vec<String>>,

        /// Set `NO_NEW_PRIVS`: exec-time privilege gain becomes impossible
        /// (Linux only).
        #[arg(long = "no-new-privs")]
        no_new_privs: bool,

        /// Scope signals: deny sending them outside the domain (Linux only).
        #[arg(long = "scope-signal")]
        scope_signal: bool,

        /// Scope abstract unix sockets (Linux only).
        #[arg(long = "scope-unix-socket")]
        scope_unix_socket: bool,

        /// Log denied operations on exec (Landlock).
        #[arg(long = "force-log")]
        force_log: bool,

        /// Confine THIS process first (`restrict_self`) and then exec —
        /// instead of the launcher pattern (`pre_exec` in the child). The
        /// child is confined either way; `--self-restrict` also confines
        /// anything this process does before spawning.
        #[arg(long = "self-restrict")]
        self_restrict: bool,

        /// The command to run, after the flags (a leading `--` is
        /// conventional and protects the command's own flags from being
        /// parsed as seatlock's).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    }

    /// The flag-built policy (or the policy file, verbatim).
    fn build_policy(mut args: Args) -> Result<Policy, String> {
        if let Some(file) = &args.policy {
            let raw = std::fs::read_to_string(file)
                .map_err(|e| format!("policy file {}: {e}", file.display()))?;
            return serde_json::from_str(&raw)
                .map_err(|e| format!("policy file {}: {e}", file.display()));
        }

        let mut roots: Vec<PathBuf> = std::mem::take(&mut args.roots);
        if roots.is_empty() {
            roots.push(std::env::current_dir().map_err(|e| format!("cwd: {e}"))?);
        }
        let root = roots.first().cloned().ok_or("no write root")?;
        let mut policy = Policy::write_confined(root);
        for extra in roots.iter().skip(1) {
            policy.write_allow.push(extra.clone());
        }
        if args.narrow_reads {
            policy.read_allow = roots;
        }
        policy.allow_temp = if args.no_temp {
            seatlock::TempAccess::Denied
        } else {
            seatlock::TempAccess::Granted
        };
        policy.allow_dev = if args.no_dev {
            seatlock::DevAccess::Denied
        } else {
            seatlock::DevAccess::Granted
        };
        policy.network.mode = if args.network == NetMode::Allow {
            seatlock::NetworkMode::Enabled
        } else {
            seatlock::NetworkMode::Disabled
        };
        policy.network.tcp_bind = std::mem::take(&mut args.tcp_bind);
        policy.network.tcp_connect = std::mem::take(&mut args.tcp_connect);
        policy.network.udp_bind = std::mem::take(&mut args.udp_bind);
        policy.network.udp_connect = std::mem::take(&mut args.udp_connect);
        policy.drop_capabilities = args.drop_caps.take().unwrap_or_default();
        policy.keep_capabilities = args.keep_caps.take().unwrap_or_default();
        policy.no_new_privs = if args.no_new_privs {
            seatlock::PrivilegeGain::Prevented
        } else {
            seatlock::PrivilegeGain::Allowed
        };
        policy.scope_signal = if args.scope_signal {
            seatlock::ScopeMode::Enabled
        } else {
            seatlock::ScopeMode::Disabled
        };
        policy.scope_abstract_unix_socket = if args.scope_unix_socket {
            seatlock::ScopeMode::Enabled
        } else {
            seatlock::ScopeMode::Disabled
        };
        policy.force_log = if args.force_log {
            seatlock::ExecLogging::On
        } else {
            seatlock::ExecLogging::Off
        };
        Ok(policy)
    }

    fn run() -> Result<i32, String> {
        let mut args = Args::parse();
        // the command argv leaves the args first: build_policy consumes
        // the rest
        let mut command_argv = std::mem::take(&mut args.command);
        let Some((program, cmd_args)) = command_argv.split_first_mut() else {
            return Err("no command given — the command (and its args) go \
                        after the flags: seatlock [flags] [--] <command> [args...] \
                        (e.g. seatlock --root /tmp/w -- sh -c 'make')"
                .to_string());
        };
        let program = program.clone();
        let cmd_args: Vec<String> = cmd_args.to_vec();
        let self_restrict = args.self_restrict;
        let policy = build_policy(args)?;

        let arg_refs: Vec<&str> = cmd_args.iter().map(String::as_str).collect();
        let mut command = if self_restrict {
            // in-process enforcement first: anything THIS process does is
            // confined too, then the child is spawned under it
            policy.restrict_self().map_err(|e| e.to_string())?;
            let mut command = std::process::Command::new(&program);
            command.args(&cmd_args);
            command
        } else {
            // the launcher pattern: the policy installs in the child's
            // pre_exec — confined from its first instruction
            policy
                .exec(&program, &arg_refs)
                .map_err(|e| e.to_string())?
        };

        let status = command.status().map_err(|e| {
            format!(
                "spawning {program}: {e} (the confinement itself refusing \
                 is the likely cause — check the grants)"
            )
        })?;
        Ok(status.code().unwrap_or(128))
    }

    pub fn main() -> ExitCode {
        match run() {
            // a negative child status (signaled) maps into the 128+n range
            Ok(code) => ExitCode::from(u8::try_from(code.clamp(0, 255)).unwrap_or(255)),
            Err(e) => {
                eprintln!("seatlock: {e}");
                ExitCode::from(2)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        #[allow(clippy::unwrap_used)] // tests: panics are the failure mode
        fn flags_map_onto_the_policy() {
            let args = Args::parse_from([
                "seatlock",
                "--root",
                "/tmp/w",
                "--no-temp",
                "--network",
                "deny",
                "--tcp-bind",
                "8080,8443",
                "--drop-caps",
                "all",
                "--keep-caps",
                "net_bind_service",
                "--no-new-privs",
                "--scope-signal",
                "--",
                "sh",
                "-c",
                "true",
            ]);
            let command = args.command.clone();
            let policy = build_policy(args).unwrap();
            assert_eq!(policy.write_allow, vec![PathBuf::from("/tmp/w")]);
            assert_eq!(policy.allow_temp, seatlock::TempAccess::Denied);
            assert_eq!(policy.network.mode, seatlock::NetworkMode::Disabled);
            assert_eq!(
                policy.network.tcp_bind.as_deref(),
                Some(&[8080u16, 8443u16][..])
            );
            assert_eq!(policy.drop_capabilities, vec!["all"]);
            assert_eq!(policy.keep_capabilities, vec!["net_bind_service"]);
            assert_eq!(policy.no_new_privs, seatlock::PrivilegeGain::Prevented);
            assert_eq!(policy.scope_signal, seatlock::ScopeMode::Enabled);
            assert_eq!(command, vec!["sh", "-c", "true"]);
        }

        #[test]
        #[allow(clippy::unwrap_used)] // tests: panics are the failure mode
        fn policy_file_round_trips() {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("policy.json");
            std::fs::write(
                &file,
                r#"{"write_allow":["/tmp/w"],"read_allow":["/"],
                   "network":{"mode":"disabled"}}"#,
            )
            .unwrap();
            let args =
                Args::parse_from(["seatlock", "--policy", file.to_str().unwrap(), "--", "sh"]);
            let policy = build_policy(args).unwrap();
            assert_eq!(policy.write_allow, vec![PathBuf::from("/tmp/w")]);
            assert_eq!(policy.network.mode, seatlock::NetworkMode::Disabled);
        }

        #[test]
        #[allow(clippy::unwrap_used)] // tests: panics are the failure mode
        fn a_typod_policy_field_is_refused_not_ignored() {
            // Unknown fields are rejected: a typo like `"tcp_connct"` must
            // fail loudly, not silently leave network access unrestricted.
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("typo.json");
            std::fs::write(
                &file,
                r#"{"write_allow":["/tmp/w"],"network":{"tcp_connct":[80]}}"#,
            )
            .unwrap();
            let args =
                Args::parse_from(["seatlock", "--policy", file.to_str().unwrap(), "--", "sh"]);
            assert!(
                build_policy(args).is_err(),
                "a typo in a policy file must be an error, not silently ignored"
            );
        }

        #[test]
        #[allow(clippy::unwrap_used)] // tests: panics are the failure mode
        fn the_launch_is_real_end_to_end() {
            // the actual launch path: a confined sh writes inside the
            // grant, and a separate confined run proves the outside write
            // is refused (each run's status is its own verdict)
            let dir = tempfile::tempdir().unwrap();
            let inside = dir.path().join("in.txt");
            let outside = dir.path().parent().unwrap().join("probe.txt");
            let policy = {
                let mut p = Policy::write_confined(dir.path());
                p.allow_temp = seatlock::TempAccess::Denied;
                p.allow_dev = seatlock::DevAccess::Denied;
                p
            };
            let mut cmd = policy
                .exec("sh", &["-c", &format!("echo ok > {}", inside.display())])
                .unwrap();
            assert!(cmd.status().unwrap().success(), "inside write must succeed");
            assert_eq!(std::fs::read_to_string(&inside).unwrap(), "ok\n");

            let mut cmd = policy
                .exec(
                    "sh",
                    &[
                        "-c",
                        &format!("echo out > {} 2>/dev/null", outside.display()),
                    ],
                )
                .unwrap();
            assert!(
                !cmd.status().unwrap().success(),
                "the outside write must be refused"
            );
            assert!(!outside.exists());
            let _ = std::fs::remove_file(&outside);
        }
    }
}

#[cfg(feature = "cli")]
fn main() -> std::process::ExitCode {
    cli::main()
}

#[cfg(not(feature = "cli"))]
fn main() -> std::process::ExitCode {
    // a library consumer built with `default-features = false`: the
    // binary is a stub naming the feature — clap never entered the build
    eprintln!("seatlock: built without the `cli` feature (default-features = false)");
    std::process::ExitCode::from(2)
}
