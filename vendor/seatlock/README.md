# seatlock

Reusable OS-level **sandbox enforcement** for processes: macOS Seatbelt,
Linux Landlock. Build a policy, then pick the enforcement point — the
two APIs:

```rust
use seatlock::Policy;

let policy = Policy::hardened(root); // or write_confined(root), then tune
                                    // with the with_* builders

// 1. confine a program from ITS first instruction — the launcher
//    pattern; the returned Command is yours to finish (cwd, env, fds)
let mut cmd = policy.exec("sh", &["-c", "./build.sh"])?;

// 2. confine THIS process: everything after the call — allocations,
//    files, sockets, and every child — is restricted. Landlock's
//    landlock_restrict_self / Seatbelt's sandbox_init, applied in-process
policy.restrict_self()?;
```

| goal | API |
|---|---|
| confine a program from its first instruction | `policy.exec(program, args)` — the policy installs in the child's `pre_exec`, then you `spawn` |
| spawn many children from one policy (macOS) | generate `seatbelt_profile(&policy)` once, reuse `install_profile(&mut cmd, &profile)` per child — hoists path canonicalization out of the hot path |
| confine already-running code (and all its future children) | `policy.restrict_self()` |
| cover every thread on Linux | apply `restrict_self` before spawning threads (`TSYNC` syncs where the kernel supports it; `BestEffort` degrades silently on old kernels) |
| avoid access through already-open descriptors | apply the policy BEFORE opening files/sockets — an open fd is access the policy cannot revoke |
| keep secrets out | narrow `read_allow` — there are no deny carve-outs; the grant lists are the whole story |

## The contract

**Deny by default, always** — one posture: what is not granted does not
exist. Reads need a grant (world-read is the grant `"/"`), writes need
`write_allow`, network needs `NetworkPolicy` port rules; on Linux the
read right also narrows *execute* to granted trees.

`policy.exec(program, args)` applies the policy in the child's `pre_exec`
(the confinement exists from the child's first instruction);
`policy.restrict_self()` applies it to the current process from the call
onward. Either way every descendant inherits the confinement.

- **Writes are denied everywhere except the granted roots** (plus system
  temp when `allow_temp`, and `/dev` when `allow_dev`).
- **Reads are the grant list**: world-read when `read_allow` carries
  `"/"` (the default shape); otherwise narrowed to exactly those trees
  (plus the platform read essentials on macOS — see the dyld caveat).
- **Network is whatever the policy says**: unrestricted, deny-all
  (`network.enabled = false`), or an allow-list of tcp/udp bind and connect
  ports — deny-all plus exactly the named ports, symmetric on both
  platforms.
- **Scopes**: abstract-unix-socket and signal scoping deny the operation
  outside the confinement domain.
- **Everything outside the model stays ambient**: process, signals, Mach
  — Seatbelt and Landlock cannot express a portable deny for those; that
  is the seccomp roadmap.
- A **write grant on a root that does not exist yet creates the root** —
  Landlock pins rules to inodes, so a missing root would otherwise carry no
  write rule (a silent deny-inside-the-grant).

## The `Policy` reference — every configuration knob

```rust
pub struct Policy {
    // filesystem
    pub write_allow: Vec<PathBuf>,  // read+write grants (dirs created if missing)
    pub read_allow: Vec<PathBuf>,   // read grants; world-read is the grant "/"

    // network
    pub network: NetworkPolicy {
        pub mode: NetworkMode,                  // Disabled = deny ALL (tcp+udp, both platforms)
        pub tcp_bind: Option<Vec<u16>>,         // Some = allow-list; None = unrestricted
        pub tcp_connect: Option<Vec<u16>>,
        pub udp_bind: Option<Vec<u16>>,
        pub udp_connect: Option<Vec<u16>>,
    },

    // scopes (landlock only — SBPL has no domain concept)
    pub scope_abstract_unix_socket: ScopeMode, // Disabled/Enabled
    pub scope_signal: ScopeMode,               // Disabled/Enabled

    // capabilities (linux only — macOS has nothing to drop)
    pub drop_capabilities: Vec<String>,   // bounding-set drops; "all" = the whole set
    pub keep_capabilities: Vec<String>,   // spared from a broad drop (all - keep)
    pub no_new_privs: PrivilegeGain,      // Allowed/Prevented

    // hygiene
    pub force_log: ExecLogging,            // Off/On
    pub allow_temp: TempAccess,            // Denied/Granted
    pub allow_dev: DevAccess,             // Denied/Granted
}
```

Presets and builders (each returns the policy for chaining):

- `Policy::write_confined(root)` — the baseline: writes only in `root`
  (+temp, +/dev), world-read (the `"/"` grant), network open. The piebox
  worker shape.
- `Policy::hardened(root)` — `write_confined` PLUS `no_new_privs`,
  `drop_capabilities = ["all"]`, and both scopes on. Fails loudly on
  Linux without `CAP_SETPCAP` rather than silently downgrading.
- `.with_network(bool)` — open or deny-all.
- `.with_capability_drops(Vec<String>)` / `.with_capability_keeps(Vec<String>)`
  — kernel names without the `cap_` prefix (`net_raw`, `dac_override`, …)
  or `"all"`. Unknown names are an ERROR at apply time, never a silent skip.
- `.with_no_new_privs(bool)`, `.with_signal_scope(bool)`,
  `.with_unix_socket_scope(bool)`, `.with_temp(bool)`, `.with_dev(bool)`.

Everything is `serde`-serializable behind the `serde` feature — a policy
is a portable artifact (ride it in a spec file or a queue), and the
parity notes in [docs/features.md](docs/features.md) say exactly what
each platform enforces.

The API is deliberately MINIMAL: there are no deny carve-outs (no
`read_deny`, no write regex denies) — deny-by-default means the grant
lists are the whole story. Keep secrets out by narrowing `read_allow`,
not by denying after the fact.

## Platform matrix

| behavior | macOS (Seatbelt) | Linux (Landlock) |
|---|---|---|
| write confinement | `(deny file-write*)` + allow subpaths | ruleset handles read+write, rules only the grants (an empty grant set denies all writes) |
| narrowed reads | `(deny file-read*)` + platform read essentials + grants — but **UNUSABLE on darwin ≥ 27**: dyld aborts (SIGABRT in `CacheFinder`) on ANY denied boot-path read, pinned empirically even with the loader dirs granted; keep world-read (the `"/"` grant) on macOS and narrow by config | `read_allow` allow-list (grant the loader dirs or nothing execs; ld.so fails loud, not fatal); the read right carries EXECUTE |
| deny all network | `(deny network*)` | all four access types handled with zero rules (tcp + udp, ABI 10) |
| port allow-list (tcp/udp bind + connect) | deny network* + per-port allows (bind → `local ip`, connect → `remote ip`) | handled access types + `NetPort` rules per port |
| capabilities | nothing to drop (deny-by-default is the whole story) | bounding-set drops via `caps` + `NO_NEW_PRIVS` via prctl |
| abstract-unix-socket / signal scopes | **not expressible** in SBPL — ignored | `Scope::AbstractUnixSocket` / `Scope::Signal` |
| unsupported kernel | n/a | **BestEffort = silently unenforced** — probe before trusting (tests do) |

Maximum security on both platforms = every field set: narrow the reads
(on Linux), grant write roots, allow-list the network ports, drop the
capabilities, scope the sockets and signals (Linux). The matrix names
the one place each platform cannot carry a field — nothing fails
silently beyond that.

## The CLI — a sandbox-exec-shaped runner

The `seatlock` binary (src/main.rs) builds the policy from flags and
launches a command confined from its first instruction — the launcher
pattern as a tool:

```sh
seatlock --root /tmp/build --network deny -- sh -c './fetch.sh'
seatlock --root . --narrow-reads -- sh -c 'make'          # Linux-reliable
seatlock --drop-caps all --keep-caps net_bind_service --no-new-privs \
  --scope-signal --scope-unix-socket -- nc -l 8080        # the hardened set
seatlock --policy sandbox.json -- ./agent                  # a serde Policy file
seatlock --self-restrict --root /tmp/w -- ./agent          # restrict_self first
```

NOT sandbox-exec parity: the flags are seatlock's minimal policy (grants,
ports, capabilities), not SBPL's profile language. Behind the `cli`
feature (on by default) — **a library consumer builds with
`default-features = false` and clap never enters the build**; the binary
compiles to a stub naming the feature.

## Verification — tests

```sh
cargo test                      # the confinement matrix against REAL kernel
                                # enforcement (spawns confined children):
                                # inside/outside writes, reads, exec,
                                # /dev/null, temp, read narrowing, network
                                # denial, fresh roots, symlinks, hostile paths
cargo test --features cli,serde # plus the CLI: flags→policy mapping, the
                                # policy-file round trip, a live launch
cargo test --test agent_workload --features serde
                                # an AGENT SESSION with no VM: the hardened
                                # policy directly on the host running a
                                # simulated coding-agent workload — the
                                # workspace session succeeds, and every
                                # escape an agent might try (direct,
                                # symlink tunnel, dotfiles, the system,
                                # exfil sockets, planted setuid) is refused
```

Linux tests probe enforcement first (spawn a confined child that writes
outside every grant) and skip with a named reason on kernels without
Landlock (< 5.13) — `BestEffort` compat means an unsupported kernel applies
nothing, and that must be VISIBLE, not a spurious failure.

Consumers: piebox's VMM workers (`__vmm`/`__krun` — write-confined seats)
and pie's `p1e-sandbox` — the boundary for every command executed outside
a VM.

## Related projects — what seatlock learns from

seatlock is tier-1 isolation (an in-process policy sandbox). These are the
neighbors up the tiers, each with something to learn:

- **[sandbox-jail](https://crates.io/crates/sandbox-jail)** (MIT,
  macOS + Linux) — Seatbelt/bubblewrap/throwaway-VM sandboxing with a
  caller-defined policy. The `AllowDefaultPolicy` posture and its
  `known` lists adapt its profile-generation ideas: rename-escape
  parent pinning, deny-after-allow ordering, the setuid deny-list.

- **[syd](https://crates.io/crates/syd)** (GPL-3, Linux-only) —
  syscall-level sandboxing via `SECCOMP_USER_NOTIF` with user-space
  argument inspection (path globs, CIDR network rules). The reference
  design for seatlock's seccomp roadmap; its rule vocabulary is the
  inspiration, its license and supervisor model are not.
- **[youki](https://github.com/youki-dev/youki)** (Apache-2.0,
  Linux-only) — a Rust OCI runtime. Its `libcontainer` core is the
  container tier (namespaces, cgroups, OCI seccomp profiles) — the
  candidate building block if seatlock ever grows a Linux container tier.
- **[Apple Containerization](https://github.com/apple/container)**
  (Apache-2.0, macOS 26) — one lightweight Linux VM per OCI container on
  Virtualization.framework. The microVM tier: the same one-isolation-
  primitive-per-workload law piebox applies, one level down.

The full tier-by-tier comparison and the per-field parity matrix live in
[docs/features.md](docs/features.md).
