# seatlock feature parity

What each enforcement backend carries, where the platforms genuinely
differ, and where seatlock sits among the isolation technologies (containers,
microVMs). Everything here is enforced behavior, pinned by tests — not
aspiration.

## The policy fields, per backend

| `Policy` field | macOS (Seatbelt, in-process `sandbox_init`) | Linux (Landlock ABI V10) | parity |
|---|---|---|---|
| `write_allow` (+`allow_temp`, `allow_dev`) | `(deny file-write*)` + `(allow file-write* (subpath …))` | write-access rules under granted paths (inodes pinned at enforce time) | **full** |
| `read_allow` (world-read = the grant `/`) | narrow: `(deny file-read*)` + essentials + per-path allows; the `/` grant: ambient reads | per-path allow rules (the `/` grant covers all); the read right carries EXECUTE | **full** — deny carve-outs are deliberately ABSENT from the model: grants are the whole story |
| `network.mode = NetworkMode::Disabled` | `(deny network*)` | handle Bind/ConnectTcp + Bind/ConnectSendUdp with zero rules | **full** |
| `network.tcp_bind` / `tcp_connect` | deny network* + `(allow network-bind/outbound (remote tcp "port:*"))` per port | handled access types + `NetPort` rules per port | **full** (ports) |
| `network.udp_bind` / `udp_connect` | same shape, `udp` | same shape, `AccessNet::BindUdp` / `ConnectSendUdp` (kernel ABI 10, via the git-pinned landlock crate) | **full** (ports; kernels < ABI 10 degrade via BestEffort — probe if you must trust it) |
| network by **address/CIDR** | expressible in SBPL (`remote ip`) — not modeled in `NetworkPolicy` yet | **not expressible** (ports only, by ABI design) | roadmap (seatbelt today, never landlock) |
| `scope_abstract_unix_socket` | **not expressible** (no domain concept) | `Scope::AbstractUnixSocket` | landlock-only |
| `scope_signal` | **not expressible** | `Scope::Signal` | landlock-only |
| `force_log` | n/a (seatbelt denial logging is not policy-controlled here) | `log_new_exec` | landlock-only |
| `no_new_privs` | n/a (nothing to gain — profiles are inherited) | `PR_SET_NO_NEW_PRIVS` before exec | landlock-only (macOS no-op by design) |
| `drop_capabilities` + `keep_capabilities` | **not expressible** (no capability sets exist) — deny-by-default instead | bounding-set drops per named capability, or `all`, minus the keep list (`drop = ["all"]`, `keep = ["net_bind_service"]`) — refused loudly when `CAP_SETPCAP` is missing | landlock-only |
| per-syscall filtering (default-deny `ptrace`, `process_vm_writev`, …) | **not expressible** | **not expressible** (Landlock is an LSM, not a syscall filter) | **neither — seccomp roadmap** |
| kernel ABIs beyond the crate (11 `NNP` flag, 12 capability/namespace rules) | n/a | ABI 11 done manually (`prctl`, in `pre_exec`); 12 not in any crate yet — the `caps`-crate path is the only capability story today | roadmap |
| argument inspection (path globs / CIDR per syscall) | no | no | **neither — seccomp-notify territory** |

Known runtime caveats (tested, documented in the README):

- **darwin ≥ 27**: a *global* read-deny profile aborts dyld (`SIGABRT` in
  `CacheFinder`) even with the loader directories granted — use
  narrowing `allow_read` by config on macOS instead (world-read default).
- **old Linux kernels**: Landlock `BestEffort` compat silently degrades
  anything the kernel predates — including UDP (ABI 10); consumers must
  probe (the tests do).
- **crate provenance**: landlock is pinned to upstream `main` (rev
  `5991c08320d2`) because crates.io 0.4.7 tops out at ABI V9 — the pin
  carries ABI 10 (UDP). Drop back to the registry dep when a release
  publishes.

## What "maximum parity" means here

`Policy` models the intersection both OS mechanisms can express, plus
every extra each platform offers, flagged `*-only` above. Nothing fails
silently beyond what the matrix names. The deliberate gap both platforms
share — syscall-level default-deny — is seatlock's roadmap (a seccomp
allow-list layer inside the Linux backend, applied in the same
`pre_exec`, same `Policy`); it does not belong to Seatbelt or Landlock
and is out of scope until then.

## Where seatlock sits among the isolation tiers

One process can be isolated four ways, strictly nested:

1. **In-process policy sandbox** — seatlock: Seatbelt/Landlock applied in
   `pre_exec`. Same kernel, restricted credentials. Cheapest
   (microseconds), finest-grained per path/port, weakest guarantee
   (kernel attack surface shared).
2. **Container** — namespaces + cgroups + seccomp + capabilities (youki /
   crun / runc on Linux). Own PID/mount/net world, still the host kernel.
   Stronger, Linux-only, heavier lifecycle (a runtime supervises it).
3. **MicroVM** — Apple Virtualization/HVF, KVM + libkrun/libkrunfw, Firecracker.
   Own kernel. Strongest kernel-boundary isolation; what piebox boots per
   sandbox (`__vmm`, `__krun` workers).
4. **Per-container microVM** — Apple's Containerization framework and
   Firecracker-style designs: one VM *per container*, trading boot
   latency for the cleanest blast radius.

seatlock guards tier 1 and composes with the others: the workers that
implement tiers 3/4 (piebox's VMM processes) are themselves confined by
seatlock — the VMM process and everything it can touch on the host ride
under the same policy the guest rides its VM under.

### What each tier actually guarantees

| guarantee | seatlock Linux (Landlock V10 + caps) | seatlock macOS (Seatbelt) | container (OCI: youki/crun/runc) | microVM (piebox HVF/KVM, libkrun) | per-container microVM (Apple Containerization, Firecracker) |
|---|---|---|---|---|---|
| kernel attack surface | **shared** — host kernel fully exposed to syscalls (no syscall filter; seccomp roadmap) | **shared** — plus the TrustedBSD/XNU surface Mach/iokit mediation narrows | shared host kernel, but namespaces shrink what syscalls can *name*; seccomp profiles can default-deny | **own kernel** — guest bugs don't touch host kernel code paths | own kernel, one per workload |
| filesystem escape | bounded by path grants; TOCTOU via inherited fds possible (Landlock re-checks at use time) | bounded by profile; `subpath` grants pin to inodes (rename-out not followed) | mount namespace: guest rootfs is a *different tree* — host paths mostly not nameable | virtiofs exposes only what's shared; guest rootfs is a private copy | same, per-container |
| network control | tcp/udp **ports** (UDP pending crate ABI 10), no addresses | tcp/udp by port **and address/CIDR** | full: netns own stack, firewall/eBPF per container | TSI/hostsock proxying, policy at the host connect path | per-VM stack; host port forwards |
| privilege/capabilities | **real drops**: bounding set + `NO_NEW_PRIVS` + scopes (the strongest of the four) | nothing to drop; deny-by-default profile, mach-lookup allow-lists | full: cap set drops, no-new-privs, seccomp, AppArmor/SELinux | host caps irrelevant to guest; VMM process is the boundary | same, per VM |
| process/IPC escape | Landlock scopes (signals, abstract sockets); pid visible | deny-by-default for process-info/mach; no domain concept | pid namespace: other host processes not nameable at all | guest cannot see host processes | same |
| escape-prone surface | kernel syscalls + inherited fds + `/proc` | kernel + Mach/iokit surface | kernel (shared!) + runtime daemon (rootful) / namespaces (rootless) | the VMM device model (virtio, vsock) + hypervisor | VM-per-container minimizes cross-workload blast radius |
| cost / latency | microseconds, zero lifecycle | microseconds, zero lifecycle | ~ms + a runtime supervising each container | ~100s of ms, one process per VM | ~1s boot per container-VM |
| works on macOS | yes (this crate) | yes (this crate) | no (Linux-only) | yes (HVF) | yes (macOS 26, Apple silicon) |

The one-line reading: **containers and seatlock share the same kernel**
— containers isolate by *hiding*, seatlock by *crediting down*; a microVM
is the only tier with a real kernel boundary. seatlock composes with all
of them (confine the runtime, the VMM, the workload).

## Projects seatlock learns from

- **[syd](https://crates.io/crates/syd)** (GPL-3, Linux) — syscall-level
  mediation via `SECCOMP_USER_NOTIF`: kernel-space filtering with
  user-space argument inspection (path globs, CIDR network rules). The
  reference for what tier-1 enforcement *can* be when per-syscall policy
  is the goal, and the vocabulary seatlock's seccomp roadmap borrows.
  Not reusable as a dependency: GPL-3, Linux-only, supervisor-process
  model.
- **[youki](https://github.com/youki-dev/youki)** (Apache-2.0, Linux) — a
  Rust OCI runtime. Its `libcontainer` core (namespaces, cgroups, OCI
  seccomp profiles, rootless operation) is the tier-2 machinery — the
  candidate library if seatlock ever grows a container tier on Linux
  fleet hosts. Not a seatlock replacement: no macOS story, and a
  container's network namespace conflicts with host-port bind models
  (TSI/hostsock).
- **[Apple Containerization](https://github.com/apple/container)**
  (Apache-2.0, macOS 26 / Apple silicon) — one lightweight Linux VM per
  OCI container over Virtualization.framework, sub-second boots. The
  tier-3/4 model piebox's sandbox-per-VM architecture mirrors: the same
  "one isolation primitive per workload" law, one tier down.

## API inventory — what each OS sandbox can actually do

### Linux Landlock (by ABI level)

| ABI | feature |
|---|---|
| 1 (5.13) | filesystem rights: `execute`, `read_file`, `read_dir`, `write_file`, `remove_dir`, `remove_file`, `make_*` (char/dir/reg/sock/fifo/block/sym). Note `fs_refer` (cross-directory link/rename) is denied by default from ABI 1, grantable from ABI 2 |
| 2 | `fs_refer` grantable — cross-directory link/rename control |
| 3 | `fs_truncate` — shrinking existing files |
| 4 | network: TCP `bind` + `connect` (port-scoped rules) |
| 5 | `fs_ioctl_dev` — ioctl on opened char/block devices |
| 6 | scopes: abstract unix sockets, signals — deny the operation toward processes outside the confinement domain |
| 7 | audit/logging knobs (`log_new_exec`, per-exec/subdomain silencing) |
| 8 | `TSYNC` — enforcement across all threads of a multithreaded process |
| 9 | `fs_resolve_unix` — pathname unix-socket connection control |
| 10 | network: UDP `bind` + `connect_send` (port-scoped) |
| 11 | `NO_NEW_PRIVS` as a ruleset flag (no separate prctl) |
| 12 | **capability + namespace rules**: `LANDLOCK_RULE_CAPABILITY` (restrict capability USE per capability set) and `LANDLOCK_RULE_NAMESPACE` (restrict creating user/pid/net/… namespaces) |

**Capability checks and drops on Linux** — three independent mechanisms, and
Landlock now touches the first of them:

- *Using capabilities*: Landlock ABI 12 can deny `capable()` checks per
  capability (e.g. keep CAP_DAC_OVERRIDE unused) — a check-level restriction.
- *Dropping capabilities*: `prctl(PR_CAPBSET_DROP)` bounds-set drops,
  `CAP_SETPCAP` inheritable manipulation, ambient capabilities,
  securebits (`SECBIT_NO_SETUID_FIXUP`, `NOROOT`) — pre-exec work, not
  Landlock, and the natural seatlock roadmap item (a `drop_capabilities`
  field applied in `pre_exec`).
- *Privilege gain*: `NO_NEW_PRIVS` (ABI 11 flag or the classic prctl) plus
  Landlock rulesets themselves require it or no-new-privs semantics —
  prevents exec-time privilege escalation. Also namespace *creation*
  restriction (ABI 12) so a confined process cannot escape by unsharing.
- *What Landlock cannot do*: mount namespaces/cgroups/uid maps — that is
  container territory (youki's libcontainer), a different tier.

### macOS Seatbelt (SBPL profile language)

Filters are `action domain predicate` rules evaluated against every
security-relevant operation; `(deny default)` or `(allow default)` sets
the base. Operation domains:

- **Filesystem**: `file-read*` (split into `file-read-data`,
  `file-read-metadata`), `file-write*` (`file-create`, `file-setattr`,
  `file-chown`, `file-chflags`, `file-extend`, `file-truncate`,
  `file-unlink`, `file-link`, `file-rename`, `file-ioctl`,
  `file-chroot`); predicates by `subpath`, `literal`, `regex`, `glob`.
- **Network**: `network-bind`, `network-outbound`, `network-inbound`,
  `socket-recv`, `socket-send`, `system-socket` — predicates by remote
 /local endpoint with `ip` (address+port, IPv4/6, wildcards) — address-
  scoped filtering Landlock cannot express.
- **IPC/Mach**: `mach-lookup` (per service name — the macOS capability
  check), `mach-register`, `ipc-posix-shm`, `ipc-posix-sem`,
  `appleevent-send` (per Apple Event target), `iokit-get-properties`.
- **Process**: `process-exec`, `process-fork`, `signal` (send-scoped),
  `debugger`, `job-creation`.
- **System**: `sysctl-read`/`sysctl-write`, `system-nvram`,
  `mount`, `file-mount-flags`, `process-info` (inspecting other
  processes' pids), `session-ownership`.

**Capability checks and drops on macOS** — no BSD capabilities exist;
the equivalent levers are:

- *mach-lookup allow-lists*: on macOS, "a capability" is largely the
  right to talk to a named XPC/Mach service (per-service predicates =
  capability grants).
- *Entitlements and TCC*: the codesigned binary's entitlements
  (com.apple.security.* , sandbox inheritance) and TCC permission grants
  live OUTSIDE Seatbelt — a profile can mediate appleevent/iokit access
  but cannot grant or revoke entitlements/TCC. Seatbelt also cannot drop
  what does not exist: there is no capability set to shed, so the macOS
  "drop" story is simply deny-by-default via `(deny default)` profiles.
- *Sandbox inheritance*: aSeatbelt-confined process's children inherit
  the profile unconditionally (no escape by exec, no privilege to gain).

### The design consequence for seatlock

`Policy` today covers the parity intersection (file grants, read rules,
port network, deny-all) plus the per-platform extras that are pure wins
(regex carve-outs, scopes). The inventory above names the roadmap in
order of value:

1. ~~`NO_NEW_PRIVS` + bounds-set capability drops~~ — **done**
   (`no_new_privs`, `drop_capabilities`, `keep_capabilities`, via the
   `caps` crate); Landlock ABI 12 capability-use *rules* remain as the
   finer-grained follow-up where the kernel is new enough.~~
2. Network address scoping modeled in `NetworkPolicy` (seatbelt-expressible
   today; landlock silently ignores — the parity law still applies).
3. Seccomp allow-list behind the same `Policy` (the per-syscall gap).
