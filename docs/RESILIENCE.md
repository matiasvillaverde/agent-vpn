# Resilience & Security Design

**Status:** Layers 1–4 shipped in 0.3.0. This document is now both the design
record and the map of what exists; the "proposed next" items remain the
forward plan (see also [ROADMAP.md](ROADMAP.md)).
**Goal:** bank-level reliability and security for a VPN CLI *driven by autonomous agents*.

## What shipped (0.3.0)

| Layer | Mechanism | Commands / code |
|---|---|---|
| 1 — least privilege | Config shell-hook gate (root-exec) | `add`/`lint`/`doctor`/`split`, `src/config.rs` |
| 2 — crash-safe state | On-disk journal + reconcile-on-start; DNS snapshot/restore | `src/state.rs`, `src/dns.rs`, `Backend::reconcile` |
| 3 — bounded blast radius | `up --lease <dur>` + watchdog | `Backend::up_with_lease`, `vpn recover` timer |
| 4 — escape hatch | `vpn recover` (no config/name needed) | `Backend::recover` |

Every mutating command (`up`/`down`/`probe`/`exec`/`recover`) reconciles first;
read-only commands stay side-effect-free. All four layers are covered by unit
tests (reconcile decision matrix, fault-injection via planted journals,
snapshot capture/restore, lease expiry, orphan teardown) and verified live on
macOS.

## Why an agent-first VPN is a different problem

A human operator runs `vpn up`, notices when the network breaks, and cleans up
by hand. An autonomous agent is the opposite:

- It runs **hundreds of up/down cycles** unattended (every `probe` sweep is a
  dozen).
- It gets **killed mid-operation constantly** — context limits, tool timeouts,
  the user hitting Ctrl-C, the laptop lid closing. `SIGKILL` at any instruction
  boundary is the *normal* case, not the exception.
- **No one is watching** to notice or repair a half-finished state.
- It holds **credentials to mutate the host** (routes, DNS, and — via the
  documented sudoers rule — root).

So two invariants must hold no matter what the agent does:

1. **Host invariant (resilience).** After *any* sequence of `vpn` commands,
   interrupted at *any* point, the owner's machine returns to a fully working
   networking state — automatically, with no human understanding required.
2. **Least privilege (security).** A process that can run `vpn` (or merely runs
   as the user) must not be able to exceed managing tunnels — in particular, it
   must not reach root.

The incident that motivated this doc: an agent brought a Proton tunnel up; the
session ended uncleanly; macOS was left with the tunnel's VPN-internal DNS
resolver pinned system-wide; with no tunnel up, that resolver was unreachable
and **all name resolution failed machine-wide**. The user could not tell the
tool was the cause. That is invariant #1 failing — and it is a *class* of bug,
not a one-off.

## Threat & failure model

| Actor / event | What it can do | Assumption |
|---|---|---|
| Buggy/killed agent | Interrupt any op; leave partial host state | **Primary** — must always self-heal |
| Prompt-injected agent | Write files as the user, run `vpn` | **Primary** — must not reach root |
| Concurrent agents | Interleave mutating ops | Serialized by the existing lock |
| Malicious config author | Ship a `.conf` with hooks / loops | Gated at `add`/`lint` |
| Root compromise | — | Out of scope (already root) |

Design target: **defense in depth** — four independent layers, each of which
*alone* prevents host lockout. No single failure is fatal.

---

## Layer 1 — Least privilege *(partly shipped)*

**Shipped:**
- Config **shell hooks** (`PreUp`/`PostUp`/`PreDown`/`PostDown`), which
  `wg-quick` runs as root, are refused by `add` (even under `--force`; only
  `--allow-hooks` installs them), flagged by `lint`, reported by `doctor`, and
  stripped by `split`. This closes a real local privilege escalation given the
  documented NOPASSWD sudoers rule.
- Configs are installed `0600`; `doctor` flags loose permissions.

**Proposed next:**
- **`Table = off` / custom `Table`** handling — a config can suppress the route
  install or point it at a custom table, defeating reasoning about egress. Lint
  should warn.
- **Endpoint/AllowedIPs sanity** already covered by the routing-loop lint;
  extend to flag `AllowedIPs = 0.0.0.0/0` *without* a corresponding endpoint
  bypass on non-default tables.
- **A hardened sudoers recipe** in docs: rather than blanket NOPASSWD on
  `wg-quick` (a shell script that reads attacker-influenced files), recommend a
  wrapper or the `wg`-only grant where possible. Research item.

---

## Layer 2 — Journaled, crash-safe host state *(the core of the fix)*

**Principle:** never trust an in-memory or external process to undo a host
mutation. Record enough on disk, *before* mutating, to reconstruct the original
state from a cold start.

### The journal

Directory `~/.config/vpn/state/` (0700). Before any `up`, write an
`intent` record and a **host snapshot**:

```jsonc
// state/<tunnel>.journal   (atomic write: temp file + rename)
{
  "tunnel": "proton",
  "phase": "up",                 // up | active | down
  "started_at": "<caller-supplied ts>",
  "snapshot": {
    "dns":   { "Wi-Fi": ["10.19.16.1"], "USB 10/100/1000 LAN": [] },
    "default_route": { "gateway": "10.19.16.1", "interface": "en0" },
    "mtu":   { "en0": 1500 }
  }
}
```

The snapshot is the four host mutations `wg-quick` makes: **DNS, default route,
interface, MTU**. DNS self-heal (already shipped as the `dns` guard) becomes one
consumer of this snapshot rather than a special case.

### Reconcile-on-start

Every `vpn` command begins with a `reconcile()` pass under the lock:

1. Read all journals.
2. For each journal not in a clean `down` state, check the live system:
   - Interface gone but DNS/routes still pointing at it → **restore from
     snapshot** (this is the incident, generalized to all four mutations).
   - Interface present but journal says `down` → tear it down.
3. Rewrite/delete the journal to match reality.

Because the recovery data is **on disk**, this survives `kill -9`, reboot, and a
lost/edited config. It is the difference between "the tool that broke my
machine" and "the tool that fixes my machine every time I run it."

### Atomicity

`up`/`down` become staged with the journal as the write-ahead log:
`write intent → mutate → mark active/clean`. A crash between stages is detected
and rolled forward or back by the next `reconcile()`. This upgrades the current
single-shot `wg-quick up` (no crash recovery) to a transaction.

---

## Layer 3 — Watchdog leases (bounded blast radius)

An agent that dies and *never* calls `down` should not strand the machine on a
foreign exit indefinitely.

- `vpn up <name> --lease 30m` records a deadline in the journal.
- `vpn reconcile` (invoked at the start of every command, and optionally from a
  `launchd`/cron timer) tears down any tunnel past its lease and restores the
  snapshot.
- Default: no lease (opt-in), so nothing changes for users who don't want it.

This bounds the worst case in *time*: even total agent death self-heals within
the lease window.

---

## Layer 4 — Unconditional recovery button

`vpn recover` (name TBD) — the "my agent broke my computer" escape hatch:

- Needs **no config, no tunnel name, no lock cooperation**.
- Reads the journal + live system; tears down **every** WireGuard interface;
  restores DNS / default route / MTU from the most complete snapshot available;
  falls back to "DNS → DHCP, remove VPN routes" when no snapshot exists.
- Prints exactly what it changed.
- Exit `0` only when the host is verified reachable afterwards.

This is what would have turned the original incident into a single command the
user could run blind.

### Continuous verification (cross-cutting)

- After `up`: actively prove egress (already done in `probe`) — if the tunnel is
  up but traffic doesn't flow, roll back rather than leave a blackhole.
- After `down`: actively prove DNS resolves *and* the default route is home;
  auto-recover if not (DNS half already shipped).

---

## Rollout order

1. **Layer 1 remainder** — small, high value, no state format. *(hooks done)*
2. **Layer 2 journal + reconcile** — the foundation; DNS guard refactors onto
   it. Ship behind the existing behavior (guard still works if journal absent).
3. **Layer 4 `recover`** — cheap once the snapshot exists; huge safety win.
4. **Layer 3 leases** — opt-in polish.

Each step is independently shippable and independently valuable.

## Test strategy

- **Unit** (mock runner): snapshot capture/restore for each of the four
  mutations; reconcile decision table (every phase × live-state combination);
  lease expiry; recover with and without a snapshot.
- **Fault injection:** simulate `SIGKILL` between each stage (drop the journal
  at phase N, assert the next `reconcile()` restores a working host).
- **Property test:** for a random sequence of up/down/probe/kill events, the
  post-reconcile host state always equals the pre-first-`up` snapshot.
- **Live smoke** (macOS, as done for the DNS fix): up → kill mid-op → new
  command auto-heals; `recover` from a deliberately corrupted state.

## Non-goals / honest limits

- Restore targets DHCP/snapshot, not a user's unknowable prior *custom static*
  DNS if the snapshot predates it. Strictly better than a dead resolver.
- Layer 1 cannot protect a user who opts into `--allow-hooks` — that is their
  informed choice.
- None of this defends an already-root attacker; the boundary is user → root.
