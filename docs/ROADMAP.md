# Roadmap — owning the agent-first VPN

This is the strategy document: what `agent-vpn` is, why it can win a category,
and the sequence of work to get there. It is opinionated on purpose — a roadmap
that tries to do everything commits to nothing.

## The thesis

Agents are becoming a primary *operator* of computers, and "see the internet
from somewhere else" is a capability they repeatedly need: debug a CDN from
São Paulo, reproduce a geo-bug in Sydney, measure latency from Tokyo, verify
region pricing. Every existing VPN tool is built for a **human** clicking a
GUI, noticing when the network breaks, and cleaning up by hand. An agent is the
opposite operator: it runs hundreds of cycles unattended, is killed
mid-operation constantly, and holds credentials to mutate the host.

So the category to own is not "another WireGuard wrapper." It is **the control
plane an autonomous agent uses to move its own network egress around the world,
safely, without ever stranding the machine it runs on.** The product is defined
by two non-negotiable invariants:

1. **Host invariant** — after *any* sequence of commands, interrupted at *any*
   point, the machine returns to a working network automatically.
2. **Least privilege** — a process that can run `vpn` cannot exceed managing
   tunnels; in particular it cannot reach root.

0.3.0 makes both real (see [RESILIENCE.md](RESILIENCE.md)). That is the
foundation the rest builds on.

## Why this is defensible

- **Correctness is the moat.** The hard part isn't bringing a tunnel up — it's
  guaranteeing the host survives an agent that dies at instruction N of M, on a
  platform (macOS) whose own tooling loses the undo state on `kill -9`. That
  took a journal, a reconcile state machine, DNS snapshotting, and a lot of
  fault-injection tests. It compounds; a GUI competitor can't bolt it on.
- **Agent-shaped interface.** Deterministic exit codes, `--json` everywhere,
  non-interactive by construction, proof-of-egress in every probe. This is what
  makes it *reliable to call from a model*, not just usable by a person.
- **Provider-agnostic.** A "location" is any WireGuard `.conf`. Proton, Mullvad,
  self-hosted — no lock-in, no API to reverse-engineer.

## Milestones

### M1 — Trustworthy core *(shipped: 0.3.0)*
Crash-safe journal, reconcile-on-start, DNS snapshot/restore, leases, `recover`,
config-hook privilege gate. The bar: you cannot make an interrupted sequence of
commands leave the host broken.

### M2 — Prove it, continuously *(next)*
Make the guarantees observable and self-checking.
- **Post-condition verification built into every op.** After `up`, actively
  prove egress flows (extend probe's trace check); after `down`, prove DNS
  resolves *and* the default route is home — auto-recover if not. Turn the
  invariants into runtime assertions, not just design intent.
- **`vpn doctor --deep`**: dry-run a full up→probe→down→recover cycle on a
  throwaway state dir and report any host residue.
- **Linux parity + CI matrix.** DNS/route restoration is macOS-specific today;
  bring the journal's route/interface reconciliation to Linux (`resolvconf`/
  `systemd-resolved`) and test both in CI with a network namespace harness.
- **Fuzz the reconcile state machine.** Property test: for any random sequence
  of {up, down, probe, kill-at-phase-K, reboot} events, post-reconcile host
  state equals the pre-first-`up` snapshot.

### M3 — The agent SDK surface
Make it the obvious building block inside an agent loop.
- **A stable JSON event contract** (`--json` on every subcommand, versioned
  schema) documented as an integration target.
- **`vpn exec` hardening**: per-command network namespacing on Linux so only
  the child's traffic is tunneled (today the tunnel is system-wide for the
  command's duration — honestly documented, but namespacing is the real answer).
- **Batch/compare primitives**: `vpn probe --json` already sweeps; add
  `vpn diff <url>` that fetches through N locations and structurally diffs
  headers/status/body-hash — the CDN-debugging workflow as one call.
- **MCP server mode** (`vpn mcp`): expose list/up/down/probe/exec/recover as MCP
  tools so any MCP-speaking agent gets world-egress with zero glue code.

### M4 — Fleet & scale
- **Multi-host coordination**: a lightweight lease registry so a fleet of agent
  boxes doesn't thrash a provider's rate limits; pick least-loaded exit.
- **Provider adapters** (opt-in): thin helpers to *generate* configs where a
  provider offers an API, without ever handling long-lived account credentials.
- **Usage/egress accounting**: per-tunnel byte + wall-clock accounting from the
  journal, `--json` for billing/attribution.

## Guardrails (what we will NOT do)

- No GUI, no daemon-by-default, no account system. Those pull the design back
  toward the human-operator tools we're differentiating from.
- No feature that can leave the host un-restorable, ever. New host mutations
  must go through the journal + reconcile path or they don't ship.
- No silent privilege expansion. Anything that needs more than the two
  WireGuard binaries under NOPASSWD must be explicit and documented.

## Immediate next steps (pull from M2)

1. Post-`down` route-home verification + auto-recover (highest safety ROI).
2. Linux DNS/route reconciliation + CI namespace harness (unblocks non-mac use).
3. `doctor --deep` self-test cycle.
4. Reconcile property/fuzz test.

Each is independently shippable and moves a concrete invariant from "designed"
to "continuously proven."
