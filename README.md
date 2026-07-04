# agent-vpn

**A VPN command-line tool built for AI agents.** It gives an agent deterministic,
JSON-first control over WireGuard tunnels so it can see the internet from
different parts of the world — on demand, without a GUI, and without ever
being prompted for anything.

The binary is simply `vpn`.

```sh
vpn probe --count 3              # median latency through EACH location, with proof of exit
vpn exec proton-jp -- curl -sI https://yoursite.com    # any command, through Tokyo
vpn up proton-jp                 # route through Tokyo
vpn --json status                # machine-readable tunnel state
vpn down proton-jp               # and back home
```

## What agents use it for

- **Debug CDNs** — is the edge in São Paulo serving stale content?
  `vpn exec proton-br -- curl -sI https://yoursite.com` from each region and
  diff the responses, headers, and cache status.
- **Test latency from different parts of the world** — `vpn probe` sends timed
  requests per location and reports a full timing breakdown
  (DNS / connect / TLS / TTFB / total), fastest first, with `--count N`
  medians to smooth out jitter.
- **Verify geo-dependent behavior** — geoblocking, region-based pricing,
  GDPR banners, localized redirects: reproduce what a user in another country
  actually sees, with **proof of where you egressed** (exit IP + country +
  answering CDN PoP in every probe result).
- **Reproduce region-specific bugs** — "it only fails for users in Australia"
  stops being unreproducible.

```text
$ vpn probe --count 3
proton-nl      median    189.4 ms   (min 185.0, max 201.2, n=3)   ttfb    189.2 ms   http 200   exit 185.107.56.1 (NL/AMS)
proton-us      median    440.2 ms   (min 431.9, max 460.8, n=3)   ttfb    440.1 ms   http 200   exit 159.26.101.9 (US/BOS)
proton-jp      median    612.7 ms   (min 601.4, max 645.0, n=3)   ttfb    612.5 ms   http 200   exit 103.5.140.1 (JP/NRT)
```

`probe` is careful by design: it brings the tunnel up only if needed, runs its
requests, then restores the tunnel to exactly the state it found. The default
URL (`https://1.1.1.1/cdn-cgi/trace`) is anycast, so each exit reaches its
*nearest* Cloudflare edge — totals compare the locations themselves, and the
trace body proves the exit IP and answering PoP. Pass `--url` to measure your
own service instead.

For anything beyond measuring, `vpn exec <name> -- <command>` runs an arbitrary
command through a location with the same activate-run-restore care: the child's
stdio streams straight through, it never runs under sudo, and its exit code
becomes vpn's exit code.

## Why it works for agents

- **Idempotent** — `up`/`down` are safe to call repeatedly and report whether
  they actually changed state. `probe` never leaves state behind.
- **Deterministic exit codes** — branch on the outcome without parsing text:

  | code | meaning |
  |------|---------|
  | 0 | success |
  | 1 | I/O / config error, lint failure, doctor failure, refused operation |
  | 2 | CLI usage error (from `clap`) |
  | 3 | tunnel not found |
  | 4 | invalid tunnel name |
  | 5 | backend command exited non-zero |
  | 6 | backend command could not be launched |
  | 7 | at least one `probe`/`diff` request failed (results still on stdout) |
  | 8 | `verify`/`recover`: host network is inconsistent (needs repair) |
  | * | `exec` passes the child command's exit code through |

- **Machine-readable** — `--json` on every command.
- **Non-interactive** — never prompts; privileged calls use `sudo -n`, and
  probe/exec child processes always run unprivileged.
- **Fleet-safe** — mutating commands take an advisory lock on the config
  directory, so concurrent agents cannot tear down each other's tunnels
  mid-measurement.
- **Self-diagnosing** — `vpn doctor` checks binaries, sudo, WireGuard state
  access, config validity, and key-file permissions, with a fix hint per
  failure; `vpn lint` statically catches broken configs (including
  split-tunnel routing loops) before they can blackhole a handshake.
- **Provider-agnostic** — a "location" is just a WireGuard `<name>.conf` file.
  ProtonVPN, Mullvad, a self-hosted server: if it speaks WireGuard, it works.
- **macOS-correct** — live tunnels are detected by matching each config's peer
  key and allowed-IPs against one `wg show all dump`, so `status` / `down` /
  `current` work even though `wg-quick`'s interface-name file is root-only.
- **Crash-safe & self-healing** — an agent gets killed mid-operation as a
  matter of course (context limits, timeouts, a closing lid). Before every
  host mutation, vpn writes a small journal to `~/.config/vpn/state/` capturing
  the pre-tunnel DNS; every command then begins by **reconciling** that journal
  against the live system, so a half-finished `up`/`down` — even after
  `kill -9` or a reboot — is rolled back to a working network the next time vpn
  runs. The recovery data lives on disk, never in a process that can die with
  it. See **[docs/RESILIENCE.md](docs/RESILIENCE.md)** for the full design.
- **DNS restore, done right (macOS)** — `wg-quick` remembers your original DNS
  only in the memory of a background process; if that dies without restoring it
  (shutdown/crash with a tunnel up, or the rapid up/down cycles a `probe` sweep
  makes), the tunnel's VPN-internal resolver stays pinned on every network
  service — so the machine has no working DNS whenever tunnels are down, and
  every later `up` snapshots the broken value, perpetuating it. vpn instead
  snapshots the *real* pre-tunnel DNS and restores exactly that (custom static
  DNS included, not just DHCP), re-checking on a short schedule to outlast
  `wg-quick`'s asynchronous restore. `vpn down` on an already-down tunnel
  repairs the state explicitly, and `vpn doctor` flags it (check `dns`).
- **Bounded blast radius** — `vpn up <name> --lease 30m` records a deadline;
  the next vpn command (or a scheduled `vpn recover`) tears the tunnel down and
  restores the host once it passes, so an agent that dies without calling
  `down` can't strand you on a foreign exit forever.
- **An escape hatch + a health assertion** — `vpn recover` needs no tunnel
  name and tolerates missing configs: it reconciles interrupted operations,
  tears down orphaned/expired tunnels, restores DNS, and then **self-verifies**
  (exit 8 if the host is somehow still inconsistent). `vpn verify` is the
  standalone, read-only version — an agent or CI job can assert "my network is
  in a sane state" and branch on the exit code.
- **`diff` across locations** — `vpn diff <url>` fetches the same URL through
  every location and reports which response fields (status, headers) differ:
  the "is São Paulo serving stale content? does Australia get a different
  redirect?" CDN/geo-debugging workflow as one call, with `--json` output.
- **Least privilege** — `wg-quick` runs config `PreUp`/`PostUp`/`PreDown`/
  `PostDown` hooks as **root**; combined with a user-writable config dir and
  the NOPASSWD sudoers rule below, that is a privilege-escalation path. vpn
  refuses to `add` a config containing hooks (even under `--force`; only the
  explicit `--allow-hooks` installs one), `lint` flags them, `doctor` reports
  any installed, and `split` strips them from generated siblings.

## Install

**Homebrew (macOS/Linux)** — pulls in `wireguard-tools` automatically:

```sh
brew install matiasvillaverde/tap/agent-vpn   # installs the `vpn` binary
```

**Cargo** — needs `wireguard-tools` on the system separately:

```sh
cargo install agent-vpn                       # installs the `vpn` binary

brew install wireguard-tools   # macOS
# sudo apt install wireguard-tools   # Debian/Ubuntu
```

Then add locations. Using ProtonVPN? Follow the step-by-step guide in
**[docs/PROTON.md](docs/PROTON.md)** — it takes ~5 minutes to build a
multi-continent library.

## Usage

Config files live in `$HOME/.config/vpn/<name>.conf` by default (override with
`--config-dir` or `VPN_CONFIG_DIR`).

```sh
vpn list                 # every location and whether it is up
vpn up proton-us         # bring a tunnel up   (idempotent)
vpn status proton-us     # detailed status: interface, handshake, transfer
vpn current              # names of active tunnels
vpn probe proton-us      # one timed request, state restored afterwards
vpn probe --count 5      # sweep every location, median of 5, fastest first
vpn exec proton-us -- curl -sI https://yoursite.com   # any command, through the tunnel
vpn up proton-us --lease 30m   # auto-tear-down deadline (safety net for agents)
vpn down proton-us       # bring it down       (idempotent)
vpn diff https://yoursite.com  # fetch through every location, diff status+headers
vpn verify               # assert the host network is consistent (exit 8 if not)
vpn recover              # repair a crashed/stuck host, then self-verify

vpn add ~/Downloads/wg-tokyo.conf --name proton-jp    # validate + install (0600)
vpn split proton-jp --exclude 100.64.0.0/10           # Tailscale-safe sibling config
vpn lint                 # static config checks (routing loops, missing keys)
vpn doctor               # environment self-check with fix hints
```

`wg-quick` needs root. Either run vpn under `sudo`, or pass `--sudo` (or set
`VPN_SUDO=1`) to have it prefix the privileged calls itself.

> **`sudo` + Homebrew:** `sudo` scrubs `PATH`, so `/opt/homebrew/bin` is dropped
> and `wg`/`wg-quick` may not be found. Point at absolute paths with `--wg` /
> `--wg-quick` (or `VPN_WG` / `VPN_WG_QUICK`).

## One-time setup for unattended agents

So an agent can run `vpn up <name>` / `vpn probe` with **no flags and no
password**, do this once:

**1. Config file** at `~/.config/vpn/config.toml`:

```toml
sudo = true
wg = "/opt/homebrew/bin/wg"
wg_quick = "/opt/homebrew/bin/wg-quick"
```

**2. NOPASSWD sudoers** scoped to exactly the two WireGuard binaries (via
`sudo visudo -f /etc/sudoers.d/vpn`):

```
your-user ALL=(root) NOPASSWD: /opt/homebrew/bin/wg-quick, /opt/homebrew/bin/wg
```

After that, the agent's entire vocabulary is `vpn probe`, `vpn up <name>`,
`vpn status`, `vpn down <name>` — flag-free and prompt-free.

> **Security — why config hooks are gated.** `wg-quick` executes any
> `PreUp`/`PostUp`/`PreDown`/`PostDown` line in a config **as root** (via
> `eval`). Because configs live in a user-writable directory, that combined
> with the NOPASSWD rule above would let any process running as your user
> escalate to root by writing a hook into a `.conf` and bringing it up. So
> `vpn add` **refuses** configs containing these hooks (even under `--force`),
> `vpn lint` flags them as errors, `vpn doctor` reports any already installed,
> and `vpn split` strips them from generated siblings. If you genuinely need a
> hook and fully trust the file, install it with `vpn add … --allow-hooks`.

**3. (Optional) A lease watchdog.** Leases are enforced whenever any mutating
vpn command runs, but if an agent dies and nothing runs again, the tunnel stays
up until its deadline is noticed. To enforce leases even then, schedule
`vpn recover` — it tears down any expired or orphaned tunnel and restores the
host. A minimal launchd agent that runs it every minute:

```sh
cat > ~/Library/LaunchAgents/com.agent-vpn.watchdog.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.agent-vpn.watchdog</string>
  <key>ProgramArguments</key>
  <array><string>/opt/homebrew/bin/vpn</string><string>recover</string></array>
  <key>StartInterval</key><integer>60</integer>
</dict></plist>
PLIST
launchctl load ~/Library/LaunchAgents/com.agent-vpn.watchdog.plist
```

Settings resolve as: **CLI flag / env → `config.toml` → built-in default**.

### Options

| flag | env | default |
|------|-----|---------|
| `--config-dir` | `VPN_CONFIG_DIR` | `$HOME/.config/vpn` |
| `--sudo` | `VPN_SUDO` | off |
| `--wg` | `VPN_WG` | `wg` |
| `--wg-quick` | `VPN_WG_QUICK` | `wg-quick` |
| `--curl` | `VPN_CURL` | `curl` |
| `--json` | — | off |

`probe` additionally takes `--url <URL>` (default
`https://1.1.1.1/cdn-cgi/trace`), `--max-time <seconds>` (default `10`), and
`--count <N>` (default `1`).

## A note on traffic scope

WireGuard routing is system-level: while a tunnel is up (including the few
seconds of a probe or exec), the machine's traffic follows that config's
`AllowedIPs`. `probe` measures one request, but it does not isolate other
traffic. Fine for a workstation or a dedicated agent box; worth knowing either
way.

## Sibling configs (full vs. split tunnel)

Two configs may target the same server with different `AllowedIPs` (e.g. a full
tunnel and a variant that excludes Tailscale's `100.64.0.0/10`). They share a
peer public key, so vpn disambiguates the live one by comparing the allowed-IPs
set reported by the kernel — each config's up/down state stays accurate.

`vpn split <name> --exclude <cidr>` generates such a sibling automatically, and
it always additionally excludes the server's own endpoint `/32` — a split
tunnel whose CIDRs cover its own endpoint routes the encrypted packets into the
tunnel itself and the handshake silently times out (`wg-quick` only guards
against this for exact default routes). `vpn lint` catches the same mistake in
hand-written configs. See [docs/PROTON.md](docs/PROTON.md) for the full story.

## Development

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

The process boundary is abstracted behind a `CommandRunner` trait: unit tests
drive the full command logic through a mock, and integration tests run the real
binary against fake `wg-quick`/`wg`/`curl` stubs — so the suite needs neither
root nor a real network. Every production line is covered.

## License

[MIT](LICENSE)
