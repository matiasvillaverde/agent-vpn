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
  | 7 | at least one probe request failed (results still on stdout) |
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

## Install

```sh
# Runtime dependency: the WireGuard userspace tools.
brew install wireguard-tools   # macOS
# sudo apt install wireguard-tools   # Debian/Ubuntu

cargo install --path .
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
vpn down proton-us       # bring it down       (idempotent)

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
