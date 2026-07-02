# agent-vpn

The binary is simply `vpn`. An **agent-first**, provider-agnostic WireGuard tunnel manager for macOS and
Linux — built to **test latency from multiple VPN locations** with a single
command. It wraps `wg-quick`/`wg`/`curl` behind a small, deterministic CLI so
scripts and automation can switch tunnels, read status, and time requests
without a GUI or a proprietary API.

It works with **any** WireGuard `.conf` file — ProtonVPN, Mullvad, or a
self-hosted server. For ProtonVPN, download the per-server WireGuard config from
your account dashboard and drop it into the config directory.

## Latency testing across locations

`probe` sends **exactly one** timed request through a tunnel: it brings the
tunnel up if needed, times one `curl` request, then restores the tunnel to its
previous state.

```sh
vpn probe proton-us    # one request through the US tunnel, timing breakdown
vpn probe              # one request through EACH tunnel, fastest first
vpn --json probe       # structured results for automation
```

```text
proton-us      total    291.0 ms   ttfb    290.0 ms   http 200   via 104.16.132.229
proton-de      total    402.7 ms   ttfb    398.1 ms   http 200   via 104.16.133.229
proton-jp      FAILED: curl: (28) Connection timed out
```

The default URL (`https://1.1.1.1/cdn-cgi/trace`) is anycast, so each exit
reaches its *nearest* Cloudflare edge — totals compare the locations themselves.
Pass `--url` to measure a specific service instead, and `--max-time` (seconds)
to bound each request.

## Why "agent-first"

- **Idempotent** — `up`/`down` are safe to call repeatedly; they report whether
  they actually changed state. `probe` restores the tunnel state it found.
- **Deterministic exit codes** — branch on the outcome without parsing text:

  | code | meaning |
  |------|---------|
  | 0 | success |
  | 1 | I/O / config file error |
  | 2 | CLI usage error (from `clap`) |
  | 3 | tunnel not found |
  | 4 | invalid tunnel name |
  | 5 | backend command exited non-zero |
  | 6 | backend command could not be launched |
  | 7 | at least one probe request failed (results still on stdout) |

- **Machine-readable** — pass `--json` for structured output on every command.
- **Non-interactive** — never prompts; privileged calls use `sudo -n`.
- **macOS-correct** — live tunnels are detected by matching each config's peer
  key and allowed-IPs against one `wg show all dump`, so `status`/`down`/
  `current` work even though `wg-quick`'s interface-name file is root-only.

## Install

```sh
# Runtime dependency: the WireGuard userspace tools.
brew install wireguard-tools   # macOS
# sudo apt install wireguard-tools   # Debian/Ubuntu

cargo install --path .
```

## Usage

Config files live in `$HOME/.config/vpn/<name>.conf` by default (override with
`--config-dir` or `VPN_CONFIG_DIR`).

```sh
vpn list                 # every tunnel and whether it is up
vpn up home              # bring 'home' up   (idempotent)
vpn status home          # detailed status
vpn current              # names of active tunnels
vpn probe home           # one timed request through 'home', state restored
vpn down home            # bring 'home' down (idempotent)

vpn --json status        # structured output for all tunnels
```

`wg-quick` needs root. Either run vpn under `sudo`, or pass `--sudo` (or set
`VPN_SUDO=1`) to have it prefix the privileged calls itself. The probe request
(`curl`) always runs unprivileged.

> **`sudo` + Homebrew:** `sudo` scrubs `PATH`, so `/opt/homebrew/bin` is dropped
> and `wg`/`wg-quick` may not be found. Point at absolute paths with `--wg` /
> `--wg-quick` (or `VPN_WG` / `VPN_WG_QUICK`).

## Agent-friendly one-time setup

So agents (or you) can run `vpn up <name>` / `vpn probe` with **no flags and no
password**, do this once:

**1. Config file** at `~/.config/vpn/config.toml` — sets the defaults so the
flags above are never needed:

```toml
sudo = true
wg = "/opt/homebrew/bin/wg"
wg_quick = "/opt/homebrew/bin/wg-quick"
```

**2. NOPASSWD sudoers** so the privileged calls don't prompt (via
`sudo visudo -f /etc/sudoers.d/vpn`):

```
your-user ALL=(root) NOPASSWD: /opt/homebrew/bin/wg-quick, /opt/homebrew/bin/wg
```

After that, the everyday commands are simply:

```sh
vpn probe          # compare latency across all locations
vpn up proton      # no flags, no prompt
vpn status proton
vpn down proton
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
`https://1.1.1.1/cdn-cgi/trace`) and `--max-time <seconds>` (default `10`).

## Sibling configs (full vs. split tunnel)

Two configs may target the same server with different `AllowedIPs` (e.g.
`proton.conf` full-tunnel and `proton-ts.conf` excluding Tailscale's
`100.64.0.0/10`). They share a peer public key, so vpn disambiguates the live
one by comparing the allowed-IPs set reported by the kernel — each config's
up/down state stays accurate.

## Development

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

The process boundary is abstracted behind a `CommandRunner` trait: unit tests
drive the full command logic through a mock, and integration tests run the real
binary against fake `wg-quick`/`wg`/`curl` stubs — so the suite needs neither
root nor a real network.

## License

MIT
