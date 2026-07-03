# Using agent-vpn with ProtonVPN

ProtonVPN has no macOS CLI and no public API for provisioning tunnels — but it
runs on WireGuard, and your account dashboard can generate per-server WireGuard
config files. Each file is a complete, self-contained credential: download it
once and `vpn` can use that location forever (until you revoke the key).

This guide takes about 5 minutes and gives an agent on-demand access to every
continent.

## Why config files (and not your Proton password)

WireGuard has no concept of a password — a tunnel authenticates with a key
pair, and the private key only exists inside the generated config file. Your
Proton password is for Proton's account API (SRP + 2FA + CAPTCHA), which is not
reasonably automatable and should never be handed to a tool anyway. The config
file **is** Proton's supported way to use WireGuard.

Key properties:

- Configs are **static** — they don't expire and don't need refreshing.
- One config = one server. Build a library covering the regions you care about.
- Each config registers a key pair with your account. Revoke any of them at any
  time in the dashboard (Downloads → WireGuard configurations).

## Step 1 — Generate the configs

1. Sign in at **account.proton.me** and open **VPN → WireGuard configuration**.
2. For each location:
   - **Name** it after the region (e.g. `agent-vpn-jp`) so you can recognize the
     key later.
   - **Platform:** GNU/Linux (gives a plain `wg-quick`-style file).
   - Leave NetShield / VPN Accelerator at their defaults unless you have
     preferences.
   - **Select a server** in the target country, then **Create** and
     **Download**.

A good multi-continent library for latency and CDN work:

| Region | Country | Suggested filename |
|---|---|---|
| North America (east) | US | `proton-us.conf` |
| North America (west) | US-CA | `proton-usw.conf` |
| South America | Brazil | `proton-br.conf` |
| Europe | Netherlands or Germany | `proton-nl.conf` |
| UK | United Kingdom | `proton-uk.conf` |
| Africa | South Africa | `proton-za.conf` |
| East Asia | Japan | `proton-jp.conf` |
| Southeast Asia | Singapore | `proton-sg.conf` |
| Oceania | Australia | `proton-au.conf` |

Tunnel names come from the file stem and must be valid interface names:
**letters, digits and `_ = + . -`, at most 15 characters**.

## Step 2 — Install the configs

```sh
mkdir -p ~/.config/vpn
install -m 600 ~/Downloads/agent-vpn-jp.conf ~/.config/vpn/proton-jp.conf
# ...repeat per file
```

Verify:

```sh
vpn list          # every location, all "down"
vpn probe         # one timed request through each — your first world sweep
```

That's it for standard use. The rest of this document covers two advanced
gotchas.

## Gotcha 1 — Split tunnels must exclude the server endpoint

Proton's generated configs are full-tunnel (`AllowedIPs = 0.0.0.0/0, ::/0`),
which `wg-quick` handles correctly: it installs an automatic bypass route so
the encrypted packets themselves reach the server over the physical link.

If you hand-craft a **split tunnel** (a list of CIDRs instead of `0.0.0.0/0`),
`wg-quick` does **not** add that bypass. If any CIDR in your list covers the
server's `Endpoint` IP, the tunnel's own packets get routed into the tunnel —
a routing loop, and the handshake times out.

**Rule: always exclude the endpoint's `/32` from a split tunnel's AllowedIPs.**

Compute the CIDR list with Python's `ipaddress` module:

```python
import ipaddress

exclusions = ["100.64.0.0/10",       # e.g. Tailscale's CGNAT range
              "79.127.160.216/32"]   # ALWAYS: the config's Endpoint IP

nets = [ipaddress.ip_network("0.0.0.0/0")]
for excl in exclusions:
    e = ipaddress.ip_network(excl)
    nets = [n for net in nets
              for n in (net.address_exclude(e) if e.subnet_of(net) else [net])]
cidrs = sorted(ipaddress.collapse_addresses(nets))
print("AllowedIPs = " + ", ".join(map(str, cidrs)) + ", ::/0")
```

Paste the output into the config's `AllowedIPs` line. `vpn` copes fine with the
resulting ~40 entries.

## Gotcha 2 — Coexisting with Tailscale (or another mesh VPN)

A full-tunnel config captures `100.64.0.0/10`, which breaks Tailscale while the
tunnel is up. If you need both simultaneously, keep two configs for the same
server:

- `proton-us.conf` — full tunnel, maximum capture.
- `proton-us-ts.conf` — split tunnel excluding `100.64.0.0/10` (and the
  endpoint `/32`, per Gotcha 1), with the `DNS =` line removed so MagicDNS
  keeps resolving.

Both share the same peer public key; `vpn` tells them apart by their
allowed-IPs sets, so `status`/`current`/`down` stay accurate whichever one is
up.

## Revoking access

Every generated config is listed under **VPN → WireGuard configuration** in
your Proton dashboard. Deleting one there invalidates its key server-side —
the local `.conf` file becomes useless. Do this if a machine holding configs is
ever compromised or retired.
