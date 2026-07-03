//! Minimal IPv4 CIDR arithmetic — parse, containment, and exclusion — with no
//! external dependencies.
//!
//! Used to detect split-tunnel routing loops (an `AllowedIPs` block covering
//! the tunnel's own `Endpoint`) and to generate split-tunnel `AllowedIPs`
//! lists that carve exclusions out of `0.0.0.0/0`.

use std::fmt;

/// An IPv4 CIDR block. The base address is stored canonicalized (host bits
/// cleared).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cidr4 {
    /// Network base address in host byte order.
    pub base: u32,
    /// Prefix length, `0..=32`.
    pub prefix: u8,
}

impl Cidr4 {
    /// Parse `"a.b.c.d/p"` (or a bare `"a.b.c.d"`, treated as `/32`). Host
    /// bits below the prefix are cleared.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr, prefix) = match s.split_once('/') {
            Some((addr, prefix)) => {
                let prefix: u8 = prefix
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid prefix in '{s}'"))?;
                if prefix > 32 {
                    return Err(format!("prefix out of range in '{s}'"));
                }
                (addr.trim(), prefix)
            }
            None => (s.trim(), 32),
        };
        let base = parse_ip4(addr)? & mask(prefix);
        Ok(Self { base, prefix })
    }

    /// Whether `ip` falls inside this block.
    #[must_use]
    pub fn contains_ip(&self, ip: u32) -> bool {
        ip & mask(self.prefix) == self.base
    }

    /// Whether this block fully contains `other`.
    #[must_use]
    pub fn contains(&self, other: &Cidr4) -> bool {
        self.prefix <= other.prefix && self.contains_ip(other.base)
    }

    /// Split into two halves of prefix `p+1`, or `None` for a `/32`.
    #[must_use]
    pub fn halves(&self) -> Option<(Cidr4, Cidr4)> {
        if self.prefix >= 32 {
            return None;
        }
        let prefix = self.prefix + 1;
        let step = 1u32 << (32 - prefix);
        Some((
            Cidr4 {
                base: self.base,
                prefix,
            },
            Cidr4 {
                base: self.base + step,
                prefix,
            },
        ))
    }
}

impl fmt::Display for Cidr4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.base.to_be_bytes();
        write!(f, "{a}.{b}.{c}.{d}/{}", self.prefix)
    }
}

/// Parse a dotted-quad IPv4 address into host byte order.
pub fn parse_ip4(s: &str) -> Result<u32, String> {
    let octets: Vec<&str> = s.trim().split('.').collect();
    if octets.len() != 4 {
        return Err(format!("'{s}' is not an IPv4 address"));
    }
    let mut value: u32 = 0;
    for octet in octets {
        let byte: u8 = octet
            .parse()
            .map_err(|_| format!("'{s}' is not an IPv4 address"))?;
        value = (value << 8) | u32::from(byte);
    }
    Ok(value)
}

/// The netmask for a prefix length.
fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// Carve `holes` out of the full IPv4 space (`0.0.0.0/0`), returning the
/// minimal sorted set of CIDRs covering everything else.
#[must_use]
pub fn exclude_from_full(holes: &[Cidr4]) -> Vec<Cidr4> {
    let mut nets = vec![Cidr4 { base: 0, prefix: 0 }];
    for hole in holes {
        nets = nets
            .into_iter()
            .flat_map(|net| exclude_one(net, *hole))
            .collect();
    }
    nets.sort();
    nets
}

/// Remove `hole` from `net`, returning the covering remainder.
fn exclude_one(net: Cidr4, hole: Cidr4) -> Vec<Cidr4> {
    if hole.contains(&net) {
        return Vec::new(); // net vanishes entirely
    }
    if !net.contains(&hole) {
        return vec![net]; // disjoint: net survives whole
    }
    // net strictly contains hole: split and recurse into the half holding it.
    let (lo, hi) = net.halves().expect("strict containment implies prefix < 32");
    let mut out = Vec::new();
    out.extend(exclude_one(lo, hole));
    out.extend(exclude_one(hi, hole));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr4 {
        Cidr4::parse(s).unwrap()
    }

    #[test]
    fn parse_and_display_round_trip() {
        assert_eq!(c("100.64.0.0/10").to_string(), "100.64.0.0/10");
        assert_eq!(c("0.0.0.0/0").to_string(), "0.0.0.0/0");
        assert_eq!(c("79.127.160.216").to_string(), "79.127.160.216/32");
        // Host bits are canonicalized away.
        assert_eq!(c("10.1.2.3/8").to_string(), "10.0.0.0/8");
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(Cidr4::parse("10.0.0.0/33").is_err());
        assert!(Cidr4::parse("10.0.0/8").is_err());
        assert!(Cidr4::parse("10.0.0.256/8").is_err());
        assert!(Cidr4::parse("::/0").is_err());
        assert!(Cidr4::parse("10.0.0.0/x").is_err());
        assert!(parse_ip4("hello").is_err());
    }

    #[test]
    fn containment() {
        assert!(c("0.0.0.0/0").contains(&c("100.64.0.0/10")));
        assert!(c("64.0.0.0/3").contains_ip(parse_ip4("79.127.160.216").unwrap()));
        assert!(!c("100.64.0.0/10").contains(&c("0.0.0.0/0")));
        assert!(c("10.0.0.0/8").contains(&c("10.0.0.0/8")));
        assert!(!c("10.0.0.0/8").contains(&c("11.0.0.0/8")));
    }

    #[test]
    fn halves_split_evenly() {
        let (lo, hi) = c("10.0.0.0/8").halves().unwrap();
        assert_eq!(lo.to_string(), "10.0.0.0/9");
        assert_eq!(hi.to_string(), "10.128.0.0/9");
        assert!(c("1.2.3.4/32").halves().is_none());
    }

    /// Every exclusion result must exactly tile the space minus the holes.
    fn assert_exact_cover(result: &[Cidr4], holes: &[Cidr4]) {
        let covered: u64 = result.iter().map(|n| 1u64 << (32 - n.prefix)).sum();
        let holed: u64 = holes.iter().map(|n| 1u64 << (32 - n.prefix)).sum();
        assert_eq!(covered, (1u64 << 32) - holed, "size must match exactly");
        for hole in holes {
            assert!(
                !result.iter().any(|n| n.contains_ip(hole.base)),
                "hole {hole} must not be covered"
            );
        }
    }

    #[test]
    fn exclude_tailscale_range() {
        let holes = [c("100.64.0.0/10")];
        let result = exclude_from_full(&holes);
        let strings: Vec<String> = result.iter().map(ToString::to_string).collect();
        assert_eq!(
            strings,
            vec![
                "0.0.0.0/2",
                "64.0.0.0/3",
                "96.0.0.0/6",
                "100.0.0.0/10",
                "100.128.0.0/9",
                "101.0.0.0/8",
                "102.0.0.0/7",
                "104.0.0.0/5",
                "112.0.0.0/4",
                "128.0.0.0/1",
            ]
        );
        assert_exact_cover(&result, &holes);
    }

    #[test]
    fn exclude_tailscale_and_endpoint_matches_reference() {
        // The exact case from live Proton testing: Tailscale CGNAT plus the
        // server endpoint /32 (38 v4 CIDRs, verified against Python's
        // ipaddress module).
        let holes = [c("100.64.0.0/10"), c("79.127.160.216/32")];
        let result = exclude_from_full(&holes);
        assert_eq!(result.len(), 38);
        assert_exact_cover(&result, &holes);
        // Spot-check the endpoint's immediate neighbors survive.
        let ip = parse_ip4("79.127.160.216").unwrap();
        assert!(!result.iter().any(|n| n.contains_ip(ip)));
        assert!(result.iter().any(|n| n.contains_ip(ip - 1)));
        assert!(result.iter().any(|n| n.contains_ip(ip + 1)));
    }

    #[test]
    fn exclude_nothing_is_everything() {
        assert_eq!(exclude_from_full(&[]), vec![c("0.0.0.0/0")]);
    }

    #[test]
    fn exclude_everything_is_nothing() {
        assert!(exclude_from_full(&[c("0.0.0.0/0")]).is_empty());
    }

    #[test]
    fn overlapping_holes_do_not_double_remove() {
        // /10 already inside a /8 hole: result identical to /8 alone.
        let with_both = exclude_from_full(&[c("100.0.0.0/8"), c("100.64.0.0/10")]);
        let with_one = exclude_from_full(&[c("100.0.0.0/8")]);
        assert_eq!(with_both, with_one);
        assert_exact_cover(&with_one, &[c("100.0.0.0/8")]);
    }
}
