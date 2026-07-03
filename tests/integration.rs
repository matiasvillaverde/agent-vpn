//! End-to-end tests driving the real binary with fake `wg-quick`/`wg`/`curl`.
//!
//! These exercise the production `SystemRunner`, argument construction, dump
//! parsing, peer-identity matching, and probe orchestration without root or a
//! real network. The fakes use only shell builtins so the tests can run with a
//! hermetic `PATH` containing nothing but the stubs.
//!
//! State model: `wg-quick up` records the tunnel's interface, peer key, and
//! allowed-IPs in `$FAKE_WG_RUN_DIR/state-<name>`; `wg-quick down` truncates
//! that file; `wg show all dump` renders every non-empty state file. Unlike the
//! real macOS `wg-quick`, no readable `<name>.name` mapping exists — matching
//! the situation the binary must handle (that file is root-only in production).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::{tempdir, TempDir};

/// Fake `wg-quick`: `up` writes a state file from the conf's peer details,
/// `down` truncates it. Builtins only.
const FAKE_WG_QUICK: &str = r#"#!/bin/sh
action="$1"
conf="$2"
name=${conf##*/}
name=${name%.conf}
run="$FAKE_WG_RUN_DIR"
case "$action" in
  up)
    pk=""; ai=""
    while IFS= read -r line; do
      case "$line" in
        PublicKey*)  pk=${line#*=}; pk=${pk# } ;;
        AllowedIPs*) ai=${line#*=}; ai=${ai# } ;;
      esac
    done < "$conf"
    printf '%s\n%s\n%s\n' "utun-$name" "$pk" "$ai" > "$run/state-$name"
    ;;
  down) : > "$run/state-$name" ;;
  *) printf 'unknown action\n' 1>&2; exit 64 ;;
esac
exit 0
"#;

/// Fake `wg`: renders `show all dump` from the state files. Builtins only.
const FAKE_WG: &str = r#"#!/bin/sh
run="$FAKE_WG_RUN_DIR"
if [ "$1" = "show" ] && [ "$2" = "all" ] && [ "$3" = "dump" ]; then
  for f in "$run"/state-*; do
    [ -f "$f" ] || continue
    iface=""; pk=""; ai=""
    { IFS= read -r iface; IFS= read -r pk; IFS= read -r ai; } < "$f"
    [ -n "$iface" ] || continue
    printf '%s\tIFPRIV\tIFPUB\t51820\toff\n' "$iface"
    printf '%s\t%s\t(none)\t203.0.113.1:51820\t%s\t1700000000\t1024\t2048\t25\n' "$iface" "$pk" "$ai"
  done
  exit 0
fi
printf 'unsupported wg invocation\n' 1>&2
exit 1
"#;

/// Fake `curl`: emits a trace body (for trace URLs) plus the marker-separated
/// write-out, or fails when the URL contains "fail".
const FAKE_CURL: &str = r#"#!/bin/sh
for a; do url=$a; done
case "$url" in
  *fail*) printf 'curl: (7) Failed to connect\n' 1>&2; exit 7 ;;
  *cdn-cgi/trace*)
    printf 'fl=x\nip=203.0.113.99\nloc=US\ncolo=EWR\n'
    printf '\n<<<VPNPROBE>>>0.004000,0.012000,0.140000,0.290000,0.291000,104.16.132.229,200'
    ;;
  *) printf '\n<<<VPNPROBE>>>0.004000,0.012000,0.140000,0.290000,0.291000,104.16.132.229,200' ;;
esac
"#;

const HOME_CONF: &str = "[Interface]\nPrivateKey = IFPRIV=\nAddress = 10.0.0.2/32\n\n\
    [Peer]\nPublicKey = HOMEPEER=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.1:51820\n";

const WORK_CONF: &str = "[Peer]\nPublicKey = WORKPEER=\nAllowedIPs = 10.0.0.0/8\n";

struct Env {
    _bin: TempDir,
    bin_path: String,
    config_dir: TempDir,
    run_dir: TempDir,
}

fn write_stub(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn setup() -> Env {
    let bin = tempdir().unwrap();
    write_stub(bin.path(), "wg-quick", FAKE_WG_QUICK);
    write_stub(bin.path(), "wg", FAKE_WG);
    write_stub(bin.path(), "curl", FAKE_CURL);

    let config_dir = tempdir().unwrap();
    fs::write(config_dir.path().join("home.conf"), HOME_CONF).unwrap();

    let run_dir = tempdir().unwrap();
    let bin_path = bin.path().to_str().unwrap().to_string();
    Env {
        _bin: bin,
        bin_path,
        config_dir,
        run_dir,
    }
}

impl Env {
    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("vpn").unwrap();
        cmd.env("PATH", &self.bin_path)
            .env("FAKE_WG_RUN_DIR", self.run_dir.path())
            .arg("--config-dir")
            .arg(self.config_dir.path());
        cmd
    }

    fn json(&self, args: &[&str]) -> (Value, i32) {
        let assert = self.cmd().arg("--json").args(args).assert();
        let output = assert.get_output();
        let code = output.status.code().unwrap();
        let value = if output.stdout.is_empty() {
            serde_json::from_slice(&output.stderr).unwrap()
        } else {
            serde_json::from_slice(&output.stdout).unwrap()
        };
        (value, code)
    }
}

#[test]
fn full_lifecycle() {
    let env = setup();

    // Initially down.
    let (v, code) = env.json(&["status", "home"]);
    assert_eq!(code, 0);
    assert_eq!(v["tunnels"][0]["up"], false);

    // Bring up: status resolves via peer matching (no name file exists).
    let (v, code) = env.json(&["up", "home"]);
    assert_eq!(code, 0);
    assert_eq!(v["changed"], true);
    assert_eq!(v["status"]["up"], true);
    assert_eq!(v["status"]["interface"], "utun-home");
    assert_eq!(v["status"]["peers"][0]["endpoint"], "203.0.113.1:51820");
    assert_eq!(v["status"]["peers"][0]["transfer_rx"], 1024);

    // Up again is a no-op.
    let (v, _) = env.json(&["up", "home"]);
    assert_eq!(v["changed"], false);

    // It shows as current and up in list.
    let (v, _) = env.json(&["current"]);
    assert_eq!(v["active"][0], "home");
    let (v, _) = env.json(&["list"]);
    assert_eq!(v["tunnels"][0]["name"], "home");
    assert_eq!(v["tunnels"][0]["up"], true);

    // Bring down (this was the macOS bug: down must see the live tunnel).
    let (v, code) = env.json(&["down", "home"]);
    assert_eq!(code, 0);
    assert_eq!(v["changed"], true);
    let (v, _) = env.json(&["down", "home"]);
    assert_eq!(v["changed"], false);

    // Nothing current after teardown.
    let (v, _) = env.json(&["current"]);
    assert!(v["active"].as_array().unwrap().is_empty());
}

#[test]
fn probe_activates_and_restores() {
    let env = setup();

    let (v, code) = env.json(&["probe", "home"]);
    assert_eq!(code, 0);
    let r = &v["results"][0];
    assert_eq!(r["name"], "home");
    assert_eq!(r["ok"], true);
    assert_eq!(r["activated"], true);
    assert_eq!(r["interface"], "utun-home");
    assert_eq!(r["http_code"], 200);
    assert_eq!(r["remote_ip"], "104.16.132.229");
    assert_eq!(r["timings"]["total_ms"], 291.0);
    assert_eq!(r["timings"]["ttfb_ms"], 290.0);
    // Exit-location evidence from the trace body.
    assert_eq!(r["exit"]["ip"], "203.0.113.99");
    assert_eq!(r["exit"]["loc"], "US");
    assert_eq!(r["exit"]["colo"], "EWR");

    // The tunnel is back down afterwards.
    let (v, _) = env.json(&["status", "home"]);
    assert_eq!(v["tunnels"][0]["up"], false);
}

#[test]
fn probe_count_reports_stats() {
    let env = setup();
    let (v, code) = env.json(&["probe", "home", "--count", "3"]);
    assert_eq!(code, 0);
    let r = &v["results"][0];
    assert_eq!(r["samples"], 3);
    assert_eq!(r["failures"], 0);
    assert_eq!(r["stats"]["median_total_ms"], 291.0);
    assert_eq!(r["stats"]["min_total_ms"], 291.0);
    assert_eq!(r["stats"]["max_total_ms"], 291.0);
    // Restored afterwards.
    let (v, _) = env.json(&["status", "home"]);
    assert_eq!(v["tunnels"][0]["up"], false);
}

#[test]
fn probe_leaves_running_tunnel_up() {
    let env = setup();
    env.json(&["up", "home"]);

    let (v, code) = env.json(&["probe", "home"]);
    assert_eq!(code, 0);
    assert_eq!(v["results"][0]["activated"], false);

    // Still up afterwards.
    let (v, _) = env.json(&["status", "home"]);
    assert_eq!(v["tunnels"][0]["up"], true);

    env.json(&["down", "home"]);
}

#[test]
fn probe_failure_exits_7_and_still_restores() {
    let env = setup();

    let (v, code) = env.json(&["probe", "home", "--url", "https://fail.example/"]);
    assert_eq!(code, 7);
    assert_eq!(v["results"][0]["ok"], false);
    assert!(v["results"][0]["error"]
        .as_str()
        .unwrap()
        .contains("Failed to connect"));

    // Tunnel state restored despite the failed request.
    let (v, _) = env.json(&["status", "home"]);
    assert_eq!(v["tunnels"][0]["up"], false);
}

#[test]
fn probe_all_covers_every_tunnel() {
    let env = setup();
    fs::write(env.config_dir.path().join("work.conf"), WORK_CONF).unwrap();

    let (v, code) = env.json(&["probe"]);
    assert_eq!(code, 0);
    let results = v["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r["ok"] == true));

    // Everything restored.
    let (v, _) = env.json(&["current"]);
    assert!(v["active"].as_array().unwrap().is_empty());
}

#[test]
fn sibling_configs_do_not_shadow_each_other() {
    let env = setup();
    // Same peer key as home, different AllowedIPs (split tunnel).
    fs::write(
        env.config_dir.path().join("home-split.conf"),
        "[Peer]\nPublicKey = HOMEPEER=\nAllowedIPs = 0.0.0.0/1, 128.0.0.0/1\n",
    )
    .unwrap();

    env.json(&["up", "home"]);
    let (v, _) = env.json(&["current"]);
    let active = v["active"].as_array().unwrap();
    assert_eq!(active.len(), 1, "only the full-tunnel config is up");
    assert_eq!(active[0], "home");
    env.json(&["down", "home"]);
}

#[test]
fn human_output_is_readable() {
    let env = setup();
    env.cmd()
        .args(["up", "home"])
        .assert()
        .success()
        .stdout(predicates::str::contains("brought up"));
    env.cmd()
        .args(["probe", "home"])
        .assert()
        .success()
        .stdout(predicates::str::contains("total"))
        .stdout(predicates::str::contains("http 200"));
    env.cmd()
        .args(["down", "home"])
        .assert()
        .success()
        .stdout(predicates::str::contains("brought down"));
}

#[test]
fn unknown_tunnel_exits_3() {
    let env = setup();
    let (v, code) = env.json(&["up", "ghost"]);
    assert_eq!(code, 3);
    assert_eq!(v["ok"], false);
    assert_eq!(v["code"], 3);
}

#[test]
fn invalid_name_exits_4() {
    let env = setup();
    let (_v, code) = env.json(&["up", "bad name"]);
    assert_eq!(code, 4);
}

#[test]
fn missing_backend_binary_exits_6() {
    let env = setup();
    // Point PATH at an empty dir so `wg` cannot be found.
    let empty = tempdir().unwrap();
    let assert = Command::cargo_bin("vpn")
        .unwrap()
        .env("PATH", empty.path())
        .env("FAKE_WG_RUN_DIR", env.run_dir.path())
        .args(["--config-dir"])
        .arg(env.config_dir.path())
        .args(["--json", "up", "home"])
        .assert()
        .failure();
    assert_eq!(assert.get_output().status.code().unwrap(), 6);
}

#[test]
fn usage_error_exits_2() {
    // clap emits its own usage error with exit code 2.
    Command::cargo_bin("vpn")
        .unwrap()
        .arg("not-a-command")
        .assert()
        .code(2);
}
