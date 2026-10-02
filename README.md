# groundtruth

Measures the state that a unit's status only promises, once a minute, and
hands it to Prometheus.

`systemctl status` said `active (exited)`, the journal said "prefixes set",
and both were true. The nftables set the unit is there to fill was empty all
the same: a deploy had restarted nftables, the set came back without
elements, and nothing restarted the unit that fills it. The rule over that
set is the barrier between the guests and the home network. It stood open for
five hours, on a host where every unit was green.

The expensive outages of the homelab this tool comes from all look like that.
podman left a DNAT rule behind after a failed teardown, iptables takes the
first of two, and three services answered 502 for sixteen hours behind units
that were `active` and containers that were `healthy`. A proxy neighbour
outlived its guest, answered the guest's duplicate address detection when it
came back, and the guest gave up its IPv6 address for as long as it ran. A
sysctl that named `enp4s0` went away on the day a second PCIe card turned the
interface into `enp8s0`.

**Watchers measure the state of the unit, and the state of the unit was
right.** groundtruth reads the thing itself.

```console
# groundtruth --config /etc/groundtruth.toml --stdout >/dev/null
ok               lan6-prefixes                2 element(s), at least 1 expected
-                zone-counters
ok               dnat-leftovers
CANNOT MEASURE   tempaddr-off                 cannot read /proc/sys/net/ipv6/conf/enp4s0/use_tempaddr
NOT AS EXPECTED  proxy-neigh-exp              missing [], unexpected ["fd00:0:0:20::13"]
ok               addr-torrent-01
ok               guest-ports-isolated
```

## How it runs

A oneshot on a timer, as root, writing a file for the
[textfile collector](https://github.com/prometheus/node_exporter#textfile-collector)
of the node exporter. No port, no daemon, no scrape job.

```
groundtruth --config FILE --output /var/lib/node-exporter-textfile/groundtruth.prom
groundtruth --config FILE --stdout
```

The file is written next to its target and renamed: the collector reads at
any moment and must never see half of it. **Do not give the unit
`RemainAfterExit`** — a timer's `start` on a unit that is still "active" is a
no-op, which is how the empty set above came about.

It exits 0 once the metrics are written, red checks included. Red is a
metric, not a failed unit: a unit that fails every minute is noise. It exits
1 if the configuration or the output fails, 2 on wrong usage.

## Metrics

```
groundtruth_ok{check="lan6-prefixes",probe="nft_set"} 1
groundtruth_value{check="lan6-prefixes",probe="nft_set",item="elements"} 2
groundtruth_probe_success{check="lan6-prefixes",probe="nft_set"} 1
groundtruth_last_run_timestamp_seconds 1789828200
groundtruth_run_duration_seconds 0.214
```

`groundtruth_probe_success` answers whether the probe could measure at all —
the command ran, the object exists. A probe that could not measure reports
`ok 0` as well: a sensor that cannot see must not look like a quiet day.

Three rules therefore cover every check there is and every one you add:

```yaml
- alert: GroundtruthNotAsExpected
  expr: groundtruth_ok == 0 and on (check) groundtruth_probe_success == 1
  for: 5m
- alert: GroundtruthCannotMeasure
  expr: groundtruth_probe_success == 0
  for: 5m
- alert: GroundtruthStale
  expr: time() - groundtruth_last_run_timestamp_seconds > 300
```

A new trap is an entry in the configuration, not a release and not a rule.

## Probes

See [`groundtruth.example.toml`](groundtruth.example.toml). An unknown key, an
unknown probe and a name used twice are errors.

| `probe` | fields | verdict |
|---|---|---|
| `nft_set` | `family`, `table`, `set`, `min` | the set holds at least `min` elements |
| `nft_counter` | `family`, `table`, `counters` | none: packets per counter as `value`; empty list means all |
| `iptables_dnat_duplicates` | | no two DNAT rules for the same protocol, destination and port, and no two jumps for the same port in a `…HOSTPORT-DNAT` chain |
| `sysctl` | `key`, `expect` | the value is the expected one; a key that cannot be read cannot be measured |
| `proxy_neigh` | `dev`, `expect` | the IPv6 proxy neighbours of the device are exactly these; an entry `{ address, machine }` is expected only while that machine runs, and is a finding while it does not |
| `machine_addr` | `machine`, `ifname`, `expect` | the running systemd machine holds these addresses, none `dadfailed` or `tentative` |
| `machine_caps` | `machine`, `expect` | the capability bounding set of the running machine's leader is exactly this hexadecimal mask; `extra` and `missing` count the bits that differ |
| `bridge_isolated` | `ports` | every bridge port matching the pattern, or one of a list (`*` is the wildcard), is `isolated` |

Notes:

- **`machine_addr` and a machine that does not run:** no verdict, `value
  {item="running"} 0`. Whether it should run is somebody else's question.
  The leader PID comes from `machinectl show`, the addresses from
  `nsenter -n ip -j addr`.
- **`machine_caps`** reads `CapBnd` from `/proc/<leader>/status`. A bit too
  many is a guest started before a cut, or by a unit that lost it; a bit
  too few means the declaration is wrong. A machine that does not run: no
  verdict, as with `machine_addr`.
- **`bridge_isolated` and patterns that match nothing at all:** cannot
  measure, and says so. One name of a list that is missing is a guest that
  does not run.
- **`sysctl` keys with a dot in the interface name** (`eth0.20`): write the key
  with slashes, `net/ipv6/conf/eth0.20/use_tempaddr`.
- Addresses compare by value: `fd00::0:1` is `fd00::1`.

The probes read the JSON of `nft`, `ip` and `bridge`, the text of
`iptables-save`, and `/proc/sys`. The Nix package wraps the binary with those
tools as a PATH *suffix*: a host that has its own is asked with its own. Each
command gets ten seconds.

## What it does not do

- **Probe paths.** It sends no packet. Whether a connection works is a
  different measurement.
- **Repair.** It reports.
- **Grade.** One verdict per check; severity and patience belong to the
  alerting rules.

## Install

```nix
inputs.groundtruth.url = "github:achimcc/groundtruth/v0.2.0";

systemd.services.groundtruth = {
  serviceConfig = {
    Type = "oneshot";
    ExecStart = "${groundtruth}/bin/groundtruth --config ${config} --output /var/lib/node-exporter-textfile/groundtruth.prom";
  };
};
systemd.timers.groundtruth = {
  wantedBy = [ "timers.target" ];
  timerConfig = { OnBootSec = "1min"; OnUnitActiveSec = "1min"; };
};
```

## License

AGPL-3.0-only.
