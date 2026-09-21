# NetWatch SOC -> Splunk

Forwards NetWatch detections into Splunk index `netwatch`, sourcetype
`netwatch:incident`, and ships an analyst dashboard plus five scheduled
alerts.

Nothing outside this directory is modified. The detection engine, the
database schema and the Flask API are untouched.

---

## What is actually being forwarded

**There is no `incidents` table in NetWatch, and there never was.** The
schema has eight tables (`DB_Manager.py`); the `alerts` table is the unit
that exists. `DB_Manager`'s own module docstring explains the design choice:
aggregate views are derived by query rather than materialised.

That matters because it changes what "forwarding incidents" can honestly
mean. Here is what was measured, not assumed:

**The `alerts` table already holds post-deduplication output.** Every one of
the 17 detectors calls `Detector._cooled_down()` *before* emitting a finding
(`detectors/base.py:212`, called from 25 sites across `detectors/*.py`), and
`ThreatDetector.analyze()` does no further aggregation. The raw pre-cooldown
volume never reaches SQLite. So forwarding alert rows 1:1 *is* forwarding the
deduplicated output — no second dedup step is needed or possible.

Measured on a deterministic 90-minute corpus (seed 1337, 113,624 frames):

```
RAW (every cooldown_s = 0)  alerts    : 613
RAW                         incidents :  25
TUNED (shipped config)      alerts    :  25   <- what is written to SQLite
TUNED                       incidents :  25
reduction                             : 95.9%
incidents lost to suppression         :   0
alerts per incident                   : 1.00
```

Reproduce:

```bash
python -c "
import collections, os, tempfile, config
from DB_Manager import DatabaseManager
from PacketSimulator import TrafficGenerator
from benchmark import collect_findings, incidents, undeduplicated_config
cfg = config.load()
db = DatabaseManager(os.path.join(tempfile.mkdtemp(), 'm.db'))
frames = TrafficGenerator(seed=1337).history(0.0, 90*60, rate_pps=20.0)
tuned, raw = collect_findings(frames, cfg, db), collect_findings(frames, undeduplicated_config(cfg), db)
print('raw', len(raw), 'tuned', len(tuned), 'incidents', len(incidents(tuned)), 'lost', len(incidents(raw)-incidents(tuned)))
"
```

**The caveat that keeps this honest.** The 1.00 ratio holds on the simulator's
corpus because `TrafficGenerator.history()` injects each attack scenario once.
It is a property of that corpus, not a guarantee of the engine. On sustained
real traffic a cooldown expires and the same incident produces a second alert
row. It held at 1.00 across 90 / 180 / 360 / 720-minute spans here, but do not
describe it as invariant — describe it as measured.

That caveat is exactly what the `incident_key` field is for.

---

## `incident_key`: what it is and what it is not

The engine stamps `Finding.incident_key` — the identity of the incident
rather than of the packet that exposed it (for a spoofed flood, the victim,
not the source). **It is not persisted.** `DB_Manager._write_alerts()` has no
column for it, so it cannot be read back out of SQLite.

The forwarder therefore *reconstructs* a correlation key from stored columns
only. It is a Splunk-side correlation field, not the engine's key, and not
new detection logic. `netwatch_hec.incident_key()`:

```
detector | threat_type | src_ip | dst_ip | <one evidence discriminator>
```

The discriminator is the first present of `pattern`, `categories`,
`sweep_type`, `vector`, `zone`, `identified_protocol`, `target`, `service`.

**Why the discriminator is not decoration.** Measured on the same corpus:

| correlation key | groups | incidents merged | incidents split |
|---|---|---|---|
| `detector + threat_type + src_ip + dst_ip` | 19 | **6** | 0 |
| ...`+ dst_port + protocol` | 19 | **6** | 0 |
| **...`+ evidence discriminator`** | **25** | **0** | **0** |

Without it, the five distinct `http_anomaly` incidents from one source to one
target (SQLi, Traversal, XSS, CmdInjection, JNDI — genuinely different
attacks) collapse into a single group, and `dc(incident_key)` under-counts.
With it, the derived key partitions the alerts into exactly the same 25 groups
as the engine's own unpersisted key. `dst_port` is deliberately excluded: a
`port_scan` incident spans many ports, so including it would split one
incident across groups when a detector re-alerts.

This is asserted by
`test_derived_key_partitions_exactly_like_the_engine_key`, so it fails loudly
if a detector's evidence shape changes.

---

## Directionality: `src_ip` is not "the attacker"

`Detector._finding()` lets a detector attribute an alert to a party other
than the packet's sender. Real rows from the test corpus:

```
id=5  brute_force     src_ip=45.33.32.156  dst_ip=10.0.2.12  src_port=21
id=10 suspicious_dns  src_ip=8.8.8.8       dst_ip=10.0.1.33  src_port=53
id=17 amplification   src_ip=91.108.4.90   dst_ip=10.0.2.30  src_port=123
id=23 arp_spoof       src_ip=10.0.1.1      dst_ip=10.0.1.1
```

Row 10's victim is `10.0.1.33`; `src_ip` is the resolver. Row 17's `src_ip` is
the reflector, not the attacker.

**No attacker/victim field is computed anywhere in this integration.** Every
column is forwarded raw and unmodified. What exists instead is RFC1918
zone classification, defined once in `props.conf` as a search-time `EVAL`:

```
EVAL-src_zone = if(cidrmatch("10.0.0.0/8",src_ip) OR cidrmatch("172.16.0.0/12",src_ip) OR cidrmatch("192.168.0.0/16",src_ip),"internal","external")
```

That states which side of the network boundary an address sits on. It does
not claim who initiated anything. Inline in SPL if you prefer:

```spl
index=netwatch sourcetype=netwatch:incident
| eval zone=if(cidrmatch("10.0.0.0/8",src_ip) OR cidrmatch("192.168.0.0/16",src_ip), "internal_src", "external_src")
```

`props.conf` also aliases `dst_ip AS dest_ip` at search time, so CIM-style
field names work in SPL without the forwarder renaming a stored column.

---

## Data flow

```
frames -> ProtocolAnalyzer -> ThreatDetector (17 detectors)
                                   |
                     _cooled_down() gates emission   <- deduplication happens HERE
                                   |
                          DB_Manager._write_alerts()
                                   |
                       SQLite: alerts + alert_techniques
                                   |
              netwatch_hec.py  (read-only, mode=ro, WAL-safe)
                 - joins alert_techniques -> mitre_techniques
                 - derives incident_key
                 - HEC "time" := alerts.ts
                                   |
                    POST /services/collector/event
                                   |
            Splunk index=netwatch sourcetype=netwatch:incident
                                   |
                   dashboard + 5 scheduled alerts
```

The forwarder opens the database with `mode=ro`, so it is safe to run against
the live engine's file — SQLite WAL lets it read during writes, and the
connection physically cannot write (asserted by `test_connection_cannot_write`).

---

## Files

| file | what it is |
|---|---|
| `netwatch_hec.py` | the forwarder |
| `test_netwatch_hec.py` | 22 tests, incl. the key-fidelity and timestamp checks |
| `netwatch_dashboard.xml` | Classic Simple XML, 5 panels |
| `savedsearches.conf` | 5 scheduled alerts, each with its false-positive note |
| `props.conf` | sourcetype config, zone/severity EVALs, CIM aliases |

---

## Running it

### 1. Produce data (if `netwatch.db` is empty)

```bash
python -c "
import config
from DB_Manager import DatabaseManager
from PacketSimulator import PacketSimulator
from ProtocolAnalyzer import ProtocolAnalyzer
from ThreatDetector import ThreatDetector
cfg = config.load(); db = DatabaseManager()
sim = PacketSimulator(db, ThreatDetector(db, cfg=cfg), ProtocolAnalyzer(), cfg=cfg)
print(len(sim.backfill(minutes=90)), 'findings'); sim.flush(); db.close()
"
```

`python engine.py` alone waits 20 seconds before its first attack scenario
(`PacketSimulator.FIRST_SCENARIO_DELAY_S`), so a short run produces zero
alerts. That is expected behaviour, not a bug.

### 2. Dry run — needs no Splunk and no token

```bash
python integrations/splunk/netwatch_hec.py --dry-run | head -40
python integrations/splunk/netwatch_hec.py --dry-run --limit 1
```

### 3. Set up Splunk (run these yourself — untested here, see below)

```bash
docker exec -it splunk /opt/splunk/bin/splunk add index netwatch \
  -auth admin:'<your-password>'

docker exec -it splunk /opt/splunk/bin/splunk http-event-collector enable \
  -uri https://localhost:8089 -auth admin:'<your-password>'

docker exec -it splunk /opt/splunk/bin/splunk http-event-collector create netwatch-hec \
  -uri https://localhost:8089 -index netwatch -sourcetype netwatch:incident \
  -disabled 0 -auth admin:'<your-password>'
```

The last command prints the token. Put it in the environment, never in a file
and never on a command line:

```bash
read -rs SPLUNK_HEC_TOKEN && export SPLUNK_HEC_TOKEN
```

`read -rs` keeps it out of your shell history. The forwarder reads
`$SPLUNK_HEC_TOKEN` and nothing else; it is never logged or echoed
(`test_token_never_appears_in_dry_run_output`).

### 4. Forward

```bash
# Splunk's default cert is self-signed, so a lab instance needs one of these:
python integrations/splunk/netwatch_hec.py --url https://localhost:8088 --insecure
# preferred, once you have the cert:
python integrations/splunk/netwatch_hec.py --url https://localhost:8088 --ca-cert /path/to/cacert.pem
```

Re-runs resume from `.hec_state.json` (gitignored), so only new alerts are
sent. `--no-state` re-sends everything.

### 5. Install the Splunk-side config

```bash
docker exec splunk mkdir -p /opt/splunk/etc/apps/netwatch/local
docker cp integrations/splunk/props.conf          splunk:/opt/splunk/etc/apps/netwatch/local/
docker cp integrations/splunk/savedsearches.conf  splunk:/opt/splunk/etc/apps/netwatch/local/
docker exec splunk mkdir -p /opt/splunk/etc/apps/netwatch/local/data/ui/views
docker cp integrations/splunk/netwatch_dashboard.xml \
  splunk:/opt/splunk/etc/apps/netwatch/local/data/ui/views/netwatch_dashboard.xml
docker exec splunk /opt/splunk/bin/splunk restart
```

---

## Verifying the timestamp mapping

The HEC envelope sets `"time"` from `alerts.ts` — detection time, carried
from the packet. `props.conf` deliberately contains no `TIME_FORMAT`: on the
`/services/collector/event` endpoint an explicit `time` key wins, so
timestamp-extraction settings would be dead configuration.

**This is the check that proves it.** Backfilled alerts span the last 90
minutes, so `_time` must be spread across that range while `_indextime` is
all "just now":

```spl
index=netwatch sourcetype=netwatch:incident
| eval detected=strftime(_time,"%F %T"), ingested=strftime(_indextime,"%F %T"), lag_s=round(_indextime-_time,1)
| table alert_id detected ingested lag_s threat_type
| sort - lag_s
```

Correct: `lag_s` varies widely (hundreds to thousands of seconds), `detected`
values are spread out.

**Broken:** `lag_s` is near zero for every event and all `detected` values are
within a second of each other — that means Splunk is stamping at ingest and
the mapping is wrong. This one-liner turns it into a pass/fail:

```spl
index=netwatch sourcetype=netwatch:incident
| stats dc(_time) AS distinct_detection_times range(_time) AS span_s count
```

`span_s` should be roughly your backfill window in seconds (about 5400 for a
90-minute backfill). A `span_s` near 0 is the bug.

---

## Saved searches

Five, in `savedsearches.conf`. Each stanza carries a full false-positive note
above it; summarised:

| alert | schedule | main false positives |
|---|---|---|
| Critical detection | 5 min | Volumetric rules (syn/udp flood) trip on load tests and backups; ARP "binding conflict" trips on DHCP churn and HA failover |
| C2 beacon, low jitter | 15 min | **The noisiest by design.** NTP, EDR heartbeats, update checks and monitoring agents all beacon cleanly. Real implants often jitter *more* to evade this |
| Outbound transfer int->ext | 10 min | Cloud backup and file sync dominate; 5 MB / 300s is low for a real network |
| Lateral movement fan-out | 10 min | Vuln scanners, SCCM, Ansible, backup agents — unusable without an allowlist of legitimate fan-out sources |
| Source across 3+ tactics | hourly | A vulnerability scanner produces this exact signature; read the tactic *sequence*, not the count |

All five suppress on `incident_key` (or `src_ip` for the cross-tactic one) so
a re-alerting detector does not reopen the same ticket every cron cycle.

The cross-tactic search is the only one that is genuinely additive rather than
a filter on a single detector: no individual detector can see that one source
is progressing through multiple ATT&CK tactics, because each only knows its
own signal.

---

## Tests

```bash
pytest integrations/splunk -q      # 22 tests
```

Not picked up by a bare `pytest` — `pytest.ini` sets `testpaths = tests`, and
that file was left alone.

Worth knowing what they cover, because several are claims this README makes:

- `test_derived_key_partitions_exactly_like_the_engine_key` — the 25/0/0 result
- `test_alert_rows_are_post_dedup` — rows written are already cooldown-gated
- `test_hec_time_is_the_detection_time_not_now` — timestamp mapping
- `test_backfilled_alerts_keep_their_past_timestamps` — events do not collapse onto one time
- `test_token_never_appears_in_dry_run_output` — secret handling
- `test_connection_cannot_write` — read-only safety against the live engine
- `test_spl_only_references_fields_the_forwarder_actually_sends` — a typo'd
  field in SPL is not an error in Splunk, it just renders an empty panel that
  looks like "no detections"
- `test_tactic_technique_pairing_survives_multi_technique_alerts` — three
  alerts in the corpus map to two techniques in *different* tactics; flat
  parallel lists would let the coverage matrix cross-join and invent cells

---

## What was not tested here

No Splunk instance was available in the environment this was built in. The
following are **written but unverified** — run them and report back:

1. **HEC delivery.** No event has been POSTed to a real collector. The
   envelope shape follows the HEC event API, but the round trip is unproven.
   ```bash
   curl -sk https://localhost:8088/services/collector/health   # expect {"text":"HEC is healthy","code":17}
   python integrations/splunk/netwatch_hec.py --url https://localhost:8088 --insecure
   ```
2. **Index/sourcetype routing.** Verify with
   `index=netwatch sourcetype=netwatch:incident | stats count` — expect it to
   match the number of alert rows the forwarder reported.
3. **The timestamp mapping end to end.** The SPL above. This is the one to run
   first: a wrong timestamp mapping is a bug, and it is invisible until you
   look.
4. **Dashboard rendering.** The XML parses and every field it references
   exists in real events, but no panel has been rendered by Splunk.
5. **Saved-search scheduling and the alert actions.** The stanzas parse, but
   nothing has been dispatched.

---

## Numbers for a resume, and what they support

Do not quote anything here that you have not re-run.

| claim | command that measures it |
|---|---|
| alert-volume reduction, incidents preserved | `python benchmark.py` |
| events forwarded | forwarder's own stderr: `forwarded N/N event(s)` |
| events landed in Splunk | `index=netwatch sourcetype=netwatch:incident \| stats count` |
| detections per incident | `... \| stats count dc(incident_key)` |
| ATT&CK coverage observed | `... \| spath output=p path=tactic_technique{} \| mvexpand p \| stats dc(p)` |

Two phrasings worth being careful about:

- **"Streamed NetWatch incidents into Splunk"** — defensible, because the
  `alerts` table holds post-deduplication output and one row corresponded to
  one incident on the measured corpus. Be ready to say why, and to state the
  caveat above. If you would rather not have to, "streamed deduplicated
  network detections" is true with no caveat attached.
- **"Correlates raw alerts into incidents"** — not defensible. Nothing in
  NetWatch does this at runtime. The 621 -> 24 figure is per-rule cooldown
  suppression measured by `benchmark.py`, verified lossless against the
  detectors' own dedup keys. That is a real and defensible engineering result;
  it is just not correlation.
