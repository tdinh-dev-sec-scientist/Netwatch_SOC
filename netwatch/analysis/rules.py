"""
ThreatDetector — the detection engine.

Owns the detector registry, feeds every parsed packet to every detector, and
returns structured Finding objects. All detection state is bounded: `expire()`
runs on a timer and drops per-key state that has aged out of its window.

The engine is deliberately dumb about persistence and I/O — it takes parsed
packets in and hands findings out. DB_Manager turns findings into rows.
"""

import time

from netwatch import config as config_module
from netwatch import detectors, mitre


class ThreatDetector:
    """Runs every registered detector over a stream of parsed packets."""

    def __init__(self, db=None, cfg=None):
        self.db = db
        self.cfg = cfg or config_module.load()
        self.detectors = detectors.build_all(self.cfg)
        self._by_name = {d.name: d for d in self.detectors}
        # protocol name -> the detectors that can possibly fire on it. Built
        # lazily per protocol seen; see _dispatch_for().
        self._dispatch = {}
        self._last_gc = time.time()
        self._gc_interval = self.cfg['engine']['gc_interval_s']
        self.packets_analyzed = 0
        self.findings_total = 0
        self.detector_errors = 0
        self._validate_technique_references()

    def _validate_technique_references(self):
        """Fail fast if a detector names a technique missing from the catalog.

        Keeps the ATT&CK mapping honest: a detector cannot silently emit an
        ID that has no catalog entry behind it.
        """
        unknown = set()
        for det in self.detectors:
            for tid in det.techniques:
                if mitre.get(tid) is None:
                    unknown.add('%s -> %s' % (det.name, tid))
        if unknown:
            raise ValueError('detectors reference unknown ATT&CK techniques: '
                             + ', '.join(sorted(unknown)))

    # ── main entry point ─────────────────────────────────────────────────────

    def analyze(self, pkt):
        """Run all detectors over one parsed packet. Returns list[Finding].

        A packet must carry a timestamp; callers that parse without one get it
        stamped here so window arithmetic always has a basis.
        """
        if pkt.get('ts') is None:
            pkt['ts'] = time.time()
        self.packets_analyzed += 1

        findings = []
        for det in self._dispatch_for(pkt.get('protocol')):
            try:
                result = det.inspect(pkt)
            except Exception:
                # One misbehaving detector must not take down the pipeline;
                # count it so the failure is visible in /api/detectors.
                self.detector_errors += 1
                continue
            if result:
                findings.extend(result)

        self.findings_total += len(findings)

        now = pkt['ts']
        if now - self._last_gc > self._gc_interval:
            self.expire(now)
        return findings

    def _dispatch_for(self, protocol):
        """Detectors worth calling for `protocol`, cached per protocol.

        Most detectors open with a protocol guard and return an empty list on
        their first line — an ARP spoofing rule has nothing to say about a TLS
        record. Calling all seventeen for every packet spends most of the
        rule stage's time entering and leaving functions. This filters on the
        `protocols` hint each detector declares; a detector that declares None
        is always called, and every detector keeps its own guard, so the hint
        can only remove work, never change a verdict.
        """
        cached = self._dispatch.get(protocol)
        if cached is None or cached[0] != len(self.detectors):
            # The registered count is part of the cache key so a detector
            # added at runtime (tests do this) cannot be silently skipped by
            # a stale entry.
            #
            # getattr rather than attribute access: a detector is a duck type,
            # not necessarily a Detector subclass, and one that does not
            # declare a hint is simply always called.
            selected = tuple(
                d for d in self.detectors
                if getattr(d, 'protocols', None) is None
                or protocol in d.protocols)
            cached = self._dispatch[protocol] = (len(self.detectors), selected)
        return cached[1]

    def expire(self, now=None):
        now = now or time.time()
        for det in self.detectors:
            try:
                det.expire(now)
            except Exception:
                self.detector_errors += 1
        self._last_gc = now

    # ── introspection ────────────────────────────────────────────────────────

    def threat_types(self):
        return [d.threat_type for d in self.detectors]

    def techniques_covered(self):
        """Distinct ATT&CK technique IDs reachable from the loaded detectors."""
        found = set()
        for det in self.detectors:
            found.update(det.techniques)
        return sorted(found)

    def stats(self):
        return {
            'packets_analyzed': self.packets_analyzed,
            'findings_total': self.findings_total,
            'detector_errors': self.detector_errors,
            'detector_count': len(self.detectors),
            'threat_type_count': len(set(self.threat_types())),
            'technique_count': len(self.techniques_covered()),
            'detectors': [
                {
                    'name': d.name,
                    'threat_type': d.threat_type,
                    'description': d.description,
                    'techniques': list(d.techniques),
                    'packets_seen': d.packets_seen,
                    'findings_emitted': d.findings_emitted,
                }
                for d in self.detectors
            ],
        }

    def get(self, name):
        return self._by_name.get(name)

    @staticmethod
    def get_mitre_info(technique_id):
        t = mitre.get(technique_id)
        return (t.id, t.name, t.tactic) if t else (technique_id, 'Unknown',
                                                   'Unknown')


# `RulesEngine` is the pipeline-facing name for this component: stage 3
# evaluates rules over parsed packets. `ThreatDetector` is kept as an alias
# because the detector modules and tests refer to it by that name.
RulesEngine = ThreatDetector
