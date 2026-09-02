"""
Frame sources — stage 1 of the pipeline.

A ``FrameSource`` is an iterator of ``(capture_ts, frame_bytes)`` pairs. That
is the entire contract, and it is deliberately the same shape a libpcap
callback hands you, so a live sniffer drops in without touching any other
stage:

    class SniffSource(FrameSource):
        def frames(self):
            for pkt in AsyncSniffer(...):
                yield time.time(), bytes(pkt)

Two implementations ship:

    SyntheticSource  generates traffic at a target rate (or as fast as the
                     pipeline will take it, when ``rate_pps`` is None)
    ListSource       replays a pre-built list of frames, for benchmarks and
                     tests that need byte-identical input every run
"""

import time

from netwatch.capture.generator import TrafficGenerator

# Attack scenarios mixed into generated workloads so the rules stage does real
# work instead of short-circuiting on uniformly benign traffic.
WORKLOAD_SCENARIOS = [
    'port_scan', 'network_recon', 'brute_force', 'credential_stuffing',
    'c2_beacon', 'dns_tunnel', 'dga_lookups', 'icmp_tunnel',
    'protocol_tunnel', 'lateral_movement', 'syn_flood', 'udp_flood',
    'ntp_amplification', 'http_attack', 'arp_spoof', 'tls_anomaly',
    'icmp_sweep',
]


class FrameSource:
    """Base class. Subclasses implement ``frames()`` as a generator."""

    name = 'source'

    def frames(self):
        raise NotImplementedError

    def __iter__(self):
        return iter(self.frames())


class ListSource(FrameSource):
    """Replays an explicit list of ``(ts, frame)`` pairs exactly once.

    ``stamp_now`` rewrites each timestamp to the wall clock at the moment the
    frame is emitted. Benchmarks want that (latency is measured against real
    ingress time); scenario tests do not (their detectors reason about the
    synthetic timeline baked into the frames).
    """

    name = 'list'

    def __init__(self, pairs, stamp_now=False):
        self._pairs = list(pairs)
        self._stamp_now = stamp_now

    def __len__(self):
        return len(self._pairs)

    def frames(self):
        if self._stamp_now:
            for _ts, frame in self._pairs:
                yield time.time(), frame
        else:
            yield from self._pairs


class SyntheticSource(FrameSource):
    """Open-ended generated traffic, optionally paced to a target rate.

    ``rate_pps=None`` means "as fast as the downstream stages will accept",
    which is what a throughput benchmark wants: the pipeline, not the source,
    becomes the limit. A numeric rate paces the source with a sleep, which is
    what a soak test wants — a steady offered load whose queue depths mean
    something.
    """

    name = 'synthetic'

    def __init__(self, seed=None, rate_pps=None, count=None, duration_s=None,
                 scenario_every_s=20.0, scenarios=None):
        self.gen = TrafficGenerator(seed)
        self.rate_pps = rate_pps
        self.count = count
        self.duration_s = duration_s
        self.scenario_every_s = scenario_every_s
        self.scenarios = list(scenarios if scenarios is not None
                              else WORKLOAD_SCENARIOS)
        self._stop = False

    def stop(self):
        self._stop = True

    def frames(self):
        emitted = 0
        started = time.time()
        interval = 1.0 / self.rate_pps if self.rate_pps else 0.0
        next_scenario = started + self.scenario_every_s
        pending = []
        next_emit = started

        while not self._stop:
            if self.count is not None and emitted >= self.count:
                return
            now = time.time()
            if self.duration_s and now - started >= self.duration_s:
                return

            if (self.scenarios and not pending
                    and self.scenario_every_s and now >= next_scenario):
                name = self.gen.rng.choice(self.scenarios)
                pending = [fr for _t, fr in self.gen.scenario(name)]
                next_scenario = now + self.scenario_every_s

            frame = pending.pop(0) if pending else self.gen.background_frame(now)
            yield now, frame
            emitted += 1

            if interval:
                # Absolute pacing: sleeping `interval` after each yield drifts
                # slow because the yield itself takes time. Tracking the next
                # deadline keeps the offered rate honest over a long soak.
                next_emit += interval
                slack = next_emit - time.time()
                if slack > 0:
                    time.sleep(slack)
                elif slack < -1.0:
                    next_emit = time.time()


def fixed_workload(packet_count, seed=1337, start_ts=0.0,
                   scenarios=WORKLOAD_SCENARIOS):
    """A reproducible ``(ts, frame)`` list: benign background + every attack.

    Interleaved by timestamp so scenario frames are spread through the run
    rather than arriving as one clump at the end.
    """
    gen = TrafficGenerator(seed)
    pairs = gen.background(packet_count, start_ts=start_ts)
    span = (pairs[-1][0] - pairs[0][0]) if len(pairs) > 1 else 60.0
    step = span / (len(scenarios) + 1)
    for i, name in enumerate(scenarios):
        pairs.extend(gen.scenario(name, start_ts=start_ts + step * (i + 1)))
    pairs.sort(key=lambda pair: pair[0])
    return pairs
