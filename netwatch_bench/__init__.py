"""
NetWatch Bench: reproducible, engine-agnostic scoring for network detections.

Replay a labelled traffic pack through a detection engine (NetWatch, Suricata,
or any tool whose alerts you can export), match every alert against ground
truth, and get a scorecard with confidence intervals and full provenance.

    python -m netwatch_bench run --pack packs/cicids2018-demo --engine netwatch
"""

__version__ = '0.2.0'
