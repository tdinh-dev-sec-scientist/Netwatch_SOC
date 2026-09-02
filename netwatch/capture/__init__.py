"""Frame sources: everything that can put raw bytes into the pipeline."""

from netwatch.capture.generator import TrafficGenerator
from netwatch.capture.source import (
    FrameSource,
    ListSource,
    SyntheticSource,
    fixed_workload,
)

__all__ = ['FrameSource', 'ListSource', 'SyntheticSource', 'TrafficGenerator',
           'fixed_workload']
