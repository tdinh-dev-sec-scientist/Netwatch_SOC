"""
Engine adapters. Each turns a capture into normalized findings.

    netwatch   NetWatch's own pipeline, in process (the reference engine)
    suricata   Suricata, from a local binary or a Docker image
    eve        an existing Suricata EVE JSON file (no replay)
    findings   any engine's alerts already in the normalized JSON-lines format
"""

from .base import Engine, EngineError
from .files import EveFileEngine, FindingsFileEngine
from .netwatch import NetWatchEngine
from .suricata import SuricataEngine

ENGINES = {
    'netwatch': NetWatchEngine,
    'suricata': SuricataEngine,
    'eve': EveFileEngine,
    'findings': FindingsFileEngine,
}

__all__ = ['ENGINES', 'Engine', 'EngineError']
