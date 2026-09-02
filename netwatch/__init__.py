"""NetWatch — a streaming packet-processing pipeline with a REST API.

The system is a five-stage pipeline joined by bounded queues:

    capture -> protocol parsing -> rules evaluation -> persistence -> REST API

Each stage runs its own worker pool and hands work to the next through a
``BoundedStageQueue``. Because every queue has a fixed capacity, a slow stage
applies backpressure to the one in front of it instead of letting an unbounded
buffer grow until the process is killed by the OOM reaper.

Package layout:

    netwatch.capture    frame sources (synthetic generator, list replay)
    netwatch.analysis   wire-format parsing and the rules/detector engine
    netwatch.db         SQLAlchemy models, bulk writer and read repository
    netwatch.pipeline   queues, stages, metrics and the orchestrator
    netwatch.api        Flask application and REST endpoints
"""

__version__ = '2.0.0'
