"""
Flask application factory.

The API is the pipeline's fifth stage in the sense that matters: it is where
processed data leaves the system. It reads from two places — PostgreSQL for
anything durable or historical, and the in-process ``LiveFeed`` that stage 5
maintains for the live tail — and never from a stage's internals.

Two deployment shapes, both supported by this factory:

    embedded  one process runs the pipeline and serves the API. Simple, and
              the right shape for a single box.
    split     a dedicated engine process runs the pipeline and any number of
              stateless API processes serve reads from the same database.
              ``create_app()`` with ``run_pipeline=False`` is the API half;
              this is what the container topology uses, and it is the reason
              persistence had to move off SQLite.
"""

import logging
import os

from flask import Flask, jsonify

from netwatch import config as config_module
from netwatch.analysis.rules import RulesEngine
from netwatch.api.errors import register_error_handlers
from netwatch.api.routes import bp, ui
from netwatch.db import schema as schema_mod
from netwatch.db import session as session_mod
from netwatch.db.repository import Repository
from netwatch.db.writer import BatchWriter
from netwatch.pipeline import LiveFeed, Pipeline, PipelineConfig

log = logging.getLogger('netwatch.api')


def _env_flag(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ('0', 'false', 'no', 'off', '')


def create_app(engine=None, repository=None, rules_engine=None, pipeline=None,
               feed=None, run_pipeline=None, create_schema=None,
               database_url=None, config=None):
    """Build the application.

    Tests inject `engine`/`repository` and leave the pipeline off. Production
    passes nothing and lets the environment decide.
    """
    app = Flask(__name__, template_folder='../templates')
    cfg = config or config_module.load()
    app.cfg = cfg

    app.db_engine = engine or session_mod.get_engine(database_url)
    if create_schema is None:
        create_schema = _env_flag('NETWATCH_CREATE_SCHEMA', False)
    if create_schema:
        schema_mod.create_all(app.db_engine)
        schema_mod.seed_reference_data(app.db_engine)

    app.repository = repository or Repository(app.db_engine)
    app.rules_engine = rules_engine or RulesEngine(cfg=cfg)
    app.feed = feed or LiveFeed(capacity=int(
        os.environ.get('NETWATCH_FEED_CAPACITY', '500')))
    app.pipeline = pipeline

    if run_pipeline is None:
        run_pipeline = _env_flag('NETWATCH_RUN_PIPELINE', False)
    if run_pipeline and app.pipeline is None:
        app.pipeline = _start_embedded_pipeline(app)

    register_error_handlers(app)
    app.register_blueprint(ui)
    app.register_blueprint(bp, url_prefix='/api')

    @app.route('/api')
    def _index():
        """A machine-readable index, so the API describes itself."""
        return jsonify({
            'service': 'netwatch',
            'endpoints': sorted(
                {'%s %s' % ('|'.join(sorted(r.methods - {'HEAD', 'OPTIONS'})),
                            str(r))
                 for r in app.url_map.iter_rules()
                 if str(r).startswith('/api')}),
        })

    return app


def _start_embedded_pipeline(app):
    """Run the pipeline inside this process (the all-in-one topology)."""
    from netwatch.capture.source import SyntheticSource

    protocol_ids, threat_ids = schema_mod.lookup_maps(app.db_engine)
    rate = os.environ.get('NETWATCH_RATE_PPS')
    source = SyntheticSource(rate_pps=float(rate) if rate else 200.0)
    pipeline = Pipeline(
        source, app.rules_engine,
        lambda: BatchWriter(app.db_engine, protocol_ids, threat_ids),
        config=PipelineConfig(
            persist_workers=int(os.environ.get('NETWATCH_PERSIST_WORKERS', '2')),
            batch_size=int(os.environ.get('NETWATCH_BATCH_SIZE', '1000'))),
        feed=app.feed)
    pipeline.start()
    log.info('embedded pipeline started at %s pps', rate or 200)
    return pipeline
