"""Packaging tests: the container image must actually contain the application.

The Dockerfile copies source files by name rather than with `COPY . .`, so that
nothing unlisted — a local database, a .env, a stray credential — can be pulled
into the image. The cost of that choice is that adding a module and forgetting
to list it produces an image that fails at import time. These tests close that
gap without needing a Docker daemon, which CI may not have.
"""

import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Modules that exist only for development and are deliberately not shipped.
NOT_SHIPPED = {'conftest'}

# gunicorn.conf.py is a gunicorn configuration file, not an importable module:
# its name is not a valid dotted path and it is executed by gunicorn itself.
NOT_IMPORTABLE = {'gunicorn.conf'}


def _read(name):
    with open(os.path.join(ROOT, name), 'r', encoding='utf-8') as fh:
        return fh.read()


def _top_level_modules():
    """Every .py file at the repository root."""
    return {f[:-3] for f in os.listdir(ROOT)
            if f.endswith('.py') and not f.startswith('_')}


def _dockerfile_runtime_payload():
    """Filenames and directories the runtime stage copies into the image."""
    text = _read('Dockerfile')
    runtime = text[text.index('FROM ${PYTHON_IMAGE} AS runtime'):]
    copied = set()
    for match in re.finditer(r'COPY --chown=\S+ ((?:[^\n]|\\\n)+?)\s+\./',
                             runtime):
        for token in match.group(1).replace('\\\n', ' ').split():
            copied.add(token.rstrip('/'))
    return copied


def test_every_shipped_module_is_copied_into_the_image():
    copied = _dockerfile_runtime_payload()
    missing = sorted(
        '%s.py' % name for name in _top_level_modules() - NOT_SHIPPED
        if '%s.py' % name not in copied)
    assert not missing, \
        'Dockerfile runtime stage does not copy: %s' % ', '.join(missing)


def test_package_directories_are_copied():
    copied = _dockerfile_runtime_payload()
    for package in ('detectors', 'tools', 'templates'):
        assert package in copied, '%s is missing from the image' % package


def test_dockerfile_copies_nothing_that_does_not_exist():
    for entry in _dockerfile_runtime_payload():
        assert os.path.exists(os.path.join(ROOT, entry)), \
            'Dockerfile copies %s, which does not exist' % entry


def test_requirements_cover_every_third_party_import():
    """A dependency used at runtime must be declared, or the image breaks."""
    requirements = _read('requirements.txt').lower()
    for package, module in (('flask', 'flask'), ('scapy', 'scapy'),
                            ('gunicorn', 'gunicorn'), ('psycopg', 'psycopg')):
        assert package in requirements, '%s is not declared' % module


def test_healthchecks_agree_with_the_schema():
    """A healthcheck asserting the wrong table count fails every container."""
    from DB_Manager import TABLES
    expected = 'table_count\')==%d' % len(TABLES)
    dockerfile = _read('Dockerfile').replace('"', "'")
    assert expected in dockerfile, \
        'Dockerfile healthcheck does not expect %d tables' % len(TABLES)
    compose = _read('docker-compose.yml').replace('"', "'")
    assert expected in compose, \
        'compose healthcheck does not expect %d tables' % len(TABLES)


def test_dockerignore_does_not_exclude_shipped_source():
    ignored = {line.strip() for line in _read('.dockerignore').splitlines()
               if line.strip() and not line.startswith('#')}
    for entry in _dockerfile_runtime_payload():
        assert entry not in ignored, '%s is copied but also ignored' % entry


def test_compose_defines_the_documented_profiles():
    compose = _read('docker-compose.yml')
    for profile in ('sqlite', 'test', 'bench', 'validate'):
        assert "'%s'" % profile in compose or '"%s"' % profile in compose, \
            'compose has no %s profile' % profile


def test_compose_publishes_no_database_port():
    """PostgreSQL must not be reachable off the compose network."""
    compose = _read('docker-compose.yml')
    postgres = compose[compose.index('  postgres:'):compose.index('  engine:')]
    # A commented-out mention is the explanation, not a published port.
    published = [line for line in postgres.splitlines()
                 if line.strip().startswith('ports:')]
    assert not published, 'postgres publishes %s' % published


def test_api_ports_are_bound_to_loopback():
    """The API has no authentication, so it must not bind 0.0.0.0."""
    for line in _read('docker-compose.yml').splitlines():
        stripped = line.strip()
        if stripped.startswith('- "') and ':5001"' in stripped:
            assert '127.0.0.1:' in stripped, \
                'port binding reachable off-host: %s' % stripped


@pytest.mark.parametrize(
    'module', sorted(_top_level_modules() - NOT_SHIPPED - NOT_IMPORTABLE))
def test_every_shipped_module_imports(module):
    """Catches an import error that would only surface at container start."""
    __import__(module)
