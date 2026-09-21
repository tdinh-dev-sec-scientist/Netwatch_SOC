"""The container image must contain everything the deployment runs.

The runtime stage of the Dockerfile copies source files by name rather than
`COPY . .`, so that nothing unlisted (a local database, a .env) can leak into
the image. The cost of an explicit list is that it can fall behind the code:
`engine.py` was once missing, and `docker compose --profile split up` failed
with "No such file" while every unit test still passed.

These tests close that gap without needing Docker: they parse the Dockerfile
and docker-compose.yml and check them against the source tree.
"""

import ast
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCKERFILE = os.path.join(ROOT, 'Dockerfile')
COMPOSE = os.path.join(ROOT, 'docker-compose.yml')

# .dockerignore excludes the Dockerfile and compose file from the build
# context, so inside the `test` image stage these files do not exist.
pytestmark = pytest.mark.skipif(
    not (os.path.exists(DOCKERFILE) and os.path.exists(COMPOSE)),
    reason='deployment files not present (running inside the image)')


def runtime_copied_paths():
    """Source paths named by COPY instructions in the `runtime` stage."""
    text = open(DOCKERFILE, encoding='utf-8').read()
    # Join backslash continuations so each instruction is one line.
    text = re.sub(r'\\\n', ' ', text)
    stage = None
    copied = set()
    for line in text.splitlines():
        line = line.strip()
        match = re.match(r'FROM\s+\S+(?:\s+AS\s+(\S+))?', line, re.I)
        if match:
            stage = (match.group(1) or '').lower()
            continue
        if stage != 'runtime' or not line.upper().startswith('COPY '):
            continue
        tokens = [t for t in line.split()[1:] if not t.startswith('--')]
        for token in tokens[:-1]:               # last token is the destination
            copied.add(token.rstrip('/'))
    return copied


def local_imports(path):
    """Top-level modules/packages in this repo imported by a source file."""
    tree = ast.parse(open(path, encoding='utf-8').read())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module.split('.')[0])
    local = set()
    for name in names:
        if os.path.exists(os.path.join(ROOT, name + '.py')):
            local.add(name + '.py')
        elif os.path.isdir(os.path.join(ROOT, name)):
            local.add(name)
    return local


def transitive_local_imports(entrypoints):
    seen, todo = set(), list(entrypoints)
    while todo:
        item = todo.pop()
        if item in seen:
            continue
        seen.add(item)
        path = os.path.join(ROOT, item)
        files = ([os.path.join(path, f) for f in os.listdir(path)
                  if f.endswith('.py')] if os.path.isdir(path) else [path])
        for f in files:
            todo.extend(local_imports(f) - seen)
    return seen


def compose_python_scripts():
    """Every `python <script>.py` a compose service runs."""
    text = open(COMPOSE, encoding='utf-8').read()
    return set(re.findall(r'\[\s*"python"\s*,\s*"([\w./-]+\.py)"', text))


def test_runtime_stage_copies_something():
    assert 'App.py' in runtime_copied_paths()


def test_every_module_the_app_imports_is_in_the_image():
    copied = runtime_copied_paths()
    needed = transitive_local_imports({'App.py', 'engine.py'})
    missing = sorted(needed - copied)
    assert not missing, (
        'the runtime image would be missing %s — add it to the COPY list in '
        'the Dockerfile runtime stage' % ', '.join(missing))


def test_every_script_compose_runs_is_in_the_image():
    copied = runtime_copied_paths()
    scripts = compose_python_scripts()
    assert 'engine.py' in scripts, 'expected the split engine service'
    missing = sorted(scripts - copied)
    assert not missing, (
        'docker-compose.yml runs %s, which the runtime image does not contain'
        % ', '.join(missing))


def test_migrations_are_in_the_image():
    """The schema lives in versioned SQL, not in the application, so without
    these the container cannot create or upgrade its database."""
    assert 'migrations' in runtime_copied_paths()


def test_every_migration_exists_for_both_backends():
    """A schema change has to be written for PostgreSQL and for the SQLite
    fallback, or the fallback silently drifts out of step."""
    root = os.path.join(ROOT, 'migrations')
    versions = {}
    for backend in ('postgresql', 'sqlite'):
        directory = os.path.join(root, backend)
        assert os.path.isdir(directory), 'no migrations for %s' % backend
        versions[backend] = {name.split('_')[0]
                             for name in os.listdir(directory)
                             if name.endswith('.sql')}
        assert versions[backend], 'no migration files for %s' % backend
    assert versions['postgresql'] == versions['sqlite'], (
        'migration versions differ between backends: postgresql has %s, '
        'sqlite has %s' % (sorted(versions['postgresql']),
                           sorted(versions['sqlite'])))


def test_templates_are_in_the_image():
    assert 'templates' in runtime_copied_paths()


def test_static_assets_are_in_the_image():
    if os.path.isdir(os.path.join(ROOT, 'static')):
        assert 'static' in runtime_copied_paths()


GUNICORN_CONF = os.path.join(ROOT, 'gunicorn.conf.py')


def load_gunicorn_conf(monkeypatch, **env):
    import runpy
    for name in ('NETWATCH_BIND', 'PORT'):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return runpy.run_path(GUNICORN_CONF)


def test_gunicorn_binds_the_documented_default(monkeypatch):
    assert load_gunicorn_conf(monkeypatch)['bind'] == '0.0.0.0:5001'


def test_gunicorn_honours_a_platform_port(monkeypatch):
    assert load_gunicorn_conf(monkeypatch, PORT='10000')['bind'] == \
        '0.0.0.0:10000'


def test_explicit_bind_overrides_platform_port(monkeypatch):
    conf = load_gunicorn_conf(monkeypatch, PORT='10000',
                              NETWATCH_BIND='127.0.0.1:9000')
    assert conf['bind'] == '127.0.0.1:9000'


@pytest.mark.parametrize('port', ['http', '0', '70000'])
def test_invalid_platform_port_is_rejected(monkeypatch, port):
    with pytest.raises(SystemExit):
        load_gunicorn_conf(monkeypatch, PORT=port)


def test_render_blueprint_runs_a_hardened_demo():
    path = os.path.join(ROOT, 'render.yaml')
    text = open(path, encoding='utf-8').read()
    assert re.search(r'runtime:\s*docker', text)
    assert re.search(r'plan:\s*free', text)
    assert re.search(r'healthCheckPath:\s*/api/health', text)
    env = dict(re.findall(r'key:\s*(\w+)\s*\n\s*value:\s*"([^"]*)"', text))
    assert env.get('NETWATCH_DEMO') == '1'
    assert float(env.get('NETWATCH_RETENTION_S', 0)) > 0, \
        'a public demo without retention grows until the disk fills'
    assert env.get('NETWATCH_GLOBAL_RATE_LIMIT', '0') != '0'


def compose_services():
    """{service name: its YAML block} for the top-level `services:` map.

    A deliberately small parser: services are the two-space-indented keys
    between `services:` and the next top-level key. Enough for the invariants
    below without adding a YAML dependency to the test suite.
    """
    lines = open(COMPOSE, encoding='utf-8').read().splitlines()
    services, current, inside = {}, None, False
    for line in lines:
        if re.match(r'^services:\s*$', line):
            inside = True
            continue
        if inside and re.match(r'^\S', line) and not line.startswith('#'):
            break
        if not inside:
            continue
        match = re.match(r'^  ([A-Za-z0-9_-]+):\s*$', line)
        if match:
            current = match.group(1)
            services[current] = []
        elif current:
            services[current].append(line)
    return {name: '\n'.join(block) for name, block in services.items()}


# The database is shared infrastructure rather than a topology, so it belongs
# to every profile that needs one. Everything else is topology-specific.
SHARED_SERVICES = {'postgres'}


def test_every_application_service_has_exactly_one_profile():
    """Profiles keep the topologies apart.

    The all-in-one service once had no profile, so `--profile split` started
    it next to the dedicated engine: two engines recording one network twice.
    """
    services = compose_services()
    assert {'netwatch', 'engine', 'web', 'tests'} <= set(services)
    for name, block in services.items():
        profiles = re.findall(r'^    profiles:\s*\[([^\]]*)\]', block, re.M)
        assert len(profiles) == 1, '%s must declare its profiles' % name
        named = [p for p in profiles[0].split(',') if p.strip()]
        if name in SHARED_SERVICES:
            assert len(named) > 1, (
                '%s is shared infrastructure and should be available to more '
                'than one profile' % name)
        else:
            assert len(named) == 1, '%s must declare exactly one profile' % name


def test_a_database_service_is_defined_and_pinned():
    """An unpinned postgres tag would let a rebuild cross a major version,
    which the server refuses to start against an existing data directory."""
    block = compose_services()['postgres']
    image = re.search(r'^    image:\s*postgres:(\S+)', block, re.M)
    assert image, 'the postgres service must name a pinned image'
    tag = image.group(1)
    assert re.match(r'^\d+\.\d+', tag), \
        'postgres image tag %r is not pinned to a patch release' % tag
    assert re.search(r'^    healthcheck:', block, re.M), \
        'the database needs a healthcheck for depends_on to wait on'
    assert 'pg_isready' in block
    assert re.search(r'volumes:\s*\n\s*-\s*netwatch-pgdata:', block), \
        'the database needs a persistent volume'


def test_every_service_that_uses_the_database_waits_for_it():
    """The application applies migrations on startup, so it must not race
    initdb. Anything less than service_healthy does."""
    for name, block in compose_services().items():
        if name in SHARED_SERVICES or 'DATABASE_URL' not in block:
            continue
        assert 'depends_on' in block, '%s has no depends_on' % name
        assert ('needs-postgres' in block
                or re.search(r'postgres:\s*\n\s*condition:\s*service_healthy',
                             block)), \
            '%s must wait for postgres to be healthy' % name


def test_no_sqlite_assumptions_remain_in_compose():
    """The sqlite3 healthcheck, the NETWATCH_DB path and the shared data volume
    all belonged to the single-writer file database."""
    text = open(COMPOSE, encoding='utf-8').read()
    for leftover in ('import sqlite3', 'NETWATCH_DB:', 'netwatch-data:'):
        assert leftover not in text, \
            'docker-compose.yml still references %r' % leftover


def test_no_profile_runs_two_engines():
    engines = {}
    for name, block in compose_services().items():
        profile = re.search(r'^    profiles:\s*\["([^"]+)"\]', block, re.M)
        simulate = re.search(r'NETWATCH_SIMULATE:\s*"(\d)"', block)
        runs_engine = 'engine.py' in block or (simulate and simulate.group(1) == '1')
        if profile and runs_engine:
            engines.setdefault(profile.group(1), []).append(name)
    assert engines, 'expected at least one engine service'
    for profile, names in engines.items():
        assert len(names) == 1, 'profile %s runs %s' % (profile, names)


def test_replicated_services_do_not_share_one_host_port():
    for name, block in compose_services().items():
        replicas = re.search(r'replicas:\s*(\d+)', block)
        if not replicas or int(replicas.group(1)) < 2:
            continue
        for mapping in re.findall(r'-\s*"([^"]+:\d+(?:-\d+)?:\d+)"', block):
            host = mapping.rsplit(':', 1)[0].rsplit(':', 1)[-1]
            assert '-' in host, (
                '%s has %s replicas but publishes a single host port (%s); '
                'only one replica could bind it' % (name, replicas.group(1),
                                                    mapping))
            low, high = (int(x) for x in host.split('-'))
            assert high - low + 1 >= int(replicas.group(1)), name


def test_forwarded_allow_ips_are_addresses_not_ranges():
    """gunicorn 23 refuses to start when given a CIDR range here."""
    text = open(COMPOSE, encoding='utf-8').read()
    for value in re.findall(r'GUNICORN_FORWARDED_ALLOW_IPS:\s*"([^"]*)"', text):
        assert '/' not in value, value
