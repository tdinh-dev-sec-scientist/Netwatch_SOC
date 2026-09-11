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


def test_templates_are_in_the_image():
    assert 'templates' in runtime_copied_paths()
