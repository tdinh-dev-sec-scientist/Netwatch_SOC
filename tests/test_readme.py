"""The README claims every number in it is measured — this checks that.

The counts in the README drifted before (endpoints documented as both 21 and
24, indexes as both 22 and 24) because the other tests assert lower bounds:
"at least fourteen endpoints", "index_count >= 20". A lower bound cannot
catch documentation that has fallen behind the code, so these tests pin every
occurrence of a headline count in the README to the value the code actually
produces. Adding an endpoint or an index is expected to fail them until the
README is updated to match.
"""

import os
import re

import pytest

import detectors
import mitre
from ProtocolAnalyzer import SUPPORTED_PROTOCOLS

README = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Readme.MD')


@pytest.fixture(scope='module')
def readme():
    with open(README, 'r', encoding='utf-8') as fh:
        return fh.read()


def claimed(text, *patterns):
    """Every number the README states for one quantity, with its context."""
    found = []
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            found.append((int(match.group(1)), match.group(0).strip()))
    assert found, 'README no longer states this count: %s' % (patterns,)
    return found


def assert_all_agree(found, actual, label):
    wrong = ['%r says %d' % (context, value)
             for value, context in found if value != actual]
    assert not wrong, '%s is actually %d, but the README %s' % (
        label, actual, '; '.join(wrong))


def test_readme_endpoint_count_matches_the_app(client):
    text = open(README, 'r', encoding='utf-8').read()
    actual = len({str(rule) for rule in client.application.url_map.iter_rules()
                  if str(rule).startswith('/api/')})
    assert_all_agree(
        claimed(text,
                r'(\d+)-endpoint REST API',
                r'(\d+) REST endpoints',
                r'(\d+) REST\b',
                r'## REST API — (\d+) endpoints',
                r'\| REST endpoints \| [^|]*\| \*\*(\d+)\*\*'),
        actual, 'the endpoint count')


def test_readme_index_count_matches_the_schema(populated_db):
    text = open(README, 'r', encoding='utf-8').read()
    actual = populated_db.health()['index_count']
    assert_all_agree(
        claimed(text,
                r'\*\*(\d+) indexes\.\*\*',
                r'\| Indexes \| [^|]*\| \*\*(\d+)\*\*'),
        actual, 'the index count')


def test_readme_table_count_matches_the_schema(populated_db):
    text = open(README, 'r', encoding='utf-8').read()
    actual = populated_db.health()['table_count']
    assert_all_agree(
        claimed(text,
                r'(\d+)-table SQLite',
                r'## Database — (\d+) tables',
                r'\| SQLite tables \| [^|]*\| \*\*(\d+)\*\*'),
        actual, 'the table count')


def test_readme_detector_count_matches_the_registry(readme):
    assert_all_agree(
        claimed(readme,
                r'(\d+) modular threat detectors',
                r'## Detection engine — (\d+) threat types',
                r'\| Threat types \| [^|]*\| \*\*(\d+)\*\*',
                r'(\d+) detectors, one module per threat family'),
        len(detectors.REGISTRY), 'the detector count')


def test_readme_protocol_count_matches_the_analyzer(readme):
    assert_all_agree(
        claimed(readme,
                r'deep packet inspection over (\d+) protocols',
                r'## Deep packet inspection — (\d+) protocols',
                r'Deep packet inspection: (\d+) protocols',
                r'\| Protocols inspected \| [^|]*\| \*\*(\d+)\*\*'),
        len(SUPPORTED_PROTOCOLS), 'the protocol count')


def test_readme_technique_count_matches_the_catalog(readme):
    assert_all_agree(
        claimed(readme,
                r'## MITRE ATT&CK — (\d+) techniques',
                r'\| ATT&CK techniques \| [^|]*\| \*\*(\d+)\*\*'),
        mitre.technique_count(), 'the ATT&CK technique count')
