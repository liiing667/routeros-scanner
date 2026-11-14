# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Offline analysis mode: reuses the existing command checks against a
# RouterOS "/export" text file (and optionally the output of
# "/ip dns cache print detail") instead of a live SSH connection.

import os
import re

from commands.version import Version
from commands.scheduler import Scheduler
from commands.files import Files
from commands.fwnat import FWNat
from commands.proxy import Proxy
from commands.socks import Socks
from commands.dns import DNS
from commands.users import Users
from commands.ports import Ports
from commands.fwrules import FW

TOKEN_RE = re.compile(r'([^\s=]+)(?:=("(?:\\.|[^"\\])*"|[^\s]+))?')
VERSION_RE = re.compile(r'by RouterOS ([\d.]+)')
DNS_CACHE_LINE_RE = re.compile(r'^\s*\d+\s')

DEFAULT_SERVICE_PORTS = {'telnet': 23, 'ftp': 21, 'www': 80, 'ssh': 22, 'www-ssl': 443, 'api': 8728,
                         'winbox': 8291, 'api-ssl': 8729}

# Commands that cannot be reproduced from an /export text file.
SSH_ONLY_COMMANDS = [Files, Proxy, Socks, FW]


def _tokenize(text):
    entry = {}
    for match in TOKEN_RE.finditer(text):
        key, value = match.group(1), match.group(2)
        if value is None:
            entry.setdefault('_bare', []).append(key)
        else:
            if value.startswith('"'):
                value = value[1:-1].replace('\\"', '"').replace('\\\\', '\\')
            entry[key] = value
    return entry


def _join_continuations(text):
    lines = []
    buf = ''
    for line in text.splitlines():
        if buf:
            line = buf + line.lstrip()
            buf = ''
        stripped = line.rstrip()
        if stripped.endswith('\\'):
            buf = stripped[:-1] + ' '
        else:
            lines.append(line)
    if buf:
        lines.append(buf)
    return lines


def parse_export(text):
    """Parse a RouterOS /export file into (version, {section_path: [entry, ...]})."""
    version = ''
    sections = {}
    current = None

    for line in _join_continuations(text):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith('#'):
            match = VERSION_RE.search(stripped)
            if match:
                version = match.group(1)
            continue
        if stripped.startswith('/'):
            current = stripped
            sections.setdefault(current, [])
            continue
        if current is None:
            continue
        if stripped.startswith('add ') or stripped.startswith('set '):
            sections[current].append(_tokenize(stripped[4:]))

    return version, sections


def parse_dns_cache(text):
    """Parse the output of "/ip dns cache print detail" into a list of dicts."""
    entries = []
    for line in text.splitlines():
        if not DNS_CACHE_LINE_RE.match(line):
            continue
        entry = _tokenize(line)
        entry.pop('_bare', None)
        if entry:
            entries.append(entry)
    return entries


def _skipped(reason):
    return {'raw_data': [],
            'suspicious': [],
            'recommendation': [],
            'skipped': reason}


def _section_result(command, sections, path, transform=None):
    entries = sections.get(path)
    if entries is None:
        return _skipped(f'section "{path}" not found in the export file')
    if transform:
        entries = transform(entries)
    sus, recommendation = command.check_results_ssh(entries)
    return {'raw_data': entries,
            'suspicious': sus,
            'recommendation': recommendation}


def _users_transform(entries):
    for entry in entries:
        entry.setdefault('address', '')
        entry.pop('_bare', None)
    return entries


def _services_transform(entries):
    services = []
    for entry in entries:
        bare = entry.pop('_bare', [])
        if not bare:
            continue
        entry['name'] = bare[0]
        if entry['name'] in DEFAULT_SERVICE_PORTS:
            entry.setdefault('port', str(DEFAULT_SERVICE_PORTS[entry['name']]))
        services.append(entry)
    return services


def _plain_transform(entries):
    for entry in entries:
        entry.pop('_bare', None)
    return entries


def run_offline(export_path, dns_cache_path=None):
    with open(export_path, 'r', encoding='utf-8', errors='replace') as f:
        export_text = f.read()

    version, sections = parse_export(export_text)
    results = {}

    if version:
        sus, recommendation = Version().check_results_ssh(version)
        results[Version().__name__] = {'raw_data': version,
                                       'suspicious': sus,
                                       'recommendation': recommendation}
    else:
        results[Version().__name__] = _skipped('RouterOS version not found in the export file header')

    results[Scheduler().__name__] = _section_result(Scheduler(), sections, '/system scheduler', _plain_transform)

    for command_cls in SSH_ONLY_COMMANDS:
        results[command_cls().__name__] = _skipped('not available in offline mode (requires live SSH access)')

    results[FWNat().__name__] = _section_result(FWNat(), sections, '/ip firewall nat', _plain_transform)

    results[DNS().__name__] = _dns_result(sections, dns_cache_path)

    results[Users().__name__] = _section_result(Users(), sections, '/user', _users_transform)

    results[Ports().__name__] = _section_result(Ports(), sections, '/ip service', _services_transform)

    # Keep the output order consistent with the live (SSH) scan.
    order = ['Version', 'Scheduler', 'Files', 'FW Nat', 'Proxy', 'Socks', 'DNS Cache', 'Users', 'Ports', 'FW Rules']
    return {name: results[name] for name in order}


def _dns_result(sections, dns_cache_path):
    dns_entries = sections.get('/ip dns', [])
    enabled = any(entry.get('allow-remote-requests', '').lower() == 'yes' for entry in dns_entries)

    if not dns_cache_path:
        return _skipped('DNS cache output file not provided (run "/ip dns cache print detail" and pass it via --dns-cache)')
    if not os.path.isfile(dns_cache_path):
        return _skipped(f'DNS cache output file not found: {dns_cache_path}')

    with open(dns_cache_path, 'r', encoding='utf-8', errors='replace') as f:
        entries = parse_dns_cache(f.read())

    sus, recommendation = DNS().check_results_ssh(entries, enabled)
    return {'raw_data': entries,
            'suspicious': sus,
            'recommendation': recommendation}
