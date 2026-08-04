"""Shared engagement-loot target discovery for read-only recon payloads.

Scans the current engagement's loot for IPs, hostnames, or URLs already
seen in earlier artifacts, so a payload can offer them as labeled,
provenance-tracked candidates instead of forcing the operator to retype
a target a previous scan already found. Every extraction is a
best-effort text heuristic: false negatives are harmless (the operator
can always type a target manually), so callers must never treat an
empty result as an error.
"""
from __future__ import annotations

import os
import re

from payloads._web_input import request_input

LOOT_FILE_SUFFIXES = (".json", ".txt", ".log", ".csv")

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_URL_RE = re.compile(r"https?://[^\s<>\"']+")
_HOSTNAME_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
# Final labels that mean the match is almost certainly a filename
# mentioned in a log ("scan_results.json"), not a real hostname.
_NOT_A_TLD = {
    "json", "txt", "log", "csv", "md", "py", "js", "html", "htm", "css",
    "yml", "yaml", "conf", "cfg", "ini", "db", "pcap", "cap", "pdf", "png",
    "jpg", "jpeg", "gif", "webp", "zip", "tar", "gz", "xml", "sh", "service",
    "socket", "key", "pem", "crt", "der", "bak", "old", "tmp",
}


def is_plausible_ip(ip_str: str) -> bool:
    """True for a syntactically valid, non-junk IPv4 address.

    Most City Pop recon targets are on the authorized LAN (unlike an
    internet-intelligence lookup), so private/RFC1918 addresses are kept
    - only 0.0.0.0, loopback, multicast, and broadcast are excluded.
    """
    try:
        octets = [int(part) for part in ip_str.split(".")]
    except ValueError:
        return False
    if len(octets) != 4 or any(o > 255 for o in octets):
        return False
    if octets[0] == 0 or octets[0] == 127 or octets[0] >= 224:
        return False
    return True


def _iter_loot_text(loot_root, own_output_dir=None):
    """Yield (relative_path, content) for every readable text-ish loot file."""
    if not loot_root or not os.path.isdir(loot_root):
        return
    own_output = os.path.realpath(own_output_dir) if own_output_dir else None
    for dirpath, dirs, files in os.walk(loot_root):
        if own_output and os.path.realpath(dirpath) == own_output:
            dirs[:] = []
            continue
        for fname in files:
            if not fname.endswith(LOOT_FILE_SUFFIXES):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r", errors="ignore") as fh:
                    content = fh.read(512 * 1024)
            except OSError:
                continue
            yield os.path.relpath(fpath, loot_root), content


def find_ips_in_loot(loot_root, own_output_dir=None):
    """Return {ip: sorted [relative file paths]} for plausible IPs in loot."""
    found: dict[str, set[str]] = {}
    for relative, content in _iter_loot_text(loot_root, own_output_dir):
        for ip in _IP_RE.findall(content):
            if is_plausible_ip(ip):
                found.setdefault(ip, set()).add(relative)
    return {ip: sorted(paths) for ip, paths in found.items()}


def find_hostnames_in_loot(loot_root, own_output_dir=None):
    """Return {hostname: sorted [relative file paths]} for hostnames in loot.

    Best-effort: filters out matches whose final label is a common file
    extension so a filename mentioned in a log isn't offered as a domain.
    """
    found: dict[str, set[str]] = {}
    for relative, content in _iter_loot_text(loot_root, own_output_dir):
        for match in _HOSTNAME_RE.findall(content):
            tld = match.rsplit(".", 1)[-1].lower()
            if tld in _NOT_A_TLD:
                continue
            found.setdefault(match, set()).add(relative)
    return {host: sorted(paths) for host, paths in found.items()}


def find_urls_in_loot(loot_root, own_output_dir=None):
    """Return {url: sorted [relative file paths]} for URLs already in loot."""
    found: dict[str, set[str]] = {}
    for relative, content in _iter_loot_text(loot_root, own_output_dir):
        for url in _URL_RE.findall(content):
            normalized = url.rstrip(".,;)'\"")
            found.setdefault(normalized, set()).add(relative)
    return {url: sorted(paths) for url, paths in found.items()}


def merge_candidates(*sources):
    """Merge one or more (mapping, source_label) pairs into one candidate list.

    Each ``mapping`` is a {value: [relative_path, ...]} dict as returned by
    the ``find_*_in_loot`` helpers above; ``source_label`` describes what
    kind of match it is (e.g. "IP seen in loot", "hostname seen in loot").
    Returns a list of {"value": ..., "sources": [...]} dicts, sorted by
    value, with per-value sources merged and de-duplicated.
    """
    candidates: list[dict] = []

    def _add(value, source):
        for entry in candidates:
            if entry["value"] == value:
                if source not in entry["sources"]:
                    entry["sources"].append(source)
                return
        candidates.append({"value": value, "sources": [source]})

    for mapping, label in sources:
        for value, files in mapping.items():
            for path in files:
                _add(value, f"{label}: {path}")

    candidates.sort(key=lambda entry: entry["value"])
    return candidates


def prompt_target_selection(candidates, prompt_label="Select a target",
                             manual_label="Enter a target"):
    """Ask once with a real select prompt, or take manual entry.

    ``candidates`` is a list of {"value": ..., "sources": [...]} dicts, as
    returned by :func:`merge_candidates`. When there are no candidates,
    skips straight to a manual-entry prompt instead of showing a select
    with nothing real to pick from. Returns the chosen string, or None if
    cancelled / left blank.
    """
    if not candidates:
        try:
            manual = request_input(manual_label, required=False).strip()
        except EOFError:
            manual = ""
        return manual or None

    choices = [
        {"value": entry["value"], "label": f"{entry['value']} — {'; '.join(entry['sources'])}"}
        for entry in candidates
    ]
    choices.append({"value": "__manual__", "label": manual_label})
    choices.append({"value": "__cancel__", "label": "Cancel"})

    try:
        answer = request_input(
            prompt_label, input_type="select", choices=choices,
            default="__cancel__", required=True,
        )
    except EOFError:
        return None

    if answer in (None, "", "__cancel__"):
        return None
    if answer == "__manual__":
        try:
            manual = request_input(manual_label, required=False).strip()
        except EOFError:
            manual = ""
        return manual or None

    return answer
