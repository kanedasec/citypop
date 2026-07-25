"""Run-scoped UFW rules for payload listeners and network clients."""
from __future__ import annotations

import ipaddress
import re
import subprocess
import uuid


class UfwRuleError(RuntimeError):
    pass


def _run(*args, timeout=15):
    return subprocess.run(
        ["sudo", "-n", "ufw", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def connected_context(address: str) -> tuple[str, str]:
    """Return (interface, network) for a local IPv4 address."""
    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "scope", "global"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise UfwRuleError(f"could not inspect local IPv4 networks: {exc}") from exc
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        try:
            interface = ipaddress.ip_interface(fields[3])
        except ValueError:
            continue
        if str(interface.ip) == address:
            return fields[1].rstrip(":"), str(interface.network)
    raise UfwRuleError(f"could not determine the connected network for {address}")


def default_route_interface(exclude: str | None = None) -> str:
    result = subprocess.run(
        ["ip", "-o", "-4", "route", "show", "default"],
        capture_output=True, text=True, timeout=5,
    )
    for line in result.stdout.splitlines():
        fields = line.split()
        if "dev" in fields:
            interface = fields[fields.index("dev") + 1]
            if interface != exclude:
                return interface
    raise UfwRuleError("could not determine an upstream default-route interface")


def interface_ipv4(interface: str) -> str:
    result = subprocess.run(
        ["ip", "-o", "-4", "addr", "show", "dev", interface, "scope", "global"],
        capture_output=True, text=True, timeout=5,
    )
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            return str(ipaddress.ip_interface(fields[3]).ip)
    raise UfwRuleError(f"{interface} has no usable IPv4 address")


class TemporaryUfwRules:
    """Insert uniquely tagged UFW rules and remove only those rules."""

    def __init__(self, purpose: str):
        safe = re.sub(r"[^a-z0-9-]+", "-", purpose.lower()).strip("-")[:24]
        self.marker = f"city-pop-{safe}-{uuid.uuid4().hex[:10]}"
        self._closed = False

    def add(self, *rule):
        result = _run("insert", "1", *rule, "comment", self.marker)
        if result.returncode:
            detail = (result.stderr or result.stdout).strip() or "unknown UFW error"
            raise UfwRuleError(f"could not add temporary UFW rule: {detail}")

    def add_route(self, *rule):
        result = _run("route", "insert", "1", *rule, "comment", self.marker)
        if result.returncode:
            detail = (result.stderr or result.stdout).strip() or "unknown UFW error"
            raise UfwRuleError(f"could not add temporary UFW route rule: {detail}")

    def allow_lan_service(self, address: str, port: int, protocol: str = "tcp"):
        interface, network = connected_context(address)
        self.add(
            "allow", "in", "on", interface, "proto", protocol,
            "from", network, "to", "any", "port", str(port),
        )
        self.add(
            "allow", "out", "on", interface, "proto", protocol,
            "from", "any", "port", str(port), "to", network,
        )
        return interface, network

    def allow_ap_service(
        self, interface: str, network: str, port: int, protocol: str = "tcp",
    ):
        network = str(ipaddress.ip_network(network, strict=False))
        self.add(
            "allow", "in", "on", interface, "proto", protocol,
            "from", network, "to", "any", "port", str(port),
        )
        self.add(
            "allow", "out", "on", interface, "proto", protocol,
            "from", "any", "port", str(port), "to", network,
        )

    def allow_ap_dhcp(self, interface: str, network: str):
        network = str(ipaddress.ip_network(network, strict=False))
        self.add(
            "allow", "in", "on", interface, "proto", "udp",
            "from", "any", "port", "68", "to", "any", "port", "67",
        )
        self.add(
            "allow", "out", "on", interface, "proto", "udp",
            "from", "any", "port", "67", "to", network, "port", "68",
        )

    def allow_outbound(
        self, interface: str, protocol: str, destination: str, port: int,
    ):
        self.add(
            "allow", "out", "on", interface, "proto", protocol,
            "to", destination, "port", str(port),
        )

    def allow_forwarding(self, incoming: str, outgoing: str, source_network: str):
        network = str(ipaddress.ip_network(source_network, strict=False))
        self.add_route(
            "allow", "in", "on", incoming, "out", "on", outgoing,
            "from", network,
        )

    def close(self):
        if self._closed:
            return
        self._closed = True
        for _ in range(8):
            status = _run("status", "numbered")
            if status.returncode:
                detail = (status.stderr or status.stdout).strip() or "unknown UFW error"
                print(f"Warning: could not inspect UFW during cleanup: {detail}", flush=True)
                return
            numbers = [
                int(match.group(1))
                for line in status.stdout.splitlines()
                if self.marker in line
                and (match := re.match(r"^\[\s*(\d+)\]", line.strip()))
            ]
            if not numbers:
                return
            for number in sorted(numbers, reverse=True):
                result = _run("--force", "delete", str(number))
                if result.returncode:
                    detail = (result.stderr or result.stdout).strip() or "unknown UFW error"
                    print(
                        f"Warning: could not remove temporary UFW rule {number}: {detail}",
                        flush=True,
                    )

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()


def cleanup_city_pop_rules():
    """Remove orphaned run-scoped rules after a payload process has exited."""
    for _ in range(16):
        status = _run("status", "numbered")
        if status.returncode:
            return
        numbers = [
            int(match.group(1))
            for line in status.stdout.splitlines()
            if "# city-pop-" in line
            and (match := re.match(r"^\[\s*(\d+)\]", line.strip()))
        ]
        if not numbers:
            return
        for number in sorted(numbers, reverse=True):
            _run("--force", "delete", str(number))
