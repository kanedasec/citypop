"""Static capability discovery used by payload guides and preflight checks."""
from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path


CALL_NAMES = {"run", "_run", "Popen", "call", "check_call", "check_output"}
COMMAND_SKIP = {"bash", "sh", "sudo", "env", "python", "python3"}
COMMAND_FALSE_POSITIVES = {"dev", "link"}
LOCAL_MODULES = {"payloads", "payload_runner", "payload_analysis"}


def _exception_names(handler: ast.ExceptHandler) -> set[str]:
    node = handler.type
    if node is None:
        return {"BaseException"}
    nodes = node.elts if isinstance(node, ast.Tuple) else [node]
    return {
        item.id if isinstance(item, ast.Name) else getattr(item, "attr", "")
        for item in nodes
    }


class _PythonCapabilities(ast.NodeVisitor):
    def __init__(self):
        self.required_modules: set[str] = set()
        self.optional_modules: set[str] = set()
        self.commands: set[str] = set()
        self.services: set[str] = set()
        self.runtime_inputs = 0
        self._optional_import = 0

    def _module(self, name: str | None):
        root = (name or "").split(".", 1)[0]
        if not root or root in LOCAL_MODULES or root in sys.stdlib_module_names:
            return
        target = self.optional_modules if self._optional_import else self.required_modules
        target.add(root)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._module(alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        self._module(node.module)

    def visit_Try(self, node: ast.Try):
        optional = any(
            {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}
            & _exception_names(handler)
            for handler in node.handlers
        )
        if optional:
            self._optional_import += 1
        for child in node.body:
            self.visit(child)
        if optional:
            self._optional_import -= 1
        for child in node.handlers + node.orelse + node.finalbody:
            self.visit(child)

    def visit_Call(self, node: ast.Call):
        name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
        if name == "request_input":
            self.runtime_inputs += 1
        if name == "which" and node.args and isinstance(node.args[0], ast.Constant):
            self.commands.add(os.path.basename(str(node.args[0].value)))
        if name in CALL_NAMES and node.args:
            argument = node.args[0]
            if isinstance(argument, (ast.List, ast.Tuple)) and argument.elts:
                tokens = [
                    str(item.value) for item in argument.elts
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                ]
                if tokens:
                    command_index = 1 if tokens[0] in {"sudo", "env"} and len(tokens) > 1 else 0
                    command = os.path.basename(tokens[command_index])
                    self.commands.add(command)
                    if command == "systemctl" and len(tokens) > command_index + 2:
                        action = tokens[command_index + 1]
                        if action in {"start", "stop", "restart", "reload", "enable", "disable", "is-active"}:
                            self.services.add(tokens[command_index + 2].removesuffix(".service"))
            elif isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                token = argument.value.strip().split(maxsplit=1)[0] if argument.value.strip() else ""
                if token and not any(char in token for char in "$|;&<>()"):
                    self.commands.add(os.path.basename(token))
        self.generic_visit(node)


def _hardware_classes(category: str, source: str) -> list[str]:
    lower = source.lower()
    hardware = set()
    category_map = {
        "wifi": "wifi", "bluetooth": "bluetooth", "sdr": "sdr",
        "nfc_rfid": "nfc", "usb": "usb",
    }
    if category in category_map:
        hardware.add(category_map[category])
    patterns = {
        "gps": ("gpsd", "gpspipe", "latitude", "longitude"),
        "i2c": ("smbus", "/dev/i2c", "i2c-"),
        "gpio": ("rpi.gpio", "gpiozero", "gpiod", "/dev/gpiochip"),
        "camera": ("videocapture", "/dev/video", "picamera"),
        "serial": ("pyserial", "serial.serial", "/dev/tty"),
        "audio": ("pyaudio", "sounddevice", "arecord"),
        "modem": ("modemmanager", "mmcli", "lte"),
    }
    for name, needles in patterns.items():
        if any(needle in lower for needle in needles):
            hardware.add(name)
    return sorted(hardware)


def analyze_payload(path: Path, meta: dict) -> dict:
    source = path.read_text(encoding="utf-8", errors="replace")
    visitor = _PythonCapabilities()
    if path.suffix == ".py":
        try:
            visitor.visit(ast.parse(source))
        except SyntaxError:
            pass
    else:
        for match in re.finditer(r"(?m)^\s*(?:sudo\s+)?([a-zA-Z0-9_.+-]+)\b", source):
            visitor.commands.add(match.group(1))
    commands = sorted(
        command for command in visitor.commands
        if len(command) > 1 and not command.startswith("-")
        and command not in COMMAND_SKIP | COMMAND_FALSE_POSITIVES
    )
    dashboard = any(token in source for token in ("DashboardServer", "dashboard.start(", "Dashboard:"))
    produces_loot = "CITYPOP_LOOT" in source
    ignored_devices = {"/dev/null", "/dev/zero", "/dev/urandom", "/dev/tcp", "/dev/input", "/dev/input/event", "/dev/mmcblk", "/dev/sd"}
    raw_devices = {item.rstrip("./") for item in re.findall(r"/dev/[a-zA-Z0-9_./*?-]+", source)}
    device_paths = sorted(
        item for item in raw_devices
        if item not in ignored_devices and not item.startswith("/dev/tcp/")
    )
    data_paths = sorted({
        item.rstrip("/") for item in re.findall(r"/usr/share/[a-zA-Z0-9_./*?-]+", source)
    })
    kernel_capabilities = set()
    if set(commands) & {"ip", "iw", "iptables", "tc", "airmon-ng", "hciconfig", "rfkill"}:
        kernel_capabilities.add("NET_ADMIN")
    if any(token in source for token in ("AF_PACKET", "scapy", "tcpdump", "tshark", "RadioTap")):
        kernel_capabilities.add("NET_RAW")
    return {
        "static_inputs": len(meta.get("inputs", [])),
        "runtime_inputs": visitor.runtime_inputs,
        "commands": commands,
        "python_modules": sorted(visitor.required_modules - visitor.optional_modules),
        "optional_python_modules": sorted(visitor.optional_modules),
        "services": sorted(visitor.services),
        "device_paths": device_paths,
        "data_paths": data_paths,
        "kernel_capabilities": sorted(kernel_capabilities),
        "hardware": _hardware_classes(str(meta.get("category", "")), source),
        "dashboard": dashboard,
        "produces_loot": produces_loot,
    }
