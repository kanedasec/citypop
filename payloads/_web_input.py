"""Structured web input with a terminal fallback."""
import json
import os
import sys
import uuid

PREFIX = "CITYPOP_INPUT_REQUEST:"

def request_input(label, *, input_type="text", choices=None, default=None,
                  required=True, secret=False):
    if os.environ.get("CITYPOP_INTERACTIVE") != "1":
        suffix = f" [{default}]" if default is not None else ""
        value = input(f"{label}{suffix}: ").strip()
        return value if value or default is None else default
    request_id = uuid.uuid4().hex
    print(PREFIX + json.dumps({"request_id": request_id, "label": str(label),
        "input_type": input_type, "choices": choices or [], "default": default,
        "required": bool(required), "secret": bool(secret)}, separators=(",", ":")), flush=True)
    for line in sys.stdin:
        try:
            response = json.loads(line)
        except json.JSONDecodeError:
            continue
        if response.get("request_id") == request_id:
            value = response.get("value")
            return default if (value in (None, "") and default is not None) else value
    raise EOFError("input channel closed")
