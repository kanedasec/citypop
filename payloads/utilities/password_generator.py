#!/usr/bin/env python3
# @name: Password Generator
# @desc: Generate a cryptographically secure password from command arguments; optionally append it to loot/Passwords/passwords.txt.
# @category: utilities
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"length","label":"Generated password length (8-64 characters)","type":"number","default":"16"},{"name":"charsets","label":"Character-set codes: l lowercase, u uppercase, d digits, s symbols","type":"text","default":"lud","placeholder":"Example: luds uses all character sets"},{"name":"save","label":"Password storage behavior","type":"select","choices":[{"value":"no","label":"Display only — print the password without writing it to disk"},{"value":"save","label":"Save to loot — append the password to the engagement password file"}],"default":"no"}]
"""
RaspyJack Payload -- Password Generator
=========================================
Author: 7h30th3r0n3

Generate cryptographically secure passwords with configurable length
and character sets.  Passwords can be saved to the loot directory.

Controls
--------
  python3 password_generator.py [length] [charsets] [save]

    length    -- password length, 8-64 (default: 16)
    charsets  -- any combination of the letters below (default: lud)
                   l = lowercase   u = uppercase
                   d = digits      s = symbols
    save      -- pass the literal word "save" to append the generated
                 password to the loot file
"""

import os
import sys
import secrets
import string

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

SAVE_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'Passwords')
SAVE_FILE = os.path.join(SAVE_DIR, "passwords.txt")

CHARSETS = {
    "l": ("lower", string.ascii_lowercase),
    "u": ("UPPER", string.ascii_uppercase),
    "d": ("0-9", string.digits),
    "s": ("!@#$", string.punctuation),
}


# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------

def _build_alphabet(charset_flags):
    """Build the character pool from the selected charset letters."""
    pool = ""
    for ch in charset_flags:
        entry = CHARSETS.get(ch)
        if entry:
            pool += entry[1]
    return pool


def _generate_password(length, alphabet):
    """Generate a cryptographically secure password."""
    if not alphabet:
        return "(no charset)"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _save_password(password):
    """Append password to the loot file. Return status message."""
    try:
        os.makedirs(SAVE_DIR, exist_ok=True)
        with open(SAVE_FILE, "a", encoding="utf-8") as fh:
            fh.write(password + "\n")
        return f"Saved to {SAVE_FILE}"
    except PermissionError:
        return "Permission denied"
    except OSError as exc:
        return str(exc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]

    if args and args[0] in ("-h", "--help"):
        print("Usage: password_generator.py [length] [charsets] [save]", flush=True)
        print("  length    password length, 8-64 (default: 16)", flush=True)
        print("  charsets  combination of l(ower) u(pper) d(igits) s(ymbols), default: lud", flush=True)
        print("  save      pass 'save' to append the password to the loot file", flush=True)
        return 0

    length = 16
    if args:
        try:
            length = int(args[0])
        except ValueError:
            print(f"Invalid length '{args[0]}', using default 16", flush=True)
            length = 16
        length = max(8, min(64, length))

    charset_flags = args[1] if len(args) > 1 else "lud"
    unknown = [ch for ch in charset_flags if ch not in CHARSETS]
    if unknown:
        print(f"Ignoring unknown charset flag(s): {''.join(unknown)}", flush=True)

    do_save = len(args) > 2 and args[2].lower() == "save"

    alphabet = _build_alphabet(charset_flags)
    if not alphabet:
        print("No valid character sets selected (use l/u/d/s), aborting.", flush=True)
        return 1

    active = ", ".join(CHARSETS[ch][0] for ch in charset_flags if ch in CHARSETS)
    print(f"Length: {length}  Charsets: {active}  Pool: {len(alphabet)} chars", flush=True)

    password = _generate_password(length, alphabet)
    print(f"Password: {password}", flush=True)

    if do_save:
        print(_save_password(password), flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
