import signal
import sys
import os
import re

from backend.core.engine import PentestEngine
from backend.core.logger import logger

try:
    import readchar
    _HAS_READCHAR = True
except ImportError:
    _HAS_READCHAR = False

_ESCAPE_SEQ_RE = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]')


def safe_input(prompt=""):
    try:
        value = input(prompt)
    except EOFError:
        return ""
    if not value:
        return value
    cleaned = _ESCAPE_SEQ_RE.sub("", value)
    return cleaned.replace("\x1b", "")


def get_choice(prompt=""):
    if not _HAS_READCHAR:
        return safe_input(prompt).strip()

    print(prompt, end="", flush=True)
    buf = []
    while True:
        key = readchar.readkey()
        if key in ("\r", "\n"):
            print()
            return "".join(buf).strip()
        if key in (readchar.key.BACKSPACE, "\x7f", "\b"):
            if buf:
                buf.pop()
                print("\b \b", end="", flush=True)
            continue
        if key.startswith("\x1b"):
            continue
        buf.append(key)
        print(key, end="", flush=True)


def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗ ██████╗███████╗  ║
║  ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║██╔════╝██╔════╝  ║
║  ██████╔╝██║     ███████║██║     █████╔╝ ██║██║     █████╗    ║
║  ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║██║     ██╔══╝    ║
║  ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██║╚██████╗███████╗  ║
║  ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝ ╚═════╝╚══════╝  ║
╚═══════════════════════════════════════════════════════════════╝
          BLACKICE - Intrusion Countermeasures
                         Version 0.4 
""")


def signal_handler(sig, frame):
    print("\nShutting down...")
    logger.finalize()
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)

    print_banner()
    logger.initialize()

    engine = PentestEngine()

    categories = {
        "1": {"name": "Reconnaissance", "modules": [
            "port_scan", "website_scan", "gateway_scan",
            "dns_enum", "subdomain_scan"
        ]},
        "2": {"name": "Vulnerability Assessment", "modules": [
            "ssl_scan", "web_vuln_scan"
        ]},
        "3": {"name": "Wireless", "modules": [
            "dns_cache_poisoning", "ddos_attacks", "arp_spoofing"
        ]},
        "4": {"name": "Network", "modules": [
            "network_segment", "firewall_ruleset", "network_topo"
            ]},
        "6": {"name": "Reporting", "modules": [
            "compliance_check", "linux_baseline_scanner", "cve_search"
        ]}
    }

    while True:
        print("\nAvailable Categories:")
        available_categories = {}

        for key, category in categories.items():
            mods = [
                m for m in category["modules"]
                if m in engine.available_modules
            ]
            if mods:
                print(f"{key}. {category['name']} ({len(mods)} modules)")
                available_categories[key] = mods

        print("0. Exit")
        choice = get_choice("Select category: ")

        if choice == "0":
            logger.finalize()
            return

        if choice not in available_categories:
            print("Invalid category")
            continue

        modules = available_categories[choice]

        while True:
            print("\nModules:")
            for i, mod in enumerate(modules, 1):
                print(f"{i}. {mod}")

            print("0. Back")
            mod_choice = get_choice("Select module: ")

            if mod_choice == "0":
                break

            if not mod_choice.isdigit():
                continue

            idx = int(mod_choice) - 1
            if idx < 0 or idx >= len(modules):
                continue

            engine.run_module(modules[idx])


if __name__ == "__main__":
    main()

