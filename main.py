import signal
import sys
import os
import re

from core.engine import PentestEngine
from core.logger import logger

try:
    import readchar
    _HAS_READCHAR = True
except ImportError:
    _HAS_READCHAR = False

_ESCAPE_SEQ_RE = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]')


def safe_input(prompt=""):
    """
    as i was testing i got annoyed because whenever i used my arrow keys it would output trash so i made these 2 functions, this is a wrapper around input() that strips escape sequences. Before it used to output like "^[[A"
    """
    try:
        value = input(prompt)
    except EOFError:
        return ""
    if not value:
        return value
    cleaned = _ESCAPE_SEQ_RE.sub("", value)
    cleaned = cleaned.replace("\x1b", "")
    return cleaned


def get_choice(prompt=""):
    """
    this gets the choice from the user using readchar, it ignores arrow keys and escape sequences in general and it falls back to safe_input if it not available, like the above function i made this because i was annoyed  
    """
    if not _HAS_READCHAR:
        return safe_input(prompt).strip()

    print(prompt, end="", flush=True)
    buf = []
    while True:
        try:
            key = readchar.readkey()
        except KeyboardInterrupt:
            raise
        if key in ("\r", "\n"):
            print()  
            return "".join(buf).strip()
        if key in (readchar.key.BACKSPACE, "\x7f", "\b"):
            if buf:
                buf.pop()
                print("\b \b", end="", flush=True)
            continue
        if key == "\x03":
            raise KeyboardInterrupt
        if key and key.startswith("\x1b"):
            continue
        if len(key) == 1:
            buf.append(key)
            print(key, end="", flush=True)
            continue
        continue


def print_banner(color=True):
    """
    Colorized banner for Linux terminals.
    'BLACK' will be italicized and 'ICE' will be red.
    Pass color=False to disable ANSI sequences.
    """
    use_color = color and os.isatty(1)

    CYAN = "\033[1;36m" if use_color else ""
    RED = "\033[1;31m" if use_color else ""
    YELLOW = "\033[1;33m" if use_color else ""
    ITALIC = "\033[3m" if use_color else ""     # ANSI italic
    BOLD = "\033[1m" if use_color else ""
    RESET = "\033[0m" if use_color else ""

    styled_blackice = f"{ITALIC}BLACK{RESET}{RED}ICE{RESET}" if use_color else "BlackICE"

    banner = fr"""
╔═══════════════════════════════════════════════════════════════╗
║  ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗ ██████╗███████╗  ║
║  ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║██╔════╝██╔════╝  ║
║  ██████╔╝██║     ███████║██║     █████╔╝ ██║██║     █████╗    ║
║  ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║██║     ██╔══╝    ║
║  ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██║╚██████╗███████╗  ║
║  ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝ ╚═════╝╚══════╝  ║
╚═══════════════════════════════════════════════════════════════╝

          {styled_blackice} - Intrusion Countermeasures
                 Version 0.2 - Alpha
                 """
    print(banner)


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\nInterrupt received. Shutting down gracefully...")
    try:
        logger.finalize()
    except Exception:
        pass
    sys.exit(0)


def main():
    """
    This is the runner that connects the modules and engine together, it allows a user to pick a categories then run the modules they want.
    Metasploit was a big inspiration for the UI so it looks similar.
    """
    signal.signal(signal.SIGINT, signal_handler)

    print_banner()

    logger.initialize()

    engine = PentestEngine()
    engine.discover_modules()

    categories = {
        "1": {"name": "Reconnaissance", "modules": [
            "port_scan", "website_scan",
            "gateway_scan", "dns_enum", "subdomain_scan"
        ]},
        "2": {"name": "Vulnerability Assessment", "modules": [
            "vuln_scan", "ssl_scan", "web_vuln_scan"
        ]},
        "3": {"name": "Wireless", "modules": [
            "dns_cache_poisoning", "ddos_attacks", "arp_spoofing"
        ]},
        "4": {"name": "Exploitation", "modules": [
        ]},
        "5": {"name": "Post-Exploitation", "modules": [
        ]},
        "6": {"name": "Reporting", "modules": [
            "compliance_check", "linux_baseline_scanner"
        ]}
    }

    while True:
        try:
            print("\nAvailable Categories:")
            print("-" * 30)

            available_categories = {}
            for key, category in categories.items():
                available_count = len([mod for mod in category["modules"] if mod in engine.modules])
                if available_count > 0:
                    print(f"{key}. {category['name']} ({available_count} modules)")
                    available_categories[key] = category

            print("0. Exit BlackICE")

            category_choice = get_choice("\nEnter category number: ").strip()

            if category_choice == "0":
                print("\nExiting BlackICE.")
                logger.finalize()
                break

            if category_choice not in available_categories:
                print("Invalid category choice.")
                continue

            category = available_categories[category_choice]
            available_modules = [mod for mod in category["modules"] if mod in engine.modules]

            if not available_modules:
                print("No modules available in this category.")
                continue

            while True:
                print(f"\n{category['name']} Modules:")
                print("-" * 30)

                for i, mod_name in enumerate(available_modules, 1):
                    module = engine.modules[mod_name]
                    description = getattr(module, 'description', 'No description available')
                    print(f"{i}. {mod_name:<20} - {description}")

                print("0. Back to categories")

                mod_choice = get_choice("\nEnter module number: ").strip()

                if mod_choice == "0":
                    break

                try:
                    if mod_choice.isdigit():
                        mod_index = int(mod_choice) - 1
                        if 0 <= mod_index < len(available_modules):
                            module_name = available_modules[mod_index]

                            print(f"\n{'='*50}")
                            print(f"Running: {module_name}")
                            print(f"{'='*50}")

                            engine.run_module(module_name)

                            while True:
                                next_action = get_choice(
                                    f"\nWhat would you like to do?\n1. Run another module in {category['name']}\n2. Back to categories\n3. Exit\nChoice (1-3): "
                                ).strip()

                                if next_action == "1":
                                    break
                                elif next_action == "2":
                                    break
                                elif next_action == "3":
                                    print("\nExiting BlackICE.")
                                    logger.finalize()
                                    return
                                else:
                                    print("Invalid choice. Please enter 1, 2, or 3.")

                            if next_action == "2":
                                break

                        else:
                            print("Invalid module number.")
                    else:
                        print("Please enter a number.")

                except KeyboardInterrupt:
                    # Allow graceful return to main menu on Ctrl+C
                    print("\nInterrupt received. Returning to main menu...")
                    break
                except Exception as e:
                    print(f"Error running module: {e}")
                    error_choice = get_choice("\n1. Try another module\n2. Back to categories\nChoice (1-2): ").strip()
                    if error_choice == "2":
                        break

        except KeyboardInterrupt:
            print("\nInterrupt received. Returning to main menu...")
            continue
        except Exception as e:
            print(f"Unexpected error: {e}")
            continue


if __name__ == "__main__":
    main()

