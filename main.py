import argparse
from core.engine import PentestEngine
from core.logger import log_info
from core.target import atk

def main():
    print("=" * 50)
    print("      BlackICE – Intrusion Countermeasures Electronics")
    print("                 Version 0.1 – Alpha")
    print("=" * 50)

    parser = argparse.ArgumentParser(
        description="BlackICE: Modular Python-based Pentesting Framework"
    )
    parser.add_argument(
        "--target", "-t", help="Target IP or domain to scan", required=False
    )
    args = parser.parse_args()

    # Ask for target if not provided
    if args.target:
        target = args.target
    else:
        target = input("Enter target IP or domain: ").strip()

    # Save globally
    atk.set_target(target)

    # Initialize engine
    engine = PentestEngine(target)
    engine.discover_modules()

    print("\nModules Found:")
    for i, mod_name in enumerate(engine.modules, start=1):
        print(f"{i}. {mod_name}")

    choice = input("\nEnter module number to run (or 'all' for all modules): ").strip()

    if choice.lower() == "all":
        engine.run_all()
    else:
        try:
            if choice.isdigit():
                mod_index = int(choice) - 1
                module_name = list(engine.modules.keys())[mod_index]
            else:
                module_name = choice
            engine.run_module(module_name)
        except Exception:
            print("Invalid module choice. Exiting.")

    log_info("Scan finished.")


if __name__ == "__main__":
    log_info("BlackICE started")
    main()

