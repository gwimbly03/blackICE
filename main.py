#metasploit was a big inspiration for the ui so it looks similar

from core.engine import PentestEngine
from core.logger import log_info

def main():
    print("=" * 50)
    print("      BlackICE – Intrusion Countermeasures Electronics")
    print("                 Version 0.1 – Alpha")
    print("=" * 50)

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
        #i am not gonna implement these modules for the mvp i will do that in other milestones since I still dont know what attack modules would be best to implement
        #"3": {"name": "Wireless", "modules": [
        #]},
        #"4": {"name": "Exploitation", "modules": [
        #]},
        #"5": {"name": "Post-Exploitation", "modules": [
        #]},
        #"6": {"name": "Reporting", "modules": [
        #]}
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
            
            category_choice = input("\nEnter category number: ").strip()

            if category_choice == "0":
                print("\nExiting BlackICE.")
                break

            if category_choice not in available_categories:
                print("❌ Invalid category choice.")
                continue

            category = available_categories[category_choice]
            available_modules = [mod for mod in category["modules"] if mod in engine.modules]
            
            if not available_modules:
                print("❌ No modules available in this category.")
                continue

            while True:
                print(f"\n{category['name']} Modules:")
                print("-" * 30)
                
                for i, mod_name in enumerate(available_modules, 1):
                    module = engine.modules[mod_name]
                    description = getattr(module, 'description', 'No description available')
                    print(f"{i}. {mod_name:<20} - {description}")
                
                print("0. Back to categories")
                
                mod_choice = input("\nEnter module number: ").strip()

                if mod_choice == "0":
                    break

                try:
                    if mod_choice.isdigit():
                        mod_index = int(mod_choice) - 1
                        if 0 <= mod_index < len(available_modules):
                            module_name = available_modules[mod_index]
                            
                            print(f"\n{'='*50}")
                            print(f"🚀 Running: {module_name}")
                            print(f"{'='*50}")
                            
                            engine.run_module(module_name)
                            
                            while True:
                                next_action = input(f"\nWhat would you like to do?\n1. Run another module in {category['name']}\n2. Back to categories\n3. Exit\nChoice (1-3): ").strip()
                                
                                if next_action == "1":
                                    break  
                                elif next_action == "2":
                                    break  
                                elif next_action == "3":
                                    print("\nExiting blackICE.")
                                    return
                                else:
                                    print("❌ Invalid choice. Please enter 1, 2, or 3.")
                            
                            if next_action == "2":
                                break
                                
                        else:
                            print("❌ Invalid module number.")
                    else:
                        print("❌ Please enter a number.")
                        
                except Exception as e:
                    print(f"Error running module: {e}")
                    error_choice = input("\n1. Try another module\n2. Back to categories\nChoice (1-2): ").strip()
                    if error_choice == "2":
                        break

        except KeyboardInterrupt:
            print("\n\nInterrupt received. Returning to main menu...")
            continue
        except Exception as e:
            print(f"Unexpected error: {e}")
            continue

if __name__ == "__main__":
    log_info("BlackICE started")
    main()
