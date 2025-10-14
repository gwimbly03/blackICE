import dns.resolver
import dns.reversename
import socket
import subprocess
from typing import Dict, List, Any

class DNSEnumerator:
    """
    This class is for dns enumeration which finds dns records, subdomains, tries to do zone transfers and reverse dns lookups
    """
    description = "DNS Enumeration finds the DNS records and subdomains"
    
    def __init__(self):
        """
        Initialize DNSEnumerator 
        """
        self.results = {}
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
            'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
            'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3',
            'chat', 'search', 'staging', 'server', 'devel', 'live', 'ad', 'adserver',
            'ads', 'exchange', 'app', 'apps', 'backup', 'crm', 'ftp2', 'mail1', 'ssh',
            'ssl', 'vps', 'web1', 'web2', 'ws1', 'ws2', 'office', 'owa', 'proxy', 'router'
        ]

    
    def enumerate_dns(self, domain: str):
        """
        Runs the entire dns enumeration on a certian url
        """
        self.results = {
            'domain': domain,
            'basic_records': {},
            'subdomains': [],
            'dns_servers': [],
            'zone_transfer': {},
            'reverse_dns': []
        }
        
        self.get_basic_records(domain)
        
        self.enumerate_subdomains(domain)
        
        self.get_dns_servers(domain)
        
        self.attempt_zone_transfer(domain)
        
        self.reverse_dns_lookup()

    def get_basic_records(self, domain: str):
        """
        Gets common dns record types 
        """
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records = [str(rdata) for rdata in answers]
                self.results['basic_records'][record_type] = records
            except Exception as e:
                self.results['basic_records'][record_type] = [f"Error: {e}"]

    def enumerate_subdomains(self, domain: str):
        """
        Will brute force subdomains and tries to discover other subdomains using zone transfer
        """
        found_subdomains = set()
        
        print("Brute-forcing common subdomains...")
        for subdomain in self.common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                dns.resolver.resolve(full_domain, 'A')
                found_subdomains.add(full_domain)
                print(f"Found: {full_domain}")
            except:
                pass
        
        if 'NS' in self.results['basic_records']:
            for ns_server in self.results['basic_records']['NS']:
                try:
                    axfr_answers = self.attempt_zone_transfer_single(ns_server, domain)
                    for record in axfr_answers:
                        if domain in str(record):
                            found_subdomains.add(str(record).split()[0])
                except:
                    pass
        
        self.results['subdomains'] = sorted(list(found_subdomains))

    def get_dns_servers(self, domain: str):
        """
        Gets authoritative name servers for url
        """
        try:
            if 'NS' in self.results['basic_records']:
                self.results['dns_servers'] = self.results['basic_records']['NS']
        except Exception as e:
            self.results['dns_servers'] = [f"Error: {e}"]

    def attempt_zone_transfer(self, domain: str):
        """
        Tries to zone transfer AXFR on the discovered name servers
        """

        zone_transfer_results = {}
        
        if 'NS' in self.results['basic_records']:
            for ns_server in self.results['basic_records']['NS']:
                try:
                    answers = self.attempt_zone_transfer_single(ns_server, domain)
                    zone_transfer_results[ns_server] = [str(r) for r in answers]
                except Exception as e:
                    zone_transfer_results[ns_server] = f"Failed: {e}"
        
        self.results['zone_transfer'] = zone_transfer_results

    def attempt_zone_transfer_single(self, ns_server: str, domain: str):
        """
        Only does a single zone transfer for name server
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [socket.gethostbyname(ns_server)]
            answers = resolver.resolve(domain, 'AXFR')
            return answers
        except:
            raise Exception("Zone transfer failed or not allowed")

    def reverse_dns_lookup(self):
        """
        Reverse DNS lookup on the the dns record (A) IP to get possible hostname
        """
        reverse_results = []
        
        if 'A' in self.results['basic_records']:
            for ip in self.results['basic_records']['A']:
                if ip.startswith('Error:'):
                    continue
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    reverse_results.append(f"{ip} -> {hostname}")
                except:
                    reverse_results.append(f"{ip} -> No PTR record")
        
        self.results['reverse_dns'] = reverse_results

    def display_results(self):
        """
        Displays formatted results of DNSEnumerator to stout
        """
        print(f"\n{'='*60}")
        print(f"DNS ENUMERATION RESULTS: {self.results['domain']}")
        print(f"{'='*60}")
        
        print("\nBASIC DNS RECORDS:")
        print("-" * 40)
        for record_type, records in self.results['basic_records'].items():
            print(f"{record_type}:")
            for record in records:
                print(f"  └─ {record}")
        
        print(f"\nSUBDOMAINS FOUND ({len(self.results['subdomains'])}):")
        print("-" * 40)
        for subdomain in self.results['subdomains']:
            print(f"  • {subdomain}")
        
        print(f"\nAUTHORITATIVE DNS SERVERS:")
        print("-" * 40)
        for ns in self.results['dns_servers']:
            print(f"  • {ns}")
        
        print(f"\nZONE TRANSFER ATTEMPTS:")
        print("-" * 40)
        for ns, result in self.results['zone_transfer'].items():
            if isinstance(result, list) and result:
                print(f"  {ns}: ZONE TRANSFER ALLOWED!")
                for record in result[:5]:  # Show first 5 records
                    print(f"     └─ {record}")
                if len(result) > 5:
                    print(f"     ... and {len(result) - 5} more records")
            else:
                print(f"  {ns}: {result}")
        
        print(f"\nREVERSE DNS LOOKUPS:")
        print("-" * 40)
        for result in self.results['reverse_dns']:
            print(f"  • {result}")
        
        print(f"\n{'='*60}")
        print(f"Enumeration complete. Found {len(self.results['subdomains'])} subdomains.")
        print(f"{'='*60}")

    def export_results(self, filename: str = None):
        """
        Export the result to a json log
        """
        if not filename:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dns_enum_{self.results['domain']}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                import json
                json.dump(self.results, f, indent=2)
            print(f"\nResults exported to: {filename}")
        except Exception as e:
            print(f"Error exporting results: {e}")

    def run(self):
        domain = input("Enter domain to enumerate (e.x., example.com): ").strip()
        
        if not domain:
            print("No domain specified. Exiting.")
            return
            
        print(f"\nStarting DNS enumeration for: {domain}")
        print("=" * 50)
        
        try:
            self.enumerate_dns(domain)
            self.display_results()
        except Exception as e:
            print(f"Error during DNS enumeration: {e}")


dns_enum = DNSEnumerator()
