from scapy.all import sniff, IP, TCP, UDP, Ether, ARP, ICMP
import time
import threading
from datetime import datetime

class PacketSniffer:
    def __init__(self, callback):
        self.callback = callback
        self.is_running = False
        self.is_paused = False
        self.packet_count = 0
        self.last_packet_time = 0
        self.throttle_interval = 0.2  # 200ms throttle
        
    def start_capture(self):
        """Start packet capture"""
        self.is_running = True
        self.is_paused = False
        print("Starting packet capture...")
        
        try:
            # Capture packets on all interfaces
            sniff(prn=self.process_packet, stop_filter=self.should_stop, store=0)
        except Exception as e:
            print(f"Error during packet capture: {e}")
            print("Make sure you're running with sudo privileges")
    
    def process_packet(self, packet):
        """Process captured packet and extract information"""
        if self.is_paused or not self.is_running:
            return
            
        # Throttle packet processing
        current_time = time.time()
        if current_time - self.last_packet_time < self.throttle_interval:
            return
        
        self.last_packet_time = current_time
        self.packet_count += 1
        
        try:
            packet_info = self.extract_packet_info(packet)
            if packet_info:
                self.callback(packet_info)
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        packet_info = {
            'id': self.packet_count,
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'protocol': 'Unknown',
            'size': len(packet),
            'src_ip': 'N/A',
            'dst_ip': 'N/A',
            'src_port': 'N/A',
            'dst_port': 'N/A',
            'src_mac': 'N/A',
            'dst_mac': 'N/A'
        }
        
        # Extract Ethernet information
        if packet.haslayer(Ether):
            ether = packet[Ether]
            packet_info['src_mac'] = ether.src
            packet_info['dst_mac'] = ether.dst
        
        # Extract IP information
        if packet.haslayer(IP):
            ip = packet[IP]
            packet_info['src_ip'] = ip.src
            packet_info['dst_ip'] = ip.dst
            
            # Determine protocol
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = tcp.sport
                packet_info['dst_port'] = tcp.dport
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = udp.sport
                packet_info['dst_port'] = udp.dport
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
            else:
                packet_info['protocol'] = f'IP ({ip.proto})'
        
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            packet_info['protocol'] = 'ARP'
            packet_info['src_ip'] = arp.psrc
            packet_info['dst_ip'] = arp.pdst
        
        return packet_info
    
    def pause(self):
        """Pause packet capture"""
        self.is_paused = True
        print("Packet capture paused")
    
    def resume(self):
        """Resume packet capture"""
        self.is_paused = False
        print("Packet capture resumed")
    
    def stop(self):
        """Stop packet capture"""
        self.is_running = False
        self.is_paused = True
        print("Packet capture stopped")
    
    def should_stop(self, packet):
        """Stop filter for scapy sniff"""
        return not self.is_running
