import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, IP, TCP, UDP  # Import required layers from scapy
import threading

class SimpleFirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Firewall")
        self.root.geometry("400x400")

        # Blocked IPs and Ports
        self.blocked_ips = []
        self.blocked_ports = []

        # Start Firewall status
        self.firewall_running = False

        # GUI Elements
        self.create_widgets()

    def create_widgets(self):
        # Title Label
        self.title_label = tk.Label(self.root, text="Simple Firewall", font=("Arial", 16))
        self.title_label.pack(pady=10)

        # Blocked IP Listbox
        self.blocked_ip_label = tk.Label(self.root, text="Blocked IPs:")
        self.blocked_ip_label.pack(pady=5)
        self.blocked_ip_listbox = tk.Listbox(self.root, height=6, width=30)
        self.blocked_ip_listbox.pack(pady=5)

        # IP input & button
        self.ip_entry_label = tk.Label(self.root, text="Enter IP to Block:")
        self.ip_entry_label.pack(pady=5)
        self.ip_entry = tk.Entry(self.root)
        self.ip_entry.pack(pady=5)

        self.block_ip_button = tk.Button(self.root, text="Block IP", command=self.block_ip)
        self.block_ip_button.pack(pady=5)

        # Blocked Port Listbox
        self.blocked_port_label = tk.Label(self.root, text="Blocked Ports:")
        self.blocked_port_label.pack(pady=5)
        self.blocked_port_listbox = tk.Listbox(self.root, height=6, width=30)
        self.blocked_port_listbox.pack(pady=5)

        # Port input & button
        self.port_entry_label = tk.Label(self.root, text="Enter Port to Block:")
        self.port_entry_label.pack(pady=5)
        self.port_entry = tk.Entry(self.root)
        self.port_entry.pack(pady=5)

        self.block_port_button = tk.Button(self.root, text="Block Port", command=self.block_port)
        self.block_port_button.pack(pady=5)

        # Start/Stop Firewall button
        self.start_button = tk.Button(self.root, text="Start Firewall", command=self.toggle_firewall)
        self.start_button.pack(pady=20)

        # Firewall Status
        self.status_label = tk.Label(self.root, text="Firewall is OFF", fg="red")
        self.status_label.pack(pady=10)

    def block_ip(self):
        ip = self.ip_entry.get()
        if ip and ip not in self.blocked_ips:
            self.blocked_ips.append(ip)
            self.blocked_ip_listbox.insert(tk.END, ip)
        self.ip_entry.delete(0, tk.END)

    def block_port(self):
        port = self.port_entry.get()
        if port.isdigit() and port not in self.blocked_ports:
            self.blocked_ports.append(port)
            self.blocked_port_listbox.insert(tk.END, port)
        self.port_entry.delete(0, tk.END)

    def toggle_firewall(self):
        if self.firewall_running:
            self.stop_firewall()
        else:
            self.start_firewall()

    def start_firewall(self):
        self.firewall_running = True
        self.start_button.config(text="Stop Firewall")
        self.status_label.config(text="Firewall is ON", fg="green")
        
        # Start the packet sniffer in a separate thread
        firewall_thread = threading.Thread(target=self.sniff_packets)
        firewall_thread.daemon = True
        firewall_thread.start()

    def stop_firewall(self):
        self.firewall_running = False
        self.start_button.config(text="Start Firewall")
        self.status_label.config(text="Firewall is OFF", fg="red")

    def packet_filter(self, packet):
        if packet.haslayer(IP):
            # Get IP addresses
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Block IP if it's in the blocked list
            if src_ip in self.blocked_ips or dst_ip in self.blocked_ips:
                print(f"Blocked packet from/to {src_ip} -> {dst_ip}")
                return None  # Drop packet

            # Check if the packet has transport layer (TCP/UDP) and check the port
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                src_port = packet.sport
                dst_port = packet.dport
                if str(src_port) in self.blocked_ports or str(dst_port) in self.blocked_ports:
                    print(f"Blocked packet on port {src_port} -> {dst_port}")
                    return None  # Drop packet
        
        return packet

    def sniff_packets(self):
        print("Firewall is active. Press Ctrl+C to stop.")
        sniff(prn=self.packet_filter, store=0, iface="eth0")  # Adjust interface if necessary

# Create the root window
root = tk.Tk()

# Create the app
app = SimpleFirewallApp(root)

# Start the GUI
root.mainloop()
