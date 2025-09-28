import tkinter as tk
from tkinter import ttk, filedialog
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap, Raw
from collections import Counter
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import time

class PacketSnifferApp:
    def __init__(self, root): 
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("1100x600")   # wider to fit payload
        self.root.resizable(False, False)
        self.stop_sniffing_flag = False
        self.packets = []
        self.suspicious_ips = ["192.168.1.100", "10.0.0.50"]  # Example

        # Title
        tk.Label(root, text="Network Packet Sniffer", font=("Arial", 16, "bold")).pack(pady=10)

        # Buttons
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Start Sniffing", command=self.start_sniffing, bg="#4CAF50", fg="white", width=15).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Stop Sniffing", command=self.stop_sniffing, bg="#f44336", fg="white", width=15).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="Save Packets", command=self.save_packets, bg="#2196F3", fg="white", width=15).grid(row=0, column=2, padx=5)

        # Search
        search_frame = tk.Frame(root)
        search_frame.pack(pady=5)
        tk.Label(search_frame, text="Search IP/Protocol:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.filter_packets)
        tk.Entry(search_frame, textvariable=self.search_var, width=40).pack(side="left", padx=5)

        # Packet Table
        columns = ("src", "dst", "proto", "payload")
        self.tree = ttk.Treeview(root, columns=columns, show="headings", height=15)
        for col in columns:
            self.tree.heading(col, text=col.title())
            if col == "payload":
                self.tree.column(col, width=400)  # wider for payload text
            else:
                self.tree.column(col, width=150)
        self.tree.pack(fill="both", expand=True, pady=10)

        scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        # Dashboard (Charts)
        dashboard_frame = tk.Frame(root)
        dashboard_frame.pack(fill="both", expand=True, pady=10)

        self.fig = plt.Figure(figsize=(9,4))  # Bigger figure for clear charts
        self.ax1 = self.fig.add_subplot(121)
        self.ax2 = self.fig.add_subplot(122)

        self.canvas = FigureCanvasTkAgg(self.fig, master=dashboard_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # Start dashboard updater
        threading.Thread(target=self.update_dashboard, daemon=True).start()

    # --- Sniffing ---
    def start_sniffing(self):
        self.stop_sniffing_flag = False
        threading.Thread(target=self.sniff_packets, daemon=True).start()
        print("[*] Sniffing started")

    def stop_sniffing(self):
        self.stop_sniffing_flag = True
        print("[*] Sniffing stopped")

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=False, stop_filter=lambda x: self.stop_sniffing_flag)

    def packet_callback(self, pkt):
        self.packets.append(pkt)
        self.add_packet_to_table(pkt)

    # --- Table with colors + payload ---
    def add_packet_to_table(self, pkt):
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "ICMP" if ICMP in pkt else "Other"

            # Extract payload (if present)
            payload = ""
            if Raw in pkt:
                try:
                    payload = bytes(pkt[Raw].load).decode(errors="ignore")
                except:
                    payload = str(pkt[Raw].load)
                payload = payload[:100] + "..." if len(payload) > 100 else payload  # truncate

            # Filter check
            f = self.search_var.get().lower()
            if f and f not in src.lower() and f not in dst.lower() and f not in proto.lower() and f not in payload.lower():
                return

            item = self.tree.insert("", "end", values=(src, dst, proto, payload))

            # Row color
            color = "white"
            if src in self.suspicious_ips or dst in self.suspicious_ips:
                color = "red"
            elif proto == "TCP":
                color = "lightblue"
            elif proto == "UDP":
                color = "lightgreen"
            elif proto == "ICMP":
                color = "lightyellow"

            self.tree.tag_configure(item, background=color)
            self.tree.item(item, tags=(item,))

    # --- Filter ---
    def filter_packets(self, *args):
        self.tree.delete(*self.tree.get_children())
        for pkt in self.packets:
            self.add_packet_to_table(pkt)

    # --- Save ---
    def save_packets(self):
        if not self.packets:
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files","*.pcap")])
        if file_path:
            wrpcap(file_path, self.packets)
            print(f"[*] Saved to {file_path}")

    # --- Dashboard ---
    def update_dashboard(self):
        while True:
            if self.packets:
                ips = [pkt[IP].src for pkt in self.packets if IP in pkt]
                protocols = [pkt.proto for pkt in self.packets if IP in pkt]

                top_ips = Counter(ips).most_common(5)
                top_protocols = Counter(protocols).most_common(5)

                self.ax1.clear()
                self.ax2.clear()

                if top_ips:
                    self.ax1.bar([ip for ip,_ in top_ips], [count for _,count in top_ips])
                    self.ax1.set_title("Top IPs")
                    self.ax1.set_xticklabels([ip for ip,_ in top_ips], rotation=45)
                if top_protocols:
                    self.ax2.bar([str(proto) for proto,_ in top_protocols], [count for _,count in top_protocols])
                    self.ax2.set_title("Top Protocols")

                self.fig.tight_layout()   # Fix overlapping
                self.canvas.draw_idle()
            time.sleep(2)

if __name__ == "__main__":  
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
